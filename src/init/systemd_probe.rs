//! Read-only systemd unit inspection for discovery.

use feldjaeger_ssh::{ExecResult, RemoteCommand, SshSession};
use tracing::info;

use super::service_name::ServiceName;
use super::{ServiceState, SystemdManager, SystemdManagerOptions};
use crate::error::{AppError, AppResult};

/// Candidate systemd unit names checked during Xray discovery.
pub const XRAY_UNIT_CANDIDATES: &[&str] = &["xray.service", "xray@.service"];

/// Read-only snapshot of a systemd unit relevant to Xray discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUnitProbe {
    /// Unit name as reported by systemd (for example `xray.service`).
    pub unit_name: String,
    /// Effective `ExecStart` text from systemd (includes drop-in overrides).
    pub exec_start: Option<String>,
    /// Parsed service state from `ActiveState` / `is-active`.
    pub state: ServiceState,
    /// Whether systemd reports the unit as loaded.
    pub loaded: bool,
}

impl SystemdManager {
    /// Probes standard Xray unit names using systemd itself (not unit file presence alone).
    ///
    /// Prefers `xray.service`, then a loaded `xray@*.service` instance, then the
    /// `xray@.service` template metadata when no instance is active.
    pub async fn discover_xray_unit<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> AppResult<Option<SystemdUnitProbe>> {
        if let Some(probe) = self.probe_unit(session, "xray.service").await?
            && probe.loaded
        {
            return Ok(Some(probe));
        }

        if let Some(instance) = self.find_xray_instance_unit(session).await?
            && let Some(probe) = self.probe_unit(session, &instance).await?
            && probe.loaded
        {
            return Ok(Some(probe));
        }

        if let Some(probe) = self.probe_unit(session, "xray@.service").await?
            && probe.loaded
        {
            return Ok(Some(probe));
        }

        Ok(None)
    }

    /// Reads unit metadata from systemd (`systemctl show`), including drop-in effects.
    pub async fn probe_unit<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> AppResult<Option<SystemdUnitProbe>> {
        let service = ServiceName::new(service_name)?;
        info!(
            target: "init",
            host = %session.profile().host,
            user = %session.profile().username,
            unit = %service.as_str(),
            "probing systemd unit"
        );

        let result = run_systemctl_show(session, self.options(), service.as_str()).await?;
        if result.exit_code != 0 {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&result.stdout);
        let load_state = property_value(&stdout, "LoadState").unwrap_or("");
        if load_state == "not-found" || load_state.is_empty() {
            return Ok(None);
        }

        let unit_name = property_value(&stdout, "Id")
            .filter(|value| !value.is_empty())
            .unwrap_or(service.as_str())
            .to_owned();

        let active_state = property_value(&stdout, "ActiveState").unwrap_or("");
        let state = match active_state {
            "active" | "activating" | "reloading" => ServiceState::Running,
            "deactivating" => ServiceState::Stopped,
            "inactive" => ServiceState::Inactive,
            "failed" => ServiceState::Failed,
            _ => ServiceState::Unknown,
        };

        let exec_start = property_value(&stdout, "ExecStart")
            .filter(|value| !value.is_empty())
            .map(str::to_owned);

        Ok(Some(SystemdUnitProbe {
            unit_name,
            exec_start,
            state,
            loaded: true,
        }))
    }

    async fn find_xray_instance_unit<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> AppResult<Option<String>> {
        let result = run_systemctl(
            session,
            self.options(),
            vec![
                "list-units".to_owned(),
                "--type=service".to_owned(),
                "--all".to_owned(),
                "--no-legend".to_owned(),
                "--no-pager".to_owned(),
                "--".to_owned(),
                "xray@*".to_owned(),
            ],
        )
        .await?;

        if result.exit_code != 0 {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&result.stdout);
        for line in stdout.lines() {
            let name = line.split_whitespace().next().unwrap_or("");
            if name.starts_with("xray@") && name.ends_with(".service") {
                return Ok(Some(name.to_owned()));
            }
        }

        Ok(None)
    }
}

async fn run_systemctl_show<S: SshSession + Sync>(
    session: &S,
    options: &SystemdManagerOptions,
    unit: &str,
) -> AppResult<ExecResult> {
    run_systemctl(
        session,
        options,
        vec![
            "show".to_owned(),
            "--property=Id".to_owned(),
            "--property=LoadState".to_owned(),
            "--property=ActiveState".to_owned(),
            "--property=ExecStart".to_owned(),
            "--no-pager".to_owned(),
            "--".to_owned(),
            unit.to_owned(),
        ],
    )
    .await
}

async fn run_systemctl<S: SshSession + Sync>(
    session: &S,
    options: &SystemdManagerOptions,
    args: Vec<String>,
) -> AppResult<ExecResult> {
    if options.systemctl_path.is_empty() {
        return Err(AppError::new("systemctl path must not be empty"));
    }
    if options.systemctl_path.chars().any(char::is_whitespace) {
        return Err(AppError::new("systemctl path must not contain whitespace"));
    }

    let command = RemoteCommand::new(&options.systemctl_path, args)
        .map_err(|error| AppError::new(error.message()))?;

    session
        .exec(&command)
        .await
        .map_err(|error| AppError::new(error.message()))
}

fn property_value<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix(key)
            && let Some(value) = rest.strip_prefix('=')
        {
            return Some(value);
        }
    }
    None
}

/// Extracts argv tokens from a systemd `ExecStart=` property value.
///
/// systemd formats the property roughly as:
/// `{ path=/usr/bin/xray ; argv[]=/usr/bin/xray run -c /etc/xray/config.json ; ... }`
pub fn parse_exec_start_argv(exec_start: &str) -> Vec<String> {
    if let Some(start) = exec_start.find("argv[]=") {
        let after = &exec_start[start + "argv[]=".len()..];
        let end = after.find(';').unwrap_or(after.len());
        let argv = after[..end].trim();
        return split_argv(argv);
    }

    // Fallback: treat the whole string as a simple command line.
    split_argv(exec_start.trim())
}

fn split_argv(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

/// Locates `-c` / `-config` / `-confdir` arguments in an ExecStart argv list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecStartConfigArg {
    /// Single config file (`-c` / `-config`).
    File(String),
    /// Config directory (`-confdir`).
    Directory(String),
}

/// Parses Xray config path flags from ExecStart argv tokens.
pub fn extract_config_arg(argv: &[String]) -> Option<ExecStartConfigArg> {
    let mut index = 0;
    while index < argv.len() {
        let token = argv[index].as_str();
        match token {
            "-c" | "-config" | "--config" => {
                if let Some(path) = argv.get(index + 1) {
                    return Some(ExecStartConfigArg::File(path.clone()));
                }
            }
            "-confdir" | "--confdir" => {
                if let Some(path) = argv.get(index + 1) {
                    return Some(ExecStartConfigArg::Directory(path.clone()));
                }
            }
            other if other.starts_with("-c=") || other.starts_with("-config=") => {
                if let Some((_, path)) = other.split_once('=') {
                    return Some(ExecStartConfigArg::File(path.to_owned()));
                }
            }
            other if other.starts_with("-confdir=") || other.starts_with("--confdir=") => {
                if let Some((_, path)) = other.split_once('=') {
                    return Some(ExecStartConfigArg::Directory(path.to_owned()));
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_argv_from_systemd_exec_start() {
        let raw = "{ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
        let argv = parse_exec_start_argv(raw);
        assert_eq!(
            argv,
            vec![
                "/usr/local/bin/xray".to_owned(),
                "run".to_owned(),
                "-c".to_owned(),
                "/usr/local/etc/xray/config.json".to_owned(),
            ]
        );
        assert_eq!(
            extract_config_arg(&argv),
            Some(ExecStartConfigArg::File(
                "/usr/local/etc/xray/config.json".to_owned()
            ))
        );
    }

    #[test]
    fn extracts_confdir_from_argv() {
        let argv = vec![
            "/usr/bin/xray".to_owned(),
            "run".to_owned(),
            "-confdir".to_owned(),
            "/usr/local/etc/xray".to_owned(),
        ];
        assert_eq!(
            extract_config_arg(&argv),
            Some(ExecStartConfigArg::Directory(
                "/usr/local/etc/xray".to_owned()
            ))
        );
    }
}
