//! Systemd unit file authoring for Xray (`Create` / `Edit`).
//!
//! Apply pipeline (ASCII):
//! ```text
//! UnitSpec → preflight (writable + config readable for User=)
//!   → backup if exists → write (SFTP or sudo -S install)
//!   → daemon-reload → on failure restore backup
//! ```
//!
//! Not on [`super::InitSystemManager`] — systemd-only (Lean Approach B).

use feldjaeger_ssh::{RemoteCommand, RemotePath, SshSession};
use tracing::{error, info, warn};

use super::error::{UnitFileError, UnitFileErrorKind, UnitFileResult};
use super::service_name::ServiceName;
use crate::remote::BackupManager;
use crate::xray::ConfigSource;

/// Default unit description (not shown in GUI v1).
pub const DEFAULT_UNIT_DESCRIPTION: &str = "Xray Service";
/// Default WantedBy target.
pub const DEFAULT_WANTED_BY: &str = "multi-user.target";
/// Default binary when discovery has none.
pub const DEFAULT_XRAY_BINARY: &str = "/usr/local/bin/xray";
/// Default single-file config when discovery has none.
pub const DEFAULT_XRAY_CONFIG: &str = "/usr/local/etc/xray/config.json";
/// Directory for managed unit files.
pub const SYSTEMD_SYSTEM_DIR: &str = "/etc/systemd/system";

/// Who the unit runs as (official install-release shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnitRunUser {
    /// `User=nobody` with caps enabled.
    #[default]
    Nobody,
    /// `User=root` with caps / NoNewPrivileges commented out.
    Root,
}

impl UnitRunUser {
    /// systemd `User=` value.
    pub fn as_systemd_user(self) -> &'static str {
        match self {
            Self::Nobody => "nobody",
            Self::Root => "root",
        }
    }
}

/// Config layout encoded into `ExecStart`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitConfigLayout {
    /// `run -config <path>`
    SingleFile(RemotePath),
    /// `run -confdir <path>`
    ConfigDirectory(RemotePath),
}

impl UnitConfigLayout {
    /// Path used for preflight.
    pub fn path(&self) -> &RemotePath {
        match self {
            Self::SingleFile(p) | Self::ConfigDirectory(p) => p,
        }
    }
}

/// Intent for a managed Xray unit file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSpec {
    /// Unit file name including `.service` (e.g. `xray.service`).
    pub unit_name: ServiceName,
    /// `[Unit] Description=`
    pub description: String,
    /// Xray binary path.
    pub binary: RemotePath,
    /// Config file or directory.
    pub config: UnitConfigLayout,
    /// Process user.
    pub user: UnitRunUser,
    /// `[Install] WantedBy=`
    pub wanted_by: String,
}

impl UnitSpec {
    /// Prefill from discovery fields; defaults when missing.
    pub fn from_discovery(
        service_name: Option<&str>,
        binary_path: Option<&RemotePath>,
        config_source: &ConfigSource,
        create: bool,
    ) -> UnitFileResult<Self> {
        let unit_name = if create {
            ServiceName::new(service_name.unwrap_or("xray.service")).map_err(|e| {
                UnitFileError::new(UnitFileErrorKind::InvalidSpec, e.message().to_owned())
            })?
        } else {
            let name = service_name.ok_or_else(|| {
                UnitFileError::new(
                    UnitFileErrorKind::InvalidSpec,
                    "service name required for edit",
                )
            })?;
            ServiceName::new(name).map_err(|e| {
                UnitFileError::new(UnitFileErrorKind::InvalidSpec, e.message().to_owned())
            })?
        };

        if unit_name.as_str().contains('@') {
            return Err(UnitFileError::new(
                UnitFileErrorKind::InvalidSpec,
                "instance units (name contains @) are not supported for Create/Edit",
            ));
        }

        let binary = match binary_path {
            Some(p) => p.clone(),
            None => RemotePath::new(DEFAULT_XRAY_BINARY).map_err(|e| {
                UnitFileError::new(UnitFileErrorKind::InvalidSpec, e.message().to_owned())
            })?,
        };

        let config = match config_source {
            ConfigSource::SingleFile(p) => UnitConfigLayout::SingleFile(p.clone()),
            ConfigSource::ConfigDirectory(p) => UnitConfigLayout::ConfigDirectory(p.clone()),
            ConfigSource::NotFound | ConfigSource::Unknown => {
                UnitConfigLayout::SingleFile(RemotePath::new(DEFAULT_XRAY_CONFIG).map_err(|e| {
                    UnitFileError::new(UnitFileErrorKind::InvalidSpec, e.message().to_owned())
                })?)
            }
        };

        Ok(Self {
            unit_name,
            description: DEFAULT_UNIT_DESCRIPTION.to_owned(),
            binary,
            config,
            user: UnitRunUser::Nobody,
            wanted_by: DEFAULT_WANTED_BY.to_owned(),
        })
    }
}

/// Absolute path `/etc/systemd/system/{name}`.
pub fn unit_file_path(unit_name: &ServiceName) -> UnitFileResult<RemotePath> {
    let path = format!("{SYSTEMD_SYSTEM_DIR}/{}", unit_name.as_str());
    RemotePath::new(path).map_err(|e| {
        UnitFileError::new(UnitFileErrorKind::InvalidSpec, e.message().to_owned())
    })
}

/// Returns true if the unit name is an instance (`@`).
pub fn is_instance_unit_name(name: &str) -> bool {
    name.contains('@')
}

/// Quote a systemd ExecStart path token when needed.
pub fn systemd_quote(path: &str) -> UnitFileResult<String> {
    if path.contains('"') || path.contains('\n') || path.contains('\r') {
        return Err(UnitFileError::new(
            UnitFileErrorKind::InvalidSpec,
            "path must not contain quotes or newlines",
        ));
    }
    let needs_quote = path.chars().any(|c| c.is_whitespace() || matches!(c, '\\' | '\'' | '$' | '`' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '{' | '}'));
    if needs_quote {
        Ok(format!("\"{path}\""))
    } else {
        Ok(path.to_owned())
    }
}

/// Render a full unit file body (official install-release fields, single file).
pub fn render_unit(spec: &UnitSpec) -> UnitFileResult<String> {
    if is_instance_unit_name(spec.unit_name.as_str()) {
        return Err(UnitFileError::new(
            UnitFileErrorKind::InvalidSpec,
            "instance units are not supported",
        ));
    }
    if spec.wanted_by.trim().is_empty()
        || spec.wanted_by.contains('\n')
        || spec.wanted_by.contains(' ')
    {
        return Err(UnitFileError::new(
            UnitFileErrorKind::InvalidSpec,
            "invalid WantedBy target",
        ));
    }

    let binary = systemd_quote(spec.binary.as_str())?;
    let config_path = systemd_quote(spec.config.path().as_str())?;
    let exec = match &spec.config {
        UnitConfigLayout::SingleFile(_) => {
            format!("ExecStart={binary} run -config {config_path}")
        }
        UnitConfigLayout::ConfigDirectory(_) => {
            format!("ExecStart={binary} run -confdir {config_path}")
        }
    };

    let (caps, ambient, nnp) = match spec.user {
        UnitRunUser::Nobody => (
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
            "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
            "NoNewPrivileges=true",
        ),
        UnitRunUser::Root => (
            "#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
            "#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
            "#NoNewPrivileges=true",
        ),
    };

    let body = format!(
        "\
[Unit]
Description={description}
After=network.target nss-lookup.target

[Service]
User={user}
{caps}
{ambient}
{nnp}
{exec}
Restart=on-failure
LimitNPROC=10000

[Install]
WantedBy={wanted_by}
",
        description = spec.description,
        user = spec.user.as_systemd_user(),
        wanted_by = spec.wanted_by,
    );

    // Invariant: never DynamicUser; always a User= line.
    debug_assert!(!body.contains("DynamicUser="));
    Ok(body)
}

/// Live ExecStart preview line for the GUI.
pub fn preview_exec_start(spec: &UnitSpec) -> UnitFileResult<String> {
    let body = render_unit(spec)?;
    body.lines()
        .find(|l| l.starts_with("ExecStart="))
        .map(str::to_owned)
        .ok_or_else(|| {
            UnitFileError::new(UnitFileErrorKind::InvalidSpec, "ExecStart missing from render")
        })
}

/// Options for [`install_or_replace_unit`].
#[derive(Debug, Clone, Default)]
pub struct InstallUnitOptions {
    /// When set, privileged steps use `sudo -S` with this password (never log).
    pub sudo_password: Option<String>,
}

/// Host probe for Create/Edit gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnitHostProbe {
    /// `/etc/systemd/system/{name}` exists.
    pub etc_unit_exists: bool,
    /// SSH user can write the unit directory (or is root).
    pub can_write_unit_dir: bool,
}

/// Probe whether the unit file exists under `/etc/systemd/system`.
pub async fn probe_unit_file_exists<S: SshSession + Sync>(
    session: &S,
    unit_name: &ServiceName,
) -> UnitFileResult<bool> {
    let path = unit_file_path(unit_name)?;
    let cmd = RemoteCommand::new(
        "test",
        vec!["-f".to_owned(), path.as_str().to_owned()],
    )
    .map_err(|e| UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned()))?;
    let result = session.exec(&cmd).await.map_err(map_ssh)?;
    Ok(result.exit_code == 0)
}

/// Probe root or writable `/etc/systemd/system`.
pub async fn probe_can_write_unit_dir<S: SshSession + Sync>(session: &S) -> UnitFileResult<bool> {
    let id_cmd = RemoteCommand::new("id", vec!["-u".to_owned()])
        .map_err(|e| UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned()))?;
    let id = session.exec(&id_cmd).await.map_err(map_ssh)?;
    if id.exit_code == 0 {
        let uid = String::from_utf8_lossy(&id.stdout).trim().to_owned();
        if uid == "0" {
            return Ok(true);
        }
    }

    let test_cmd = RemoteCommand::new(
        "test",
        vec![
            "-w".to_owned(),
            SYSTEMD_SYSTEM_DIR.to_owned(),
        ],
    )
    .map_err(|e| UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned()))?;
    let result = session.exec(&test_cmd).await.map_err(map_ssh)?;
    Ok(result.exit_code == 0)
}

/// Full host probe for a unit name.
pub async fn probe_unit_host<S: SshSession + Sync>(
    session: &S,
    unit_name: &ServiceName,
) -> UnitFileResult<UnitHostProbe> {
    Ok(UnitHostProbe {
        etc_unit_exists: probe_unit_file_exists(session, unit_name).await?,
        can_write_unit_dir: probe_can_write_unit_dir(session).await?,
    })
}

/// Preflight: config path must be readable by the unit user (mode-bit oriented).
pub async fn preflight_config_readable<S: SshSession + Sync>(
    session: &S,
    spec: &UnitSpec,
) -> UnitFileResult<()> {
    match &spec.config {
        UnitConfigLayout::SingleFile(path) => {
            ensure_other_readable_file(session, path).await?;
            ensure_parents_other_executable(session, path).await?;
        }
        UnitConfigLayout::ConfigDirectory(path) => {
            ensure_dir_other_rx(session, path).await?;
            ensure_parents_other_executable(session, path).await?;
            // Empty dir: warn only (still allow).
            let ls = RemoteCommand::new(
                "find",
                vec![
                    path.as_str().to_owned(),
                    "-maxdepth".to_owned(),
                    "1".to_owned(),
                    "-type".to_owned(),
                    "f".to_owned(),
                    "-name".to_owned(),
                    "*.json".to_owned(),
                ],
            )
            .map_err(|e| {
                UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned())
            })?;
            let out = session.exec(&ls).await.map_err(map_ssh)?;
            if out.exit_code == 0 {
                let files = String::from_utf8_lossy(&out.stdout);
                if files.trim().is_empty() {
                    warn!(
                        target: "init",
                        path = %path.as_str(),
                        "confdir has no *.json files; Apply allowed with warning"
                    );
                } else {
                    for line in files.lines() {
                        let p = line.trim();
                        if p.is_empty() {
                            continue;
                        }
                        let rp = RemotePath::new(p).map_err(|e| {
                            UnitFileError::new(
                                UnitFileErrorKind::PreflightFailed,
                                e.message().to_owned(),
                            )
                        })?;
                        ensure_other_readable_file(session, &rp).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn ensure_other_readable_file<S: SshSession + Sync>(
    session: &S,
    path: &RemotePath,
) -> UnitFileResult<()> {
    // Prefer stat -c %a; fall back to test -r as secondary signal only for existence.
    let stat = RemoteCommand::new(
        "stat",
        vec!["-c".to_owned(), "%a".to_owned(), path.as_str().to_owned()],
    )
    .map_err(|e| UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned()))?;
    let result = session.exec(&stat).await.map_err(map_ssh)?;
    if result.exit_code != 0 {
        return Err(UnitFileError::new(
            UnitFileErrorKind::PreflightFailed,
            format!("config path not readable for unit user: {}", path.as_str()),
        ));
    }
    let mode = String::from_utf8_lossy(&result.stdout).trim().to_owned();
    let mode_num = mode.parse::<u32>().unwrap_or(0);
    // other-read bit: 0004
    if mode_num & 0o004 == 0 {
        return Err(UnitFileError::new(
            UnitFileErrorKind::PreflightFailed,
            format!(
                "config file needs other-read (o+r) for User=nobody; mode={mode} path={}",
                path.as_str()
            ),
        ));
    }
    Ok(())
}

async fn ensure_dir_other_rx<S: SshSession + Sync>(
    session: &S,
    path: &RemotePath,
) -> UnitFileResult<()> {
    let stat = RemoteCommand::new(
        "stat",
        vec!["-c".to_owned(), "%a".to_owned(), path.as_str().to_owned()],
    )
    .map_err(|e| UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned()))?;
    let result = session.exec(&stat).await.map_err(map_ssh)?;
    if result.exit_code != 0 {
        return Err(UnitFileError::new(
            UnitFileErrorKind::PreflightFailed,
            format!("config directory missing: {}", path.as_str()),
        ));
    }
    let mode = String::from_utf8_lossy(&result.stdout).trim().to_owned();
    let mode_num = mode.parse::<u32>().unwrap_or(0);
    if mode_num & 0o005 != 0o005 {
        return Err(UnitFileError::new(
            UnitFileErrorKind::PreflightFailed,
            format!(
                "config directory needs other rx (o+rx); mode={mode} path={}",
                path.as_str()
            ),
        ));
    }
    Ok(())
}

async fn ensure_parents_other_executable<S: SshSession + Sync>(
    session: &S,
    path: &RemotePath,
) -> UnitFileResult<()> {
    // Walk parents with path truncation (no shell).
    let mut current = path.as_str().to_owned();
    loop {
        let parent = match current.rsplit_once('/') {
            Some(("", _)) => break, // "/"
            Some((p, _)) if p.is_empty() => "/".to_owned(),
            Some((p, _)) => p.to_owned(),
            None => break,
        };
        if parent == "/" {
            break;
        }
        let parent_path = RemotePath::new(&parent).map_err(|e| {
            UnitFileError::new(UnitFileErrorKind::PreflightFailed, e.message().to_owned())
        })?;
        let stat = RemoteCommand::new(
            "stat",
            vec![
                "-c".to_owned(),
                "%a".to_owned(),
                parent_path.as_str().to_owned(),
            ],
        )
        .map_err(|e| {
            UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned())
        })?;
        let result = session.exec(&stat).await.map_err(map_ssh)?;
        if result.exit_code != 0 {
            return Err(UnitFileError::new(
                UnitFileErrorKind::PreflightFailed,
                format!("parent path not accessible: {parent}"),
            ));
        }
        let mode = String::from_utf8_lossy(&result.stdout).trim().to_owned();
        let mode_num = mode.parse::<u32>().unwrap_or(0);
        if mode_num & 0o001 == 0 {
            return Err(UnitFileError::new(
                UnitFileErrorKind::PreflightFailed,
                format!("parent needs other-execute (o+x); mode={mode} path={parent}"),
            ));
        }
        current = parent;
    }
    Ok(())
}

/// Install or replace the unit file; daemon-reload; restore on failure.
pub async fn install_or_replace_unit<S: SshSession + Sync>(
    session: &S,
    spec: &UnitSpec,
    options: InstallUnitOptions,
) -> UnitFileResult<()> {
    if is_instance_unit_name(spec.unit_name.as_str()) {
        return Err(UnitFileError::new(
            UnitFileErrorKind::InvalidSpec,
            "instance units are not supported",
        ));
    }

    let path = unit_file_path(&spec.unit_name)?;
    let body = render_unit(spec)?;
    let bytes = body.into_bytes();

    let can_write = probe_can_write_unit_dir(session).await?;
    let use_sudo = !can_write;
    if use_sudo && options.sudo_password.is_none() {
        return Err(UnitFileError::new(
            UnitFileErrorKind::PermissionDenied,
            "cannot write /etc/systemd/system; provide sudo password or reconnect as root",
        ));
    }

    preflight_config_readable(session, spec).await?;

    let exists = probe_unit_file_exists(session, &spec.unit_name).await?;
    let backup_manager = BackupManager::new();
    let backup = if exists {
        Some(
            backup_manager
                .create_backup(session, &path)
                .await
                .map_err(|e| {
                    UnitFileError::new(UnitFileErrorKind::BackupFailed, e.message().to_owned())
                })?,
        )
    } else {
        None
    };

    let write_result = if use_sudo {
        let password = options.sudo_password.as_deref().unwrap_or("");
        sudo_write_unit_file(session, &path, &bytes, password).await
    } else {
        session
            .write_file_atomic(&path, &bytes)
            .await
            .map_err(|e| UnitFileError::new(UnitFileErrorKind::WriteFailed, e.message().to_owned()))
    };

    if let Err(err) = write_result {
        if let Some(ref b) = backup {
            let _ = backup_manager.restore_backup(session, b).await;
        }
        return Err(err);
    }

    info!(
        target: "init",
        unit = %spec.unit_name.as_str(),
        path = %path.as_str(),
        "unit file written"
    );

    let reload = if use_sudo {
        let password = options.sudo_password.as_deref().unwrap_or("");
        sudo_daemon_reload(session, password).await
    } else {
        daemon_reload(session).await
    };

    if let Err(err) = reload {
        error!(target: "init", error = %err, "daemon-reload failed after unit write");
        if let Some(ref b) = backup {
            if let Err(restore_err) = backup_manager.restore_backup(session, b).await {
                error!(
                    target: "init",
                    error = %restore_err,
                    "best-effort unit backup restore failed"
                );
            } else {
                warn!(target: "init", "restored unit file from backup after daemon-reload failure");
            }
        }
        return Err(err);
    }

    Ok(())
}

async fn daemon_reload<S: SshSession + Sync>(session: &S) -> UnitFileResult<()> {
    let cmd = RemoteCommand::new("systemctl", vec!["daemon-reload".to_owned()]).map_err(|e| {
        UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned())
    })?;
    let result = session.exec(&cmd).await.map_err(map_ssh)?;
    if result.exit_code != 0 {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let detail = crate::logging::redact::sanitize_detail(stderr.trim());
        return Err(UnitFileError::new(
            UnitFileErrorKind::DaemonReloadFailed,
            format!("systemctl daemon-reload failed: {detail}"),
        ));
    }
    Ok(())
}

async fn sudo_daemon_reload<S: SshSession + Sync>(
    session: &S,
    password: &str,
) -> UnitFileResult<()> {
    let cmd = RemoteCommand::new(
        "sudo",
        vec![
            "-S".to_owned(),
            "--".to_owned(),
            "systemctl".to_owned(),
            "daemon-reload".to_owned(),
        ],
    )
    .map_err(|e| UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned()))?;
    let mut stdin = password.as_bytes().to_vec();
    stdin.push(b'\n');
    let result = session
        .exec_with_stdin(&cmd, &stdin)
        .await
        .map_err(map_ssh)?;
    // Best-effort wipe of local stdin copy
    for b in &mut stdin {
        *b = 0;
    }
    if result.exit_code != 0 {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let lower = stderr.to_ascii_lowercase();
        let kind = if lower.contains("sorry")
            || lower.contains("password")
            || lower.contains("authentication")
        {
            UnitFileErrorKind::SudoFailed
        } else {
            UnitFileErrorKind::DaemonReloadFailed
        };
        let detail = crate::logging::redact::sanitize_detail(stderr.trim());
        return Err(UnitFileError::new(
            kind,
            format!("sudo systemctl daemon-reload failed: {detail}"),
        ));
    }
    Ok(())
}

async fn sudo_write_unit_file<S: SshSession + Sync>(
    session: &S,
    path: &RemotePath,
    contents: &[u8],
    password: &str,
) -> UnitFileResult<()> {
    // Write to /tmp then sudo install -m 644
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = RemotePath::new(format!(
        "/tmp/feldjaeger-unit.{stamp}.{}",
        path.as_str().rsplit('/').next().unwrap_or("unit.service")
    ))
    .map_err(|e| UnitFileError::new(UnitFileErrorKind::WriteFailed, e.message().to_owned()))?;

    session
        .write_file(&tmp, contents)
        .await
        .map_err(|e| UnitFileError::new(UnitFileErrorKind::WriteFailed, e.message().to_owned()))?;

    let cmd = RemoteCommand::new(
        "sudo",
        vec![
            "-S".to_owned(),
            "--".to_owned(),
            "install".to_owned(),
            "-m".to_owned(),
            "644".to_owned(),
            tmp.as_str().to_owned(),
            path.as_str().to_owned(),
        ],
    )
    .map_err(|e| UnitFileError::new(UnitFileErrorKind::CommandFailed, e.message().to_owned()))?;

    let mut stdin = password.as_bytes().to_vec();
    stdin.push(b'\n');
    let result = session
        .exec_with_stdin(&cmd, &stdin)
        .await
        .map_err(map_ssh)?;
    for b in &mut stdin {
        *b = 0;
    }

    let _ = session.remove_file(&tmp).await;

    if result.exit_code != 0 {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let lower = stderr.to_ascii_lowercase();
        let kind = if lower.contains("sorry")
            || lower.contains("password")
            || lower.contains("authentication")
        {
            UnitFileErrorKind::SudoFailed
        } else if lower.contains("permission") {
            UnitFileErrorKind::PermissionDenied
        } else {
            UnitFileErrorKind::WriteFailed
        };
        let detail = crate::logging::redact::sanitize_detail(stderr.trim());
        return Err(UnitFileError::new(
            kind,
            format!("sudo install unit failed: {detail}"),
        ));
    }
    Ok(())
}

fn map_ssh(err: feldjaeger_ssh::SshError) -> UnitFileError {
    let msg = err.message().to_owned();
    let lower = msg.to_ascii_lowercase();
    let kind = if lower.contains("connect")
        || lower.contains("connection")
        || lower.contains("disconnect")
        || lower.contains("timeout")
    {
        UnitFileErrorKind::SshConnectionFailed
    } else {
        UnitFileErrorKind::CommandFailed
    };
    UnitFileError::new(kind, crate::logging::redact::sanitize_detail(&msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec(layout: UnitConfigLayout) -> UnitSpec {
        UnitSpec {
            unit_name: ServiceName::new("xray.service").unwrap(),
            description: DEFAULT_UNIT_DESCRIPTION.to_owned(),
            binary: RemotePath::new("/usr/local/bin/xray").unwrap(),
            config: layout,
            user: UnitRunUser::Nobody,
            wanted_by: DEFAULT_WANTED_BY.to_owned(),
        }
    }

    fn has_line(body: &str, line: &str) -> bool {
        body.lines().any(|l| l == line)
    }

    #[test]
    fn render_nobody_has_user_and_caps_no_dynamic_user() {
        let body = render_unit(&sample_spec(UnitConfigLayout::SingleFile(
            RemotePath::new("/usr/local/etc/xray/config.json").unwrap(),
        )))
        .unwrap();
        assert!(has_line(&body, "User=nobody"));
        assert!(!body.lines().any(|l| l.starts_with("DynamicUser=")));
        assert!(!body.lines().any(|l| l.starts_with("Group=")));
        assert!(has_line(
            &body,
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
        ));
        assert!(has_line(&body, "LimitNPROC=10000"));
        assert!(has_line(
            &body,
            "ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json"
        ));
    }

    #[test]
    fn render_root_comments_caps() {
        let mut spec = sample_spec(UnitConfigLayout::SingleFile(
            RemotePath::new("/usr/local/etc/xray/config.json").unwrap(),
        ));
        spec.user = UnitRunUser::Root;
        let body = render_unit(&spec).unwrap();
        assert!(has_line(&body, "User=root"));
        assert!(body.contains("#CapabilityBoundingSet="));
        assert!(body.contains("#NoNewPrivileges=true"));
    }

    #[test]
    fn render_confdir() {
        let body = render_unit(&sample_spec(UnitConfigLayout::ConfigDirectory(
            RemotePath::new("/usr/local/etc/xray").unwrap(),
        )))
        .unwrap();
        assert!(body.contains("run -confdir /usr/local/etc/xray"));
        assert!(!body.contains("run -config "));
    }

    #[test]
    fn quotes_paths_with_spaces() {
        let spec = UnitSpec {
            unit_name: ServiceName::new("xray.service").unwrap(),
            description: DEFAULT_UNIT_DESCRIPTION.to_owned(),
            binary: RemotePath::new("/opt/my bin/xray").unwrap(),
            config: UnitConfigLayout::SingleFile(
                RemotePath::new("/etc/xray/my config.json").unwrap(),
            ),
            user: UnitRunUser::Nobody,
            wanted_by: DEFAULT_WANTED_BY.to_owned(),
        };
        let body = render_unit(&spec).unwrap();
        assert!(body.contains(
            "ExecStart=\"/opt/my bin/xray\" run -config \"/etc/xray/my config.json\""
        ));
    }

    #[test]
    fn rejects_quote_in_path() {
        let err = systemd_quote("/tmp/foo\"bar").unwrap_err();
        assert_eq!(err.kind(), UnitFileErrorKind::InvalidSpec);
    }

    #[test]
    fn rejects_instance_unit() {
        let mut spec = sample_spec(UnitConfigLayout::SingleFile(
            RemotePath::new(DEFAULT_XRAY_CONFIG).unwrap(),
        ));
        spec.unit_name = ServiceName::new("xray@foo.service").unwrap();
        assert!(render_unit(&spec).is_err());
    }
}
