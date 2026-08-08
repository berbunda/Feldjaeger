//! Read-only remote Xray installation discovery.

use feldjaeger_ssh::{ExecResult, RemoteCommand, RemotePath, SshError, SshSession};
use tracing::{info, warn};

use super::installation::{
    ConfigSource, DiscoveryErrorKind, DiscoveryWarning, InitSystemKind, XrayInstallation,
};
use super::{
    BurstObservatorySummary, DnsSummary, EditableXrayConfig, FakeDnsSummary, InboundSummary,
    ObservatorySummary, OutboundSummary, PolicySummary, RoutingSummary, VlessClientSummary,
    XrayConfigParser, extract_vless_clients, parse_file_roots,
};
use crate::error::{AppError, AppResult};
use crate::init::{
    ExecStartConfigArg, InitSystemManager, SystemdManager, extract_config_arg,
    parse_exec_start_argv,
};

/// Well-known absolute paths checked when `command -v xray` fails.
const BINARY_FALLBACK_PATHS: &[&str] = &["/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray"];

/// Fallback single-file config paths when ExecStart has no config argument.
const CONFIG_FILE_FALLBACKS: &[&str] =
    &["/usr/local/etc/xray/config.json", "/etc/xray/config.json"];

/// Fallback config directories checked only when they contain `.json` files.
const CONFIG_DIR_FALLBACKS: &[&str] = &["/usr/local/etc/xray", "/etc/xray"];

/// Outcome of a full discovery pass over an active SSH session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum DiscoveryResult {
    /// Xray binary (and related metadata) was found.
    Found {
        /// Installation metadata.
        installation: XrayInstallation,
        /// Parsed inbound summaries when configuration was loaded.
        inbound_summaries: Vec<InboundSummary>,
        /// Parsed outbound summaries when configuration was loaded.
        outbound_summaries: Vec<OutboundSummary>,
        /// Parsed DNS summary when the section was present.
        dns_summary: Option<DnsSummary>,
        /// Parsed FakeDNS summary when the section was present.
        fakedns_summary: Option<FakeDnsSummary>,
        /// Parsed Observatory summary when the section was present.
        observatory_summary: Option<ObservatorySummary>,
        /// Parsed Burst Observatory summary when the section was present.
        burst_observatory_summary: Option<BurstObservatorySummary>,
        /// Parsed routing summary when the section was present.
        routing_summary: Option<RoutingSummary>,
        /// Parsed policy summary when the section was present.
        policy_summary: Option<PolicySummary>,
        /// Parsed VLESS client summaries when configuration was loaded.
        vless_clients: Vec<VlessClientSummary>,
        /// Non-fatal configuration parse warnings (safe for UI).
        config_warnings: Vec<String>,
        /// `true` when configuration JSON was parsed into the internal model.
        config_loaded: bool,
        /// Editable config retained for future write-back when parse succeeded.
        editable_config: Option<EditableXrayConfig>,
    },
    /// Host was probed successfully but no Xray binary exists.
    NotFound {
        /// OS description collected during probing.
        operating_system: String,
        /// Architecture collected during probing.
        architecture: String,
        /// Detected init system.
        init_system: InitSystemKind,
        /// Non-fatal warnings from probing.
        warnings: Vec<DiscoveryWarning>,
    },
    /// Technical failure (SSH lost, permission, unexpected).
    Failed {
        /// Classified failure kind.
        kind: DiscoveryErrorKind,
        /// Safe detail for UI / logs (no secrets).
        detail: String,
    },
}

/// Performs read-only discovery of an existing Xray installation over SSH.
///
/// Never writes files, never restarts services, and never installs packages.
#[derive(Debug, Clone, Default)]
pub struct XrayDiscoveryService {
    parser: XrayConfigParser,
}

impl XrayDiscoveryService {
    /// Creates a discovery service with a default config parser.
    pub fn new() -> Self {
        Self {
            parser: XrayConfigParser::new(),
        }
    }

    /// Discovers Xray on the remote host using the given session and init manager.
    ///
    /// All remote operations are informational / read-only.
    pub async fn discover<S, I>(&self, session: &S, init: &I) -> DiscoveryResult
    where
        S: SshSession + Sync,
        I: InitSystemManager + Sync,
    {
        info!(
            target: "discovery",
            host = %session.profile().host,
            user = %session.profile().username,
            "starting Xray discovery"
        );

        let mut warnings = Vec::new();

        let operating_system = match detect_operating_system(session).await {
            Ok(value) => value,
            Err(error) => return map_fatal_error(error),
        };

        let architecture = match detect_architecture(session).await {
            Ok(value) => value,
            Err(error) => return map_fatal_error(error),
        };

        let init_system = match detect_init_system(session).await {
            Ok(value) => value,
            Err(error) => return map_fatal_error(error),
        };

        if !init_system.supports_service_control() && init_system != InitSystemKind::Unknown {
            warnings.push(DiscoveryWarning::UnsupportedInitSystem { kind: init_system });
        }

        let binary_path = match find_xray_binary(session).await {
            Ok(path) => path,
            Err(error) => return map_fatal_error(error),
        };

        let Some(binary_path) = binary_path else {
            info!(
                target: "discovery",
                host = %session.profile().host,
                user = %session.profile().username,
                "Xray binary not found"
            );
            return DiscoveryResult::NotFound {
                operating_system,
                architecture,
                init_system,
                warnings,
            };
        };

        let version = match query_xray_version(session, &binary_path).await {
            Ok(Some(version)) => Some(version),
            Ok(None) => {
                warnings.push(DiscoveryWarning::VersionUnavailable);
                None
            }
            Err(error) => {
                if is_connection_lost(&error) || is_permission_denied(&error) {
                    return map_fatal_error(error);
                }
                warn!(
                    target: "discovery",
                    path = %binary_path.as_str(),
                    error = %crate::logging::redact::sanitize_detail(error.message()),
                    "Xray version unavailable"
                );
                warnings.push(DiscoveryWarning::VersionUnavailable);
                None
            }
        };

        let mut service_name = None;
        let mut service_state = None;
        let mut exec_start = None;
        let mut config_from_service: Option<ExecStartConfigArg> = None;

        if init_system == InitSystemKind::Systemd {
            // Unit metadata (ExecStart, drop-ins) comes from SystemdManager probes.
            let systemd = SystemdManager::new();
            match systemd.discover_xray_unit(session).await {
                Ok(Some(probe)) => {
                    service_name = Some(probe.unit_name.clone());
                    service_state = Some(probe.state);
                    if let Some(raw) = probe.exec_start {
                        let argv = parse_exec_start_argv(&raw);
                        config_from_service = extract_config_arg(&argv);
                        exec_start = Some(raw);
                    }
                    // Prefer InitSystemManager for lifecycle state.
                    match init.service_state(session, &probe.unit_name).await {
                        Ok(state) => service_state = Some(state),
                        Err(error) => {
                            let app_error = crate::error::AppError::from(error);
                            if is_connection_lost(&app_error) || is_permission_denied(&app_error) {
                                return map_fatal_error(app_error);
                            }
                            warnings.push(DiscoveryWarning::Other {
                                detail: format!(
                                    "service state query failed: {}",
                                    app_error.message()
                                ),
                            });
                        }
                    }
                }
                Ok(None) => {
                    warnings.push(DiscoveryWarning::ServiceNotFound);
                }
                Err(error) => {
                    if is_connection_lost(&error) || is_permission_denied(&error) {
                        return map_fatal_error(error);
                    }
                    warnings.push(DiscoveryWarning::Other {
                        detail: format!("systemd unit probe failed: {}", error.message()),
                    });
                    warnings.push(DiscoveryWarning::ServiceNotFound);
                }
            }
        }

        let config = match resolve_and_read_config(
            session,
            &self.parser,
            config_from_service.as_ref(),
            &mut warnings,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return map_fatal_error(error),
        };

        DiscoveryResult::Found {
            installation: XrayInstallation {
                operating_system,
                architecture,
                init_system,
                binary_path: Some(binary_path),
                version,
                service_name,
                service_state,
                exec_start,
                config_source: config.source,
                config_readable: config.readable,
                config_files: config.files,
                discovery_warnings: warnings,
            },
            inbound_summaries: config.inbound_summaries,
            outbound_summaries: config.outbound_summaries,
            dns_summary: config.dns_summary,
            fakedns_summary: config.fakedns_summary,
            observatory_summary: config.observatory_summary,
            burst_observatory_summary: config.burst_observatory_summary,
            routing_summary: config.routing_summary,
            policy_summary: config.policy_summary,
            vless_clients: config.vless_clients,
            config_warnings: config.parse_warnings,
            config_loaded: config.loaded,
            editable_config: config.editable,
        }
    }
}

async fn detect_operating_system<S: SshSession + Sync>(session: &S) -> AppResult<String> {
    let path = RemotePath::new("/etc/os-release").map_err(app_from_ssh)?;
    match session.read_file(&path).await {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            Ok(parse_os_release(&text))
        }
        Err(error) if is_connection_lost_ssh(&error) || is_permission_denied_ssh(&error) => {
            Err(app_from_ssh(error))
        }
        Err(_) => {
            // Fallback: uname -s
            let result = exec_program(session, "uname", vec!["-s".to_owned()]).await?;
            if result.exit_code == 0 {
                Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
            } else {
                Ok("unknown".to_owned())
            }
        }
    }
}

fn parse_os_release(text: &str) -> String {
    let mut pretty = None;
    let mut name = None;
    let mut version = None;

    for line in text.lines() {
        if let Some(value) = strip_os_release_value(line, "PRETTY_NAME") {
            pretty = Some(value);
        } else if let Some(value) = strip_os_release_value(line, "NAME") {
            name = Some(value);
        } else if let Some(value) = strip_os_release_value(line, "VERSION") {
            version = Some(value);
        }
    }

    if let Some(pretty) = pretty {
        return pretty;
    }

    match (name, version) {
        (Some(name), Some(version)) => format!("{name} {version}"),
        (Some(name), None) => name,
        _ => "Linux".to_owned(),
    }
}

fn strip_os_release_value(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?.strip_prefix('=')?;
    let trimmed = rest.trim().trim_matches('"').to_owned();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

async fn detect_architecture<S: SshSession + Sync>(session: &S) -> AppResult<String> {
    let result = exec_program(session, "uname", vec!["-m".to_owned()]).await?;
    if result.exit_code == 0 {
        Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
    } else {
        Ok("unknown".to_owned())
    }
}

/// Detects the init system from runtime markers (not distribution names).
async fn detect_init_system<S: SshSession + Sync>(session: &S) -> AppResult<InitSystemKind> {
    if remote_path_is_dir(session, "/run/systemd/system").await? {
        return Ok(InitSystemKind::Systemd);
    }

    if remote_command_exists(session, "systemctl").await? {
        return Ok(InitSystemKind::Systemd);
    }

    if remote_path_is_file(session, "/sbin/openrc").await?
        || remote_path_is_file(session, "/usr/sbin/openrc").await?
    {
        return Ok(InitSystemKind::OpenRC);
    }

    // OpenRC often ships /etc/init.d with openrc-run shebang scripts.
    if remote_path_is_dir(session, "/etc/init.d").await?
        && (remote_path_is_file(session, "/sbin/openrc-run").await?
            || remote_path_is_file(session, "/usr/sbin/openrc-run").await?
            || remote_command_exists(session, "rc-service").await?)
    {
        return Ok(InitSystemKind::OpenRC);
    }

    if remote_path_is_dir(session, "/etc/runit").await?
        || remote_path_is_dir(session, "/etc/sv").await?
        || remote_command_exists(session, "sv").await?
    {
        return Ok(InitSystemKind::Runit);
    }

    Ok(InitSystemKind::Unknown)
}

async fn find_xray_binary<S: SshSession + Sync>(session: &S) -> AppResult<Option<RemotePath>> {
    // Official discovery probe: `command -v xray` (POSIX shell builtin via SSH exec).
    let lookup = exec_program(session, "command", vec!["-v".to_owned(), "xray".to_owned()]).await?;

    info!(
        target: "discovery",
        probe = "command -v xray",
        exit_code = lookup.exit_code,
        stdout_bytes = lookup.stdout.len(),
        stderr_bytes = lookup.stderr.len(),
        "xray binary PATH lookup"
    );

    if lookup.exit_code == 0 {
        // Must trim before treating stdout as a path; never compare raw bytes to
        // an absolute path string (trailing newline would falsely reject it).
        if let Some(path) = parse_binary_path_stdout(&lookup.stdout) {
            info!(
                target: "discovery",
                path = %path.as_str(),
                "xray binary found via PATH"
            );
            // A successful `command -v` is authoritative. Do not discard the path
            // if a later `test -x` probe fails — that would incorrectly report
            // "Xray not found" despite a resolved binary.
            return Ok(Some(path));
        }
    }

    for candidate in BINARY_FALLBACK_PATHS {
        let probe = exec_program(
            session,
            "test",
            vec!["-x".to_owned(), (*candidate).to_owned()],
        )
        .await?;
        info!(
            target: "discovery",
            probe = "test -x",
            candidate = %candidate,
            exit_code = probe.exit_code,
            stdout_bytes = probe.stdout.len(),
            stderr_bytes = probe.stderr.len(),
            "xray binary fallback probe"
        );
        if probe.exit_code == 0 {
            info!(
                target: "discovery",
                path = %candidate,
                "xray binary found via fallback path"
            );
            return Ok(Some(RemotePath::new(*candidate).map_err(app_from_ssh)?));
        }
    }

    Ok(None)
}

/// Parses an absolute binary path from `command -v` / `which` stdout.
///
/// Applies [`str::trim`] before validation so a trailing newline does not reject
/// a valid path.
fn parse_binary_path_stdout(stdout: &[u8]) -> Option<RemotePath> {
    let trimmed = String::from_utf8_lossy(stdout);
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Prefer the first line when a tool prints extra noise.
    let first_line = trimmed.lines().next().unwrap_or(trimmed).trim();
    if !first_line.starts_with('/') {
        return None;
    }

    RemotePath::new(first_line.to_owned()).ok()
}

async fn query_xray_version<S: SshSession + Sync>(
    session: &S,
    binary: &RemotePath,
) -> AppResult<Option<String>> {
    let result = exec_program(session, binary.as_str(), vec!["version".to_owned()]).await?;

    if result.exit_code != 0 {
        // Some builds accept `-version`.
        let fallback = exec_program(session, binary.as_str(), vec!["-version".to_owned()]).await?;
        if fallback.exit_code != 0 {
            return Ok(None);
        }
        return Ok(parse_xray_version_output(&fallback.stdout));
    }

    Ok(parse_xray_version_output(&result.stdout))
}

fn parse_xray_version_output(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Official output often starts with "Xray ..." or contains "Version".
        if let Some(rest) = line.strip_prefix("Xray ") {
            let version = rest.split_whitespace().next().unwrap_or(rest).to_owned();
            if !version.is_empty() {
                return Some(version);
            }
        }
        if let Some(idx) = line.to_ascii_lowercase().find("version") {
            let after = line[idx + "version".len()..].trim();
            let after = after.trim_start_matches([':', ' ']);
            let token = after.split_whitespace().next().unwrap_or(after);
            if !token.is_empty() {
                return Some(token.to_owned());
            }
        }
        // Last resort: first non-empty line token that looks like a version.
        if line.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
            return Some(line.split_whitespace().next()?.to_owned());
        }
    }
    None
}

/// Result of reading and parsing remote configuration during discovery.
struct DiscoveredConfig {
    source: ConfigSource,
    files: Vec<RemotePath>,
    readable: bool,
    inbound_summaries: Vec<InboundSummary>,
    outbound_summaries: Vec<OutboundSummary>,
    dns_summary: Option<DnsSummary>,
    fakedns_summary: Option<FakeDnsSummary>,
    observatory_summary: Option<ObservatorySummary>,
    burst_observatory_summary: Option<BurstObservatorySummary>,
    routing_summary: Option<RoutingSummary>,
    policy_summary: Option<PolicySummary>,
    vless_clients: Vec<VlessClientSummary>,
    parse_warnings: Vec<String>,
    loaded: bool,
    editable: Option<EditableXrayConfig>,
}

impl DiscoveredConfig {
    fn empty(source: ConfigSource) -> Self {
        Self {
            source,
            files: Vec::new(),
            readable: false,
            inbound_summaries: Vec::new(),
            outbound_summaries: Vec::new(),
            dns_summary: None,
            fakedns_summary: None,
            observatory_summary: None,
            burst_observatory_summary: None,
            routing_summary: None,
            policy_summary: None,
            vless_clients: Vec::new(),
            parse_warnings: Vec::new(),
            loaded: false,
            editable: None,
        }
    }
}

async fn resolve_and_read_config<S: SshSession + Sync>(
    session: &S,
    parser: &XrayConfigParser,
    from_service: Option<&ExecStartConfigArg>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> AppResult<DiscoveredConfig> {
    if let Some(arg) = from_service {
        match arg {
            ExecStartConfigArg::File(path) => {
                return read_single_config(session, parser, path, warnings).await;
            }
            ExecStartConfigArg::Directory(path) => {
                return read_config_directory(session, parser, path, warnings).await;
            }
        }
    }

    for path in CONFIG_FILE_FALLBACKS {
        if remote_path_is_file(session, path).await? {
            return read_single_config(session, parser, path, warnings).await;
        }
    }

    for path in CONFIG_DIR_FALLBACKS {
        if remote_path_is_dir(session, path).await? {
            let json_files = list_json_files(session, path).await?;
            if !json_files.is_empty() {
                return read_config_directory(session, parser, path, warnings).await;
            }
        }
    }

    warnings.push(DiscoveryWarning::ConfigNotFound);
    Ok(DiscoveredConfig::empty(ConfigSource::NotFound))
}

async fn read_single_config<S: SshSession + Sync>(
    session: &S,
    parser: &XrayConfigParser,
    path: &str,
    warnings: &mut Vec<DiscoveryWarning>,
) -> AppResult<DiscoveredConfig> {
    let remote = match RemotePath::new(path) {
        Ok(path) => path,
        Err(error) => {
            warnings.push(DiscoveryWarning::Other {
                detail: format!("invalid config path from discovery: {}", error.message()),
            });
            return Ok(DiscoveredConfig::empty(ConfigSource::Unknown));
        }
    };

    if !remote_path_is_file(session, remote.as_str()).await? {
        warnings.push(DiscoveryWarning::ConfigNotFound);
        return Ok(DiscoveredConfig::empty(ConfigSource::NotFound));
    }

    match session.read_file(&remote).await {
        Ok(bytes) => {
            let outcome = parser.parse_single_file_bytes(remote.as_str(), &bytes);
            let mut parse_warnings = Vec::new();
            if !outcome.is_success() {
                let detail = outcome
                    .errors()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                warnings.push(DiscoveryWarning::ConfigInvalid {
                    detail: detail.clone(),
                });
                parse_warnings.push(detail);
            }

            let loaded = !outcome.has_fatal_errors();
            let (
                inbound_summaries,
                outbound_summaries,
                dns_summary,
                fakedns_summary,
                observatory_summary,
                burst_observatory_summary,
                routing_summary,
                policy_summary,
                vless_clients,
            ) = if loaded {
                (
                    outcome.sections().inbound_summaries(),
                    outcome.sections().outbound_summaries(),
                    outcome.sections().dns_summary(),
                    outcome.sections().fakedns_summary(),
                    outcome.sections().observatory_summary(),
                    outcome.sections().burst_observatory_summary(),
                    outcome.sections().routing_summary(),
                    outcome.sections().policy_summary(),
                    extract_vless_clients(outcome.sections()),
                )
            } else {
                (
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                )
            };

            let editable = if loaded {
                match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Ok(root) if root.is_object() => Some(EditableXrayConfig::from_single_file(
                        remote.as_str(),
                        root,
                        outcome.sections().clone(),
                    )),
                    _ => None,
                }
            } else {
                None
            };

            Ok(DiscoveredConfig {
                source: ConfigSource::SingleFile(remote.clone()),
                files: vec![remote],
                readable: true,
                inbound_summaries,
                outbound_summaries,
                dns_summary,
                fakedns_summary,
                observatory_summary,
                burst_observatory_summary,
                routing_summary,
                policy_summary,
                vless_clients,
                parse_warnings,
                loaded,
                editable,
            })
        }
        Err(error) if is_permission_denied_ssh(&error) => {
            warnings.push(DiscoveryWarning::ConfigUnreadable {
                detail: "permission denied".to_owned(),
            });
            Ok(DiscoveredConfig {
                source: ConfigSource::SingleFile(remote),
                files: Vec::new(),
                readable: false,
                inbound_summaries: Vec::new(),
                outbound_summaries: Vec::new(),
                dns_summary: None,
                fakedns_summary: None,
                observatory_summary: None,
                burst_observatory_summary: None,
                routing_summary: None,
                policy_summary: None,
                vless_clients: Vec::new(),
                parse_warnings: Vec::new(),
                loaded: false,
                editable: None,
            })
        }
        Err(error) if is_connection_lost_ssh(&error) => Err(app_from_ssh(error)),
        Err(error) => {
            warnings.push(DiscoveryWarning::ConfigUnreadable {
                detail: sanitize_detail(error.message()),
            });
            Ok(DiscoveredConfig {
                source: ConfigSource::SingleFile(remote),
                files: Vec::new(),
                readable: false,
                inbound_summaries: Vec::new(),
                outbound_summaries: Vec::new(),
                dns_summary: None,
                fakedns_summary: None,
                observatory_summary: None,
                burst_observatory_summary: None,
                routing_summary: None,
                policy_summary: None,
                vless_clients: Vec::new(),
                parse_warnings: Vec::new(),
                loaded: false,
                editable: None,
            })
        }
    }
}

async fn read_config_directory<S: SshSession + Sync>(
    session: &S,
    parser: &XrayConfigParser,
    path: &str,
    warnings: &mut Vec<DiscoveryWarning>,
) -> AppResult<DiscoveredConfig> {
    let remote = match RemotePath::new(path) {
        Ok(path) => path,
        Err(error) => {
            warnings.push(DiscoveryWarning::Other {
                detail: format!("invalid config directory: {}", error.message()),
            });
            return Ok(DiscoveredConfig::empty(ConfigSource::Unknown));
        }
    };

    let files = list_json_files(session, remote.as_str()).await?;
    if files.is_empty() {
        warnings.push(DiscoveryWarning::ConfigNotFound);
        return Ok(DiscoveredConfig::empty(ConfigSource::NotFound));
    }

    let mut readable = false;
    let mut file_contents: Vec<(String, String)> = Vec::new();

    for file in &files {
        match session.read_file(file).await {
            Ok(bytes) => {
                readable = true;
                match String::from_utf8(bytes) {
                    Ok(text) => file_contents.push((file.as_str().to_owned(), text)),
                    Err(error) => {
                        let detail = format!("{}: invalid UTF-8 ({error})", file.as_str());
                        warnings.push(DiscoveryWarning::ConfigInvalid {
                            detail: detail.clone(),
                        });
                    }
                }
            }
            Err(error) if is_connection_lost_ssh(&error) => {
                return Err(app_from_ssh(error));
            }
            Err(error) if is_permission_denied_ssh(&error) => {
                warnings.push(DiscoveryWarning::ConfigUnreadable {
                    detail: format!("{}: permission denied", file.as_str()),
                });
            }
            Err(error) => {
                warnings.push(DiscoveryWarning::ConfigUnreadable {
                    detail: format!("{}: {}", file.as_str(), sanitize_detail(error.message())),
                });
            }
        }
    }

    if file_contents.is_empty() {
        return Ok(DiscoveredConfig {
            source: ConfigSource::ConfigDirectory(remote),
            files,
            readable,
            inbound_summaries: Vec::new(),
            outbound_summaries: Vec::new(),
            dns_summary: None,
            fakedns_summary: None,
            observatory_summary: None,
            burst_observatory_summary: None,
            routing_summary: None,
            policy_summary: None,
            vless_clients: Vec::new(),
            parse_warnings: Vec::new(),
            loaded: false,
            editable: None,
        });
    }

    let outcome = parser.parse_directory(
        file_contents
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    );
    let mut parse_warnings = Vec::new();
    if !outcome.is_success() {
        for error in outcome.errors() {
            let detail = error.to_string();
            warnings.push(DiscoveryWarning::ConfigInvalid {
                detail: detail.clone(),
            });
            parse_warnings.push(detail);
        }
    }

    let loaded = !outcome.has_fatal_errors();
    let (
        inbound_summaries,
        outbound_summaries,
        dns_summary,
        fakedns_summary,
        observatory_summary,
        burst_observatory_summary,
        routing_summary,
        policy_summary,
        vless_clients,
    ) = if loaded {
        (
            outcome.sections().inbound_summaries(),
            outcome.sections().outbound_summaries(),
            outcome.sections().dns_summary(),
            outcome.sections().fakedns_summary(),
            outcome.sections().observatory_summary(),
            outcome.sections().burst_observatory_summary(),
            outcome.sections().routing_summary(),
            outcome.sections().policy_summary(),
            extract_vless_clients(outcome.sections()),
        )
    } else {
        (
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
    };

    let editable = if loaded {
        match parse_file_roots(file_contents) {
            Ok(roots) => Some(EditableXrayConfig::new(outcome.sections().clone(), roots)),
            Err(_) => None,
        }
    } else {
        None
    };

    Ok(DiscoveredConfig {
        source: ConfigSource::ConfigDirectory(remote),
        files,
        readable,
        inbound_summaries,
        outbound_summaries,
        dns_summary,
        fakedns_summary,
        observatory_summary,
        burst_observatory_summary,
        routing_summary,
        policy_summary,
        vless_clients,
        parse_warnings,
        loaded,
        editable,
    })
}

async fn list_json_files<S: SshSession + Sync>(
    session: &S,
    directory: &str,
) -> AppResult<Vec<RemotePath>> {
    let result = exec_program(session, "ls", vec!["-1".to_owned(), directory.to_owned()]).await?;

    if result.exit_code != 0 {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&result.stdout);
    let mut files = Vec::new();
    let base = directory.trim_end_matches('/');

    for name in stdout.lines() {
        let name = name.trim();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        if !name.ends_with(".json") {
            continue;
        }
        // Reject path separators in listed names to avoid traversal via odd ls output.
        if name.contains('/') || name.contains('\\') {
            continue;
        }
        let full = format!("{base}/{name}");
        if let Ok(path) = RemotePath::new(full) {
            files.push(path);
        }
    }

    files.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(files)
}

async fn remote_path_is_file<S: SshSession + Sync>(session: &S, path: &str) -> AppResult<bool> {
    let result = exec_program(session, "test", vec!["-f".to_owned(), path.to_owned()]).await?;
    Ok(result.exit_code == 0)
}

async fn remote_path_is_dir<S: SshSession + Sync>(session: &S, path: &str) -> AppResult<bool> {
    let result = exec_program(session, "test", vec!["-d".to_owned(), path.to_owned()]).await?;
    Ok(result.exit_code == 0)
}

async fn remote_command_exists<S: SshSession + Sync>(session: &S, name: &str) -> AppResult<bool> {
    let result = exec_program(session, "command", vec!["-v".to_owned(), name.to_owned()]).await?;
    Ok(result.exit_code == 0)
}

async fn exec_program<S: SshSession + Sync>(
    session: &S,
    program: &str,
    args: Vec<String>,
) -> AppResult<ExecResult> {
    let command =
        RemoteCommand::new(program, args).map_err(|error| AppError::new(error.message()))?;
    session
        .exec(&command)
        .await
        .map_err(|error| AppError::new(error.message()))
}

fn map_fatal_error(error: AppError) -> DiscoveryResult {
    let detail = sanitize_detail(error.message());
    let kind = if is_connection_lost(&error) {
        DiscoveryErrorKind::SshConnectionLost
    } else if is_permission_denied(&error) {
        DiscoveryErrorKind::PermissionDenied
    } else {
        DiscoveryErrorKind::Unexpected
    };
    DiscoveryResult::Failed { kind, detail }
}

fn is_connection_lost(error: &AppError) -> bool {
    let lower = error.message().to_ascii_lowercase();
    lower.contains("connection closed")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("connection lost")
        || lower.contains("ssh operation failed")
            && (lower.contains("closed") || lower.contains("disconnect"))
}

fn is_connection_lost_ssh(error: &SshError) -> bool {
    is_connection_lost(&AppError::new(error.message()))
}

fn is_permission_denied(error: &AppError) -> bool {
    let lower = error.message().to_ascii_lowercase();
    lower.contains("permission denied") || lower.contains("access denied")
}

fn is_permission_denied_ssh(error: &SshError) -> bool {
    is_permission_denied(&AppError::new(error.message()))
}

fn app_from_ssh(error: SshError) -> AppError {
    AppError::new(error.message())
}

fn sanitize_detail(message: &str) -> String {
    crate::logging::redact::sanitize_detail(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{ServiceState, SystemdManager};
    use feldjaeger_ssh::{ConnectionProfile, RemoteCommand, RemotePath, SshResult};
    use std::collections::HashMap;
    use std::future;
    use std::sync::{Arc, Mutex};

    type MockFileMap = HashMap<String, Result<Vec<u8>, String>>;

    #[derive(Clone)]
    struct MockSession {
        profile: ConnectionProfile,
        exec_results: Arc<Mutex<HashMap<String, ExecResult>>>,
        file_contents: Arc<Mutex<MockFileMap>>,
        exec_calls: Arc<Mutex<Vec<RemoteCommand>>>,
        write_calls: Arc<Mutex<Vec<String>>>,
    }

    impl Default for MockSession {
        fn default() -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                exec_results: Arc::new(Mutex::new(HashMap::new())),
                file_contents: Arc::new(Mutex::new(HashMap::new())),
                exec_calls: Arc::new(Mutex::new(Vec::new())),
                write_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl MockSession {
        fn new() -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                ..Self::default()
            }
        }

        fn with_exec(self, key: impl Into<String>, result: ExecResult) -> Self {
            self.exec_results.lock().unwrap().insert(key.into(), result);
            self
        }

        fn with_file(self, path: impl Into<String>, contents: Vec<u8>) -> Self {
            self.file_contents
                .lock()
                .unwrap()
                .insert(path.into(), Ok(contents));
            self
        }

        fn with_file_error(self, path: impl Into<String>, message: impl Into<String>) -> Self {
            self.file_contents
                .lock()
                .unwrap()
                .insert(path.into(), Err(message.into()));
            self
        }

        fn exec_calls(&self) -> Vec<RemoteCommand> {
            self.exec_calls.lock().unwrap().clone()
        }

        fn write_calls(&self) -> Vec<String> {
            self.write_calls.lock().unwrap().clone()
        }
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        fn read_file(
            &self,
            path: &RemotePath,
        ) -> impl std::future::Future<Output = SshResult<Vec<u8>>> + Send {
            let contents = self
                .file_contents
                .lock()
                .unwrap()
                .get(path.as_str())
                .cloned();
            future::ready(match contents {
                Some(Ok(bytes)) => Ok(bytes),
                Some(Err(message)) => Err(SshError::new(message)),
                None => Err(SshError::new(format!("no mock file for {}", path.as_str()))),
            })
        }

        fn write_file(
            &self,
            path: &RemotePath,
            _contents: &[u8],
        ) -> impl std::future::Future<Output = SshResult<()>> + Send {
            self.write_calls
                .lock()
                .unwrap()
                .push(path.as_str().to_owned());
            future::ready(Err(SshError::new(
                "write_file must not be called during discovery",
            )))
        }

        fn write_file_atomic(
            &self,
            path: &RemotePath,
            _contents: &[u8],
        ) -> impl std::future::Future<Output = SshResult<()>> + Send {
            self.write_calls
                .lock()
                .unwrap()
                .push(path.as_str().to_owned());
            future::ready(Err(SshError::new(
                "write_file_atomic must not be called during discovery",
            )))
        }

        fn rename_file(
            &self,
            _from: &RemotePath,
            _to: &RemotePath,
        ) -> impl std::future::Future<Output = SshResult<()>> + Send {
            future::ready(Err(SshError::new(
                "rename_file must not be called during discovery",
            )))
        }

        fn remove_file(
            &self,
            _path: &RemotePath,
        ) -> impl std::future::Future<Output = SshResult<()>> + Send {
            future::ready(Err(SshError::new(
                "remove_file must not be called during discovery",
            )))
        }

        fn path_is_file(
            &self,
            _path: &RemotePath,
        ) -> impl Future<Output = SshResult<bool>> + Send {
            async { Ok(true) }
        }

        fn exec(
            &self,
            command: &RemoteCommand,
        ) -> impl std::future::Future<Output = SshResult<ExecResult>> + Send {
            self.exec_calls.lock().unwrap().push(command.clone());
            let key = exec_key(command);
            let result = self
                .exec_results
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_else(|| {
                    // Default: test -f/-d/-x fail; command -v / which fail; other commands fail.
                    let is_lookup_miss = matches!(command.program(), "test" | "which")
                        || (command.program() == "command"
                            && command.args().first().map(String::as_str) == Some("-v"));
                    if is_lookup_miss {
                        ExecResult::new(Vec::new(), Vec::new(), 1)
                    } else {
                        ExecResult::new(
                            Vec::new(),
                            format!("no mock response for {key}").into_bytes(),
                            1,
                        )
                    }
                });
            future::ready(Ok(result))
        }

    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
        let _ = stdin;
        self.exec(command)
    }

        fn disconnect(self) -> impl std::future::Future<Output = SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    fn exec_key(command: &RemoteCommand) -> String {
        let args = command.args().join(" ");
        format!("{} {args}", command.program())
    }

    fn ok_out(stdout: &str) -> ExecResult {
        ExecResult::new(stdout.as_bytes().to_vec(), Vec::new(), 0)
    }

    fn base_host(session: MockSession) -> MockSession {
        session
            .with_file(
                "/etc/os-release",
                b"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\n"
                    .to_vec(),
            )
            .with_exec("uname -m", ok_out("x86_64\n"))
            .with_exec(
                "test -d /run/systemd/system",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
    }

    #[tokio::test]
    async fn finds_xray_via_path() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ok_out("/usr/local/bin/xray\n"))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec(
                "/usr/local/bin/xray version",
                ok_out("Xray 25.7.1 (Xray, Penetrates Everything.) Custom\n"),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out(
                    "Id=xray.service\nLoadState=loaded\nActiveState=active\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json ; }\n",
                ),
            )
            .with_exec(
                "systemctl is-active -- xray.service",
                ok_out("active\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_file(
                "/usr/local/etc/xray/config.json",
                br#"{"inbounds":[],"outbounds":[]}"#.to_vec(),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                inbound_summaries,
                config_loaded,
                ..
            } => {
                assert_eq!(
                    install.binary_path.as_ref().map(RemotePath::as_str),
                    Some("/usr/local/bin/xray")
                );
                assert_eq!(install.version.as_deref(), Some("25.7.1"));
                assert_eq!(install.service_name.as_deref(), Some("xray.service"));
                assert_eq!(install.service_state, Some(ServiceState::Running));
                assert!(install.config_readable);
                assert!(config_loaded);
                assert!(inbound_summaries.is_empty());
                assert!(matches!(
                    install.config_source,
                    ConfigSource::SingleFile(ref path) if path.as_str() == "/usr/local/etc/xray/config.json"
                ));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn finds_xray_via_fallback_path() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ExecResult::new(Vec::new(), Vec::new(), 1))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 1))
            .with_exec("test -x /usr/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec(
                "/usr/bin/xray version",
                ok_out("Xray 1.8.0\n"),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out("Id=xray.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "systemctl list-units --type=service --all --no-legend --no-pager -- xray@*",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray@.service",
                ok_out("Id=xray@.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /usr/local/etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert_eq!(
                    install.binary_path.as_ref().map(RemotePath::as_str),
                    Some("/usr/bin/xray")
                );
                assert!(
                    install
                        .discovery_warnings
                        .iter()
                        .any(|w| matches!(w, DiscoveryWarning::ServiceNotFound))
                );
                assert!(
                    install
                        .discovery_warnings
                        .iter()
                        .any(|w| matches!(w, DiscoveryWarning::ConfigNotFound))
                );
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn xray_not_found() {
        let session = base_host(MockSession::new())
            .with_exec(
                "command -v xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -x /usr/local/bin/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -x /usr/bin/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -x /opt/xray/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        assert!(matches!(result, DiscoveryResult::NotFound { .. }));
    }

    #[tokio::test]
    async fn version_unavailable_keeps_binary() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ok_out("/usr/local/bin/xray\n"))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec(
                "/usr/local/bin/xray version",
                ExecResult::new(Vec::new(), b"error\n".to_vec(), 1),
            )
            .with_exec(
                "/usr/local/bin/xray -version",
                ExecResult::new(Vec::new(), b"error\n".to_vec(), 1),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out("Id=xray.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "systemctl list-units --type=service --all --no-legend --no-pager -- xray@*",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray@.service",
                ok_out("Id=xray@.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /usr/local/etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert!(install.version.is_none());
                assert!(install.binary_path.is_some());
                assert!(
                    install
                        .discovery_warnings
                        .contains(&DiscoveryWarning::VersionUnavailable)
                );
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn extracts_confdir_from_exec_start() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ok_out("/usr/local/bin/xray\n"))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec("/usr/local/bin/xray version", ok_out("Xray 25.1\n"))
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out(
                    "Id=xray.service\nLoadState=loaded\nActiveState=inactive\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -confdir /usr/local/etc/xray ; }\n",
                ),
            )
            .with_exec(
                "systemctl is-active -- xray.service",
                ExecResult::new(b"inactive\n".to_vec(), Vec::new(), 3),
            )
            .with_exec(
                "ls -1 /usr/local/etc/xray",
                ok_out("01_log.json\n10_inbounds.json\n"),
            )
            .with_file(
                "/usr/local/etc/xray/01_log.json",
                br#"{"log":{"loglevel":"warning"}}"#.to_vec(),
            )
            .with_file(
                "/usr/local/etc/xray/10_inbounds.json",
                br#"{"inbounds":[]}"#.to_vec(),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert!(matches!(
                    install.config_source,
                    ConfigSource::ConfigDirectory(ref path)
                        if path.as_str() == "/usr/local/etc/xray"
                ));
                assert_eq!(install.config_files.len(), 2);
                assert_eq!(
                    install.config_files[0].as_str(),
                    "/usr/local/etc/xray/01_log.json"
                );
                assert!(install.config_readable);
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fallback_usr_local_etc_config() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ok_out("/usr/local/bin/xray\n"))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec("/usr/local/bin/xray version", ok_out("Xray 25.1\n"))
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out("Id=xray.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "systemctl list-units --type=service --all --no-legend --no-pager -- xray@*",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray@.service",
                ok_out("Id=xray@.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_file(
                "/usr/local/etc/xray/config.json",
                br#"{"inbounds":[],"outbounds":[]}"#.to_vec(),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert!(matches!(
                    install.config_source,
                    ConfigSource::SingleFile(ref path)
                        if path.as_str() == "/usr/local/etc/xray/config.json"
                ));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fallback_etc_xray_config() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ok_out("/usr/local/bin/xray\n"))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec("/usr/local/bin/xray version", ok_out("Xray 25.1\n"))
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out("Id=xray.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "systemctl list-units --type=service --all --no-legend --no-pager -- xray@*",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray@.service",
                ok_out("Id=xray@.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_file(
                "/etc/xray/config.json",
                br#"{"inbounds":[],"outbounds":[]}"#.to_vec(),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert!(matches!(
                    install.config_source,
                    ConfigSource::SingleFile(ref path) if path.as_str() == "/etc/xray/config.json"
                ));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn config_unreadable_adds_warning() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ok_out("/usr/local/bin/xray\n"))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec("/usr/local/bin/xray version", ok_out("Xray 25.1\n"))
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out(
                    "Id=xray.service\nLoadState=loaded\nActiveState=active\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -c /etc/xray/config.json ; }\n",
                ),
            )
            .with_exec(
                "systemctl is-active -- xray.service",
                ok_out("active\n"),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_file_error("/etc/xray/config.json", "permission denied");

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert!(!install.config_readable);
                assert!(
                    install
                        .discovery_warnings
                        .iter()
                        .any(|w| matches!(w, DiscoveryWarning::ConfigUnreadable { .. }))
                );
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_json_adds_warning() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ok_out("/usr/local/bin/xray\n"))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec("/usr/local/bin/xray version", ok_out("Xray 25.1\n"))
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out(
                    "Id=xray.service\nLoadState=loaded\nActiveState=active\nExecStart={ path=/usr/local/bin/xray ; argv[]=/usr/local/bin/xray run -c /etc/xray/config.json ; }\n",
                ),
            )
            .with_exec(
                "systemctl is-active -- xray.service",
                ok_out("active\n"),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_file("/etc/xray/config.json", b"{not-json".to_vec());

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert!(install.config_readable);
                assert!(
                    install
                        .discovery_warnings
                        .iter()
                        .any(|w| matches!(w, DiscoveryWarning::ConfigInvalid { .. }))
                );
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn openrc_detected_as_unsupported() {
        let session = MockSession::new()
            .with_file(
                "/etc/os-release",
                b"PRETTY_NAME=\"Alpine Linux v3.20\"\n".to_vec(),
            )
            .with_exec("uname -m", ok_out("x86_64\n"))
            .with_exec(
                "test -d /run/systemd/system",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "command -v systemctl",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /sbin/openrc",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec("command -v xray", ok_out("/usr/bin/xray\n"))
            .with_exec(
                "test -x /usr/bin/xray",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec("/usr/bin/xray version", ok_out("Xray 1.8.4\n"))
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_file(
                "/etc/xray/config.json",
                br#"{"inbounds":[],"outbounds":[]}"#.to_vec(),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert_eq!(install.init_system, InitSystemKind::OpenRC);
                assert!(!install.service_control_supported());
                assert!(install.discovery_warnings.iter().any(|w| matches!(
                    w,
                    DiscoveryWarning::UnsupportedInitSystem {
                        kind: InitSystemKind::OpenRC
                    }
                )));
                assert!(install.service_name.is_none());
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ssh_connection_lost_during_discovery() {
        let session = MockSession::new()
            .with_file_error("/etc/os-release", "SSH connection closed: channel reset");

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Failed {
                kind: DiscoveryErrorKind::SshConnectionLost,
                ..
            } => {}
            other => panic!("expected SshConnectionLost, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn discovery_does_not_write() {
        let session = base_host(MockSession::new())
            .with_exec("command -v xray", ok_out("/usr/local/bin/xray\n"))
            .with_exec("test -x /usr/local/bin/xray", ExecResult::new(Vec::new(), Vec::new(), 0))
            .with_exec("/usr/local/bin/xray version", ok_out("Xray 25.1\n"))
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out("Id=xray.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "systemctl list-units --type=service --all --no-legend --no-pager -- xray@*",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray@.service",
                ok_out("Id=xray@.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /usr/local/etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            );

        let _ = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        assert!(session.write_calls().is_empty());
        for call in session.exec_calls() {
            let program = call.program();
            assert!(
                !matches!(program, "systemctl")
                    || call.args().first().is_some_and(|a| {
                        matches!(
                            a.as_str(),
                            "show" | "list-units" | "is-active" | "cat" | "status"
                        )
                    }),
                "unexpected systemctl action: {:?}",
                call.args()
            );
            assert_ne!(program, "rm");
            assert_ne!(program, "mv");
            assert_ne!(program, "cp");
            assert_ne!(program, "apk");
            assert_ne!(program, "apt-get");
        }
    }

    #[test]
    fn parses_version_lines() {
        assert_eq!(
            parse_xray_version_output(b"Xray 25.7.1 (Xray, Penetrates Everything.)\n"),
            Some("25.7.1".to_owned())
        );
        assert_eq!(
            parse_xray_version_output(b"Version: 1.8.0\n"),
            Some("1.8.0".to_owned())
        );
    }

    #[test]
    fn parse_binary_path_stdout_trims_trailing_newline() {
        let path = parse_binary_path_stdout(b"/usr/local/bin/xray\n").expect("path");
        assert_eq!(path.as_str(), "/usr/local/bin/xray");
    }

    #[test]
    fn parse_binary_path_stdout_rejects_untrimmed_comparison_pitfall() {
        // Raw stdout must not be compared to an absolute path without trim.
        let raw = b"/usr/local/bin/xray\n";
        assert_ne!(raw.as_slice(), b"/usr/local/bin/xray".as_slice());
        assert_eq!(
            parse_binary_path_stdout(raw)
                .expect("trimmed path")
                .as_str(),
            "/usr/local/bin/xray"
        );
    }

    #[test]
    fn command_v_remote_command_payload() {
        let command = RemoteCommand::new("command", vec!["-v".to_owned(), "xray".to_owned()])
            .expect("command should construct");
        assert_eq!(command.program(), "command");
        assert_eq!(command.args(), &["-v".to_owned(), "xray".to_owned()]);

        // Mirrors feldjaeger-ssh::russh::exec::build_exec_payload join rules.
        let mut payload = command.program().to_owned();
        for arg in command.args() {
            payload.push(' ');
            payload.push_str(arg);
        }
        assert_eq!(payload, "command -v xray");
    }

    #[tokio::test]
    async fn command_v_stdout_with_trailing_newline_finds_binary() {
        // Regression: exit 0 + stdout "/usr/local/bin/xray\n" must resolve the binary.
        // No `test -x` mock is provided — PATH lookup alone must be enough.
        let session = base_host(MockSession::new())
            .with_exec(
                "command -v xray",
                ExecResult::new(b"/usr/local/bin/xray\n".to_vec(), Vec::new(), 0),
            )
            .with_exec(
                "/usr/local/bin/xray version",
                ok_out("Xray 25.7.1\n"),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out("Id=xray.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "systemctl list-units --type=service --all --no-legend --no-pager -- xray@*",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray@.service",
                ok_out("Id=xray@.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /usr/local/etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert_eq!(
                    install.binary_path.as_ref().map(RemotePath::as_str),
                    Some("/usr/local/bin/xray")
                );
            }
            other => panic!("expected Found from command -v stdout, got {other:?}"),
        }

        let calls = session.exec_calls();
        let lookup = calls
            .iter()
            .find(|call| call.program() == "command" && call.args() == ["-v", "xray"])
            .expect("command -v xray must be executed");
        assert_eq!(lookup.program(), "command");
        assert_eq!(lookup.args(), &["-v".to_owned(), "xray".to_owned()]);
    }

    #[tokio::test]
    async fn binary_found_service_missing_is_not_xray_not_found() {
        let session = base_host(MockSession::new())
            .with_exec(
                "command -v xray",
                ExecResult::new(b"/usr/local/bin/xray\n".to_vec(), Vec::new(), 0),
            )
            .with_exec("/usr/local/bin/xray version", ok_out("Xray 25.7.1\n"))
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out("Id=xray.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "systemctl list-units --type=service --all --no-legend --no-pager -- xray@*",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray@.service",
                ok_out("Id=xray@.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /usr/local/etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert!(install.binary_path.is_some());
                assert!(install.service_name.is_none());
                assert!(
                    install
                        .discovery_warnings
                        .contains(&DiscoveryWarning::ServiceNotFound)
                );
                assert!(
                    install
                        .discovery_warnings
                        .contains(&DiscoveryWarning::ConfigNotFound)
                );
            }
            DiscoveryResult::NotFound { .. } => {
                panic!("service/config absence must not become Xray not found")
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn binary_found_even_when_test_x_would_fail() {
        // If PATH lookup succeeds, a failing test -x must not discard the binary.
        let session = base_host(MockSession::new())
            .with_exec(
                "command -v xray",
                ExecResult::new(b"/usr/local/bin/xray\n".to_vec(), Vec::new(), 0),
            )
            .with_exec(
                "test -x /usr/local/bin/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec("/usr/local/bin/xray version", ok_out("Xray 25.7.1\n"))
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray.service",
                ok_out("Id=xray.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "systemctl list-units --type=service --all --no-legend --no-pager -- xray@*",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_exec(
                "systemctl show --property=Id --property=LoadState --property=ActiveState --property=ExecStart --no-pager -- xray@.service",
                ok_out("Id=xray@.service\nLoadState=not-found\nActiveState=inactive\nExecStart=\n"),
            )
            .with_exec(
                "test -f /usr/local/etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -f /etc/xray/config.json",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /usr/local/etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            )
            .with_exec(
                "test -d /etc/xray",
                ExecResult::new(Vec::new(), Vec::new(), 1),
            );

        let result = XrayDiscoveryService::new()
            .discover(&session, &SystemdManager::new())
            .await;

        match result {
            DiscoveryResult::Found {
                installation: install,
                ..
            } => {
                assert_eq!(
                    install.binary_path.as_ref().map(RemotePath::as_str),
                    Some("/usr/local/bin/xray")
                );
            }
            other => panic!("expected Found despite test -x failure, got {other:?}"),
        }
    }
}
