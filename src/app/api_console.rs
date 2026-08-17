//! API Console page view model (Roadmap §3:128 — Xray gRPC/API live operations panel).
//!
//! The Xray `api` section (`api.listen` / `api.tag` / `api.services`) has no structured editor
//! yet (Roadmap §2.1:54 is a separate, unchecked Tier‑2 item) — it is preserved as an opaque
//! JSON object like every other not-yet-typed section (`XrayConfigSections::api`). This page
//! therefore treats a configured `api.listen` address as a *precondition*, not something it can
//! set up itself: if it's missing, the page explains how to add it through the existing Raw
//! JSON escape hatch (Roadmap §3:125) rather than duplicating a section editor here.
//!
//! Once `api.listen` resolves, every action on this page runs `xray api <subcommand>` on the
//! remote host over SSH-exec (`xray::run_xray_api`) — the same transport already used for
//! `xray x25519`/`xray run -test` — targeting that address directly (it is always reached from
//! the remote host itself, so no local gRPC client or SSH port-forward is needed).

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, XrayConfigSections};

/// High-level state shown by the API Console page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiConsolePageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded, but `api.listen` is absent or empty.
    ApiNotConfigured,
    /// `api.listen` resolved — live operations can run.
    Ready,
}

impl ApiConsolePageState {
    /// User-facing explanation for this state.
    pub fn message(self) -> &'static str {
        match self {
            Self::NoSshConnection => {
                "No SSH connection. Connect to a server on the Connection page first."
            }
            Self::XrayNotDiscovered => {
                "Xray installation not discovered. Run Discover Xray on the Connection page."
            }
            Self::ConfigurationNotLoaded => {
                "Configuration not loaded. Discover Xray again after the config becomes readable."
            }
            Self::ApiNotConfigured => {
                "No `api.listen` address in the loaded configuration. Add one through the Raw \
                 JSON editor (an inbound or outbound's escape hatch does not cover top-level \
                 sections — use the Outbounds page's Raw JSON action on any outbound, or add the \
                 `api` object directly to a confdir file), e.g. `\"api\": {\"tag\": \"api\", \
                 \"listen\": \"127.0.0.1:8080\", \"services\": [\"HandlerService\", \
                 \"LoggerService\", \"RoutingService\"]}`, then restart or reload Xray."
            }
            Self::Ready => "Connected to the live Xray API.",
        }
    }
}

/// Read-only model exposed to the API Console page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConsolePageModel {
    /// Coarse page state.
    pub state: ApiConsolePageState,
    /// Resolved `api.listen` address (`host:port`), present only when `state == Ready`.
    pub server_addr: Option<String>,
    /// `api.services[]` as configured, verbatim (empty when the key is absent).
    pub services: Vec<String>,
    /// Informational only (mirrors the warn-don't-block philosophy of the Policy page's wiring
    /// checks, Roadmap §2.5:106) — services this panel's operations rely on that are missing
    /// from `api.services`. Calls are not blocked client-side; Xray itself will reject them.
    pub missing_services_warning: Option<String>,
}

/// Derives the API Console page state from connection, discovery, and config state.
pub fn derive_api_console_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> ApiConsolePageState {
    if ssh != SshStatus::Connected {
        return ApiConsolePageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => ApiConsolePageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                ApiConsolePageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded { editable, .. } => {
                let Some(editable) = editable else {
                    return ApiConsolePageState::ConfigurationNotLoaded;
                };
                match resolve_api_listen(editable.sections()) {
                    Some(_) => ApiConsolePageState::Ready,
                    None => ApiConsolePageState::ApiNotConfigured,
                }
            }
        },
    }
}

/// Builds the read-only API Console page model.
pub fn build_api_console_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> ApiConsolePageModel {
    let state = derive_api_console_page_state(ssh, discovery, config);
    let sections = config.editable().map(|editable| editable.sections());
    let server_addr = sections.and_then(resolve_api_listen);
    let services = sections.map(resolve_api_services).unwrap_or_default();
    let missing_services_warning = if state == ApiConsolePageState::Ready {
        missing_services_warning(&services)
    } else {
        None
    };
    ApiConsolePageModel {
        state,
        server_addr,
        services,
        missing_services_warning,
    }
}

/// Reads `api.listen` from the loaded configuration's `api` section, if present and non-empty.
pub fn resolve_api_listen(sections: &XrayConfigSections) -> Option<String> {
    let listen = sections.api()?.value().get("listen")?.as_str()?;
    let trimmed = listen.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Reads `api.services[]` from the loaded configuration's `api` section (empty when absent or
/// not an array of strings).
pub fn resolve_api_services(sections: &XrayConfigSections) -> Vec<String> {
    let Some(api) = sections.api() else {
        return Vec::new();
    };
    api.value()
        .get("services")
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|v| v.as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn missing_services_warning(services: &[String]) -> Option<String> {
    let lower: Vec<String> = services.iter().map(|s| s.to_ascii_lowercase()).collect();
    let mut missing = Vec::new();
    for (needle, label) in [
        ("handlerservice", "HandlerService"),
        ("routingservice", "RoutingService"),
        ("loggerservice", "LoggerService"),
    ] {
        if !lower.iter().any(|s| s == needle) {
            missing.push(label);
        }
    }
    if missing.is_empty() {
        None
    } else {
        Some(format!(
            "`api.services` does not list {} — related actions below may fail with an \
             Unimplemented error from Xray until it's added.",
            missing.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{ConfigSource, EditableXrayConfig, InitSystemKind, XrayConfigParser, XrayInstallation};

    fn succeeded(config_source: ConfigSource) -> DiscoveryState {
        DiscoveryState::Succeeded(XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: None,
            version: None,
            service_name: None,
            service_state: None,
            exec_start: None,
            config_source,
            config_readable: true,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        })
    }

    fn editable_from(path: &str, json: &str) -> EditableXrayConfig {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file(path, json);
        assert!(!outcome.has_fatal_errors(), "{:?}", outcome.errors());
        let root: serde_json::Value = serde_json::from_str(json).expect("json");
        EditableXrayConfig::from_single_file(path, root, outcome.into_sections())
    }

    fn loaded(editable: Option<EditableXrayConfig>) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable,
        }
    }

    #[test]
    fn resolves_listen_and_services() {
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{"api":{"tag":"api","listen":"127.0.0.1:8080","services":["HandlerService","StatsService"]}}"#,
        );
        assert_eq!(
            resolve_api_listen(editable.sections()),
            Some("127.0.0.1:8080".to_owned())
        );
        assert_eq!(
            resolve_api_services(editable.sections()),
            vec!["HandlerService".to_owned(), "StatsService".to_owned()]
        );
    }

    #[test]
    fn missing_api_section_has_no_listen() {
        let editable = editable_from("/etc/xray/config.json", r#"{}"#);
        assert_eq!(resolve_api_listen(editable.sections()), None);
        assert!(resolve_api_services(editable.sections()).is_empty());
    }

    #[test]
    fn blank_listen_is_treated_as_absent() {
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{"api":{"tag":"api","listen":"  "}}"#,
        );
        assert_eq!(resolve_api_listen(editable.sections()), None);
    }

    #[test]
    fn page_state_ready_requires_listen() {
        let with_listen = editable_from(
            "/etc/xray/config.json",
            r#"{"api":{"tag":"api","listen":"127.0.0.1:8080"}}"#,
        );
        let without_listen = editable_from("/etc/xray/config.json", r#"{}"#);
        let source = ConfigSource::SingleFile(
            feldjaeger_ssh::RemotePath::new("/etc/xray/config.json").unwrap(),
        );

        let model = build_api_console_page_model(
            SshStatus::Connected,
            &succeeded(source.clone()),
            &loaded(Some(with_listen)),
        );
        assert_eq!(model.state, ApiConsolePageState::Ready);
        assert_eq!(model.server_addr.as_deref(), Some("127.0.0.1:8080"));

        let model = build_api_console_page_model(
            SshStatus::Connected,
            &succeeded(source),
            &loaded(Some(without_listen)),
        );
        assert_eq!(model.state, ApiConsolePageState::ApiNotConfigured);
        assert_eq!(model.server_addr, None);
    }

    #[test]
    fn missing_services_warning_lists_what_is_absent() {
        assert!(missing_services_warning(&[]).is_some());
        assert_eq!(
            missing_services_warning(&[
                "HandlerService".to_owned(),
                "RoutingService".to_owned(),
                "LoggerService".to_owned(),
            ]),
            None
        );
        let partial = missing_services_warning(&["HandlerService".to_owned()]).unwrap();
        assert!(partial.contains("RoutingService"));
        assert!(partial.contains("LoggerService"));
        assert!(!partial.contains("HandlerService"));
    }

    #[test]
    fn not_connected_and_not_discovered_states() {
        assert_eq!(
            derive_api_console_page_state(
                SshStatus::Disconnected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            ApiConsolePageState::NoSshConnection
        );
        assert_eq!(
            derive_api_console_page_state(
                SshStatus::Connected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            ApiConsolePageState::XrayNotDiscovered
        );
    }
}
