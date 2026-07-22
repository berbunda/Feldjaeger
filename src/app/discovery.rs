//! Asynchronous Xray discovery orchestration for [`super::ApplicationService`].

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::{build_connect_request, classify_ssh_error};
use crate::app::inbounds::LoadedConfigSnapshot;
use crate::init::SystemdManager;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    DiscoveryErrorKind, DiscoveryResult, DiscoveryState, DiscoveryWarning, InitSystemKind,
    XrayDiscoveryService, XrayInstallation,
};

/// Outcome delivered from the discovery worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryOutcome {
    /// Mapped discovery result for UI state.
    pub state: DiscoveryState,
    /// Parsed configuration snapshot for read-only pages.
    pub config: LoadedConfigSnapshot,
}

/// Runs connect → read-only discovery → disconnect on a background runtime.
pub async fn run_discovery<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    init: &SystemdManager,
) -> DiscoveryOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request = build_connect_request(profile, secrets);

    info!(
        target: "discovery",
        host = %request.profile.host,
        port = request.profile.port,
        user = %request.profile.username,
        "Xray discovery connect"
    );

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            let failure = classify_ssh_error(&error);
            warn!(
                target: "discovery",
                error_kind = ?failure.summary,
                detail = %failure.detail,
                "Xray discovery SSH connection failed"
            );
            return DiscoveryOutcome {
                state: DiscoveryState::Failed {
                    kind: DiscoveryErrorKind::SshConnectionLost,
                    detail: crate::logging::redact::user_message_see_log(
                        "Unable to connect to server.",
                    ),
                },
                config: LoadedConfigSnapshot::None,
            };
        }
    };

    let discovery = XrayDiscoveryService::new();
    let result = discovery.discover(&session, init).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "discovery",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "Xray discovery disconnect warning"
        );
    }

    let outcome = map_discovery_result(result);
    match &outcome.state {
        DiscoveryState::Succeeded(_) => {
            info!(target: "discovery", "Xray discovery completed");
        }
        DiscoveryState::NotFound { .. } => {
            info!(target: "discovery", "Xray discovery finished: installation not found");
        }
        DiscoveryState::Failed { .. } | DiscoveryState::Idle | DiscoveryState::Discovering => {}
    }
    outcome
}

fn map_discovery_result(result: DiscoveryResult) -> DiscoveryOutcome {
    match result {
        DiscoveryResult::Found {
            installation,
            inbound_summaries,
            outbound_summaries,
            dns_summary,
            fakedns_summary,
            observatory_summary,
            burst_observatory_summary,
            routing_summary,
            policy_summary,
            vless_clients,
            config_warnings,
            config_loaded,
            editable_config,
        } => {
            let config = if config_loaded {
                LoadedConfigSnapshot::Loaded {
                    inbounds: inbound_summaries,
                    outbounds: outbound_summaries,
                    dns: dns_summary,
                    fakedns: fakedns_summary,
                    observatory: observatory_summary,
                    burst_observatory: burst_observatory_summary,
                    routing: routing_summary,
                    policy: policy_summary,
                    vless_clients,
                    warnings: config_warnings,
                    editable: editable_config,
                }
            } else {
                LoadedConfigSnapshot::NotLoaded
            };
            DiscoveryOutcome {
                state: DiscoveryState::Succeeded(installation),
                config,
            }
        }
        DiscoveryResult::NotFound {
            operating_system,
            architecture,
            init_system,
            warnings,
        } => DiscoveryOutcome {
            state: DiscoveryState::NotFound {
                operating_system,
                architecture,
                init_system,
                warnings,
            },
            config: LoadedConfigSnapshot::None,
        },
        DiscoveryResult::Failed { kind, detail } => {
            let safe_detail = crate::logging::redact::sanitize_detail(&detail);
            let user_detail = match kind {
                DiscoveryErrorKind::SshConnectionLost => {
                    crate::logging::redact::user_message_see_log("Unable to connect to server.")
                }
                DiscoveryErrorKind::PermissionDenied => {
                    crate::logging::redact::user_message_see_log(
                        "Permission denied while discovering Xray.",
                    )
                }
                DiscoveryErrorKind::Unexpected => {
                    crate::logging::redact::user_message_see_log("Unexpected discovery error.")
                }
            };
            warn!(
                target: "discovery",
                error_kind = ?kind,
                detail = %safe_detail,
                "Xray discovery failed"
            );
            DiscoveryOutcome {
                state: DiscoveryState::Failed {
                    kind,
                    detail: user_detail,
                },
                config: LoadedConfigSnapshot::None,
            }
        }
    }
}

/// Formats a successful installation for the Connection page summary.
pub fn format_installation_summary(installation: &XrayInstallation) -> Vec<(String, String)> {
    let service = installation
        .service_name
        .clone()
        .unwrap_or_else(|| "—".to_owned());
    let service_state = installation
        .service_state
        .map(crate::init::ServiceState::label)
        .unwrap_or("—")
        .to_owned();
    let warnings = if installation.discovery_warnings.is_empty() {
        "none".to_owned()
    } else {
        installation
            .discovery_warnings
            .iter()
            .map(DiscoveryWarning::message)
            .collect::<Vec<_>>()
            .join("; ")
    };

    vec![
        ("OS".to_owned(), installation.operating_system.clone()),
        ("Architecture".to_owned(), installation.architecture.clone()),
        (
            "Init system".to_owned(),
            format!(
                "{}{}",
                installation.init_system.label(),
                if installation.service_control_supported() {
                    ""
                } else {
                    " (unsupported for service control)"
                }
            ),
        ),
        (
            "Xray binary".to_owned(),
            installation
                .binary_path
                .as_ref()
                .map(|path| path.as_str().to_owned())
                .unwrap_or_else(|| "—".to_owned()),
        ),
        (
            "Xray version".to_owned(),
            installation
                .version
                .clone()
                .unwrap_or_else(|| "—".to_owned()),
        ),
        ("Service".to_owned(), service),
        ("Service state".to_owned(), service_state),
        (
            "Config source".to_owned(),
            installation.config_source.label(),
        ),
        (
            "Config readable".to_owned(),
            if installation.config_readable {
                "yes".to_owned()
            } else {
                "no".to_owned()
            },
        ),
        ("Warnings".to_owned(), warnings),
    ]
}

/// Formats a NotFound discovery for the Connection page.
pub fn format_not_found_summary(
    operating_system: &str,
    architecture: &str,
    init_system: InitSystemKind,
    warnings: &[DiscoveryWarning],
) -> Vec<(String, String)> {
    let warnings_text = if warnings.is_empty() {
        "none".to_owned()
    } else {
        warnings
            .iter()
            .map(DiscoveryWarning::message)
            .collect::<Vec<_>>()
            .join("; ")
    };

    vec![
        (
            "Result".to_owned(),
            "Xray installation not found".to_owned(),
        ),
        ("OS".to_owned(), operating_system.to_owned()),
        ("Architecture".to_owned(), architecture.to_owned()),
        ("Init system".to_owned(), init_system.label().to_owned()),
        ("Warnings".to_owned(), warnings_text),
    ]
}
