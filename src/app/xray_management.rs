//! Asynchronous Xray install / update / remove orchestration for [`super::ApplicationService`].

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::{error, info, warn};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::logging::redact::{sanitize_detail, user_message_see_log};
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    AvailableVersions, DiscoveryState, InitSystemKind, InstallChannel, InstallerError,
    InstallerErrorKind, XrayInstallation, XrayInstaller, version_gt,
};

/// Binary lifecycle operation requested from the Xray Management page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayLifecycleOperation {
    /// Official install-release.sh `install`.
    Install,
    /// Official install-release.sh `install` against an existing installation.
    Update,
    /// Official install-release.sh `remove` (keeps configuration).
    Remove,
}

impl XrayLifecycleOperation {
    /// Status Bar text while the operation is in flight.
    pub fn status_message(self) -> &'static str {
        match self {
            Self::Install => "Installing Xray...",
            Self::Update => "Updating Xray...",
            Self::Remove => "Removing Xray...",
        }
    }

    /// Short label for UI buttons.
    pub fn button_label(self) -> &'static str {
        match self {
            Self::Install => "Install",
            Self::Update => "Update",
            Self::Remove => "Remove",
        }
    }

    /// Confirmation dialog body for the selected channel and target tag.
    pub fn confirmation_prompt(
        self,
        channel: InstallChannel,
        current_version: Option<&str>,
        target_version: Option<&str>,
    ) -> String {
        let channel_label = match channel {
            InstallChannel::Stable => "stable",
            InstallChannel::Beta => "beta",
        };
        match self {
            Self::Install => match target_version {
                Some(to) if channel == InstallChannel::Beta => {
                    format!(
                        "Install Xray (beta) version {to}? Warning: pre-release may be unstable."
                    )
                }
                Some(to) => format!("Install Xray ({channel_label}) version {to}?"),
                None => format!("Install Xray ({channel_label})?"),
            },
            Self::Update => match (current_version, target_version) {
                (Some(from), Some(to)) if channel == InstallChannel::Beta => {
                    format!(
                        "Update Xray from {from} to {to} (beta)? Warning: pre-release may be unstable."
                    )
                }
                (Some(from), Some(to)) => {
                    format!("Update Xray from {from} to {to} ({channel_label})?")
                }
                _ => format!("Update Xray ({channel_label})?"),
            },
            Self::Remove => {
                "Remove Xray?\nConfiguration files will be preserved.".to_owned()
            }
        }
    }
}

/// GUI lifecycle of an install/update/remove operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum XrayLifecycleState {
    /// No operation in flight.
    #[default]
    Idle,
    /// An operation is running off the UI thread.
    Busy(XrayLifecycleOperation),
    /// Last operation failed; detail is safe for the UI.
    Failed {
        /// Classified failure kind.
        kind: InstallerErrorKind,
        /// Safe user-facing detail.
        detail: String,
    },
}

impl XrayLifecycleState {
    /// Returns `true` while a lifecycle operation is in flight.
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Busy(_))
    }
}

/// High-level installation status for the management page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationStatus {
    /// Discovery has not completed successfully.
    Unknown,
    /// Discovery found an Xray binary.
    Installed,
    /// Discovery completed and Xray was not found.
    NotInstalled,
}

impl InstallationStatus {
    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown — run discovery first",
            Self::Installed => "Installed",
            Self::NotInstalled => "Not installed",
        }
    }
}

/// Read-only model for the Xray Management page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayManagementPageModel {
    /// Aggregated installation status.
    pub status: InstallationStatus,
    /// Current installed version when known.
    pub current_version: Option<String>,
    /// Selected release channel (session-only).
    pub channel: InstallChannel,
    /// Latest stable tag from Check versions.
    pub available_stable: Option<String>,
    /// Beta/`--beta` candidate tag from Check versions.
    pub available_beta: Option<String>,
    /// Tag for the selected channel (convenience for confirms).
    pub available_version: Option<String>,
    /// Stable probe error detail when present.
    pub stable_error: Option<String>,
    /// Beta probe error detail when present.
    pub beta_error: Option<String>,
    /// Binary path when known.
    pub binary_path: Option<String>,
    /// systemd unit name when known.
    pub service_name: Option<String>,
    /// Configuration path label when known.
    pub config_path: Option<String>,
    /// Detected init system.
    pub init_system: Option<InitSystemKind>,
    /// Whether Install may be started.
    pub can_install: bool,
    /// Whether Update may be started.
    pub can_update: bool,
    /// Whether Remove may be started.
    pub can_remove: bool,
    /// Whether a version check may be started.
    pub can_check_version: bool,
    /// Explanation when actions are blocked (discovery / unsupported).
    pub blocked_reason: Option<&'static str>,
    /// Channel-specific hint (empty candidate / already latest).
    pub channel_hint: Option<&'static str>,
    /// Current lifecycle operation state.
    pub lifecycle: XrayLifecycleState,
    /// Whether a version check is in flight.
    pub version_check_busy: bool,
}

/// Snapshot of discovery data required by the lifecycle worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleDiscoverySnapshot {
    /// Whether Xray is already installed (Succeeded discovery).
    pub installed: bool,
    /// Init system from discovery (Succeeded or NotFound).
    pub init_system: InitSystemKind,
    /// Full installation when present.
    pub installation: Option<XrayInstallation>,
}

/// Outcome delivered from the lifecycle worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayLifecycleOutcome {
    /// Operation that was attempted.
    pub operation: XrayLifecycleOperation,
    /// Operation result.
    pub result: Result<(), InstallerError>,
}

/// Outcome delivered from the version-check worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionCheckOutcome {
    /// Dual-channel probe result, or SSH/setup failure before probing.
    pub result: Result<AvailableVersions, InstallerError>,
}

/// Runs connect → install/update/remove → disconnect.
pub async fn run_xray_lifecycle<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    installer: &XrayInstaller,
    snapshot: &LifecycleDiscoverySnapshot,
    operation: XrayLifecycleOperation,
    channel: InstallChannel,
) -> XrayLifecycleOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request = build_connect_request(profile, secrets);

    match operation {
        XrayLifecycleOperation::Install => {
            info!(target: "app", channel = ?channel, "Starting Xray installation");
        }
        XrayLifecycleOperation::Update => {
            info!(target: "app", channel = ?channel, "Starting Xray update");
        }
        XrayLifecycleOperation::Remove => {
            info!(target: "app", "Starting Xray removal");
        }
    }

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            let detail = sanitize_detail(error.message());
            warn!(
                target: "app",
                detail = %detail,
                "SSH connection failed for Xray lifecycle operation"
            );
            return XrayLifecycleOutcome {
                operation,
                result: Err(InstallerError::new(
                    InstallerErrorKind::SshConnectionFailed,
                    detail,
                )),
            };
        }
    };

    let result = match operation {
        XrayLifecycleOperation::Install => {
            installer
                .install(
                    &session,
                    snapshot.init_system,
                    snapshot.installed,
                    channel,
                )
                .await
        }
        XrayLifecycleOperation::Update => match &snapshot.installation {
            Some(installation) => installer.update(&session, installation, channel).await,
            None => Err(InstallerError::new(
                InstallerErrorKind::CommandFailed,
                "Xray is not installed.",
            )),
        },
        XrayLifecycleOperation::Remove => match &snapshot.installation {
            Some(installation) => installer.remove(&session, installation).await,
            None => Err(InstallerError::new(
                InstallerErrorKind::CommandFailed,
                "Xray is not installed.",
            )),
        },
    };

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "Xray lifecycle disconnect warning"
        );
    }

    match &result {
        Ok(()) => match operation {
            XrayLifecycleOperation::Install => {
                info!(target: "app", "Xray installation completed");
            }
            XrayLifecycleOperation::Update => {
                info!(target: "app", "Xray version updated");
            }
            XrayLifecycleOperation::Remove => {
                info!(target: "app", "Xray removal completed");
            }
        },
        Err(error) => {
            error!(
                target: "app",
                kind = ?error.kind(),
                detail = %sanitize_detail(error.detail()),
                "Xray {} failed",
                match operation {
                    XrayLifecycleOperation::Install => "installation",
                    XrayLifecycleOperation::Update => "update",
                    XrayLifecycleOperation::Remove => "removal",
                }
            );
        }
    }

    XrayLifecycleOutcome { operation, result }
}

/// Runs connect → available_versions → disconnect.
pub async fn run_version_check<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    installer: &XrayInstaller,
) -> VersionCheckOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request = build_connect_request(profile, secrets);

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            return VersionCheckOutcome {
                result: Err(InstallerError::new(
                    InstallerErrorKind::SshConnectionFailed,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let versions = installer.available_versions(&session).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "version check disconnect warning"
        );
    }

    VersionCheckOutcome {
        result: Ok(versions),
    }
}

/// Maps an installer error to a short user-facing Status Bar message.
pub fn user_facing_installer_error(error: &InstallerError) -> String {
    match error.kind() {
        InstallerErrorKind::SshConnectionFailed => {
            user_message_see_log("SSH connection failed.")
        }
        InstallerErrorKind::DownloadFailed => user_message_see_log("Download failed."),
        InstallerErrorKind::VerificationFailed => user_message_see_log("Verification failed."),
        InstallerErrorKind::PermissionDenied => user_message_see_log("Permission denied."),
        InstallerErrorKind::ServiceCreationFailed => {
            user_message_see_log("Service creation failed.")
        }
        InstallerErrorKind::ServiceStartFailed => user_message_see_log("Service start failed."),
        InstallerErrorKind::BackupFailed => user_message_see_log("Backup failed."),
        InstallerErrorKind::AlreadyInstalled => "Xray is already installed.".to_owned(),
        InstallerErrorKind::UnsupportedSystem => "Unsupported system.".to_owned(),
        InstallerErrorKind::CommandFailed => user_message_see_log("Xray operation failed."),
    }
}

/// Builds the management page model from discovery and lifecycle state.
pub fn build_xray_management_page_model(
    discovery: &DiscoveryState,
    lifecycle: &XrayLifecycleState,
    channel: InstallChannel,
    available: &AvailableVersions,
    version_check_busy: bool,
) -> XrayManagementPageModel {
    let busy = lifecycle.is_busy() || version_check_busy;
    let selected_tag = available.tag_for(channel).map(str::to_owned);
    let (can_use_tag, channel_hint) = channel_action_gate(
        channel,
        available,
        match discovery {
            DiscoveryState::Succeeded(installation) => installation.version.as_deref(),
            _ => None,
        },
        matches!(discovery, DiscoveryState::Succeeded(_)),
    );

    match discovery {
        DiscoveryState::Succeeded(installation) => {
            let supported = installation.service_control_supported();
            XrayManagementPageModel {
                status: InstallationStatus::Installed,
                current_version: installation.version.clone(),
                channel,
                available_stable: available.stable.clone(),
                available_beta: available.beta.clone(),
                available_version: selected_tag,
                stable_error: available.stable_error.clone(),
                beta_error: available.beta_error.clone(),
                binary_path: installation
                    .binary_path
                    .as_ref()
                    .map(|p| p.as_str().to_owned()),
                service_name: installation.service_name.clone(),
                config_path: Some(installation.config_source.label()),
                init_system: Some(installation.init_system),
                can_install: false,
                can_update: supported && !busy && can_use_tag,
                can_remove: supported && !busy,
                can_check_version: !busy,
                blocked_reason: if supported {
                    Some("Xray is already installed.")
                } else {
                    Some("Unsupported init system for Xray lifecycle management.")
                },
                channel_hint,
                lifecycle: lifecycle.clone(),
                version_check_busy,
            }
        }
        DiscoveryState::NotFound { init_system, .. } => {
            let supported = init_system.supports_service_control();
            XrayManagementPageModel {
                status: InstallationStatus::NotInstalled,
                current_version: None,
                channel,
                available_stable: available.stable.clone(),
                available_beta: available.beta.clone(),
                available_version: selected_tag,
                stable_error: available.stable_error.clone(),
                beta_error: available.beta_error.clone(),
                binary_path: None,
                service_name: None,
                config_path: None,
                init_system: Some(*init_system),
                can_install: supported && !busy && can_use_tag,
                can_update: false,
                can_remove: false,
                can_check_version: !busy,
                blocked_reason: if supported {
                    None
                } else {
                    Some("Unsupported init system for Xray lifecycle management.")
                },
                channel_hint,
                lifecycle: lifecycle.clone(),
                version_check_busy,
            }
        }
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::Failed { .. } => XrayManagementPageModel {
            status: InstallationStatus::Unknown,
            current_version: None,
            channel,
            available_stable: available.stable.clone(),
            available_beta: available.beta.clone(),
            available_version: selected_tag,
            stable_error: available.stable_error.clone(),
            beta_error: available.beta_error.clone(),
            binary_path: None,
            service_name: None,
            config_path: None,
            init_system: None,
            can_install: false,
            can_update: false,
            can_remove: false,
            can_check_version: false,
            blocked_reason: Some("Run discovery on the Connection page first."),
            channel_hint: None,
            lifecycle: lifecycle.clone(),
            version_check_busy,
        },
    }
}

/// Whether Install/Update may use the selected channel tag, plus optional hint.
fn channel_action_gate(
    channel: InstallChannel,
    available: &AvailableVersions,
    current: Option<&str>,
    installed: bool,
) -> (bool, Option<&'static str>) {
    let Some(tag) = available.tag_for(channel) else {
        let hint = match channel {
            InstallChannel::Beta => Some("No install candidate from GitHub releases list."),
            InstallChannel::Stable => {
                if available.stable_error.is_some() {
                    Some("Stable version check failed — retry Check versions.")
                } else {
                    Some("Check versions first to enable Install/Update.")
                }
            }
        };
        return (false, hint);
    };

    if !installed {
        return (true, None);
    }

    match current {
        Some(cur) if version_gt(tag, cur) => (true, None),
        Some(_) => (
            false,
            Some("Already on latest/newer for this channel."),
        ),
        None => (true, None),
    }
}

/// Extracts a lifecycle snapshot from discovery state.
pub fn lifecycle_snapshot_from_discovery(
    discovery: &DiscoveryState,
) -> Option<LifecycleDiscoverySnapshot> {
    match discovery {
        DiscoveryState::Succeeded(installation) => Some(LifecycleDiscoverySnapshot {
            installed: true,
            init_system: installation.init_system,
            installation: Some(installation.clone()),
        }),
        DiscoveryState::NotFound { init_system, .. } => Some(LifecycleDiscoverySnapshot {
            installed: false,
            init_system: *init_system,
            installation: None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::ConfigSource;
    use feldjaeger_ssh::RemotePath;

    fn sample_installation(init: InitSystemKind) -> XrayInstallation {
        XrayInstallation {
            operating_system: "Linux".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: init,
            binary_path: Some(RemotePath::new("/usr/local/bin/xray").unwrap()),
            version: Some("26.3.27".to_owned()),
            service_name: Some("xray.service".to_owned()),
            service_state: None,
            exec_start: None,
            config_source: ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        }
    }

    fn versions(stable: Option<&str>, beta: Option<&str>) -> AvailableVersions {
        AvailableVersions {
            stable: stable.map(str::to_owned),
            beta: beta.map(str::to_owned),
            stable_error: None,
            beta_error: None,
        }
    }

    #[test]
    fn page_model_blocks_install_when_installed() {
        let discovery =
            DiscoveryState::Succeeded(sample_installation(InitSystemKind::Systemd));
        let available = versions(Some("26.3.31"), None);
        let model = build_xray_management_page_model(
            &discovery,
            &XrayLifecycleState::Idle,
            InstallChannel::Stable,
            &available,
            false,
        );
        assert!(!model.can_install);
        assert!(model.can_update);
        assert!(model.can_remove);
        assert_eq!(
            model.blocked_reason,
            Some("Xray is already installed.")
        );
    }

    #[test]
    fn page_model_update_requires_newer_tag() {
        let discovery =
            DiscoveryState::Succeeded(sample_installation(InitSystemKind::Systemd));
        let available = versions(Some("26.3.27"), None);
        let model = build_xray_management_page_model(
            &discovery,
            &XrayLifecycleState::Idle,
            InstallChannel::Stable,
            &available,
            false,
        );
        assert!(!model.can_update);
        assert_eq!(
            model.channel_hint,
            Some("Already on latest/newer for this channel.")
        );
    }

    #[test]
    fn page_model_allows_install_when_not_installed_with_tag() {
        let discovery = DiscoveryState::NotFound {
            operating_system: "Linux".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            warnings: Vec::new(),
        };
        let available = versions(Some("26.3.31"), None);
        let model = build_xray_management_page_model(
            &discovery,
            &XrayLifecycleState::Idle,
            InstallChannel::Stable,
            &available,
            false,
        );
        assert!(model.can_install);
        assert!(!model.can_update);
        assert!(!model.can_remove);
    }

    #[test]
    fn page_model_beta_empty_disables_actions() {
        let discovery = DiscoveryState::NotFound {
            operating_system: "Linux".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            warnings: Vec::new(),
        };
        let available = versions(Some("26.3.31"), None);
        let model = build_xray_management_page_model(
            &discovery,
            &XrayLifecycleState::Idle,
            InstallChannel::Beta,
            &available,
            false,
        );
        assert!(!model.can_install);
        assert_eq!(
            model.channel_hint,
            Some("No install candidate from GitHub releases list.")
        );
    }

    #[test]
    fn page_model_requires_discovery() {
        let model = build_xray_management_page_model(
            &DiscoveryState::Idle,
            &XrayLifecycleState::Idle,
            InstallChannel::Stable,
            &AvailableVersions::default(),
            false,
        );
        assert_eq!(model.status, InstallationStatus::Unknown);
        assert_eq!(
            model.blocked_reason,
            Some("Run discovery on the Connection page first.")
        );
    }

    #[test]
    fn confirmation_prompts() {
        assert_eq!(
            XrayLifecycleOperation::Install.confirmation_prompt(
                InstallChannel::Stable,
                None,
                Some("26.3.31")
            ),
            "Install Xray (stable) version 26.3.31?"
        );
        assert!(
            XrayLifecycleOperation::Install
                .confirmation_prompt(InstallChannel::Beta, None, Some("26.4.0-pre"))
                .contains("beta")
        );
        assert_eq!(
            XrayLifecycleOperation::Update.confirmation_prompt(
                InstallChannel::Stable,
                Some("1.0"),
                Some("2.0")
            ),
            "Update Xray from 1.0 to 2.0 (stable)?"
        );
        assert!(
            XrayLifecycleOperation::Remove
                .confirmation_prompt(InstallChannel::Stable, None, None)
                .contains("Configuration files will be preserved")
        );
    }
}
