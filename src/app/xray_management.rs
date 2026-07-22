//! Asynchronous Xray install / update / remove orchestration for [`super::ApplicationService`].

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::{error, info, warn};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::logging::redact::{sanitize_detail, user_message_see_log};
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    DiscoveryState, InitSystemKind, InstallerError, InstallerErrorKind, XrayInstallation,
    XrayInstaller,
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

    /// Confirmation dialog body.
    pub fn confirmation_prompt(
        self,
        current_version: Option<&str>,
        available_version: Option<&str>,
    ) -> String {
        match self {
            Self::Install => "Install Xray?".to_owned(),
            Self::Update => match (current_version, available_version) {
                (Some(from), Some(to)) => format!("Update Xray from version {from} to {to}?"),
                _ => "Update Xray?".to_owned(),
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
    /// Latest available version from GitHub (when checked).
    pub available_version: Option<String>,
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
    /// Explanation when actions are blocked.
    pub blocked_reason: Option<&'static str>,
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
    /// Parsed available version, or classified error.
    pub result: Result<String, InstallerError>,
}

/// Runs connect → install/update/remove → disconnect.
pub async fn run_xray_lifecycle<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    installer: &XrayInstaller,
    snapshot: &LifecycleDiscoverySnapshot,
    operation: XrayLifecycleOperation,
) -> XrayLifecycleOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request = build_connect_request(profile, secrets);

    match operation {
        XrayLifecycleOperation::Install => {
            info!(target: "app", "Starting Xray installation");
        }
        XrayLifecycleOperation::Update => {
            info!(target: "app", "Starting Xray update");
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
                .install(&session, snapshot.init_system, snapshot.installed)
                .await
        }
        XrayLifecycleOperation::Update => match &snapshot.installation {
            Some(installation) => installer.update(&session, installation).await,
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

/// Runs connect → available_version → disconnect.
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

    let result = installer.available_version(&session).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "version check disconnect warning"
        );
    }

    VersionCheckOutcome { result }
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
    available_version: Option<&str>,
    version_check_busy: bool,
) -> XrayManagementPageModel {
    let busy = lifecycle.is_busy() || version_check_busy;

    match discovery {
        DiscoveryState::Succeeded(installation) => {
            let supported = installation.service_control_supported();
            XrayManagementPageModel {
                status: InstallationStatus::Installed,
                current_version: installation.version.clone(),
                available_version: available_version.map(str::to_owned),
                binary_path: installation
                    .binary_path
                    .as_ref()
                    .map(|p| p.as_str().to_owned()),
                service_name: installation.service_name.clone(),
                config_path: Some(installation.config_source.label()),
                init_system: Some(installation.init_system),
                can_install: false,
                can_update: supported && !busy,
                can_remove: supported && !busy,
                can_check_version: !busy,
                blocked_reason: if supported {
                    Some("Xray is already installed.")
                } else {
                    Some("Unsupported init system for Xray lifecycle management.")
                },
                lifecycle: lifecycle.clone(),
                version_check_busy,
            }
        }
        DiscoveryState::NotFound { init_system, .. } => {
            let supported = init_system.supports_service_control();
            XrayManagementPageModel {
                status: InstallationStatus::NotInstalled,
                current_version: None,
                available_version: available_version.map(str::to_owned),
                binary_path: None,
                service_name: None,
                config_path: None,
                init_system: Some(*init_system),
                can_install: supported && !busy,
                can_update: false,
                can_remove: false,
                can_check_version: !busy,
                blocked_reason: if supported {
                    None
                } else {
                    Some("Unsupported init system for Xray lifecycle management.")
                },
                lifecycle: lifecycle.clone(),
                version_check_busy,
            }
        }
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::Failed { .. } => XrayManagementPageModel {
            status: InstallationStatus::Unknown,
            current_version: None,
            available_version: available_version.map(str::to_owned),
            binary_path: None,
            service_name: None,
            config_path: None,
            init_system: None,
            can_install: false,
            can_update: false,
            can_remove: false,
            can_check_version: false,
            blocked_reason: Some("Run discovery on the Connection page first."),
            lifecycle: lifecycle.clone(),
            version_check_busy,
        },
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

    #[test]
    fn page_model_blocks_install_when_installed() {
        let discovery =
            DiscoveryState::Succeeded(sample_installation(InitSystemKind::Systemd));
        let model = build_xray_management_page_model(
            &discovery,
            &XrayLifecycleState::Idle,
            Some("26.3.31"),
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
    fn page_model_allows_install_when_not_installed() {
        let discovery = DiscoveryState::NotFound {
            operating_system: "Linux".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            warnings: Vec::new(),
        };
        let model = build_xray_management_page_model(
            &discovery,
            &XrayLifecycleState::Idle,
            None,
            false,
        );
        assert!(model.can_install);
        assert!(!model.can_update);
        assert!(!model.can_remove);
    }

    #[test]
    fn page_model_requires_discovery() {
        let model = build_xray_management_page_model(
            &DiscoveryState::Idle,
            &XrayLifecycleState::Idle,
            None,
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
            XrayLifecycleOperation::Install.confirmation_prompt(None, None),
            "Install Xray?"
        );
        assert_eq!(
            XrayLifecycleOperation::Update
                .confirmation_prompt(Some("1.0"), Some("2.0")),
            "Update Xray from version 1.0 to 2.0?"
        );
        assert!(
            XrayLifecycleOperation::Remove
                .confirmation_prompt(None, None)
                .contains("Configuration files will be preserved")
        );
    }
}
