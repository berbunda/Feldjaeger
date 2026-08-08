//! Classified errors for Cloudflare WARP integration operations.

use std::fmt;

/// Classifies a failed WARP operation for UI and logs (no secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarpErrorKind {
    /// SSH connection missing or lost.
    NoSshConnection,
    /// Xray installation was not discovered.
    XrayNotDiscovered,
    /// Detected Xray version may lack WireGuard outbound support.
    UnsupportedXrayVersion,
    /// Remote OS is not Linux.
    UnsupportedOperatingSystem,
    /// Remote CPU architecture is not supported for the helper.
    UnsupportedArchitecture,
    /// Helper download from the approved source failed.
    HelperDownloadFailed,
    /// Helper failed integrity / format / version verification.
    HelperVerificationFailed,
    /// Running the registration helper failed.
    HelperExecutionFailed,
    /// Helper binary is missing from the managed tools directory.
    HelperMissing,
    /// Helper is present but cannot be used (permission / format).
    HelperUnavailable,
    /// No permission to install the helper under the managed tools path.
    NoPermissionToInstallHelper,
    /// No permission to modify Xray configuration.
    NoPermissionToModifyConfiguration,
    /// Cloudflare WARP device registration failed.
    WarpRegistrationFailed,
    /// Generated Xray outbound JSON was missing.
    GeneratedConfigurationMissing,
    /// Generated Xray outbound JSON failed structural checks.
    GeneratedConfigurationInvalid,
    /// Requested outbound tag conflicts with an existing outbound.
    OutboundTagConflict,
    /// Creating a required backup failed; operation aborted.
    BackupFailed,
    /// Writing a remote file failed.
    RemoteWriteFailed,
    /// Xray configuration validation failed.
    XrayValidationFailed,
    /// Restarting Xray failed (reported separately from config write).
    XrayRestartFailed,
    /// Connectivity test timed out.
    ConnectivityTestTimedOut,
    /// Cloudflare reports WARP inactive for a diagnostic probe.
    WarpInactive,
    /// UDP path required for WireGuard appears blocked.
    UdpBlocked,
    /// Routing or other references block outbound removal.
    ConfigurationReferencePreventsRemoval,
    /// Rollback after a failed write did not succeed.
    RollbackFailed,
    /// Cloudflare registration API unreachable.
    CloudflareRegistrationUnavailable,
    /// Cloudflare WARP endpoint unreachable.
    CloudflareEndpointUnreachable,
    /// Environment explicitly unsupported for this integration.
    UnsupportedEnvironment,
    /// Generic remote command failure (sanitized detail).
    CommandFailed,
    /// Outbound-specific connectivity test cannot be performed safely.
    OutboundSpecificTestUnavailable,
    /// Managed WARP outbound was not found.
    ManagedOutboundMissing,
    /// Operation cancelled because another exclusive remote op is running.
    OperationBusy,
    /// Stale asynchronous result discarded.
    StaleResult,
}

impl WarpErrorKind {
    /// Stable user-facing label (no secrets).
    pub fn label(self) -> &'static str {
        match self {
            Self::NoSshConnection => "No SSH connection",
            Self::XrayNotDiscovered => "Xray not discovered",
            Self::UnsupportedXrayVersion => "Unsupported Xray version",
            Self::UnsupportedOperatingSystem => "Unsupported operating system",
            Self::UnsupportedArchitecture => "Unsupported architecture",
            Self::HelperDownloadFailed => "Helper download failed",
            Self::HelperVerificationFailed => "Helper verification failed",
            Self::HelperExecutionFailed => "Helper execution failed",
            Self::HelperMissing => "Helper not installed",
            Self::HelperUnavailable => "Helper unavailable",
            Self::NoPermissionToInstallHelper => "No permission to install helper",
            Self::NoPermissionToModifyConfiguration => "No permission to modify configuration",
            Self::WarpRegistrationFailed => "WARP registration failed",
            Self::GeneratedConfigurationMissing => "Generated configuration missing",
            Self::GeneratedConfigurationInvalid => "Generated configuration invalid",
            Self::OutboundTagConflict => "Outbound tag conflict",
            Self::BackupFailed => "Backup failed",
            Self::RemoteWriteFailed => "Remote write failed",
            Self::XrayValidationFailed => "Xray validation failed",
            Self::XrayRestartFailed => "Xray restart failed",
            Self::ConnectivityTestTimedOut => "Connectivity test timed out",
            Self::WarpInactive => "WARP inactive",
            Self::UdpBlocked => "UDP blocked",
            Self::ConfigurationReferencePreventsRemoval => {
                "Configuration reference prevents removal"
            }
            Self::RollbackFailed => "Rollback failed",
            Self::CloudflareRegistrationUnavailable => "Cloudflare registration unavailable",
            Self::CloudflareEndpointUnreachable => "Cloudflare endpoint unreachable",
            Self::UnsupportedEnvironment => "Unsupported environment",
            Self::CommandFailed => "Command failed",
            Self::OutboundSpecificTestUnavailable => {
                "Outbound-specific connectivity test is unavailable"
            }
            Self::ManagedOutboundMissing => "Managed WARP outbound missing",
            Self::OperationBusy => "Another operation is already running",
            Self::StaleResult => "Stale asynchronous result",
        }
    }
}

/// Error returned by [`super::WarpManager`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpError {
    kind: WarpErrorKind,
    detail: String,
}

impl WarpError {
    /// Creates an error with a classified kind and safe detail text.
    pub fn new(kind: WarpErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Error classification.
    pub fn kind(&self) -> WarpErrorKind {
        self.kind
    }

    /// Additional detail safe for UI (no secrets).
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Combined message: kind label plus optional detail.
    pub fn message(&self) -> String {
        if self.detail.is_empty() {
            self.kind.label().to_owned()
        } else {
            format!("{}: {}", self.kind.label(), self.detail)
        }
    }
}

impl fmt::Display for WarpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for WarpError {}

/// Convenience alias for WARP results.
pub type WarpResult<T> = Result<T, WarpError>;
