//! Discovered remote Xray installation model.

use feldjaeger_ssh::RemotePath;

use crate::init::ServiceState;

/// Init system detected on the remote host.
///
/// Detection uses runtime markers, not distribution names alone.
/// Only [`InitSystemKind::Systemd`] supports service control in the MVP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystemKind {
    /// systemd (`/run/systemd/system`, `systemctl`, …).
    Systemd,
    /// OpenRC (`/sbin/openrc`, OpenRC-style `/etc/init.d`, …).
    OpenRC,
    /// runit (`/etc/runit`, `/etc/sv`, …).
    Runit,
    /// Init system could not be identified.
    Unknown,
}

impl InitSystemKind {
    /// Human-readable label for UI summaries.
    pub fn label(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::OpenRC => "OpenRC",
            Self::Runit => "runit",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` when Feldjaeger can control services on this init system.
    pub fn supports_service_control(self) -> bool {
        matches!(self, Self::Systemd)
    }
}

/// Where the Xray configuration was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Single JSON configuration file.
    SingleFile(RemotePath),
    /// Configuration directory containing one or more `.json` files.
    ConfigDirectory(RemotePath),
    /// No configuration path could be located.
    NotFound,
    /// A path was hinted but could not be classified.
    Unknown,
}

impl ConfigSource {
    /// Short label for UI summaries.
    pub fn label(&self) -> String {
        match self {
            Self::SingleFile(path) => format!("file: {}", path.as_str()),
            Self::ConfigDirectory(path) => format!("directory: {}", path.as_str()),
            Self::NotFound => "not found".to_owned(),
            Self::Unknown => "unknown".to_owned(),
        }
    }
}

/// Non-fatal discovery findings that do not abort the overall result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryWarning {
    /// Binary exists but `xray version` could not be parsed.
    VersionUnavailable,
    /// No matching systemd unit was found.
    ServiceNotFound,
    /// No configuration path was discovered.
    ConfigNotFound,
    /// Configuration path exists but could not be read.
    ConfigUnreadable {
        /// Safe detail (no secrets).
        detail: String,
    },
    /// Configuration bytes were read but failed JSON/Xray parsing.
    ConfigInvalid {
        /// Parser error detail (no secrets).
        detail: String,
    },
    /// Init system was detected but service control is unsupported.
    UnsupportedInitSystem {
        /// Detected init system.
        kind: InitSystemKind,
    },
    /// Additional informational warning.
    Other {
        /// Safe detail text.
        detail: String,
    },
}

impl DiscoveryWarning {
    /// Human-readable warning text for the UI.
    pub fn message(&self) -> String {
        match self {
            Self::VersionUnavailable => "Xray binary found but version is unavailable".to_owned(),
            Self::ServiceNotFound => "Xray service not found".to_owned(),
            Self::ConfigNotFound => "Xray configuration not found".to_owned(),
            Self::ConfigUnreadable { detail } => {
                format!("Xray configuration is unreadable: {detail}")
            }
            Self::ConfigInvalid { detail } => {
                format!("Xray configuration is invalid: {detail}")
            }
            Self::UnsupportedInitSystem { kind } => {
                format!(
                    "Init system {} is unsupported for service control",
                    kind.label()
                )
            }
            Self::Other { detail } => detail.clone(),
        }
    }
}

/// Classified discovery failure that is not “Xray not installed”.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryErrorKind {
    /// SSH session failed mid-discovery.
    SshConnectionLost,
    /// Remote permission denied for a required read/query.
    PermissionDenied,
    /// Unexpected internal or remote failure.
    Unexpected,
}

impl DiscoveryErrorKind {
    /// Short label for UI / Status Bar.
    pub fn label(self) -> &'static str {
        match self {
            Self::SshConnectionLost => "SSH connection lost",
            Self::PermissionDenied => "Permission denied",
            Self::Unexpected => "Unexpected discovery error",
        }
    }
}

/// Read-only snapshot of a discovered remote Xray installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayInstallation {
    /// Linux distribution / OS description from `/etc/os-release`.
    pub operating_system: String,
    /// Machine architecture from `uname -m`.
    pub architecture: String,
    /// Detected init system.
    pub init_system: InitSystemKind,
    /// Absolute path to the Xray binary, when found.
    pub binary_path: Option<RemotePath>,
    /// Version reported by the official Xray executable.
    pub version: Option<String>,
    /// systemd unit name (or equivalent), when found.
    pub service_name: Option<String>,
    /// Service lifecycle state, when queryable.
    pub service_state: Option<ServiceState>,
    /// Effective `ExecStart` command line from systemd, when available.
    pub exec_start: Option<String>,
    /// Discovered configuration source.
    pub config_source: ConfigSource,
    /// Whether at least one configuration file was readable.
    pub config_readable: bool,
    /// Ordered list of `.json` files for [`ConfigSource::ConfigDirectory`].
    pub config_files: Vec<RemotePath>,
    /// Non-fatal findings collected during discovery.
    pub discovery_warnings: Vec<DiscoveryWarning>,
}

impl XrayInstallation {
    /// Returns `true` when service start/stop/restart is supported.
    pub fn service_control_supported(&self) -> bool {
        self.init_system.supports_service_control()
    }
}

/// Explicit lifecycle of a GUI-triggered discovery operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DiscoveryState {
    /// No discovery has been started.
    #[default]
    Idle,
    /// Discovery is running off the UI thread.
    Discovering,
    /// Xray installation was found.
    Succeeded(XrayInstallation),
    /// Host was reachable but no Xray binary was found.
    NotFound {
        /// Optional host OS summary collected before giving up.
        operating_system: String,
        /// Optional architecture collected before giving up.
        architecture: String,
        /// Detected init system, if any.
        init_system: InitSystemKind,
        /// Warnings gathered while probing the host.
        warnings: Vec<DiscoveryWarning>,
    },
    /// Discovery failed for a technical reason (not “not installed”).
    Failed {
        /// Classified failure kind.
        kind: DiscoveryErrorKind,
        /// Safe detail for UI (no secrets).
        detail: String,
    },
}

impl DiscoveryState {
    /// Returns `true` while discovery is in flight.
    pub fn is_discovering(&self) -> bool {
        matches!(self, Self::Discovering)
    }

    /// Button label for the Discover control.
    pub fn button_label(&self) -> &'static str {
        if self.is_discovering() {
            "Discovering..."
        } else {
            "Discover Xray"
        }
    }
}
