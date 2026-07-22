//! Errors for read-only Xray log access.

use std::fmt;

/// Classified failure while resolving or reading Xray runtime logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayLogErrorKind {
    /// No active SSH connection.
    NoSshConnection,
    /// Discovery has not found Xray.
    XrayNotDiscovered,
    /// Selected source is disabled in configuration.
    LogSourceDisabled,
    /// Configured log file is missing.
    LogFileMissing,
    /// Remote path or journal is not readable.
    PermissionDenied,
    /// Destination is stdout/stderr/unknown or otherwise unsupported for file read.
    UnsupportedLogDestination,
    /// Host init system is not systemd (journal only).
    UnsupportedInitSystem,
    /// Discovery did not yield a service unit name.
    ServiceNotFound,
    /// `journalctl` failed or journal is unavailable.
    JournalUnavailable,
    /// Generic remote read failure.
    RemoteReadFailed,
    /// Follow worker stopped unexpectedly.
    FollowSessionInterrupted,
}

impl XrayLogErrorKind {
    /// Short user-facing label.
    pub fn label(self) -> &'static str {
        match self {
            Self::NoSshConnection => "No SSH connection",
            Self::XrayNotDiscovered => "Xray not discovered",
            Self::LogSourceDisabled => "Log source disabled",
            Self::LogFileMissing => "Log file missing",
            Self::PermissionDenied => "Permission denied",
            Self::UnsupportedLogDestination => "Unsupported log destination",
            Self::UnsupportedInitSystem => "Unsupported init system",
            Self::ServiceNotFound => "Service not found",
            Self::JournalUnavailable => "Journal unavailable",
            Self::RemoteReadFailed => "Remote read failed",
            Self::FollowSessionInterrupted => "Follow session interrupted",
        }
    }
}

/// Error returned by [`super::XrayLogService`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayLogError {
    /// Classification for GUI state.
    pub kind: XrayLogErrorKind,
    /// Safe user-facing detail (no remote log bodies).
    pub detail: String,
}

impl XrayLogError {
    /// Creates a classified error.
    pub fn new(kind: XrayLogErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for XrayLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.label(), self.detail)
    }
}

impl std::error::Error for XrayLogError {}

/// Result alias for log service operations.
pub type XrayLogResult<T> = Result<T, XrayLogError>;
