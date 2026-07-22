//! Typed errors for remote service control operations.

use std::fmt;

use crate::error::AppError;

/// Classifies a failed service lifecycle operation for UI and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOperationErrorKind {
    /// SSH connection could not be established or was lost.
    SshConnectionFailed,
    /// Remote user lacks permission to run systemctl.
    PermissionDenied,
    /// The discovered unit does not exist on the remote host.
    ServiceNotFound,
    /// `systemctl` returned a non-zero exit code not covered above.
    CommandFailed,
    /// Init system is not systemd (or otherwise unsupported).
    UnsupportedInitSystem,
    /// Service state could not be determined after the operation.
    StateUnknown,
}

impl ServiceOperationErrorKind {
    /// Stable user-facing label (no secrets).
    pub fn label(self) -> &'static str {
        match self {
            Self::SshConnectionFailed => "SSH connection failed",
            Self::PermissionDenied => "Permission denied",
            Self::ServiceNotFound => "Service not found",
            Self::CommandFailed => "systemctl command failed",
            Self::UnsupportedInitSystem => "Unsupported init system",
            Self::StateUnknown => "Service state unknown",
        }
    }
}

/// Error returned by init-system service control operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceControlError {
    kind: ServiceOperationErrorKind,
    detail: String,
}

impl ServiceControlError {
    /// Creates an error with a classified kind and safe detail text.
    pub fn new(kind: ServiceOperationErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Error classification.
    pub fn kind(&self) -> ServiceOperationErrorKind {
        self.kind
    }

    /// Additional detail safe for UI (no passwords, keys, or secrets).
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

impl fmt::Display for ServiceControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for ServiceControlError {}

impl From<ServiceControlError> for AppError {
    fn from(error: ServiceControlError) -> Self {
        AppError::new(error.message())
    }
}

/// Convenience alias for init-system service control results.
pub type ServiceControlResult<T> = Result<T, ServiceControlError>;

/// Classifies a `systemctl` failure from exit code and stderr text.
pub fn classify_systemctl_failure(
    action: &str,
    service_name: &str,
    exit_code: i32,
    stderr: &str,
) -> ServiceControlError {
    let sanitized = crate::logging::redact::sanitize_detail(stderr.trim());
    let lower = sanitized.to_ascii_lowercase();

    let kind = if lower.contains("permission denied")
        || lower.contains("access denied")
        || lower.contains("interactive authentication required")
        || lower.contains("authentication is required")
        || lower.contains("not authorized")
    {
        ServiceOperationErrorKind::PermissionDenied
    } else if lower.contains("not found")
        || lower.contains("could not be found")
        || lower.contains("unit file") && lower.contains("does not exist")
        || exit_code == 5
    {
        ServiceOperationErrorKind::ServiceNotFound
    } else {
        ServiceOperationErrorKind::CommandFailed
    };

    let detail = if sanitized.is_empty() {
        format!("systemctl {action} {service_name} failed with exit code {exit_code}")
    } else {
        format!(
            "systemctl {action} {service_name} failed with exit code {exit_code}: {sanitized}"
        )
    };

    ServiceControlError::new(kind, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_permission_denied() {
        let error = classify_systemctl_failure(
            "stop",
            "xray.service",
            1,
            "Failed to stop xray.service: Interactive authentication required.",
        );
        assert_eq!(error.kind(), ServiceOperationErrorKind::PermissionDenied);
        assert_eq!(error.kind().label(), "Permission denied");
    }

    #[test]
    fn classifies_service_not_found() {
        let error = classify_systemctl_failure(
            "start",
            "xray.service",
            5,
            "Unit xray.service could not be found.",
        );
        assert_eq!(error.kind(), ServiceOperationErrorKind::ServiceNotFound);
    }

    #[test]
    fn classifies_generic_command_failure() {
        let error =
            classify_systemctl_failure("restart", "xray.service", 1, "Job for xray.service failed.");
        assert_eq!(error.kind(), ServiceOperationErrorKind::CommandFailed);
        assert!(error.message().contains("systemctl command failed"));
    }
}
