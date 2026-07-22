//! Typed errors for VLESS client configuration modifications.

use std::fmt;

use crate::error::AppError;

/// Classifies a failed configuration modification for UI and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigModifyErrorKind {
    /// Remote backup could not be created; write was aborted.
    BackupFailed,
    /// Resulting configuration failed validation.
    ValidationFailed,
    /// Modified configuration could not be serialized to JSON.
    SerializationFailed,
    /// Uploading the new configuration file failed.
    UploadFailed,
    /// Remote filesystem denied the operation.
    PermissionDenied,
    /// SSH session was lost during the operation.
    ConnectionLost,
    /// Target client was not found in the inbound.
    UserNotFound,
    /// Target inbound was not found or is out of range.
    InboundNotFound,
    /// Selected inbound protocol is not editable (not VLESS).
    UnsupportedInbound,
    /// Another client already uses the same UUID.
    UuidConflict,
    /// Another client already uses the same email.
    EmailConflict,
}

impl ConfigModifyErrorKind {
    /// Stable user-facing label (no secrets).
    pub fn label(self) -> &'static str {
        match self {
            Self::BackupFailed => "Backup failed",
            Self::ValidationFailed => "Validation failed",
            Self::SerializationFailed => "Serialization failed",
            Self::UploadFailed => "Upload failed",
            Self::PermissionDenied => "Permission denied",
            Self::ConnectionLost => "Connection lost",
            Self::UserNotFound => "User not found",
            Self::InboundNotFound => "Inbound not found",
            Self::UnsupportedInbound => "Unsupported inbound type",
            Self::UuidConflict => "Validation failed",
            Self::EmailConflict => "Validation failed",
        }
    }
}

/// Error returned by configuration modification operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigModifyError {
    kind: ConfigModifyErrorKind,
    detail: String,
}

impl ConfigModifyError {
    /// Creates an error with a classified kind and safe detail text.
    pub fn new(kind: ConfigModifyErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Error classification.
    pub fn kind(&self) -> ConfigModifyErrorKind {
        self.kind
    }

    /// Additional detail safe for UI (no passwords, keys, or foreign UUIDs).
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

impl fmt::Display for ConfigModifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for ConfigModifyError {}

impl From<ConfigModifyError> for AppError {
    fn from(value: ConfigModifyError) -> Self {
        AppError::new(value.message())
    }
}

/// Result alias for configuration modification helpers.
pub type ConfigModifyResult<T> = Result<T, ConfigModifyError>;
