//! Typed errors for configuration modifications (users, log settings, …).

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
    /// Selected inbound protocol is not editable (not Tier‑2 / not enabled).
    UnsupportedInbound,
    /// Inbound has both `settings.clients` and `settings.users`.
    AmbiguousClientsArray,
    /// Client JSON fingerprint does not match the expected value (stale UI).
    FingerprintMismatch,
    /// Another client already uses the same UUID.
    UuidConflict,
    /// Another client already uses the same email.
    EmailConflict,
    /// Top-level `log` value is not a JSON object.
    MalformedLogObject,
    /// A log field contains an unsupported value that blocks the requested edit.
    UnsupportedLogValue,
    /// Access/error file path failed validation.
    InvalidFilePath,
    /// Custom `maskAddress` format is invalid.
    InvalidMaskFormat,
    /// Remote file changed since the configuration was loaded.
    ConfigurationChangedRemotely,
    /// Official / structural Xray configuration validation failed.
    XrayValidationFailed,
    /// Requested outbound tag already exists.
    OutboundTagConflict,
    /// Target outbound was not found.
    OutboundNotFound,
}

impl ConfigModifyErrorKind {
    /// Stable user-facing label (no secrets).
    pub fn label(self) -> &'static str {
        match self {
            Self::BackupFailed => "Backup failed",
            Self::ValidationFailed => "Validation failed",
            Self::SerializationFailed => "Serialization failed",
            Self::UploadFailed => "Remote write failed",
            Self::PermissionDenied => "Permission denied",
            Self::ConnectionLost => "No SSH connection",
            Self::UserNotFound => "User not found",
            Self::InboundNotFound => "Inbound not found",
            Self::UnsupportedInbound => "Unsupported inbound type",
            Self::AmbiguousClientsArray => "Ambiguous clients/users arrays",
            Self::FingerprintMismatch => "Configuration changed since edit started",
            Self::UuidConflict => "Validation failed",
            Self::EmailConflict => "Validation failed",
            Self::MalformedLogObject => "Malformed log object",
            Self::UnsupportedLogValue => "Unsupported log value",
            Self::InvalidFilePath => "Invalid file path",
            Self::InvalidMaskFormat => "Invalid mask format",
            Self::ConfigurationChangedRemotely => "Configuration changed remotely",
            Self::XrayValidationFailed => "Xray configuration validation failed",
            Self::OutboundTagConflict => "Outbound tag conflict",
            Self::OutboundNotFound => "Outbound not found",
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
