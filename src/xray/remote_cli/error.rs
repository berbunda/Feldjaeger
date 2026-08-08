//! Errors from remote Xray CLI helpers.

use std::fmt;

/// Classifies a remote CLI failure for UI and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteCliErrorKind {
    /// SSH / transport failure.
    ConnectionLost,
    /// Binary path missing or command rejected.
    CommandFailed,
    /// Non-zero exit from `xray`.
    NonZeroExit,
    /// Stdout did not match expected labels.
    ParseFailed,
    /// Operation timed out.
    TimedOut,
}

impl RemoteCliErrorKind {
    /// Stable UI label.
    pub fn label(self) -> &'static str {
        match self {
            Self::ConnectionLost => "No SSH connection",
            Self::CommandFailed => "Xray CLI failed",
            Self::NonZeroExit => "Xray CLI exited with error",
            Self::ParseFailed => "Unexpected Xray CLI output",
            Self::TimedOut => "Xray CLI timed out",
        }
    }
}

/// Error returned by remote CLI helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCliError {
    kind: RemoteCliErrorKind,
    detail: String,
}

impl RemoteCliError {
    /// Creates a classified error (detail must not contain secrets).
    pub fn new(kind: RemoteCliErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Error kind.
    pub fn kind(&self) -> RemoteCliErrorKind {
        self.kind
    }

    /// Safe detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Combined message.
    pub fn message(&self) -> String {
        if self.detail.is_empty() {
            self.kind.label().to_owned()
        } else {
            format!("{}: {}", self.kind.label(), self.detail)
        }
    }
}

impl fmt::Display for RemoteCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for RemoteCliError {}

/// Result alias.
pub type RemoteCliResult<T> = Result<T, RemoteCliError>;
