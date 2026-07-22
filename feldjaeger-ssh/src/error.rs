//! SSH-layer error types.

use std::fmt;

/// Error type for SSH transport operations.
///
/// Expected runtime failures are represented here instead of panicking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshError {
    message: String,
}

impl SshError {
    /// Creates a new SSH error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SshError {}

/// Convenience alias for results in the SSH layer.
pub type SshResult<T> = Result<T, SshError>;
