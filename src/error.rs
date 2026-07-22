//! Application-wide error types.

use std::fmt;

/// Unified error type for Feldjaeger operations.
///
/// All expected runtime failures are represented here instead of panicking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    message: String,
}

impl AppError {
    /// Creates a new error with the given message.
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

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AppError {}

/// Convenience alias for results in Feldjaeger.
pub type AppResult<T> = Result<T, AppError>;
