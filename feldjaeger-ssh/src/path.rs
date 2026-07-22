//! Remote filesystem path model.

use crate::error::{SshError, SshResult};

/// Validated absolute path on a remote server.
///
/// Paths are validated before any remote operation to reduce attack surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePath {
    path: String,
}

impl RemotePath {
    /// Creates a new remote path after validation.
    pub fn new(path: impl Into<String>) -> SshResult<Self> {
        let path = path.into();

        if path.is_empty() {
            return Err(SshError::new("remote path must not be empty"));
        }

        if !path.starts_with('/') {
            return Err(SshError::new("remote path must be absolute"));
        }

        if path.contains('\0') {
            return Err(SshError::new("remote path must not contain null bytes"));
        }

        Ok(Self { path })
    }

    /// Returns the path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.path
    }
}
