//! High-level remote administration facade.

use feldjaeger_ssh::{RemotePath, SshError, SshSession};
use tracing::info;

use crate::error::{AppError, AppResult};
use crate::remote::{BackupManager, ConfigBackup};

/// Orchestrates remote operations over an SSH session.
///
/// Upper layers (GUI, Xray) interact with the remote server through this type
/// instead of calling SSH APIs directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAdmin {
    backup: BackupManager,
}

impl RemoteAdmin {
    /// Creates a new remote admin facade.
    pub fn new() -> Self {
        Self {
            backup: BackupManager::new(),
        }
    }

    /// Returns the backup manager used before configuration writes.
    pub fn backup_manager(&self) -> &BackupManager {
        &self.backup
    }

    /// Reads a remote file via the given SSH session.
    pub async fn read_config<S: SshSession>(
        &self,
        session: &S,
        path: &RemotePath,
    ) -> AppResult<Vec<u8>> {
        session
            .read_file(path)
            .await
            .map_err(|error| AppError::new(sanitize_ssh_detail(error.message())))
    }

    /// Creates a backup, then atomically replaces the remote configuration file.
    ///
    /// Returns the backup metadata so callers can restore after a failed
    /// `xray run -test` (IB-L6).
    ///
    /// If backup creation fails, the original file is left untouched and the
    /// error message starts with `Backup failed`.
    pub async fn write_config_safe<S: SshSession>(
        &self,
        session: &S,
        path: &RemotePath,
        contents: &[u8],
    ) -> AppResult<ConfigBackup> {
        info!(
            target: "remote",
            host = %session.profile().host,
            user = %session.profile().username,
            path = %path.as_str(),
            bytes = contents.len(),
            "safe config write"
        );

        let backup = self
            .backup
            .create_backup(session, path)
            .await
            .map_err(|error| {
                AppError::new(format!(
                    "Backup failed: {}",
                    sanitize_ssh_detail(error.message())
                ))
            })?;

        session
            .write_file_atomic(path, contents)
            .await
            .map_err(map_upload_error)?;

        info!(
            target: "remote",
            host = %session.profile().host,
            user = %session.profile().username,
            path = %path.as_str(),
            "safe config write completed"
        );

        Ok(backup)
    }
}

impl Default for RemoteAdmin {
    fn default() -> Self {
        Self::new()
    }
}

fn map_upload_error(error: SshError) -> AppError {
    let detail = sanitize_ssh_detail(error.message());
    let lower = detail.to_ascii_lowercase();
    if lower.contains("permission denied") || lower.contains("permissiondenied") {
        AppError::new(format!("Permission denied: {detail}"))
    } else if lower.contains("connection")
        || lower.contains("broken pipe")
        || lower.contains("reset")
        || lower.contains("closed")
        || lower.contains("timed out")
        || lower.contains("timeout")
    {
        AppError::new(format!("Connection lost: {detail}"))
    } else {
        AppError::new(format!("Upload failed: {detail}"))
    }
}

fn sanitize_ssh_detail(message: &str) -> String {
    crate::logging::redact::sanitize_detail(message)
}
