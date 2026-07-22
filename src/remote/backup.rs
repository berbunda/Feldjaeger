//! Remote configuration backup types.

use feldjaeger_ssh::RemotePath;

/// Metadata describing a backup of a remote configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigBackup {
    /// Path to the original remote configuration file.
    pub original_path: RemotePath,
    /// Path where the backup was stored on the remote server.
    pub backup_path: RemotePath,
    /// UTC unix timestamp (seconds) when the backup was created.
    pub created_at_unix: u64,
    /// Size of the backup payload in bytes.
    pub size_bytes: usize,
}

impl ConfigBackup {
    /// Creates a new backup descriptor.
    pub fn new(
        original_path: RemotePath,
        backup_path: RemotePath,
        created_at_unix: u64,
        size_bytes: usize,
    ) -> Self {
        Self {
            original_path,
            backup_path,
            created_at_unix,
            size_bytes,
        }
    }
}
