//! Remote administration operations.
//!
//! Orchestrates SSH-backed file operations such as configuration backup.
//! Does not expose raw SSH commands to upper layers.

mod admin;
mod backup;
mod backup_manager;

pub use admin::RemoteAdmin;
pub use backup::ConfigBackup;
pub use backup_manager::{BackupManager, BackupManagerOptions};
