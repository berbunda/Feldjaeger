//! Backup listing / content fetch / restore remote orchestration (Roadmap §3:127 — Rollback UI).

use feldjaeger_ssh::{RemotePath, SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::config_write::{RemoteConfigValidateHint, map_app_error_to_modify, write_config_validated};
use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::remote::{ConfigBackup, RemoteAdmin};
use crate::storage::StoredConnectionProfile;
use crate::xray::{ConfigModifyError, ConfigModifyErrorKind};

/// Outcome of listing backups for one config source file.
#[derive(Debug, Clone)]
pub struct BackupListOutcome {
    /// The original file the listing was requested for.
    pub original_path: String,
    /// Backups found (newest first), or a classified error message.
    pub result: Result<Vec<ConfigBackup>, String>,
}

/// Lists previously created backups for `original_path` (read-only; no config mutation).
pub async fn run_list_backups<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    original_path: String,
) -> BackupListOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let path = match RemotePath::new(&original_path) {
        Ok(path) => path,
        Err(error) => {
            return BackupListOutcome {
                original_path,
                result: Err(sanitize_detail(error.message())),
            };
        }
    };

    let request = build_connect_request(profile, secrets);
    info!(target: "app", host = %request.profile.host, path = %original_path, "list backups connect");

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            return BackupListOutcome {
                original_path,
                result: Err(sanitize_detail(error.message())),
            };
        }
    };

    let result = remote
        .backup_manager()
        .list_backups(&session, &path)
        .await
        .map_err(|error| sanitize_detail(error.message()));

    if let Err(error) = session.disconnect().await {
        warn!(target: "app", detail = %sanitize_detail(error.message()), "list backups disconnect warning");
    }

    BackupListOutcome {
        original_path,
        result,
    }
}

/// Outcome of fetching one backup's raw content, for the pre-restore diff preview.
#[derive(Debug, Clone)]
pub struct BackupContentOutcome {
    /// The backup file that was read.
    pub backup_path: String,
    /// File bytes, or a classified error message.
    pub result: Result<Vec<u8>, String>,
}

/// Reads a single backup file's content (read-only; no config mutation).
pub async fn run_fetch_backup_content<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    backup_path: String,
) -> BackupContentOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let path = match RemotePath::new(&backup_path) {
        Ok(path) => path,
        Err(error) => {
            return BackupContentOutcome {
                backup_path,
                result: Err(sanitize_detail(error.message())),
            };
        }
    };

    let request = build_connect_request(profile, secrets);
    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            return BackupContentOutcome {
                backup_path,
                result: Err(sanitize_detail(error.message())),
            };
        }
    };

    let result = session
        .read_file(&path)
        .await
        .map_err(|error| sanitize_detail(error.message()));

    if let Err(error) = session.disconnect().await {
        warn!(target: "app", detail = %sanitize_detail(error.message()), "fetch backup content disconnect warning");
    }

    BackupContentOutcome {
        backup_path,
        result,
    }
}

/// Outcome of restoring a named backup over its original file.
#[derive(Debug, Clone)]
pub struct BackupRestoreOutcome {
    /// Classified success/error.
    pub result: Result<(), ConfigModifyError>,
}

/// Restores `backup_path`'s content over `original_path`.
///
/// Goes through the same backup → write → `xray run -test` → restore-on-failure pipeline as
/// every other config mutation ([`write_config_validated`]) — restoring itself is reversible:
/// the file's state right before the rollback is backed up too, and a failed post-restore
/// `-test` reverts to that pre-rollback state, not to the picked backup.
///
/// `expected_current_bytes` is what Feldjäger currently has loaded for `original_path`
/// (`EditableXrayConfig::serialize_source_file`, computed locally, no extra round trip); before
/// writing, the live remote file is read and compared (same conflict-check convention as
/// [`super::log_settings_ops::run_update_log_settings`]) — if someone changed the file
/// remotely since the last Discover, the restore is refused rather than silently clobbering it.
pub async fn run_restore_backup<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    original_path: String,
    backup_path: String,
    expected_current_bytes: Vec<u8>,
    validate_hint: RemoteConfigValidateHint,
) -> BackupRestoreOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let original = match RemotePath::new(&original_path) {
        Ok(path) => path,
        Err(error) => {
            return BackupRestoreOutcome {
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };
    let backup = match RemotePath::new(&backup_path) {
        Ok(path) => path,
        Err(error) => {
            return BackupRestoreOutcome {
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let request = build_connect_request(profile, secrets);
    info!(target: "app", host = %request.profile.host, original = %original_path, backup = %backup_path, "restore backup connect");

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            return BackupRestoreOutcome {
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result = restore_with_conflict_check(
        remote,
        &session,
        &original,
        &backup,
        &expected_current_bytes,
        &validate_hint,
    )
    .await;

    if let Err(error) = session.disconnect().await {
        warn!(target: "app", detail = %sanitize_detail(error.message()), "restore backup disconnect warning");
    }

    if write_result.is_ok() {
        info!(target: "app", original = %original_path, backup = %backup_path, "backup restored");
    }

    BackupRestoreOutcome {
        result: write_result,
    }
}

async fn restore_with_conflict_check<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    original: &RemotePath,
    backup: &RemotePath,
    expected_current_bytes: &[u8],
    validate_hint: &RemoteConfigValidateHint,
) -> Result<(), ConfigModifyError> {
    let remote_bytes = session
        .read_file(original)
        .await
        .map_err(|error| map_app_error_to_modify(crate::error::AppError::new(sanitize_detail(error.message()))))?;
    if !json_bytes_equivalent(&remote_bytes, expected_current_bytes) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ConfigurationChangedRemotely,
            "remote configuration file differs from the loaded copy — reload before restoring"
                .to_owned(),
        ));
    }

    let backup_bytes = session.read_file(backup).await.map_err(|error| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::UploadFailed,
            format!(
                "failed to read backup content: {}",
                sanitize_detail(error.message())
            ),
        )
    })?;

    write_config_validated(remote, session, original, &backup_bytes, validate_hint).await
}

fn json_bytes_equivalent(left: &[u8], right: &[u8]) -> bool {
    let Ok(left_value) = serde_json::from_slice::<serde_json::Value>(left) else {
        return left == right;
    };
    let Ok(right_value) = serde_json::from_slice::<serde_json::Value>(right) else {
        return left == right;
    };
    left_value == right_value
}

fn sanitize_detail(message: &str) -> String {
    crate::logging::redact::sanitize_detail(message)
}
