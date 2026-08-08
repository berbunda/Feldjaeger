//! Remote write helpers for WARP outbound configuration mutations.
//!
//! Reuses the same conflict-check + backup + atomic write path as log settings.

use feldjaeger_ssh::{RemotePath, SshSession};
use tracing::info;

use crate::app::config_write::{RemoteConfigValidateHint, write_config_validated};
use crate::remote::RemoteAdmin;
use crate::xray::{
    ConfigModifyError, ConfigModifyErrorKind, EditableXrayConfig, ModifyConfigOutcome, WarpError,
    WarpErrorKind,
};

/// Successful remote write of an outbound mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpConfigWriteSuccess {
    /// Editable model after the in-memory mutation (already applied remotely).
    pub editable: EditableXrayConfig,
}

/// Writes an added outbound through the shared safe config path.
pub async fn apply_add_outbound<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    editable: &EditableXrayConfig,
    outcome: ModifyConfigOutcome,
    validate_hint: &RemoteConfigValidateHint,
) -> Result<WarpConfigWriteSuccess, WarpError> {
    write_with_conflict_check(remote, session, &outcome, validate_hint).await?;
    Ok(WarpConfigWriteSuccess {
        editable: editable.clone(),
    })
}

/// Writes a replaced outbound through the shared safe config path.
pub async fn apply_replace_outbound<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    editable: &EditableXrayConfig,
    outcome: ModifyConfigOutcome,
    validate_hint: &RemoteConfigValidateHint,
) -> Result<WarpConfigWriteSuccess, WarpError> {
    write_with_conflict_check(remote, session, &outcome, validate_hint).await?;
    Ok(WarpConfigWriteSuccess {
        editable: editable.clone(),
    })
}

/// Writes an outbound removal through the shared safe config path.
pub async fn apply_remove_outbound<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    editable: &EditableXrayConfig,
    outcome: ModifyConfigOutcome,
    validate_hint: &RemoteConfigValidateHint,
) -> Result<WarpConfigWriteSuccess, WarpError> {
    write_with_conflict_check(remote, session, &outcome, validate_hint).await?;
    Ok(WarpConfigWriteSuccess {
        editable: editable.clone(),
    })
}

async fn write_with_conflict_check<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    outcome: &ModifyConfigOutcome,
    validate_hint: &RemoteConfigValidateHint,
) -> Result<(), WarpError> {
    let path = RemotePath::new(&outcome.source_file).map_err(|error| {
        WarpError::new(
            WarpErrorKind::RemoteWriteFailed,
            sanitize_detail(error.message()),
        )
    })?;

    match session.read_file(&path).await {
        Ok(remote_bytes) => {
            if !json_bytes_equivalent(&remote_bytes, &outcome.original_serialized) {
                return Err(WarpError::new(
                    WarpErrorKind::RemoteWriteFailed,
                    "remote configuration file differs from the loaded copy",
                ));
            }
        }
        Err(error) => {
            let message = error.message();
            if !message.to_ascii_lowercase().contains("not found")
                && !message.to_ascii_lowercase().contains("no such file")
            {
                return Err(WarpError::new(
                    WarpErrorKind::RemoteWriteFailed,
                    sanitize_detail(message),
                ));
            }
        }
    }

    write_config_validated(remote, session, &path, &outcome.serialized, validate_hint)
        .await
        .map_err(map_config_error_to_warp)?;

    info!(target: "app", path = %outcome.source_file, "WARP outbound configuration written");
    Ok(())
}

/// Maps a config-modify error into [`WarpError`].
pub fn map_config_error_to_warp(error: ConfigModifyError) -> WarpError {
    let kind = match error.kind() {
        ConfigModifyErrorKind::BackupFailed => WarpErrorKind::BackupFailed,
        ConfigModifyErrorKind::OutboundTagConflict => WarpErrorKind::OutboundTagConflict,
        ConfigModifyErrorKind::OutboundNotFound => WarpErrorKind::ManagedOutboundMissing,
        ConfigModifyErrorKind::XrayValidationFailed | ConfigModifyErrorKind::ValidationFailed => {
            WarpErrorKind::XrayValidationFailed
        }
        ConfigModifyErrorKind::PermissionDenied => {
            WarpErrorKind::NoPermissionToModifyConfiguration
        }
        ConfigModifyErrorKind::ConnectionLost => WarpErrorKind::NoSshConnection,
        ConfigModifyErrorKind::UploadFailed
        | ConfigModifyErrorKind::SerializationFailed
        | ConfigModifyErrorKind::ConfigurationChangedRemotely => WarpErrorKind::RemoteWriteFailed,
        _ => WarpErrorKind::RemoteWriteFailed,
    };
    WarpError::new(kind, sanitize_detail(error.detail()))
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
