//! Shared remote configuration write + optional `xray run -test` (IB-L6).

use std::time::Duration;

use feldjaeger_ssh::{RemotePath, SshSession};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::remote::RemoteAdmin;
use crate::xray::{
    ConfigModifyError, ConfigModifyErrorKind, ConfigSource, ConfigTestTarget, RemoteCliErrorKind,
    run_config_test,
};

/// Timeout for remote `xray run -test`.
const CONFIG_TEST_TIMEOUT: Duration = Duration::from_secs(45);

/// Discovery hint used to decide whether / how to run post-write validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConfigValidateHint {
    /// Absolute path to the remote `xray` binary, when known.
    pub binary_path: Option<String>,
    /// Layout discovered on the host (single file vs confdir).
    pub config_source: ConfigSource,
}

impl RemoteConfigValidateHint {
    /// No binary / unknown layout — write only, skip `-test`.
    pub fn skip() -> Self {
        Self {
            binary_path: None,
            config_source: ConfigSource::Unknown,
        }
    }

    /// Hint from a successful discovery installation.
    pub fn from_installation(
        binary_path: Option<&RemotePath>,
        config_source: &ConfigSource,
    ) -> Self {
        Self {
            binary_path: binary_path.map(|p| p.as_str().to_owned()),
            config_source: config_source.clone(),
        }
    }
}

/// Backup + atomic write, then optional `xray run -test` with restore on failure.
pub async fn write_config_validated<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    path: &RemotePath,
    contents: &[u8],
    hint: &RemoteConfigValidateHint,
) -> Result<(), ConfigModifyError> {
    let backup = remote
        .write_config_safe(session, path, contents)
        .await
        .map_err(map_app_error_to_modify)?;

    let Some(binary) = hint
        .binary_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        info!(
            target: "app",
            path = %path.as_str(),
            "skipping xray run -test (binary path unknown)"
        );
        return Ok(());
    };

    let target = ConfigTestTarget::from_source_or_file(&hint.config_source, path.as_str());
    info!(
        target: "app",
        path = %path.as_str(),
        target = ?target,
        "post-write xray run -test"
    );

    let test_result = match timeout(CONFIG_TEST_TIMEOUT, run_config_test(session, binary, &target))
        .await
    {
        Ok(inner) => inner,
        Err(_elapsed) => {
            warn!(
                target: "app",
                path = %path.as_str(),
                "xray run -test timed out; restoring backup"
            );
            restore_after_failed_test(remote, session, &backup).await?;
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::XrayValidationFailed,
                "xray run -test timed out after 45 seconds; previous config restored".to_owned(),
            ));
        }
    };

    match test_result {
        Ok(()) => Ok(()),
        Err(error) => {
            let detail = crate::logging::redact::sanitize_detail(error.detail());
            warn!(
                target: "app",
                kind = ?error.kind(),
                detail = %detail,
                "xray run -test failed; restoring backup"
            );
            restore_after_failed_test(remote, session, &backup).await?;

            let kind = match error.kind() {
                RemoteCliErrorKind::ConnectionLost => ConfigModifyErrorKind::ConnectionLost,
                RemoteCliErrorKind::TimedOut => ConfigModifyErrorKind::XrayValidationFailed,
                RemoteCliErrorKind::CommandFailed
                | RemoteCliErrorKind::NonZeroExit
                | RemoteCliErrorKind::ParseFailed => ConfigModifyErrorKind::XrayValidationFailed,
            };
            let message = if detail.is_empty() {
                "xray run -test failed; previous config restored".to_owned()
            } else {
                format!("{detail}; previous config restored")
            };
            Err(ConfigModifyError::new(kind, message))
        }
    }
}

async fn restore_after_failed_test<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    backup: &crate::remote::ConfigBackup,
) -> Result<(), ConfigModifyError> {
    remote
        .backup_manager()
        .restore_backup(session, backup)
        .await
        .map_err(|error| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::XrayValidationFailed,
                format!(
                    "xray run -test failed and restore also failed: {}",
                    crate::logging::redact::sanitize_detail(error.message())
                ),
            )
        })
}

/// Maps [`crate::error::AppError`] from backup/upload into modify errors.
pub fn map_app_error_to_modify(error: crate::error::AppError) -> ConfigModifyError {
    let message = error.message();
    if let Some(detail) = message.strip_prefix("Backup failed: ") {
        ConfigModifyError::new(ConfigModifyErrorKind::BackupFailed, detail.to_owned())
    } else if let Some(detail) = message.strip_prefix("Permission denied: ") {
        ConfigModifyError::new(ConfigModifyErrorKind::PermissionDenied, detail.to_owned())
    } else if let Some(detail) = message.strip_prefix("Connection lost: ") {
        ConfigModifyError::new(ConfigModifyErrorKind::ConnectionLost, detail.to_owned())
    } else if let Some(detail) = message.strip_prefix("Upload failed: ") {
        ConfigModifyError::new(ConfigModifyErrorKind::UploadFailed, detail.to_owned())
    } else if message.starts_with("Backup failed") {
        ConfigModifyError::new(ConfigModifyErrorKind::BackupFailed, message.to_owned())
    } else {
        ConfigModifyError::new(ConfigModifyErrorKind::UploadFailed, message.to_owned())
    }
}
