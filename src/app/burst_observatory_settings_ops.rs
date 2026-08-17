//! Asynchronous Xray `burstObservatory` top-level settings modification orchestration
//! (Roadmap §2.1:51).
//!
//! Mirrors [`super::dns_settings_ops`] — same validate → mutate → conflict-check → backup →
//! write pipeline, just targeting `burstObservatory` instead of `dns`.

use feldjaeger_ssh::{RemotePath, SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::config_write::{
    RemoteConfigValidateHint, map_app_error_to_modify, write_config_validated,
};
use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::remote::RemoteAdmin;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    ConfigModifyError, ConfigModifyErrorKind, EditableXrayConfig, ModifyConfigOutcome,
    UpdateBurstObservatorySettingsRequest, update_burst_observatory_settings,
};

/// Outcome delivered from the burst-observatory-settings worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstObservatorySettingsMutationOutcome {
    /// Success payload or classified error.
    pub result: Result<BurstObservatorySettingsMutationSuccess, ConfigModifyError>,
}

/// Successful remote write of updated burstObservatory settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstObservatorySettingsMutationSuccess {
    /// Editable model after the in-memory mutation (already applied remotely).
    pub editable: EditableXrayConfig,
}

/// Validates, mutates, conflict-checks, backs up, and writes burstObservatory settings.
pub async fn run_update_burst_observatory_settings<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    editable: EditableXrayConfig,
    request: UpdateBurstObservatorySettingsRequest,
    validate_hint: RemoteConfigValidateHint,
) -> BurstObservatorySettingsMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    info!(target: "app", "Xray burstObservatory settings edit started");

    let mut editable = editable;
    let outcome = match update_burst_observatory_settings(&mut editable, request) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                target: "app",
                detail = %crate::logging::redact::sanitize_detail(error.message().as_str()),
                "Xray burstObservatory settings validation failed"
            );
            return BurstObservatorySettingsMutationOutcome {
                result: Err(error),
            };
        }
    };

    let connect_request = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %connect_request.profile.host,
        path = %outcome.source_file,
        "burstObservatory settings mutation connect"
    );

    let session = match backend.connect(&connect_request).await {
        Ok(session) => session,
        Err(error) => {
            return BurstObservatorySettingsMutationOutcome {
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result = write_with_conflict_check(remote, &session, &outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "burstObservatory settings disconnect warning"
        );
    }

    match write_result {
        Ok(()) => {
            info!(target: "app", "Xray burstObservatory settings updated");
            BurstObservatorySettingsMutationOutcome {
                result: Ok(BurstObservatorySettingsMutationSuccess { editable }),
            }
        }
        Err(error) => BurstObservatorySettingsMutationOutcome {
            result: Err(error),
        },
    }
}

async fn write_with_conflict_check<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    outcome: &ModifyConfigOutcome,
    validate_hint: &RemoteConfigValidateHint,
) -> Result<(), ConfigModifyError> {
    let path = RemotePath::new(&outcome.source_file).map_err(|error| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            sanitize_detail(error.message()),
        )
    })?;

    match session.read_file(&path).await {
        Ok(remote_bytes) => {
            if !json_bytes_equivalent(&remote_bytes, &outcome.original_serialized) {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConfigurationChangedRemotely,
                    "remote configuration file differs from the loaded copy".to_owned(),
                ));
            }
        }
        Err(error) => {
            // If the file is missing on a brand-new create path, continue to write.
            let message = error.message();
            if !message.to_ascii_lowercase().contains("not found")
                && !message.to_ascii_lowercase().contains("no such file")
            {
                return Err(map_app_error_to_modify(crate::error::AppError::new(
                    format!("Remote write failed: {message}"),
                )));
            }
        }
    }

    write_config_validated(remote, session, &path, &outcome.serialized, validate_hint).await
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
