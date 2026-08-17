//! Asynchronous Xray `dns` top-level settings modification orchestration (Roadmap §2.1:46).
//!
//! Mirrors [`super::api_settings_ops`] — same validate → mutate → conflict-check → backup →
//! write pipeline, just targeting `dns` instead of `api`.

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
    UpdateDnsSettingsRequest, update_dns_settings,
};

/// Outcome delivered from the dns-settings worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettingsMutationOutcome {
    /// Success payload or classified error.
    pub result: Result<DnsSettingsMutationSuccess, ConfigModifyError>,
}

/// Successful remote write of updated dns settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettingsMutationSuccess {
    /// Editable model after the in-memory mutation (already applied remotely).
    pub editable: EditableXrayConfig,
}

/// Validates, mutates, conflict-checks, backs up, and writes dns settings.
pub async fn run_update_dns_settings<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    editable: EditableXrayConfig,
    request: UpdateDnsSettingsRequest,
    validate_hint: RemoteConfigValidateHint,
) -> DnsSettingsMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    info!(target: "app", "Xray dns settings edit started");

    let mut editable = editable;
    let outcome = match update_dns_settings(&mut editable, request) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                target: "app",
                detail = %crate::logging::redact::sanitize_detail(error.message().as_str()),
                "Xray dns settings validation failed"
            );
            return DnsSettingsMutationOutcome {
                result: Err(error),
            };
        }
    };

    let connect_request = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %connect_request.profile.host,
        path = %outcome.source_file,
        "dns settings mutation connect"
    );

    let session = match backend.connect(&connect_request).await {
        Ok(session) => session,
        Err(error) => {
            return DnsSettingsMutationOutcome {
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
            "dns settings disconnect warning"
        );
    }

    match write_result {
        Ok(()) => {
            info!(target: "app", "Xray dns settings updated");
            DnsSettingsMutationOutcome {
                result: Ok(DnsSettingsMutationSuccess { editable }),
            }
        }
        Err(error) => DnsSettingsMutationOutcome {
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
