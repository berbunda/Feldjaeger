//! Outbound delete remote mutation orchestration.

use feldjaeger_ssh::{RemotePath, SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::config_write::{RemoteConfigValidateHint, write_config_validated};
use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::remote::RemoteAdmin;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    ConfigModifyError, ConfigModifyErrorKind, DeleteOutboundRequest, EditableXrayConfig,
    ModifyConfigOutcome, delete_outbound,
};

/// Kind of outbound mutation in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundMutationKind {
    /// Delete outbound from remote config.
    Delete,
}

/// Successful outbound mutation payload.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields reserved for future selection/adjust logic
pub enum OutboundMutationSuccess {
    /// Outbound removed; model already mutated in memory.
    Delete {
        /// Editable config after delete.
        editable: EditableXrayConfig,
        /// Removed merged index.
        deleted_index: usize,
    },
}

/// Outcome of a background outbound mutation.
#[derive(Debug)]
#[allow(dead_code)]
pub struct OutboundMutationOutcome {
    /// Which mutation ran.
    pub kind: OutboundMutationKind,
    /// Result.
    pub result: Result<OutboundMutationSuccess, ConfigModifyError>,
}

/// Delete outbound by index and write to remote.
pub async fn run_delete_outbound<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: DeleteOutboundRequest,
    validate_hint: RemoteConfigValidateHint,
) -> OutboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let deleted_index = request.outbound_index;
    let outcome = match delete_outbound(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Delete,
                result: Err(error),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "delete outbound connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Delete,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result = write_modified_file(remote, &session, &outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "delete outbound disconnect warning"
        );
    }

    match write_result {
        Ok(()) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Delete,
            result: Ok(OutboundMutationSuccess::Delete {
                editable,
                deleted_index,
            }),
        },
        Err(error) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Delete,
            result: Err(error),
        },
    }
}

async fn write_modified_file<S: SshSession + Sync>(
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

    write_config_validated(remote, session, &path, &outcome.serialized, validate_hint).await
}

fn sanitize_detail(message: &str) -> String {
    crate::logging::redact::sanitize_detail(message)
}
