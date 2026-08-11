//! Outbound Shell (Add / Edit / Delete) remote mutation orchestration.

use feldjaeger_ssh::{RemotePath, SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::config_write::{RemoteConfigValidateHint, write_config_validated};
use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::remote::RemoteAdmin;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    AddOutboundShellRequest, ConfigModifyError, ConfigModifyErrorKind, DeleteOutboundRequest,
    EditableXrayConfig, ModifyConfigOutcome, OutboundGeneral, OutboundRef, OutboundSettingsDraft,
    UpdateOutboundShellRequest, add_outbound_shell, delete_outbound, update_outbound_shell,
};

/// IB-L1-style unified outbound editor session (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
///
/// `is_add = true` means an Add Outbound flow; `outbound_ref` is `None` in that case. Tag is
/// editable only on Add — Shell Save rejects rename (Roadmap §2.4:99, separate follow-up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundEditorSession {
    /// Outbound index in the merged list (`usize::MAX` for Add).
    pub outbound_index: usize,
    /// Identity + fingerprint for Shell Save; `None` for Add.
    pub outbound_ref: Option<OutboundRef>,
    /// General tab draft.
    pub general: OutboundGeneral,
    /// Protocol tab draft (Freedom or Blackhole).
    pub settings: OutboundSettingsDraft,
    /// `true` when this is an Add Outbound flow (not editing existing).
    pub is_add: bool,
}

/// Kind of outbound mutation in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundMutationKind {
    /// Add a new outbound (Freedom/Blackhole shell).
    Add,
    /// Shell Save an existing outbound (Freedom/Blackhole shell).
    Update,
    /// Delete outbound from remote config.
    Delete,
}

/// Successful outbound mutation payload.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields reserved for future selection/adjust logic
pub enum OutboundMutationSuccess {
    /// Outbound appended; model already mutated in memory.
    Add {
        /// Editable config after add.
        editable: EditableXrayConfig,
    },
    /// Outbound Shell Save completed.
    Update {
        /// Editable config after the in-memory mutation.
        editable: EditableXrayConfig,
    },
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

/// Add Outbound: appends a new shell-editable outbound and writes to remote.
pub async fn run_add_outbound_shell<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: AddOutboundShellRequest,
    validate_hint: RemoteConfigValidateHint,
) -> OutboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let outcome = match add_outbound_shell(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Add,
                result: Err(error),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "add outbound connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Add,
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
            "add outbound disconnect warning"
        );
    }

    match write_result {
        Ok(()) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Add,
            result: Ok(OutboundMutationSuccess::Add { editable }),
        },
        Err(error) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Add,
            result: Err(error),
        },
    }
}

/// Update Outbound: Shell Save (General + Protocol) for an existing shell-editable outbound.
pub async fn run_update_outbound_shell<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: UpdateOutboundShellRequest,
    validate_hint: RemoteConfigValidateHint,
) -> OutboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let outcome = match update_outbound_shell(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Update,
                result: Err(error),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "update outbound shell connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Update,
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
            "update outbound shell disconnect warning"
        );
    }

    match write_result {
        Ok(()) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Update,
            result: Ok(OutboundMutationSuccess::Update { editable }),
        },
        Err(error) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Update,
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
