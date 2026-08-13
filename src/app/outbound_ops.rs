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
    DuplicateOutboundRequest, EditableXrayConfig, ModifyConfigOutcome, OutboundGeneral,
    OutboundRef, OutboundSettingsDraft, RenameOutboundTagRequest, UpdateOutboundShellRequest,
    add_outbound_shell, delete_outbound, duplicate_outbound, rename_outbound_tag,
    update_outbound_shell,
};

/// IB-L1-style unified outbound editor session (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
///
/// `is_add = true` means an Add Outbound flow; `outbound_ref` is `None` in that case. Tag is
/// editable only on Add — Shell Save rejects rename by design; use `run_rename_outbound_tag`
/// instead, a standalone action available for any protocol (Roadmap §2.4:99).
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
    /// Duplicate a shell-editable outbound (Freedom/Blackhole/DNS).
    Duplicate,
    /// Rename an outbound's tag (any protocol).
    Rename,
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
    /// Outbound duplicated; model already mutated in memory.
    Duplicate {
        /// Editable config after duplicate.
        editable: EditableXrayConfig,
        /// Merged index of the newly appended copy.
        new_index: usize,
    },
    /// Outbound tag renamed; model already mutated in memory.
    Rename {
        /// Editable config after rename.
        editable: EditableXrayConfig,
        /// Tag before the rename.
        old_tag: String,
        /// Tag after the rename.
        new_tag: String,
        /// Routing/balancer references still pointing at `old_tag` (not auto-updated).
        stale_references: Vec<String>,
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

/// Duplicate Outbound: deep-copies a shell-editable outbound and writes to remote.
pub async fn run_duplicate_outbound<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: DuplicateOutboundRequest,
    validate_hint: RemoteConfigValidateHint,
) -> OutboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let outcome = match duplicate_outbound(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Duplicate,
                result: Err(error),
            };
        }
    };

    let new_index = editable.sections().outbounds().len().saturating_sub(1);

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "duplicate outbound connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Duplicate,
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
            "duplicate outbound disconnect warning"
        );
    }

    match write_result {
        Ok(()) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Duplicate,
            result: Ok(OutboundMutationSuccess::Duplicate { editable, new_index }),
        },
        Err(error) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Duplicate,
            result: Err(error),
        },
    }
}

/// Rename Outbound tag: renames by merged index (any protocol) and writes to remote.
///
/// Never blocked by stale routing/balancer references — those are surfaced in the success
/// payload for the caller to warn about (Roadmap §2.4:99, v1 scope).
pub async fn run_rename_outbound_tag<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: RenameOutboundTagRequest,
    validate_hint: RemoteConfigValidateHint,
) -> OutboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let rename = match rename_outbound_tag(&mut editable, request) {
        Ok(rename) => rename,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Rename,
                result: Err(error),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %rename.outcome.source_file,
        "rename outbound tag connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return OutboundMutationOutcome {
                kind: OutboundMutationKind::Rename,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result = write_modified_file(remote, &session, &rename.outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "rename outbound tag disconnect warning"
        );
    }

    match write_result {
        Ok(()) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Rename,
            result: Ok(OutboundMutationSuccess::Rename {
                editable,
                old_tag: rename.old_tag,
                new_tag: rename.new_tag,
                stale_references: rename.stale_references,
            }),
        },
        Err(error) => OutboundMutationOutcome {
            kind: OutboundMutationKind::Rename,
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
