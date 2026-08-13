//! Confdir file Add / Remove remote mutation orchestration (Roadmap §2.5:107).

use feldjaeger_ssh::{RemotePath, SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::config_write::{
    RemoteConfigValidateHint, create_confdir_file_validated, remove_confdir_file_validated,
};
use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::remote::RemoteAdmin;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    AddConfdirFileRequest, ConfigModifyError, ConfigModifyErrorKind, EditableXrayConfig,
    RemoveConfdirFileRequest, add_confdir_file, remove_confdir_file,
};

/// Kind of confdir-file mutation in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfdirFileMutationKind {
    /// Add a new, empty file.
    Add,
    /// Remove an empty file.
    Remove,
}

/// Successful confdir-file mutation payload.
#[derive(Debug, Clone)]
pub enum ConfdirFileMutationSuccess {
    /// File added; model already mutated in memory.
    Add {
        /// Editable config after add.
        editable: EditableXrayConfig,
    },
    /// File removed; model already mutated in memory.
    Remove {
        /// Editable config after remove.
        editable: EditableXrayConfig,
        /// Path that was removed.
        removed_path: String,
    },
}

/// Outcome of a background confdir-file mutation.
#[derive(Debug)]
#[allow(dead_code)] // kind is reserved for future selection/adjust logic (mirrors OutboundMutationOutcome)
pub struct ConfdirFileMutationOutcome {
    /// Which mutation ran.
    pub kind: ConfdirFileMutationKind,
    /// Result.
    pub result: Result<ConfdirFileMutationSuccess, ConfigModifyError>,
}

/// Adds a new, empty file to the confdir and writes it to remote.
pub async fn run_add_confdir_file<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: AddConfdirFileRequest,
    validate_hint: RemoteConfigValidateHint,
) -> ConfdirFileMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let outcome = match add_confdir_file(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return ConfdirFileMutationOutcome {
                kind: ConfdirFileMutationKind::Add,
                result: Err(error),
            };
        }
    };

    let path = match RemotePath::new(&outcome.source_file) {
        Ok(path) => path,
        Err(error) => {
            return ConfdirFileMutationOutcome {
                kind: ConfdirFileMutationKind::Add,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "add confdir file connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return ConfdirFileMutationOutcome {
                kind: ConfdirFileMutationKind::Add,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result =
        create_confdir_file_validated(remote, &session, &path, &outcome.serialized, &validate_hint)
            .await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "add confdir file disconnect warning"
        );
    }

    match write_result {
        Ok(()) => ConfdirFileMutationOutcome {
            kind: ConfdirFileMutationKind::Add,
            result: Ok(ConfdirFileMutationSuccess::Add { editable }),
        },
        Err(error) => ConfdirFileMutationOutcome {
            kind: ConfdirFileMutationKind::Add,
            result: Err(error),
        },
    }
}

/// Removes an empty confdir file from remote.
pub async fn run_remove_confdir_file<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: RemoveConfdirFileRequest,
    validate_hint: RemoteConfigValidateHint,
) -> ConfdirFileMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let removed_path = request.path.clone();
    if let Err(error) = remove_confdir_file(&mut editable, request) {
        return ConfdirFileMutationOutcome {
            kind: ConfdirFileMutationKind::Remove,
            result: Err(error),
        };
    }

    let path = match RemotePath::new(&removed_path) {
        Ok(path) => path,
        Err(error) => {
            return ConfdirFileMutationOutcome {
                kind: ConfdirFileMutationKind::Remove,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %removed_path,
        "remove confdir file connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return ConfdirFileMutationOutcome {
                kind: ConfdirFileMutationKind::Remove,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result = remove_confdir_file_validated(remote, &session, &path, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "remove confdir file disconnect warning"
        );
    }

    match write_result {
        Ok(()) => ConfdirFileMutationOutcome {
            kind: ConfdirFileMutationKind::Remove,
            result: Ok(ConfdirFileMutationSuccess::Remove {
                editable,
                removed_path,
            }),
        },
        Err(error) => ConfdirFileMutationOutcome {
            kind: ConfdirFileMutationKind::Remove,
            result: Err(error),
        },
    }
}

fn sanitize_detail(message: &str) -> String {
    crate::logging::redact::sanitize_detail(message)
}
