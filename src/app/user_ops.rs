//! Asynchronous VLESS user modification orchestration for ApplicationService.

use feldjaeger_ssh::{RemotePath, SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::remote::RemoteAdmin;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    AddUserRequest, ConfigModifyError, ConfigModifyErrorKind, DeleteUserRequest,
    EditableXrayConfig, ModifyUserOutcome, UpdateUserRequest, add_user, delete_user, update_user,
};

/// Which user mutation is in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMutationKind {
    /// AddUser application action.
    Add,
    /// UpdateUser application action.
    Update,
    /// DeleteUser application action.
    Delete,
}

impl UserMutationKind {
    /// Status Bar label while the mutation runs.
    pub fn busy_label(self) -> &'static str {
        match self {
            Self::Add => "Adding user...",
            Self::Update => "Updating user...",
            Self::Delete => "Deleting user...",
        }
    }
}

/// Outcome delivered from the user-mutation worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMutationOutcome {
    /// Operation that completed.
    pub kind: UserMutationKind,
    /// Success payload or classified error.
    pub result: Result<UserMutationSuccess, ConfigModifyError>,
}

/// Successful remote write of a modified configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMutationSuccess {
    /// Editable model after the in-memory mutation (already applied remotely).
    pub editable: EditableXrayConfig,
}

/// Applies an AddUser mutation locally then writes it safely over SSH.
pub async fn run_add_user<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    editable: EditableXrayConfig,
    request: AddUserRequest,
) -> UserMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    run_mutation(
        backend,
        profile,
        secrets,
        remote,
        editable,
        UserMutationKind::Add,
        |config| add_user(config, request),
    )
    .await
}

/// Applies an UpdateUser mutation locally then writes it safely over SSH.
pub async fn run_update_user<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    editable: EditableXrayConfig,
    request: UpdateUserRequest,
) -> UserMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    run_mutation(
        backend,
        profile,
        secrets,
        remote,
        editable,
        UserMutationKind::Update,
        |config| update_user(config, request),
    )
    .await
}

/// Applies a DeleteUser mutation locally then writes it safely over SSH.
pub async fn run_delete_user<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    editable: EditableXrayConfig,
    request: DeleteUserRequest,
) -> UserMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    run_mutation(
        backend,
        profile,
        secrets,
        remote,
        editable,
        UserMutationKind::Delete,
        |config| delete_user(config, request),
    )
    .await
}

async fn run_mutation<B, F>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    kind: UserMutationKind,
    mutate: F,
) -> UserMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
    F: FnOnce(&mut EditableXrayConfig) -> Result<ModifyUserOutcome, ConfigModifyError>,
{
    let outcome = match mutate(&mut editable) {
        Ok(value) => value,
        Err(error) => {
            return UserMutationOutcome {
                kind,
                result: Err(error),
            };
        }
    };

    let request = build_connect_request(profile, secrets);
    info!(
        target: "app",
        kind = ?kind,
        host = %request.profile.host,
        path = %outcome.source_file,
        "user mutation connect"
    );

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            return UserMutationOutcome {
                kind,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result = write_modified_file(remote, &session, &outcome).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "user mutation disconnect warning"
        );
    }

    match write_result {
        Ok(()) => UserMutationOutcome {
            kind,
            result: Ok(UserMutationSuccess { editable }),
        },
        Err(error) => UserMutationOutcome {
            kind,
            result: Err(error),
        },
    }
}

async fn write_modified_file<S: SshSession>(
    remote: &RemoteAdmin,
    session: &S,
    outcome: &ModifyUserOutcome,
) -> Result<(), ConfigModifyError> {
    let path = RemotePath::new(&outcome.source_file).map_err(|error| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            sanitize_detail(error.message()),
        )
    })?;

    remote
        .write_config_safe(session, &path, &outcome.serialized)
        .await
        .map_err(map_app_error_to_modify)
}

fn map_app_error_to_modify(error: crate::error::AppError) -> ConfigModifyError {
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

fn sanitize_detail(message: &str) -> String {
    crate::logging::redact::sanitize_detail(message)
}
