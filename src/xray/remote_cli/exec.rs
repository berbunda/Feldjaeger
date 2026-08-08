//! Shared SSH exec classification for remote Xray CLI helpers.

use feldjaeger_ssh::SshError;

use super::error::{RemoteCliError, RemoteCliErrorKind};

pub(super) fn classify_exec_error(error: SshError) -> RemoteCliError {
    let message = error.message().to_owned();
    let lower = message.to_ascii_lowercase();
    let kind = if lower.contains("connection")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("broken pipe")
    {
        RemoteCliErrorKind::ConnectionLost
    } else {
        RemoteCliErrorKind::CommandFailed
    };
    RemoteCliError::new(kind, message)
}
