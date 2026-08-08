//! Shared remote command/path helpers used across the WARP submodules.
//!
//! Centralizes SSH `exec` classification and small filesystem probes so
//! [`super::helper`], [`super::registration`], [`super::configuration`], and
//! [`super::connectivity`] do not each re-implement them.

use feldjaeger_ssh::{ExecResult, RemoteCommand, RemotePath, SshError, SshSession};

use super::error::{WarpError, WarpErrorKind, WarpResult};
use crate::logging::redact::sanitize_detail;

/// Runs a remote command, classifying SSH transport failures.
///
/// Never treats a non-zero exit code as a transport error — callers inspect
/// [`ExecResult::exit_code`] themselves so they can attach an operation-specific
/// [`WarpErrorKind`].
pub(super) async fn run_remote<S: SshSession + Sync>(
    session: &S,
    program: &str,
    args: Vec<String>,
) -> WarpResult<ExecResult> {
    let command = RemoteCommand::new(program, args).map_err(|error| {
        WarpError::new(WarpErrorKind::CommandFailed, error.message().to_owned())
    })?;
    session.exec(&command).await.map_err(classify_exec_error)
}

/// Returns `true` when a remote path exists and is a regular file.
pub(super) async fn remote_path_is_file<S: SshSession + Sync>(
    session: &S,
    path: &str,
) -> WarpResult<bool> {
    let result = run_remote(session, "test", vec!["-f".to_owned(), path.to_owned()]).await?;
    Ok(result.exit_code == 0)
}

/// Creates a remote directory (and any missing parents).
pub(super) async fn mkdir_p<S: SshSession + Sync>(session: &S, dir: &str) -> WarpResult<()> {
    let result = run_remote(session, "mkdir", vec!["-p".to_owned(), dir.to_owned()]).await?;
    if result.exit_code != 0 {
        return Err(WarpError::new(
            WarpErrorKind::RemoteWriteFailed,
            format!("mkdir -p failed (exit code {})", result.exit_code),
        ));
    }
    Ok(())
}

/// Restricts a remote path's permission bits via `chmod`.
pub(super) async fn chmod<S: SshSession + Sync>(
    session: &S,
    mode: &str,
    path: &str,
) -> WarpResult<()> {
    let result = run_remote(session, "chmod", vec![mode.to_owned(), path.to_owned()]).await?;
    if result.exit_code != 0 {
        return Err(WarpError::new(
            WarpErrorKind::RemoteWriteFailed,
            format!("chmod {mode} failed (exit code {})", result.exit_code),
        ));
    }
    Ok(())
}

/// Downloads a URL to a remote destination path via `curl -L -f -o`.
pub(super) async fn download_file<S: SshSession + Sync>(
    session: &S,
    dest: &RemotePath,
    url: &str,
) -> WarpResult<()> {
    let result = run_remote(
        session,
        "curl",
        vec![
            "-L".to_owned(),
            "-f".to_owned(),
            "-o".to_owned(),
            dest.as_str().to_owned(),
            url.to_owned(),
        ],
    )
    .await?;

    if result.exit_code != 0 {
        return Err(WarpError::new(
            WarpErrorKind::HelperDownloadFailed,
            format!("curl exited with code {}", result.exit_code),
        ));
    }
    Ok(())
}

/// Joins a directory and file name into a validated [`RemotePath`].
pub(super) fn join_path(dir: &str, file_name: &str) -> WarpResult<RemotePath> {
    let dir = dir.trim_end_matches('/');
    RemotePath::new(format!("{dir}/{file_name}"))
        .map_err(|error| WarpError::new(WarpErrorKind::CommandFailed, error.message().to_owned()))
}

/// Rewrites an error's kind to `permission_kind` when its (already sanitized)
/// detail looks like a permission failure; otherwise returns it unchanged.
pub(super) fn as_permission_error(error: WarpError, permission_kind: WarpErrorKind) -> WarpError {
    if error.detail().to_ascii_lowercase().contains("permission denied") {
        WarpError::new(permission_kind, error.detail().to_owned())
    } else {
        error
    }
}

fn classify_exec_error(error: SshError) -> WarpError {
    let message = sanitize_detail(error.message());
    let lower = message.to_ascii_lowercase();
    let kind = if lower.contains("connection")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("broken pipe")
    {
        WarpErrorKind::NoSshConnection
    } else {
        WarpErrorKind::CommandFailed
    };
    WarpError::new(kind, message)
}
