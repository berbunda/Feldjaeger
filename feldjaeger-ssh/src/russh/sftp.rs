//! SFTP helpers built on top of russh-sftp.

use std::time::{SystemTime, UNIX_EPOCH};

use russh::Channel;
use russh::client::Msg;
use russh_sftp::client::SftpSession;
use tokio::io::AsyncWriteExt;

use crate::error::{SshError, SshResult};
use crate::path::RemotePath;

pub async fn read_remote_file(
    handle: &russh::client::Handle<super::handler::ClientHandler>,
    path: &RemotePath,
) -> SshResult<Vec<u8>> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(map_russh_error)?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(map_russh_error)?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(map_sftp_error)?;

    sftp.read(path.as_str()).await.map_err(map_sftp_error)
}

pub async fn write_remote_file(
    handle: &russh::client::Handle<super::handler::ClientHandler>,
    path: &RemotePath,
    contents: &[u8],
) -> SshResult<()> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(map_russh_error)?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(map_russh_error)?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(map_sftp_error)?;

    let mut file = sftp
        .open_with_flags(
            path.as_str(),
            russh_sftp::protocol::OpenFlags::CREATE
                | russh_sftp::protocol::OpenFlags::TRUNCATE
                | russh_sftp::protocol::OpenFlags::WRITE,
        )
        .await
        .map_err(map_sftp_error)?;

    file.write_all(contents).await.map_err(map_io_error)?;
    file.sync_all().await.map_err(map_sftp_error)?;
    file.shutdown().await.map_err(map_io_error)?;

    Ok(())
}

/// Writes to a temp file next to `path`, flushes, then replaces the original.
///
/// Never deletes the live destination before the replacement is in place. If the
/// first rename fails (common when the destination already exists), the live file
/// is moved aside, the temp file is moved into place, and the aside copy is removed
/// only after success. On failure, the aside copy is restored when possible.
pub async fn write_remote_file_atomic(
    handle: &russh::client::Handle<super::handler::ClientHandler>,
    path: &RemotePath,
    contents: &[u8],
) -> SshResult<()> {
    let temp_path = temporary_sibling_path(path)?;

    if let Err(error) = write_remote_file(handle, &temp_path, contents).await {
        let _ = remove_remote_file(handle, &temp_path).await;
        return Err(error);
    }

    let first_rename_ok = rename_remote_file(handle, &temp_path, path).await.is_ok();
    match plan_atomic_replace(first_rename_ok) {
        AtomicReplaceStep::Complete => return Ok(()),
        AtomicReplaceStep::DisplaceAsideThenReplace => {}
    }

    // Many SFTP servers refuse rename when the destination exists. Move the live
    // file aside first — never delete it — then move temp into place.
    let aside_path = aside_sibling_path(path)?;
    if let Err(error) = rename_remote_file(handle, path, &aside_path).await {
        // Leave temp in place for diagnosis; original (if any) is untouched.
        return Err(error);
    }

    match rename_remote_file(handle, &temp_path, path).await {
        Ok(()) => {
            let _ = remove_remote_file(handle, &aside_path).await;
            Ok(())
        }
        Err(error) => {
            let _ = rename_remote_file(handle, &aside_path, path).await;
            Err(error)
        }
    }
}

pub async fn rename_remote_file(
    handle: &russh::client::Handle<super::handler::ClientHandler>,
    from: &RemotePath,
    to: &RemotePath,
) -> SshResult<()> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(map_russh_error)?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(map_russh_error)?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(map_sftp_error)?;

    sftp.rename(from.as_str(), to.as_str())
        .await
        .map_err(map_sftp_error)
}

pub async fn remove_remote_file(
    handle: &russh::client::Handle<super::handler::ClientHandler>,
    path: &RemotePath,
) -> SshResult<()> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(map_russh_error)?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(map_russh_error)?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(map_sftp_error)?;

    sftp.remove_file(path.as_str())
        .await
        .map_err(map_sftp_error)
}

/// Returns `true` when `path` exists and is a regular file.
///
/// Missing paths → `Ok(false)`. Non-file entries (dirs, etc.) → `Ok(false)`.
pub async fn remote_path_is_file(
    handle: &russh::client::Handle<super::handler::ClientHandler>,
    path: &RemotePath,
) -> SshResult<bool> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(map_russh_error)?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(map_russh_error)?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(map_sftp_error)?;

    match sftp.metadata(path.as_str()).await {
        Ok(metadata) => Ok(metadata.file_type().is_file()),
        Err(russh_sftp::client::error::Error::Status(status))
            if status.status_code == russh_sftp::protocol::StatusCode::NoSuchFile =>
        {
            Ok(false)
        }
        Err(error) => Err(map_sftp_error(error)),
    }
}

pub async fn run_remote_command_with_stdin(
    channel: &mut Channel<Msg>,
    payload: &str,
    stdin: &[u8],
) -> SshResult<crate::exec::ExecResult> {
    channel
        .exec(true, payload.as_bytes())
        .await
        .map_err(map_russh_error)?;

    if !stdin.is_empty() {
        channel
            .data(stdin)
            .await
            .map_err(map_russh_error)?;
        channel.eof().await.map_err(map_russh_error)?;
    }

    super::exec::collect_exec_output(channel).await
}

fn temporary_sibling_path(path: &RemotePath) -> SshResult<RemotePath> {
    sibling_with_suffix(path, "tmp")
}

fn aside_sibling_path(path: &RemotePath) -> SshResult<RemotePath> {
    sibling_with_suffix(path, "old")
}

fn sibling_with_suffix(path: &RemotePath, kind: &str) -> SshResult<RemotePath> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let temp = format!("{}.feldjaeger.{kind}.{stamp}", path.as_str());
    RemotePath::new(temp)
}

fn map_russh_error(error: russh::Error) -> SshError {
    SshError::new(format!("SSH operation failed: {error}"))
}

fn map_sftp_error(error: russh_sftp::client::error::Error) -> SshError {
    SshError::new(format!("SFTP operation failed: {error}"))
}

fn map_io_error(error: std::io::Error) -> SshError {
    SshError::new(format!("SSH I/O failed: {error}"))
}

/// Pure planning helper for atomic-replace recovery (unit-tested without SFTP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicReplaceStep {
    /// First rename(temp→path) succeeded.
    Complete,
    /// First rename failed; displace live file aside, then rename temp→path.
    DisplaceAsideThenReplace,
}

pub(crate) fn plan_atomic_replace(first_rename_ok: bool) -> AtomicReplaceStep {
    if first_rename_ok {
        AtomicReplaceStep::Complete
    } else {
        AtomicReplaceStep::DisplaceAsideThenReplace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_plan_never_deletes_original_first() {
        assert_eq!(
            plan_atomic_replace(true),
            AtomicReplaceStep::Complete
        );
        assert_eq!(
            plan_atomic_replace(false),
            AtomicReplaceStep::DisplaceAsideThenReplace
        );
    }

    #[test]
    fn sibling_paths_are_absolute_and_distinct() {
        let path = RemotePath::new("/etc/xray/config.json").expect("path");
        let tmp = temporary_sibling_path(&path).expect("tmp");
        let old = aside_sibling_path(&path).expect("old");
        assert!(tmp.as_str().starts_with("/etc/xray/config.json.feldjaeger.tmp."));
        assert!(old.as_str().starts_with("/etc/xray/config.json.feldjaeger.old."));
        assert_ne!(tmp.as_str(), old.as_str());
    }
}
