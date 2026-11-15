//! SFTP helpers built on top of russh-sftp.

use russh::Channel;
use russh::client::Msg;
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{FileAttributes, OpenFlags, Packet, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::command::RemoteCommand;
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

    let result = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        let mut file = sftp.open(path.as_str()).await.map_err(map_sftp_error)?;
        read_bounded(&mut file, 32 * 1024 * 1024).await
    })
    .await
    .map_err(|_| SshError::new("SFTP read deadline exceeded"))
    .and_then(|result| result);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), sftp.close()).await;
    result
}

async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> SshResult<Vec<u8>> {
    read_bounded_with_idle(reader, limit, std::time::Duration::from_secs(30)).await
}

async fn read_bounded_with_idle<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
    idle: std::time::Duration,
) -> SshResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        let count = tokio::time::timeout(idle, reader.read(&mut chunk))
            .await
            .map_err(|_| SshError::new("SFTP response idle timeout"))?
            .map_err(map_io_error)?;
        if count == 0 {
            return Ok(output);
        }
        super::exec::append_bounded(&mut output, &chunk[..count], limit)?;
    }
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

    let uid = remote_uid(handle).await?;
    for parent in parent_paths(path)? {
        let attrs = sftp
            .symlink_metadata(&parent)
            .await
            .map_err(map_sftp_error)?;
        verify_trusted_directory(&attrs, uid)?;
    }
    write_private_file(&sftp, path, contents).await
}

async fn write_private_file(
    sftp: &SftpSession,
    path: &RemotePath,
    contents: &[u8],
) -> SshResult<()> {
    let mut file = sftp
        .open_with_flags_and_attributes(
            path.as_str(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            FileAttributes {
                permissions: Some(0o600),
                ..FileAttributes::empty()
            },
        )
        .await
        .map_err(map_sftp_error)?;

    // Verify the effective mode before sending secrets: the server's umask and
    // inherited ACL must not make a newly created file readable to others.
    let metadata = file.metadata().await.map_err(map_sftp_error)?;
    verify_private_mode(&metadata)?;
    file.write_all(contents).await.map_err(map_io_error)?;
    file.sync_all().await.map_err(map_sftp_error)?;
    file.shutdown().await.map_err(map_io_error)?;

    Ok(())
}

/// Writes inside a private sibling directory, flushes, then replaces the original.
///
/// Requires POSIX rename v1: unsupported servers fail before staging any bytes.
/// Never moves the live file aside. An unacknowledged commit may have succeeded;
/// retain the staged path on failure and report that the outcome needs checking.
pub async fn write_remote_file_atomic(
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
    let sftp = atomic_session(channel.into_stream()).await?;
    let uid = remote_uid(handle).await?;
    for parent in parent_paths(path)? {
        let attrs = sftp.lstat(parent).await.map_err(map_sftp_error)?.attrs;
        verify_trusted_directory(&attrs, uid)?;
    }
    let original = match sftp.lstat(path.as_str()).await {
        Ok(reply) => {
            let attributes = reply.attrs;
            if !is_regular_file(&attributes) {
                return Err(SshError::new("refusing to replace a non-regular file"));
            }
            // Missing fields cannot be treated as permission to discard metadata.
            if attributes.uid.is_none() || attributes.gid.is_none() {
                return Err(SshError::new("server did not provide file ownership"));
            }
            Some(attributes)
        }
        Err(russh_sftp::client::error::Error::Status(status))
            if status.status_code == StatusCode::NoSuchFile =>
        {
            None
        }
        Err(error) => return Err(map_sftp_error(error)),
    };
    let stage_dir = temporary_sibling_path(path)?;
    sftp.mkdir(
        stage_dir.as_str(),
        FileAttributes {
            permissions: Some(0o700),
            ..FileAttributes::empty()
        },
    )
    .await
    .map_err(map_sftp_error)?;
    let attrs = sftp
        .lstat(stage_dir.as_str())
        .await
        .map_err(map_sftp_error)?
        .attrs;
    verify_private_directory(&attrs, uid)?;
    let temp_path = RemotePath::new(format!("{}/contents", stage_dir.as_str()))?;

    if let Err(error) = write_remote_file(handle, &temp_path, contents).await {
        // An exclusive-create failure may mean this path belongs to somebody else.
        return Err(error);
    }

    if let Some(original) = original {
        let preserve = async {
            let command = preserve_metadata_command(path, &temp_path)?;
            tracing::info!(target: "ssh", program = "cp", "SSH preserve file permissions and ownership");
            let payload = super::exec::build_exec_payload(&command)?;
            let mut channel = handle.channel_open_session().await.map_err(map_russh_error)?;
            let result = run_remote_command_with_stdin(&mut channel, &payload, &[]).await?;
            if result.exit_code != 0 {
                return Err(SshError::new("cannot preserve file permissions/ACL and ownership; original unchanged (requires GNU cp)"));
            }
            let actual = sftp.lstat(temp_path.as_str()).await.map_err(map_sftp_error)?.attrs;
            verify_preserved_metadata(&original, &actual)
        }.await;
        if let Err(error) = preserve {
            let _ = remove_remote_file(handle, &temp_path).await;
            return Err(error);
        }
    }

    commit_atomic_replace(&sftp, &temp_path, path).await?;
    let _ = sftp.rmdir(stage_dir.as_str()).await;
    Ok(())
}

const POSIX_RENAME: &str = "posix-rename@openssh.com";

async fn atomic_session<S>(stream: S) -> SshResult<RawSftpSession>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let session = RawSftpSession::new(stream);
    let version = session.init().await.map_err(map_sftp_error)?;
    if version.extensions.get(POSIX_RENAME).map(String::as_str) != Some("1") {
        return Err(SshError::new(
            "atomic replacement requires SFTP posix-rename@openssh.com version 1; live file unchanged",
        ));
    }
    Ok(session)
}

async fn commit_atomic_replace(
    session: &RawSftpSession,
    staged: &RemotePath,
    live: &RemotePath,
) -> SshResult<()> {
    // SSH strings are a big-endian byte length followed by UTF-8 bytes. This is
    // protocol data, not a shell command. Both paths were already validated.
    let mut data = Vec::new();
    for path in [staged, live] {
        let bytes = path.as_str().as_bytes();
        let len = u32::try_from(bytes.len()).map_err(|_| SshError::new("remote path too long"))?;
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(bytes);
    }
    match session.extended(POSIX_RENAME, data).await {
        Ok(Packet::Status(status)) if status.status_code == StatusCode::Ok => Ok(()),
        _ => Err(SshError::new(format!(
            "atomic replacement not confirmed; verify live file {}; staged file {} may remain; live file was never moved aside",
            live.as_str(),
            staged.as_str()
        ))),
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
    let result = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        channel
            .exec(true, payload.as_bytes())
            .await
            .map_err(map_russh_error)?;

        if !stdin.is_empty() {
            channel.data(stdin).await.map_err(map_russh_error)?;
            channel.eof().await.map_err(map_russh_error)?;
        }

        super::exec::collect_exec_output(channel).await
    })
    .await
    .map_err(|_| SshError::new("SSH command deadline exceeded"))
    .and_then(|result| result);
    // Closing is best effort and bounded even when the peer stops responding.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), channel.close()).await;
    result
}

fn temporary_sibling_path(path: &RemotePath) -> SshResult<RemotePath> {
    sibling_with_suffix(path, "tmp")
}

fn verify_private_mode(attributes: &FileAttributes) -> SshResult<()> {
    if attributes.permissions.map(|mode| mode & 0o7777) != Some(0o600) {
        return Err(SshError::new(
            "server did not create a private file (mode 0600 required)",
        ));
    }
    Ok(())
}

fn is_regular_file(attributes: &FileAttributes) -> bool {
    attributes.permissions.map(|mode| mode & 0o170000) == Some(0o100000)
}

fn preserve_metadata_command(source: &RemotePath, target: &RemotePath) -> SshResult<RemoteCommand> {
    // SFTP v3 does not expose POSIX ACL. GNU cp preserves ACL as part of mode;
    // explicit preserve attributes make failure fatal instead of silently
    // accepting metadata loss. Do not copy timestamps or the original contents.
    RemoteCommand::new(
        "cp",
        vec![
            "--attributes-only".to_owned(),
            "--preserve=mode,ownership".to_owned(),
            "--no-target-directory".to_owned(),
            "--".to_owned(),
            source.as_str().to_owned(),
            target.as_str().to_owned(),
        ],
    )
}

fn verify_preserved_metadata(original: &FileAttributes, actual: &FileAttributes) -> SshResult<()> {
    if !is_regular_file(actual)
        || original.permissions.map(|mode| mode & 0o7777)
            != actual.permissions.map(|mode| mode & 0o7777)
        || original.uid != actual.uid
        || original.gid != actual.gid
    {
        return Err(SshError::new(
            "file metadata preservation failed; original unchanged",
        ));
    }
    Ok(())
}

fn sibling_with_suffix(path: &RemotePath, kind: &str) -> SshResult<RemotePath> {
    RemotePath::new(format!(
        "{}.feldjaeger.{kind}.{}",
        path.as_str(),
        uuid::Uuid::new_v4()
    ))
}

// Checking every ancestor prevents following a symlink or staging inside a
// directory controlled by another uid. Processes sharing our uid are trusted.
fn parent_paths(path: &RemotePath) -> SshResult<Vec<String>> {
    let mut paths = vec!["/".to_owned()];
    let components: Vec<_> = path.as_str().split('/').filter(|p| !p.is_empty()).collect();
    if components.is_empty()
        || path.as_str().ends_with('/')
        || components.iter().any(|p| *p == "." || *p == "..")
    {
        return Err(SshError::new(
            "write path must name a file without dot components",
        ));
    }
    let mut current = String::new();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push('/');
        current.push_str(component);
        paths.push(current.clone());
    }
    Ok(paths)
}

fn verify_trusted_directory(attrs: &FileAttributes, uid: u32) -> SshResult<()> {
    let owner_ok = attrs.uid.is_some_and(|owner| owner == 0 || owner == uid);
    let mode_ok = attrs
        .permissions
        .is_some_and(|mode| mode & 0o170000 == 0o040000 && mode & 0o022 == 0);
    if !owner_ok || !mode_ok {
        return Err(SshError::new(
            "unsafe remote write directory: require a real directory owned by root or SSH user without group/other write permission",
        ));
    }
    Ok(())
}

fn verify_private_directory(attrs: &FileAttributes, uid: u32) -> SshResult<()> {
    verify_trusted_directory(attrs, uid)?;
    if attrs.uid != Some(uid) || attrs.permissions.map(|mode| mode & 0o7777) != Some(0o700) {
        return Err(SshError::new(
            "server did not create a private staging directory",
        ));
    }
    Ok(())
}

async fn remote_uid(
    handle: &russh::client::Handle<super::handler::ClientHandler>,
) -> SshResult<u32> {
    tracing::debug!(target: "ssh", program = "id", "SSH resolve write identity");
    let command = RemoteCommand::new("id", vec!["-u".to_owned()])?;
    let payload = super::exec::build_exec_payload(&command)?;
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(map_russh_error)?;
    let result = run_remote_command_with_stdin(&mut channel, &payload, &[]).await?;
    if result.exit_code != 0 {
        return Err(SshError::new("cannot resolve remote write identity"));
    }
    std::str::from_utf8(&result.stdout)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .ok_or_else(|| SshError::new("invalid remote write identity"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FileState {
        exists: bool,
        bytes: Vec<u8>,
    }

    struct TestServer {
        state: std::sync::Arc<std::sync::Mutex<FileState>>,
        mode: u32,
    }

    impl russh_sftp::server::Handler for TestServer {
        type Error = StatusCode;
        fn unimplemented(&self) -> StatusCode {
            StatusCode::OpUnsupported
        }

        async fn open(
            &mut self,
            id: u32,
            _filename: String,
            flags: OpenFlags,
            attrs: FileAttributes,
        ) -> Result<russh_sftp::protocol::Handle, StatusCode> {
            assert!(flags.contains(OpenFlags::EXCLUDE | OpenFlags::CREATE | OpenFlags::WRITE));
            assert!(!flags.contains(OpenFlags::TRUNCATE));
            assert_eq!(attrs.permissions, Some(0o600));
            let mut state = self.state.lock().expect("state");
            if state.exists {
                return Err(StatusCode::Failure);
            }
            state.exists = true;
            Ok(russh_sftp::protocol::Handle {
                id,
                handle: "file".to_owned(),
            })
        }

        async fn fstat(
            &mut self,
            id: u32,
            _handle: String,
        ) -> Result<russh_sftp::protocol::Attrs, StatusCode> {
            Ok(russh_sftp::protocol::Attrs {
                id,
                attrs: FileAttributes {
                    permissions: Some(self.mode),
                    ..FileAttributes::empty()
                },
            })
        }

        async fn write(
            &mut self,
            id: u32,
            _handle: String,
            _offset: u64,
            data: Vec<u8>,
        ) -> Result<russh_sftp::protocol::Status, StatusCode> {
            self.state.lock().expect("state").bytes.extend(data);
            Ok(ok_status(id))
        }

        async fn close(
            &mut self,
            id: u32,
            _handle: String,
        ) -> Result<russh_sftp::protocol::Status, StatusCode> {
            Ok(ok_status(id))
        }
    }

    fn ok_status(id: u32) -> russh_sftp::protocol::Status {
        russh_sftp::protocol::Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: String::new(),
        }
    }

    #[tokio::test]
    async fn sftp_private_creation_rejects_unsafe_mode_and_preserves_existing_files() {
        for (mode, exists) in [(0o100600, false), (0o100644, false), (0o100600, true)] {
            let initial = if exists {
                b"previous backup".to_vec()
            } else {
                Vec::new()
            };
            let state = std::sync::Arc::new(std::sync::Mutex::new(FileState {
                exists,
                bytes: initial.clone(),
            }));
            let (client, server) = tokio::io::duplex(65536);
            let task = tokio::spawn(russh_sftp::server::run(
                server,
                TestServer {
                    state: state.clone(),
                    mode,
                },
            ));
            let sftp = SftpSession::new(client).await.expect("session");
            let result = write_private_file(
                &sftp,
                &RemotePath::new("/backup").expect("path"),
                b"new secret",
            )
            .await;
            if mode == 0o100600 && !exists {
                assert!(result.is_ok(), "{result:?}");
                assert_eq!(state.lock().expect("state").bytes, b"new secret");
            } else {
                assert!(result.is_err());
                assert_eq!(state.lock().expect("state").bytes, initial);
            }
            task.abort();
        }
    }

    #[test]
    fn rejects_readable_or_missing_private_mode_before_writing_secrets() {
        for mode in [
            None,
            Some(0o100644),
            Some(0o100640),
            Some(0o100660),
            Some(0o104600),
        ] {
            assert!(
                verify_private_mode(&FileAttributes {
                    permissions: mode,
                    ..FileAttributes::empty()
                })
                .is_err()
            );
        }
        assert!(
            verify_private_mode(&FileAttributes {
                permissions: Some(0o100600),
                ..FileAttributes::empty()
            })
            .is_ok()
        );
    }

    #[test]
    fn replacement_rejects_changed_owner_group_or_mode() {
        let original = FileAttributes {
            uid: Some(1000),
            gid: Some(1001),
            permissions: Some(0o100640),
            ..FileAttributes::empty()
        };
        assert!(verify_preserved_metadata(&original, &original).is_ok());
        for actual in [
            FileAttributes {
                uid: Some(0),
                ..original.clone()
            },
            FileAttributes {
                gid: Some(0),
                ..original.clone()
            },
            FileAttributes {
                permissions: Some(0o100644),
                ..original.clone()
            },
            FileAttributes {
                permissions: None,
                ..original.clone()
            },
            FileAttributes {
                uid: None,
                ..original.clone()
            },
            FileAttributes {
                permissions: Some(0o120640),
                ..original.clone()
            },
        ] {
            assert!(verify_preserved_metadata(&original, &actual).is_err());
        }
    }

    #[test]
    fn metadata_copy_is_attributes_only_and_paths_are_shell_quoted() {
        let source = RemotePath::new("/etc/xray/a '$(id).json").expect("source");
        let target = RemotePath::new("/etc/xray/temp file").expect("target");
        let command = preserve_metadata_command(&source, &target).expect("command");
        assert_eq!(
            command.args(),
            [
                "--attributes-only",
                "--preserve=mode,ownership",
                "--no-target-directory",
                "--",
                source.as_str(),
                target.as_str()
            ]
        );
        let payload = super::super::exec::build_exec_payload(&command).expect("quoted payload");
        assert!(payload.contains("'\\''"));
        assert!(payload.ends_with("'/etc/xray/temp file'"));
    }

    #[cfg(unix)]
    #[test]
    fn gnu_cp_preserves_mode_without_overwriting_updated_contents() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "feldjaeger-metadata-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("private dir");
        let source = dir.join("source");
        let target = dir.join("target");
        std::fs::write(&source, b"old config").expect("source");
        std::fs::write(&target, b"updated config").expect("target");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).expect("mode");
        let command = preserve_metadata_command(
            &RemotePath::new(source.to_string_lossy()).expect("source path"),
            &RemotePath::new(target.to_string_lossy()).expect("target path"),
        )
        .expect("command");
        let status = std::process::Command::new(command.program())
            .args(command.args())
            .status()
            .expect("GNU cp required");
        assert!(status.success());
        assert_eq!(std::fs::read(&target).expect("read"), b"updated config");
        assert_eq!(
            std::fs::metadata(&target)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn temporary_path_is_a_sibling() {
        let path = RemotePath::new("/etc/xray/config.json").expect("path");
        let tmp = temporary_sibling_path(&path).expect("tmp");
        assert!(
            tmp.as_str()
                .starts_with("/etc/xray/config.json.feldjaeger.tmp.")
        );
        assert_ne!(tmp, path);
    }
}

#[cfg(test)]
mod bounded_read_tests {
    use super::*;

    #[tokio::test]
    async fn stalled_reader_times_out_and_releases_session_lock() {
        let (_writer, reader) = tokio::io::duplex(32);
        let session = tokio::sync::Mutex::new(reader);
        let result = {
            let mut guard = session.lock().await;
            read_bounded_with_idle(&mut *guard, 4, std::time::Duration::from_millis(10)).await
        };
        assert!(result.unwrap_err().message().contains("idle timeout"));
        assert!(session.try_lock().is_ok());
    }

    #[tokio::test]
    async fn exact_limit_and_overflow_without_waiting_for_eof() {
        let mut exact = &b"1234"[..];
        assert_eq!(read_bounded(&mut exact, 4).await.unwrap(), b"1234");
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(b"12345").await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_bounded(&mut reader, 4),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().message().contains("byte limit"));
    }
}

#[cfg(test)]
mod atomic_protocol_tests {
    use super::*;
    use russh_sftp::protocol::{Status, Version};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct State {
        live: Vec<u8>,
        staged: Option<Vec<u8>>,
        requests: usize,
    }

    struct Server {
        version: Option<&'static str>,
        reject: bool,
        lose_reply: bool,
        state: Arc<Mutex<State>>,
        committed: Arc<tokio::sync::Notify>,
    }

    impl russh_sftp::server::Handler for Server {
        type Error = StatusCode;
        fn unimplemented(&self) -> StatusCode {
            StatusCode::OpUnsupported
        }
        async fn init(
            &mut self,
            _: u32,
            _: std::collections::HashMap<String, String>,
        ) -> Result<Version, StatusCode> {
            let mut version = Version::new();
            if let Some(value) = self.version {
                version
                    .extensions
                    .insert(POSIX_RENAME.to_owned(), value.to_owned());
            }
            Ok(version)
        }
        async fn extended(
            &mut self,
            id: u32,
            request: String,
            data: Vec<u8>,
        ) -> Result<Packet, StatusCode> {
            assert_eq!(request, POSIX_RENAME);
            // Verify wire framing, order, and UTF-8 byte lengths against independent
            // expected bytes. Shell metacharacters must remain literal path data.
            let mut expected = Vec::new();
            for path in ["/config.tmp '€", "/config live"] {
                expected.extend_from_slice(&(path.len() as u32).to_be_bytes());
                expected.extend_from_slice(path.as_bytes());
            }
            assert_eq!(data, expected);
            {
                let mut state = self.state.lock().unwrap();
                state.requests += 1;
                if self.reject {
                    return Err(StatusCode::PermissionDenied);
                }
                state.live = state.staged.take().unwrap();
            }
            self.committed.notify_one();
            if self.lose_reply {
                std::future::pending::<()>().await;
            }
            Ok(Packet::Status(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: String::new(),
            }))
        }
    }

    fn server(version: Option<&'static str>, reject: bool, lose_reply: bool) -> Server {
        Server {
            version,
            reject,
            lose_reply,
            state: Arc::new(Mutex::new(State {
                live: b"old".to_vec(),
                staged: Some(b"new".to_vec()),
                requests: 0,
            })),
            committed: Arc::new(tokio::sync::Notify::new()),
        }
    }

    #[tokio::test]
    async fn unsupported_or_wrong_extension_version_refuses_before_commit() {
        for version in [None, Some("2"), Some("01")] {
            let server = server(version, false, false);
            let state = server.state.clone();
            let (client, stream) = tokio::io::duplex(65536);
            let task = tokio::spawn(russh_sftp::server::run(stream, server));
            assert!(atomic_session(client).await.is_err());
            let state = state.lock().unwrap();
            assert_eq!(state.live, b"old");
            assert_eq!(state.requests, 0);
            task.abort();
        }
    }

    #[tokio::test]
    async fn posix_commit_success_or_rejection_never_displaces_live() {
        for reject in [false, true] {
            let server = server(Some("1"), reject, false);
            let state = server.state.clone();
            let (client, stream) = tokio::io::duplex(65536);
            let task = tokio::spawn(russh_sftp::server::run(stream, server));
            let session = atomic_session(client).await.unwrap();
            let result = commit_atomic_replace(
                &session,
                &RemotePath::new("/config.tmp '€").unwrap(),
                &RemotePath::new("/config live").unwrap(),
            )
            .await;
            assert_eq!(result.is_err(), reject);
            let state = state.lock().unwrap();
            assert_eq!(state.requests, 1);
            assert_eq!(state.live, if reject { b"old" } else { b"new" });
            assert_eq!(state.staged.is_some(), reject);
            if let Err(error) = result {
                assert!(error.message().contains("not confirmed"));
                assert!(error.message().contains("/config.tmp"));
            }
            task.abort();
        }
    }

    #[tokio::test]
    async fn missing_commit_reply_reports_unknown_outcome_without_rollback() {
        let server = server(Some("1"), false, true);
        let committed = server.committed.clone();
        let state = server.state.clone();
        let (client, stream) = tokio::io::duplex(65536);
        let server_task = tokio::spawn(russh_sftp::server::run(stream, server));
        let session = atomic_session(client).await.unwrap();
        session.set_timeout(1);
        let commit = tokio::spawn(async move {
            commit_atomic_replace(
                &session,
                &RemotePath::new("/config.tmp '€").unwrap(),
                &RemotePath::new("/config live").unwrap(),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), committed.notified())
            .await
            .unwrap();
        server_task.abort();
        let error = tokio::time::timeout(std::time::Duration::from_secs(3), commit)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.message().contains("not confirmed"));
        let state = state.lock().unwrap();
        assert_eq!(state.live, b"new");
        assert_eq!(state.requests, 1);
    }
}

#[cfg(test)]
mod directory_security_tests {
    use super::*;
    #[test]
    fn rejects_symlinks_shared_directories_and_foreign_owners() {
        for (uid, mode) in [
            (Some(1001), Some(0o040700)),
            (Some(1000), Some(0o040770)),
            (Some(0), Some(0o041777)),
            (Some(0), Some(0o120755)),
            (None, Some(0o040755)),
            (Some(0), None),
        ] {
            assert!(
                verify_trusted_directory(
                    &FileAttributes {
                        uid,
                        permissions: mode,
                        ..FileAttributes::empty()
                    },
                    1000
                )
                .is_err()
            );
        }
        for uid in [0, 1000] {
            assert!(
                verify_trusted_directory(
                    &FileAttributes {
                        uid: Some(uid),
                        permissions: Some(0o040755),
                        ..FileAttributes::empty()
                    },
                    1000
                )
                .is_ok()
            );
        }
        assert!(
            verify_private_directory(
                &FileAttributes {
                    uid: Some(1000),
                    permissions: Some(0o040700),
                    ..FileAttributes::empty()
                },
                1000
            )
            .is_ok()
        );
        assert!(
            verify_private_directory(
                &FileAttributes {
                    uid: Some(0),
                    permissions: Some(0o040700),
                    ..FileAttributes::empty()
                },
                1000
            )
            .is_err()
        );
    }
    #[test]
    fn validates_full_parent_chain_and_randomizes_staging_names() {
        let path = RemotePath::new("/etc/xray/config.json").unwrap();
        assert_eq!(parent_paths(&path).unwrap(), ["/", "/etc", "/etc/xray"]);
        for value in ["/etc/../config", "/etc/.", "/", "/etc/"] {
            assert!(parent_paths(&RemotePath::new(value).unwrap()).is_err());
        }
        assert_ne!(
            temporary_sibling_path(&path).unwrap(),
            temporary_sibling_path(&path).unwrap()
        );
    }
}
