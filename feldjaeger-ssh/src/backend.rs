//! SSH backend and session trait definitions.

use std::future::Future;

use crate::command::RemoteCommand;
use crate::connection::ConnectRequest;
use crate::connection::ConnectionProfile;
use crate::error::SshResult;
use crate::exec::ExecResult;
use crate::path::RemotePath;

/// Backend-agnostic SSH transport interface.
///
/// Concrete implementations (Russh, OpenSSH CLI) must log every operation and
/// must never write passwords or private keys to logs.
pub trait SshBackend: Send + Sync {
    /// Session type produced by this backend.
    type Session: SshSession;

    /// Establishes a connection using the given request.
    fn connect(
        &self,
        request: &ConnectRequest,
    ) -> impl Future<Output = SshResult<Self::Session>> + Send;
}

/// Operational interface for an active SSH session.
///
/// File and command operations are performed on an established session.
/// Callers pass structured [`RemoteCommand`] values; backends must not accept
/// opaque shell scripts from the application layer. Note that SSH `exec`
/// channels are often interpreted by a remote login shell, so argument
/// validation/quoting remains mandatory in the transport implementation.
pub trait SshSession: Send {
    /// Returns the connection profile for this session.
    fn profile(&self) -> &ConnectionProfile;

    /// Reads the contents of a remote file.
    fn read_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<Vec<u8>>> + Send;

    /// Writes bytes to a remote file (create/truncate).
    ///
    /// Prefer [`write_file_atomic`](Self::write_file_atomic) when replacing an
    /// existing configuration so a crash cannot leave a truncated file.
    fn write_file(
        &self,
        path: &RemotePath,
        contents: &[u8],
    ) -> impl Future<Output = SshResult<()>> + Send;

    /// Writes `contents` to a temporary sibling path, flushes, then replaces `path`.
    ///
    /// Intended for configuration updates after a successful backup.
    fn write_file_atomic(
        &self,
        path: &RemotePath,
        contents: &[u8],
    ) -> impl Future<Output = SshResult<()>> + Send;

    /// Renames a remote file.
    fn rename_file(
        &self,
        from: &RemotePath,
        to: &RemotePath,
    ) -> impl Future<Output = SshResult<()>> + Send;

    /// Removes a remote file.
    fn remove_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<()>> + Send;

    /// Returns `true` when `path` exists and is a regular file (SFTP metadata).
    ///
    /// Missing paths yield `Ok(false)`. Other SFTP errors are propagated.
    fn path_is_file(
        &self,
        path: &RemotePath,
    ) -> impl Future<Output = SshResult<bool>> + Send;

    /// Executes a remote command with explicit arguments.
    fn exec(&self, command: &RemoteCommand) -> impl Future<Output = SshResult<ExecResult>> + Send;

    /// Executes a remote command and writes `stdin` to the channel before collecting output.
    ///
    /// Used for `sudo -S` (password on stdin only — never place secrets in argv).
    /// Callers must not log `stdin`.
    fn exec_with_stdin(
        &self,
        command: &RemoteCommand,
        stdin: &[u8],
    ) -> impl Future<Output = SshResult<ExecResult>> + Send;

    /// Closes the SSH session.
    fn disconnect(self) -> impl Future<Output = SshResult<()>> + Send;
}
