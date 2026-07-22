//! Russh SSH session implementation.

use std::sync::Arc;

use russh::client;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::handler::ClientHandler;
use super::{exec, sftp};
use crate::backend::SshSession;
use crate::command::RemoteCommand;
use crate::connection::ConnectionProfile;
use crate::error::{SshError, SshResult};
use crate::exec::ExecResult;
use crate::path::RemotePath;

/// Active SSH session powered by Russh.
pub struct RusshSession {
    profile: ConnectionProfile,
    handle: Arc<Mutex<client::Handle<ClientHandler>>>,
}

impl RusshSession {
    pub(crate) fn new(profile: ConnectionProfile, handle: client::Handle<ClientHandler>) -> Self {
        Self {
            profile,
            handle: Arc::new(Mutex::new(handle)),
        }
    }
}

impl SshSession for RusshSession {
    fn profile(&self) -> &ConnectionProfile {
        &self.profile
    }

    fn read_file(
        &self,
        path: &RemotePath,
    ) -> impl std::future::Future<Output = SshResult<Vec<u8>>> + Send {
        let handle = Arc::clone(&self.handle);
        let path = path.clone();
        let remote_path = path.as_str().to_owned();

        async move {
            debug!(target: "ssh", path = %remote_path, "SSH read_file");

            let handle = handle.lock().await;
            match sftp::read_remote_file(&handle, &path).await {
                Ok(bytes) => {
                    debug!(
                        target: "ssh",
                        path = %remote_path,
                        bytes = bytes.len(),
                        "SSH read_file completed"
                    );
                    Ok(bytes)
                }
                Err(error) => {
                    warn!(
                        target: "ssh",
                        path = %remote_path,
                        error = %error.message(),
                        "SSH read_file failed"
                    );
                    Err(error)
                }
            }
        }
    }

    fn write_file(
        &self,
        path: &RemotePath,
        contents: &[u8],
    ) -> impl std::future::Future<Output = SshResult<()>> + Send {
        let handle = Arc::clone(&self.handle);
        let path = path.clone();
        let remote_path = path.as_str().to_owned();
        let contents = contents.to_vec();

        async move {
            info!(
                target: "ssh",
                path = %remote_path,
                bytes = contents.len(),
                "SSH write_file"
            );

            let handle = handle.lock().await;
            sftp::write_remote_file(&handle, &path, &contents).await
        }
    }

    fn write_file_atomic(
        &self,
        path: &RemotePath,
        contents: &[u8],
    ) -> impl std::future::Future<Output = SshResult<()>> + Send {
        let handle = Arc::clone(&self.handle);
        let path = path.clone();
        let remote_path = path.as_str().to_owned();
        let contents = contents.to_vec();

        async move {
            info!(
                target: "ssh",
                path = %remote_path,
                bytes = contents.len(),
                "SSH write_file_atomic"
            );

            let handle = handle.lock().await;
            sftp::write_remote_file_atomic(&handle, &path, &contents).await
        }
    }

    fn rename_file(
        &self,
        from: &RemotePath,
        to: &RemotePath,
    ) -> impl std::future::Future<Output = SshResult<()>> + Send {
        let handle = Arc::clone(&self.handle);
        let from = from.clone();
        let to = to.clone();
        let from_path = from.as_str().to_owned();
        let to_path = to.as_str().to_owned();

        async move {
            info!(
                target: "ssh",
                from = %from_path,
                to = %to_path,
                "SSH rename_file"
            );
            let handle = handle.lock().await;
            sftp::rename_remote_file(&handle, &from, &to).await
        }
    }

    fn remove_file(
        &self,
        path: &RemotePath,
    ) -> impl std::future::Future<Output = SshResult<()>> + Send {
        let handle = Arc::clone(&self.handle);
        let path = path.clone();
        let remote_path = path.as_str().to_owned();

        async move {
            info!(target: "ssh", path = %remote_path, "SSH remove_file");
            let handle = handle.lock().await;
            sftp::remove_remote_file(&handle, &path).await
        }
    }

    fn exec(
        &self,
        command: &RemoteCommand,
    ) -> impl std::future::Future<Output = SshResult<ExecResult>> + Send {
        let handle = Arc::clone(&self.handle);
        let command = command.clone();
        let program = command.program().to_owned();

        async move {
            debug!(target: "ssh", program = %program, "SSH exec");

            let payload = exec::build_exec_payload(&command)?;
            let handle = handle.lock().await;
            let mut channel = handle
                .channel_open_session()
                .await
                .map_err(map_russh_error)?;

            let result = sftp::run_remote_command(&mut channel, &payload).await?;
            debug!(
                target: "ssh",
                program = %program,
                exit_code = result.exit_code,
                stdout_bytes = result.stdout.len(),
                stderr_bytes = result.stderr.len(),
                "SSH exec completed"
            );
            Ok(result)
        }
    }

    async fn disconnect(self) -> SshResult<()> {
        info!(
            target: "ssh",
            host = %self.profile.host,
            user = %self.profile.username,
            "SSH disconnect"
        );

        let handle = self.handle.lock().await;
        handle
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await
            .map_err(map_russh_error)
    }
}

fn map_russh_error(error: russh::Error) -> SshError {
    SshError::new(format!("SSH operation failed: {error}"))
}
