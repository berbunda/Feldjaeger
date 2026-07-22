//! Russh SSH client backend.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use tracing::{info, warn};

use super::handler::ClientHandler;
use super::host_key::HostKeyPolicy;
use super::session::RusshSession;
use crate::backend::SshBackend;
use crate::connection::{AuthCredentials, ConnectRequest};
use crate::error::{SshError, SshResult};

/// Configuration for [`RusshClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RusshClientOptions {
    /// Host key verification policy.
    pub host_key_policy: HostKeyPolicy,
    /// Maximum time allowed for establishing and authenticating a connection.
    pub connect_timeout: Duration,
}

impl Default for RusshClientOptions {
    fn default() -> Self {
        Self {
            host_key_policy: HostKeyPolicy::default(),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Russh-powered SSH client implementing [`SshBackend`].
///
/// Credentials are never written to logs. File and command operations are logged
/// without payload contents.
#[derive(Clone)]
pub struct RusshClient {
    options: RusshClientOptions,
}

impl fmt::Debug for RusshClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RusshClient")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl RusshClient {
    /// Creates a client with default options.
    pub fn new() -> Self {
        Self::with_options(RusshClientOptions::default())
    }

    /// Creates a client with the given options.
    pub fn with_options(options: RusshClientOptions) -> Self {
        Self { options }
    }

    /// Returns the configured options.
    pub fn options(&self) -> &RusshClientOptions {
        &self.options
    }
}

impl Default for RusshClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SshBackend for RusshClient {
    type Session = RusshSession;

    fn connect(
        &self,
        request: &ConnectRequest,
    ) -> impl std::future::Future<Output = SshResult<Self::Session>> + Send {
        let request = request.clone();
        let options = self.options.clone();

        async move {
            let timeout = options.connect_timeout;
            match tokio::time::timeout(timeout, connect_inner(request, options)).await {
                Ok(result) => result,
                Err(_) => {
                    warn!(target: "ssh", "SSH connection timed out");
                    Err(SshError::new("SSH connection timed out"))
                }
            }
        }
    }
}

async fn connect_inner(
    request: ConnectRequest,
    options: RusshClientOptions,
) -> SshResult<RusshSession> {
    let profile = request.profile.clone();
    info!(
        target: "ssh",
        host = %profile.host,
        port = profile.port,
        user = %profile.username,
        auth = ?request.credentials.method(),
        "SSH connection attempt started"
    );

    let config = Arc::new(client::Config::default());
    let handler = ClientHandler::new(options.host_key_policy, profile.host.clone(), profile.port);

    let address = (profile.host.as_str(), profile.port);
    let mut handle = client::connect(config, address, handler)
        .await
        .map_err(map_russh_error)?;

    authenticate(&mut handle, &request).await?;

    info!(
        target: "ssh",
        host = %profile.host,
        port = profile.port,
        user = %profile.username,
        "SSH connection established"
    );

    Ok(RusshSession::new(profile, handle))
}

async fn authenticate(
    handle: &mut client::Handle<ClientHandler>,
    request: &ConnectRequest,
) -> SshResult<()> {
    let username = request.profile.username.clone();
    let auth_result = match &request.credentials {
        AuthCredentials::Password(password) => handle
            .authenticate_password(username, password.clone())
            .await
            .map_err(map_russh_error)?,
        AuthCredentials::PrivateKey {
            key_path,
            passphrase,
        } => {
            let private_key = load_private_key(key_path, passphrase.as_deref())?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
            handle
                .authenticate_publickey(username, key)
                .await
                .map_err(map_russh_error)?
        }
    };

    if auth_result.success() {
        Ok(())
    } else {
        warn!(target: "ssh", "SSH authentication failed");
        Err(SshError::new("SSH authentication failed"))
    }
}

fn load_private_key(key_path: &std::path::Path, passphrase: Option<&str>) -> SshResult<PrivateKey> {
    let key = PrivateKey::read_openssh_file(key_path).map_err(|error| {
        SshError::new(format!(
            "failed to load private key from {}: {error}",
            key_path.display()
        ))
    })?;

    if !key.is_encrypted() {
        return Ok(key);
    }

    let passphrase = passphrase.ok_or_else(|| {
        SshError::new(format!(
            "passphrase required for encrypted private key {}",
            key_path.display()
        ))
    })?;

    key.decrypt(passphrase).map_err(|error| {
        SshError::new(format!(
            "failed to decrypt private key {}: {error}",
            key_path.display()
        ))
    })
}

fn map_russh_error(error: russh::Error) -> SshError {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();
    if lower.contains("connection refused")
        || lower.contains("actively refused")
        || lower.contains("econnrefused")
    {
        SshError::new(format!("SSH connection refused: {text}"))
    } else if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("etimedout")
    {
        SshError::new(format!("SSH connection timed out: {text}"))
    } else if lower.contains("name or service not known")
        || lower.contains("nodename nor servname")
        || lower.contains("no such host")
        || lower.contains("failed to lookup")
        || lower.contains("host unreachable")
        || lower.contains("network is unreachable")
    {
        SshError::new(format!("SSH host not found: {text}"))
    } else if lower.contains("connection reset")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
    {
        SshError::new(format!("SSH connection closed: {text}"))
    } else if lower.contains("too many authentication") {
        SshError::new(format!("SSH too many authentication failures: {text}"))
    } else if lower.contains("unknown key")
        || lower.contains("key changed")
        || lower.contains("host key")
    {
        SshError::new(format!("SSH host key verification failed: {text}"))
    } else if lower.contains("auth") {
        SshError::new(format!("SSH authentication failed: {text}"))
    } else {
        SshError::new(format!("SSH operation failed: {text}"))
    }
}
