//! SSH connection test orchestration.

use std::fmt;
use std::path::PathBuf;

use feldjaeger_ssh::{
    AuthCredentials, AuthMethod, ConnectRequest, SshBackend, SshError, SshResult, SshSession,
};
use tracing::info;

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::status::SshStatus;
use crate::storage::{ConnectionDraft, ConnectionValidationErrors, StoredConnectionProfile};

/// Lifecycle of a connection test started from the Connection page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConnectionTestState {
    /// No test is running.
    #[default]
    Idle,
    /// SSH connect + authenticate is in progress.
    Connecting,
    /// The last test completed successfully.
    Succeeded,
    /// The last test failed.
    Failed {
        /// Short Status Bar summary.
        summary: String,
        /// Longer detail for UI tooltip / inline message (never contains secrets).
        detail: String,
    },
}

impl ConnectionTestState {
    /// Returns `true` while a test is in flight.
    pub fn is_connecting(&self) -> bool {
        matches!(self, Self::Connecting)
    }

    /// Button label for the Test connection control.
    pub fn button_label(&self) -> &'static str {
        if self.is_connecting() {
            "Connecting..."
        } else {
            "Test connection"
        }
    }

    /// Detail text for a failed test, if any.
    pub fn failure_detail(&self) -> Option<&str> {
        match self {
            Self::Failed { detail, .. } => Some(detail.as_str()),
            _ => None,
        }
    }
}

/// Outcome of a background connection test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTestOutcome {
    /// `Ok(())` on success; otherwise a classified SSH failure.
    pub result: Result<(), ConnectionTestFailure>,
}

/// Classified failure of a connection test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTestFailure {
    /// Short Status Bar / SSH status summary.
    pub summary: SshStatus,
    /// Technical detail safe for UI display (no secrets).
    pub detail: String,
}

impl fmt::Display for ConnectionTestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.summary.label(), self.detail)
    }
}

/// Validates draft + secrets required to start a connection test.
#[allow(clippy::result_large_err)]
pub fn validate_for_connection_test(
    draft: &ConnectionDraft,
    secrets: &ConnectionSecrets,
) -> Result<StoredConnectionProfile, ConnectionValidationErrors> {
    let mut profile = draft.validate()?;
    let mut errors = ConnectionValidationErrors::default();

    match profile.auth_method {
        AuthMethod::Password => {
            if secrets.password().trim().is_empty() {
                errors.password = Some("Password must not be empty.".to_owned());
            }
        }
        AuthMethod::PrivateKey => {
            if profile.private_key_path.trim().is_empty() {
                errors.private_key_path =
                    Some("Private key path is required for private key authentication.".to_owned());
            }
        }
    }

    if errors.has_errors() {
        return Err(errors);
    }

    // Re-assign trimmed path already done by validate.
    let _ = &mut profile;
    Ok(profile)
}

/// Builds a [`ConnectRequest`] from a validated profile and in-memory secrets.
pub fn build_connect_request(
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
) -> ConnectRequest {
    let credentials = match profile.auth_method {
        AuthMethod::Password => AuthCredentials::Password(secrets.password().to_owned()),
        AuthMethod::PrivateKey => {
            let passphrase = secrets.passphrase().trim();
            AuthCredentials::PrivateKey {
                key_path: PathBuf::from(&profile.private_key_path),
                passphrase: if passphrase.is_empty() {
                    None
                } else {
                    Some(passphrase.to_owned())
                },
            }
        }
    };

    ConnectRequest::new(profile.to_ssh_profile(), credentials)
}

/// Connects, authenticates, then disconnects without further remote work.
pub async fn run_connection_test<B: SshBackend>(
    backend: &B,
    request: &ConnectRequest,
) -> SshResult<()> {
    info!(
        target: "ssh",
        host = %request.profile.host,
        port = request.profile.port,
        user = %request.profile.username,
        "SSH connection test start"
    );

    let session = backend.connect(request).await?;
    session.disconnect().await?;

    info!(
        target: "ssh",
        host = %request.profile.host,
        port = request.profile.port,
        user = %request.profile.username,
        "SSH connection test succeeded"
    );
    Ok(())
}

/// Maps an [`SshError`] to a short Status Bar summary and safe technical detail.
///
/// The returned [`ConnectionTestFailure::detail`] is sanitized for secrets but
/// remains technical. Call [`user_facing_connection_failure`] before showing it
/// in the GUI.
pub fn classify_ssh_error(error: &SshError) -> ConnectionTestFailure {
    let detail = crate::logging::redact::sanitize_detail(error.message());
    let lower = detail.to_ascii_lowercase();

    let summary = if lower.contains("host key") {
        SshStatus::HostKeyVerificationFailed
    } else if lower.contains("too many authentication") {
        SshStatus::TooManyAuthFailures
    } else if lower.contains("authentication failed")
        || (lower.contains("auth") && lower.contains("fail"))
        || lower.contains("decrypt private key")
        || lower.contains("passphrase required")
    {
        SshStatus::AuthenticationFailed
    } else if lower.contains("connection refused") || lower.contains("actively refused") {
        SshStatus::ConnectionRefused
    } else if lower.contains("timed out") || lower.contains("timeout") {
        SshStatus::TimedOut
    } else if lower.contains("host not found")
        || lower.contains("name or service not known")
        || lower.contains("nodename nor servname")
        || lower.contains("no such host")
        || lower.contains("failed to lookup")
    {
        SshStatus::HostNotFound
    } else if lower.contains("connection closed")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
    {
        SshStatus::ConnectionClosed
    } else {
        SshStatus::UnknownError
    };

    ConnectionTestFailure { summary, detail }
}

/// Converts a classified SSH failure into a short user-facing message.
pub fn user_facing_connection_failure(failure: &ConnectionTestFailure) -> ConnectionTestFailure {
    ConnectionTestFailure {
        summary: failure.summary,
        detail: crate::logging::redact::user_message_see_log("Unable to connect to server."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::status::SshStatus;
    use feldjaeger_ssh::{
        AuthCredentials, AuthMethod, ConnectRequest, ConnectionProfile, ExecResult, RemoteCommand,
        RemotePath, SshBackend, SshError, SshResult, SshSession,
    };
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn valid_draft() -> ConnectionDraft {
        ConnectionDraft {
            profile_name: "vm".to_owned(),
            host: "192.0.2.10".to_owned(),
            port: "22".to_owned(),
            username: "root".to_owned(),
            auth_method: AuthMethod::Password,
            private_key_path: String::new(),
        }
    }

    #[test]
    fn rejects_invalid_profile_before_network() {
        let mut draft = valid_draft();
        draft.host.clear();
        let secrets = ConnectionSecrets::new();
        let err = validate_for_connection_test(&draft, &secrets).expect_err("host required");
        assert!(err.host.is_some());
    }

    #[test]
    fn rejects_empty_password_before_network() {
        let draft = valid_draft();
        let secrets = ConnectionSecrets::new();
        let err = validate_for_connection_test(&draft, &secrets).expect_err("password required");
        assert!(err.password.is_some());
    }

    #[test]
    fn classifies_common_ssh_errors() {
        assert_eq!(
            classify_ssh_error(&SshError::new("SSH connection refused: ...")).summary,
            SshStatus::ConnectionRefused
        );
        assert_eq!(
            classify_ssh_error(&SshError::new("SSH authentication failed")).summary,
            SshStatus::AuthenticationFailed
        );
        assert_eq!(
            classify_ssh_error(&SshError::new("SSH too many authentication failures")).summary,
            SshStatus::TooManyAuthFailures
        );
        assert_eq!(
            classify_ssh_error(&SshError::new("SSH connection timed out")).summary,
            SshStatus::TimedOut
        );
        assert_eq!(
            classify_ssh_error(&SshError::new("unknown SSH host key for example.com")).summary,
            SshStatus::HostKeyVerificationFailed
        );
        assert_eq!(
            classify_ssh_error(&SshError::new("SSH host not found: ...")).summary,
            SshStatus::HostNotFound
        );
        assert_eq!(
            classify_ssh_error(&SshError::new("SSH connection closed: ...")).summary,
            SshStatus::ConnectionClosed
        );
        assert_eq!(
            classify_ssh_error(&SshError::new("something else")).summary,
            SshStatus::UnknownError
        );
    }

    #[test]
    fn classify_redacts_password_markers() {
        let failure = classify_ssh_error(&SshError::new("boom password=secret-value trailing"));
        assert!(!failure.detail.contains("secret-value"));
        assert!(failure.detail.contains("[REDACTED]"));
    }

    #[test]
    fn user_facing_failure_points_to_log() {
        let technical = classify_ssh_error(&SshError::new("SSH connection refused"));
        let user = user_facing_connection_failure(&technical);
        assert!(user.detail.contains("See application log for details."));
        assert!(!user.detail.contains("refused"));
    }

    struct MockSession {
        profile: ConnectionProfile,
        disconnect_count: Arc<AtomicUsize>,
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        async fn read_file(&self, _path: &RemotePath) -> SshResult<Vec<u8>> {
            Err(SshError::new("not used"))
        }

        async fn write_file(&self, _path: &RemotePath, _contents: &[u8]) -> SshResult<()> {
            Err(SshError::new("not used"))
        }

        async fn write_file_atomic(&self, _path: &RemotePath, _contents: &[u8]) -> SshResult<()> {
            Err(SshError::new("not used"))
        }

        async fn rename_file(&self, _from: &RemotePath, _to: &RemotePath) -> SshResult<()> {
            Err(SshError::new("not used"))
        }

        async fn remove_file(&self, _path: &RemotePath) -> SshResult<()> {
            Err(SshError::new("not used"))
        }

        async fn path_is_file(&self, _path: &RemotePath) -> SshResult<bool> {
            Ok(true)
        }

        async fn exec(&self, _command: &RemoteCommand) -> SshResult<ExecResult> {
            Err(SshError::new("not used"))
        }

    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
        let _ = stdin;
        self.exec(command)
    }

        async fn disconnect(self) -> SshResult<()> {
            self.disconnect_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct MockBackend {
        should_fail: bool,
        disconnect_count: Arc<AtomicUsize>,
        connect_count: AtomicUsize,
    }

    impl SshBackend for MockBackend {
        type Session = MockSession;

        fn connect(
            &self,
            request: &ConnectRequest,
        ) -> impl Future<Output = SshResult<Self::Session>> + Send {
            self.connect_count.fetch_add(1, Ordering::SeqCst);
            let profile = request.profile.clone();
            let disconnect_count = Arc::clone(&self.disconnect_count);
            let should_fail = self.should_fail;
            async move {
                if should_fail {
                    Err(SshError::new("SSH authentication failed"))
                } else {
                    Ok(MockSession {
                        profile,
                        disconnect_count,
                    })
                }
            }
        }
    }

    #[tokio::test]
    async fn success_path_calls_disconnect() {
        let disconnect_count = Arc::new(AtomicUsize::new(0));
        let backend = MockBackend {
            should_fail: false,
            disconnect_count: Arc::clone(&disconnect_count),
            connect_count: AtomicUsize::new(0),
        };
        let request = ConnectRequest::new(
            ConnectionProfile::new("127.0.0.1", 22, "root"),
            AuthCredentials::Password("x".to_owned()),
        );
        run_connection_test(&backend, &request)
            .await
            .expect("test should succeed");
        assert_eq!(disconnect_count.load(Ordering::SeqCst), 1);
        assert_eq!(backend.connect_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failure_path_skips_disconnect() {
        let disconnect_count = Arc::new(AtomicUsize::new(0));
        let backend = MockBackend {
            should_fail: true,
            disconnect_count: Arc::clone(&disconnect_count),
            connect_count: AtomicUsize::new(0),
        };
        let request = ConnectRequest::new(
            ConnectionProfile::new("127.0.0.1", 22, "root"),
            AuthCredentials::Password("x".to_owned()),
        );
        let err = run_connection_test(&backend, &request)
            .await
            .expect_err("should fail");
        assert!(err.message().contains("authentication failed"));
        assert_eq!(disconnect_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn debug_of_failure_has_no_secret_payload() {
        let failure = ConnectionTestFailure {
            summary: SshStatus::AuthenticationFailed,
            detail: "SSH authentication failed".to_owned(),
        };
        let debug = format!("{failure:?}");
        assert!(!debug.to_ascii_lowercase().contains("password="));
    }
}
