//! systemd init system backend (MVP).

use std::future::Future;

use feldjaeger_ssh::{ExecResult, RemoteCommand, SshSession};
use tracing::{info, warn};

use super::error::{
    ServiceControlError, ServiceControlResult, ServiceOperationErrorKind, classify_systemctl_failure,
};
use super::service_name::ServiceName;
use super::{InitSystemManager, ServiceState};

/// Configuration for [`SystemdManager`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdManagerOptions {
    /// Absolute or PATH-resolved path to the `systemctl` executable on the remote host.
    pub systemctl_path: String,
}

impl Default for SystemdManagerOptions {
    fn default() -> Self {
        Self {
            systemctl_path: "systemctl".to_owned(),
        }
    }
}

/// systemd implementation of [`InitSystemManager`].
///
/// Controls services on the remote Linux host by invoking `systemctl` with explicit
/// arguments over SSH. No shell interpolation is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdManager {
    options: SystemdManagerOptions,
}

impl SystemdManager {
    /// Creates a manager with default options.
    pub fn new() -> Self {
        Self {
            options: SystemdManagerOptions::default(),
        }
    }

    /// Creates a manager with the given options.
    pub fn with_options(options: SystemdManagerOptions) -> Self {
        Self { options }
    }

    /// Returns the configured options.
    pub fn options(&self) -> &SystemdManagerOptions {
        &self.options
    }
}

impl Default for SystemdManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InitSystemManager for SystemdManager {
    fn service_state<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<ServiceState>> + Send {
        let options = self.options.clone();
        async move {
            let service = ServiceName::new(service_name).map_err(|error| {
                ServiceControlError::new(ServiceOperationErrorKind::CommandFailed, error.message())
            })?;
            info!(
                target: "init",
                host = %session.profile().host,
                user = %session.profile().username,
                service = %service.as_str(),
                "querying systemd service state"
            );

            let result = run_systemctl(
                session,
                &options.systemctl_path,
                vec![
                    "is-active".to_owned(),
                    "--".to_owned(),
                    service.as_str().to_owned(),
                ],
            )
            .await?;

            parse_service_state(&result)
        }
    }

    fn start_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send {
        run_lifecycle_action(session, &self.options, service_name, "start")
    }

    fn stop_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send {
        run_lifecycle_action(session, &self.options, service_name, "stop")
    }

    fn restart_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send {
        run_lifecycle_action(session, &self.options, service_name, "restart")
    }

    fn reload_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send {
        run_lifecycle_action(session, &self.options, service_name, "reload")
    }

    fn enable_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send {
        run_lifecycle_action(session, &self.options, service_name, "enable")
    }

    fn disable_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send {
        run_lifecycle_action(session, &self.options, service_name, "disable")
    }
}

fn run_lifecycle_action<S: SshSession + Sync>(
    session: &S,
    options: &SystemdManagerOptions,
    service_name: &str,
    action: &str,
) -> impl Future<Output = ServiceControlResult<()>> + Send {
    let options = options.clone();
    let action = action.to_owned();

    async move {
        let service = ServiceName::new(service_name).map_err(|error| {
            ServiceControlError::new(ServiceOperationErrorKind::CommandFailed, error.message())
        })?;
        info!(
            target: "init",
            action = %action,
            host = %session.profile().host,
            user = %session.profile().username,
            service = %service.as_str(),
            "systemd service action"
        );

        let result = run_systemctl(
            session,
            &options.systemctl_path,
            vec![
                action.clone(),
                "--".to_owned(),
                service.as_str().to_owned(),
            ],
        )
        .await?;

        if result.exit_code == 0 {
            info!(
                target: "init",
                action = %action,
                service = %service.as_str(),
                "systemd service action succeeded"
            );
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&result.stderr);
            Err(classify_systemctl_failure(
                &action,
                service.as_str(),
                result.exit_code,
                &stderr,
            ))
        }
    }
}

async fn run_systemctl<S: SshSession + Sync>(
    session: &S,
    systemctl_path: &str,
    args: Vec<String>,
) -> ServiceControlResult<ExecResult> {
    validate_systemctl_path(systemctl_path)?;

    let command = RemoteCommand::new(systemctl_path, args).map_err(|error| {
        ServiceControlError::new(ServiceOperationErrorKind::CommandFailed, error.message())
    })?;

    session.exec(&command).await.map_err(|error| {
        let message = error.message();
        let lower = message.to_ascii_lowercase();
        let kind = if lower.contains("permission denied") || lower.contains("access denied") {
            ServiceOperationErrorKind::PermissionDenied
        } else if lower.contains("connection")
            || lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("broken pipe")
        {
            ServiceOperationErrorKind::SshConnectionFailed
        } else {
            ServiceOperationErrorKind::CommandFailed
        };
        ServiceControlError::new(kind, crate::logging::redact::sanitize_detail(message))
    })
}

fn validate_systemctl_path(path: &str) -> ServiceControlResult<()> {
    if path.is_empty() {
        return Err(ServiceControlError::new(
            ServiceOperationErrorKind::CommandFailed,
            "systemctl path must not be empty",
        ));
    }

    if path.chars().any(char::is_whitespace) {
        return Err(ServiceControlError::new(
            ServiceOperationErrorKind::CommandFailed,
            "systemctl path must not contain whitespace",
        ));
    }

    Ok(())
}

fn parse_service_state(result: &ExecResult) -> ServiceControlResult<ServiceState> {
    let stdout = String::from_utf8_lossy(&result.stdout);
    let state = stdout.trim();

    let parsed = match state {
        "active" | "activating" | "reloading" => ServiceState::Running,
        "deactivating" => ServiceState::Stopped,
        "inactive" => ServiceState::Inactive,
        "failed" => ServiceState::Failed,
        _ if result.exit_code == 0 => ServiceState::Running,
        _ if result.exit_code == 3 => ServiceState::Inactive,
        _ => ServiceState::Unknown,
    };

    if parsed == ServiceState::Unknown {
        warn!(
            target: "init",
            exit_code = result.exit_code,
            stdout_bytes = result.stdout.len(),
            stderr_bytes = result.stderr.len(),
            "unable to determine systemd service state"
        );
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use feldjaeger_ssh::ConnectionProfile;
    use std::collections::HashMap;
    use std::future;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockSession {
        profile: ConnectionProfile,
        exec_results: Arc<Mutex<HashMap<String, ExecResult>>>,
        exec_calls: Arc<Mutex<Vec<RemoteCommand>>>,
    }

    impl Default for MockSession {
        fn default() -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                exec_results: Arc::new(Mutex::new(HashMap::new())),
                exec_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl MockSession {
        fn new() -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                ..Self::default()
            }
        }

        fn with_result(self, key: impl Into<String>, result: ExecResult) -> Self {
            self.exec_results.lock().unwrap().insert(key.into(), result);
            self
        }

        fn calls(&self) -> Vec<RemoteCommand> {
            self.exec_calls.lock().unwrap().clone()
        }
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        fn read_file(
            &self,
            _path: &feldjaeger_ssh::RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<Vec<u8>>> + Send {
            future::ready(Err(feldjaeger_ssh::SshError::new(
                "read_file not supported in mock session",
            )))
        }

        fn write_file(
            &self,
            _path: &feldjaeger_ssh::RemotePath,
            _contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Err(feldjaeger_ssh::SshError::new(
                "write_file not supported in mock session",
            )))
        }

        fn write_file_atomic(
            &self,
            _path: &feldjaeger_ssh::RemotePath,
            _contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Err(feldjaeger_ssh::SshError::new(
                "write_file_atomic not supported in mock session",
            )))
        }

        fn rename_file(
            &self,
            _from: &feldjaeger_ssh::RemotePath,
            _to: &feldjaeger_ssh::RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Err(feldjaeger_ssh::SshError::new(
                "rename_file not supported in mock session",
            )))
        }

        fn remove_file(
            &self,
            _path: &feldjaeger_ssh::RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Err(feldjaeger_ssh::SshError::new(
                "remove_file not supported in mock session",
            )))
        }

        fn exec(
            &self,
            command: &RemoteCommand,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<ExecResult>> + Send {
            self.exec_calls.lock().unwrap().push(command.clone());

            let key = exec_key(command);
            let result = self
                .exec_results
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_else(|| {
                    ExecResult::new(
                        Vec::new(),
                        format!("no mock response for {key}").into_bytes(),
                        1,
                    )
                });

            future::ready(Ok(result))
        }

        fn disconnect(self) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    fn exec_key(command: &RemoteCommand) -> String {
        let args = command
            .args()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        format!("{} {args}", command.program())
    }

    #[tokio::test]
    async fn service_state_active() {
        let session = MockSession::new().with_result(
            "systemctl is-active -- xray",
            ExecResult::new(b"active\n".to_vec(), Vec::new(), 0),
        );
        let manager = SystemdManager::new();
        let state = manager
            .service_state(&session, "xray")
            .await
            .expect("state query should succeed");

        assert_eq!(state, ServiceState::Running);
        assert_eq!(session.calls().len(), 1);
    }

    #[tokio::test]
    async fn service_state_inactive() {
        let session = MockSession::new().with_result(
            "systemctl is-active -- xray",
            ExecResult::new(b"inactive\n".to_vec(), Vec::new(), 3),
        );
        let manager = SystemdManager::new();
        let state = manager
            .service_state(&session, "xray")
            .await
            .expect("state query should succeed");

        assert_eq!(state, ServiceState::Inactive);
    }

    #[tokio::test]
    async fn service_state_failed() {
        let session = MockSession::new().with_result(
            "systemctl is-active -- xray.service",
            ExecResult::new(b"failed\n".to_vec(), Vec::new(), 3),
        );
        let manager = SystemdManager::new();
        let state = manager
            .service_state(&session, "xray.service")
            .await
            .expect("state query should succeed");

        assert_eq!(state, ServiceState::Failed);
    }

    #[tokio::test]
    async fn start_service_invokes_systemctl() {
        let session = MockSession::new().with_result(
            "systemctl start -- xray.service",
            ExecResult::new(Vec::new(), Vec::new(), 0),
        );
        let manager = SystemdManager::new();
        manager
            .start_service(&session, "xray.service")
            .await
            .expect("start should succeed");

        let calls = session.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program(), "systemctl");
        assert_eq!(calls[0].args(), &["start", "--", "xray.service"]);
    }

    #[tokio::test]
    async fn stop_service_invokes_systemctl() {
        let session = MockSession::new().with_result(
            "systemctl stop -- xray.service",
            ExecResult::new(Vec::new(), Vec::new(), 0),
        );
        let manager = SystemdManager::new();
        manager
            .stop_service(&session, "xray.service")
            .await
            .expect("stop should succeed");

        let calls = session.calls();
        assert_eq!(calls[0].args(), &["stop", "--", "xray.service"]);
    }

    #[tokio::test]
    async fn reload_enable_disable_invoke_systemctl() {
        let session = MockSession::new()
            .with_result(
                "systemctl reload -- xray.service",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                "systemctl enable -- xray.service",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                "systemctl disable -- xray.service",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            );
        let manager = SystemdManager::new();

        manager
            .reload_service(&session, "xray.service")
            .await
            .expect("reload");
        manager
            .enable_service(&session, "xray.service")
            .await
            .expect("enable");
        manager
            .disable_service(&session, "xray.service")
            .await
            .expect("disable");

        let calls = session.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].args(), &["reload", "--", "xray.service"]);
        assert_eq!(calls[1].args(), &["enable", "--", "xray.service"]);
        assert_eq!(calls[2].args(), &["disable", "--", "xray.service"]);
    }

    #[tokio::test]
    async fn restart_service_reports_service_not_found() {
        let session = MockSession::new().with_result(
            "systemctl restart -- xray",
            ExecResult::new(Vec::new(), b"Unit xray.service not found.\n".to_vec(), 5),
        );
        let manager = SystemdManager::new();
        let error = manager
            .restart_service(&session, "xray")
            .await
            .expect_err("restart should fail");

        assert_eq!(error.kind(), ServiceOperationErrorKind::ServiceNotFound);
        assert!(error.message().contains("Service not found"));
    }

    #[tokio::test]
    async fn stop_service_reports_permission_denied() {
        let session = MockSession::new().with_result(
            "systemctl stop -- xray.service",
            ExecResult::new(
                Vec::new(),
                b"Failed to stop xray.service: Access denied\n".to_vec(),
                1,
            ),
        );
        let manager = SystemdManager::new();
        let error = manager
            .stop_service(&session, "xray.service")
            .await
            .expect_err("stop should fail");

        assert_eq!(error.kind(), ServiceOperationErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn rejects_unsafe_service_name() {
        let session = MockSession::new();
        let manager = SystemdManager::new();
        let error = manager
            .start_service(&session, "xray; reboot")
            .await
            .expect_err("unsafe service name should fail");

        assert!(
            error.detail().contains("unsupported characters")
                || error.detail().contains("whitespace")
        );
        assert!(session.calls().is_empty());
    }

    #[test]
    fn parse_failed_state() {
        let result = ExecResult::new(b"failed\n".to_vec(), Vec::new(), 3);
        let state = parse_service_state(&result).expect("parse should succeed");
        assert_eq!(state, ServiceState::Failed);
    }

    #[test]
    fn parse_inactive_state() {
        let result = ExecResult::new(b"inactive\n".to_vec(), Vec::new(), 3);
        let state = parse_service_state(&result).expect("parse should succeed");
        assert_eq!(state, ServiceState::Inactive);
    }
}
