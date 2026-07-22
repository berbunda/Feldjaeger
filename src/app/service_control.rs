//! Asynchronous Xray service lifecycle orchestration for [`super::ApplicationService`].

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::{error, info, warn};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::init::{
    InitSystemManager, ServiceControlError, ServiceOperationErrorKind, ServiceState, SystemdManager,
};
use crate::logging::redact::{sanitize_detail, user_message_see_log};
use crate::storage::StoredConnectionProfile;
use crate::xray::InitSystemKind;

/// Lifecycle operation requested from the Service page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOperation {
    /// `systemctl start`
    Start,
    /// `systemctl stop`
    Stop,
    /// `systemctl restart`
    Restart,
    /// `systemctl reload`
    Reload,
    /// `systemctl enable`
    Enable,
    /// `systemctl disable`
    Disable,
}

impl ServiceOperation {
    /// Status Bar text while the operation is in flight.
    pub fn status_message(self) -> &'static str {
        match self {
            Self::Start => "Starting Xray...",
            Self::Stop => "Stopping Xray...",
            Self::Restart => "Restarting Xray...",
            Self::Reload => "Reloading Xray...",
            Self::Enable => "Enabling Xray service...",
            Self::Disable => "Disabling Xray service...",
        }
    }

    /// Confirmation dialog title/body for destructive operations.
    ///
    /// Returns `None` when no confirmation is required (Start, Reload).
    pub fn confirmation_prompt(self) -> Option<&'static str> {
        match self {
            Self::Stop => Some("Stop Xray?"),
            Self::Restart => Some("Restart Xray?"),
            Self::Disable => Some("Disable Xray startup?"),
            Self::Start | Self::Reload | Self::Enable => None,
        }
    }

    /// Verb used in application log lines (`Starting`, `Stopping`, …).
    pub fn log_gerund(self) -> &'static str {
        match self {
            Self::Start => "Starting",
            Self::Stop => "Stopping",
            Self::Restart => "Restarting",
            Self::Reload => "Reloading",
            Self::Enable => "Enabling",
            Self::Disable => "Disabling",
        }
    }

    /// Past-tense verb for success log lines (`started`, `stopped`, …).
    pub fn log_past(self) -> &'static str {
        match self {
            Self::Start => "started",
            Self::Stop => "stopped",
            Self::Restart => "restarted",
            Self::Reload => "reloaded",
            Self::Enable => "enabled",
            Self::Disable => "disabled",
        }
    }

    /// Short label for UI buttons.
    pub fn button_label(self) -> &'static str {
        match self {
            Self::Start => "Start",
            Self::Stop => "Stop",
            Self::Restart => "Restart",
            Self::Reload => "Reload",
            Self::Enable => "Enable",
            Self::Disable => "Disable",
        }
    }
}

/// GUI lifecycle of a service-control operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ServiceControlState {
    /// No operation in flight; last error cleared or never set.
    #[default]
    Idle,
    /// An operation is running off the UI thread.
    Busy(ServiceOperation),
    /// Last operation failed; detail is safe for the UI.
    Failed {
        /// Classified failure kind.
        kind: ServiceOperationErrorKind,
        /// Safe user-facing detail.
        detail: String,
    },
}

impl ServiceControlState {
    /// Returns `true` while a service operation is in flight.
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Busy(_))
    }
}

/// Read-only model for the Service page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePageModel {
    /// Whether discovery has produced an installation snapshot.
    pub discovery_ready: bool,
    /// Discovered unit name, when available.
    pub service_name: Option<String>,
    /// Detected init system label (for example `systemd`).
    pub init_system: Option<InitSystemKind>,
    /// Last known service state.
    pub state: Option<ServiceState>,
    /// Whether Start/Stop/… buttons may be used.
    pub management_allowed: bool,
    /// Explanation when management is not allowed.
    pub blocked_reason: Option<&'static str>,
    /// Current control-operation lifecycle.
    pub control: ServiceControlState,
}

/// Outcome delivered from the service-control worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceOperationOutcome {
    /// Operation that was attempted.
    pub operation: ServiceOperation,
    /// Validated service name used for the remote command.
    pub service_name: String,
    /// Operation result; on failure includes classified kind and safe detail.
    pub result: Result<(), ServiceControlError>,
    /// Fresh state queried after the action (when reachable).
    pub refreshed_state: Option<ServiceState>,
}

/// Runs connect → service action → refresh state → disconnect.
pub async fn run_service_operation<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    init: &SystemdManager,
    service_name: &str,
    operation: ServiceOperation,
) -> ServiceOperationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request = build_connect_request(profile, secrets);

    info!(
        target: "app",
        "{} Xray service {}",
        operation.log_gerund(),
        service_name
    );

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            let detail = sanitize_detail(error.message());
            warn!(
                target: "app",
                detail = %detail,
                "SSH connection failed for service operation"
            );
            return ServiceOperationOutcome {
                operation,
                service_name: service_name.to_owned(),
                result: Err(ServiceControlError::new(
                    ServiceOperationErrorKind::SshConnectionFailed,
                    detail,
                )),
                refreshed_state: None,
            };
        }
    };

    let action_result = match operation {
        ServiceOperation::Start => init.start_service(&session, service_name).await,
        ServiceOperation::Stop => init.stop_service(&session, service_name).await,
        ServiceOperation::Restart => init.restart_service(&session, service_name).await,
        ServiceOperation::Reload => init.reload_service(&session, service_name).await,
        ServiceOperation::Enable => init.enable_service(&session, service_name).await,
        ServiceOperation::Disable => init.disable_service(&session, service_name).await,
    };

    let refreshed_state = match init.service_state(&session, service_name).await {
        Ok(state) => Some(state),
        Err(error) => {
            warn!(
                target: "init",
                detail = %sanitize_detail(error.detail()),
                "failed to refresh service state after operation"
            );
            None
        }
    };

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "service operation disconnect warning"
        );
    }

    match &action_result {
        Ok(()) => {
            info!(
                target: "app",
                "Xray service {} successfully",
                operation.log_past()
            );
        }
        Err(error) => {
            error!(
                target: "app",
                kind = ?error.kind(),
                detail = %sanitize_detail(error.detail()),
                "Failed to {} Xray service",
                operation.log_past()
            );
        }
    }

    ServiceOperationOutcome {
        operation,
        service_name: service_name.to_owned(),
        result: action_result,
        refreshed_state,
    }
}

/// Maps a service-control error to a short user-facing Status Bar message.
pub fn user_facing_service_error(error: &ServiceControlError) -> String {
    match error.kind() {
        ServiceOperationErrorKind::SshConnectionFailed => {
            user_message_see_log("SSH connection failed.")
        }
        ServiceOperationErrorKind::PermissionDenied => user_message_see_log("Permission denied."),
        ServiceOperationErrorKind::ServiceNotFound => "Service not found.".to_owned(),
        ServiceOperationErrorKind::CommandFailed => {
            user_message_see_log("systemctl command failed.")
        }
        ServiceOperationErrorKind::UnsupportedInitSystem => "Unsupported init system.".to_owned(),
        ServiceOperationErrorKind::StateUnknown => "Service state unknown.".to_owned(),
    }
}

/// Builds the Service page model from discovery and control state.
pub fn build_service_page_model(
    discovery: &crate::xray::DiscoveryState,
    control: &ServiceControlState,
    override_state: Option<ServiceState>,
) -> ServicePageModel {
    use crate::xray::DiscoveryState;

    match discovery {
        DiscoveryState::Succeeded(installation) => {
            let management_allowed = installation.service_control_supported()
                && installation.service_name.is_some();
            let blocked_reason = if !installation.service_control_supported() {
                Some("Do not attempt service management.")
            } else if installation.service_name.is_none() {
                Some("Xray service unit was not found during discovery.")
            } else {
                None
            };
            ServicePageModel {
                discovery_ready: true,
                service_name: installation.service_name.clone(),
                init_system: Some(installation.init_system),
                state: override_state.or(installation.service_state),
                management_allowed,
                blocked_reason,
                control: control.clone(),
            }
        }
        DiscoveryState::NotFound { init_system, .. } => ServicePageModel {
            discovery_ready: true,
            service_name: None,
            init_system: Some(*init_system),
            state: None,
            management_allowed: false,
            blocked_reason: if init_system.supports_service_control() {
                Some("Xray installation not found.")
            } else {
                Some("Do not attempt service management.")
            },
            control: control.clone(),
        },
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::Failed { .. } => ServicePageModel {
            discovery_ready: false,
            service_name: None,
            init_system: None,
            state: None,
            management_allowed: false,
            blocked_reason: Some("Run discovery on the Connection page first."),
            control: control.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::connection_secrets::ConnectionSecrets;
    use crate::init::{ServiceOperationErrorKind, ServiceState, SystemdManager};
    use crate::storage::StoredConnectionProfile;
    use crate::xray::{ConfigSource, DiscoveryState, InitSystemKind, XrayInstallation};
    use feldjaeger_ssh::{
        AuthMethod, ConnectRequest, ConnectionProfile, ExecResult, RemoteCommand, RemotePath,
        SshBackend, SshError, SshResult, SshSession,
    };
    use std::collections::HashMap;
    use std::future::{self, Future};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockSession {
        profile: ConnectionProfile,
        exec_results: Arc<Mutex<HashMap<String, ExecResult>>>,
        exec_calls: Arc<Mutex<Vec<RemoteCommand>>>,
    }

    impl MockSession {
        fn new() -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                exec_results: Arc::new(Mutex::new(HashMap::new())),
                exec_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn with_result(self, key: impl Into<String>, result: ExecResult) -> Self {
            self.exec_results.lock().unwrap().insert(key.into(), result);
            self
        }
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        fn read_file(
            &self,
            _path: &RemotePath,
        ) -> impl Future<Output = SshResult<Vec<u8>>> + Send {
            future::ready(Err(SshError::new("not supported")))
        }

        fn write_file(
            &self,
            _path: &RemotePath,
            _contents: &[u8],
        ) -> impl Future<Output = SshResult<()>> + Send {
            future::ready(Err(SshError::new("not supported")))
        }

        fn write_file_atomic(
            &self,
            _path: &RemotePath,
            _contents: &[u8],
        ) -> impl Future<Output = SshResult<()>> + Send {
            future::ready(Err(SshError::new("not supported")))
        }

        fn rename_file(
            &self,
            _from: &RemotePath,
            _to: &RemotePath,
        ) -> impl Future<Output = SshResult<()>> + Send {
            future::ready(Err(SshError::new("not supported")))
        }

        fn remove_file(
            &self,
            _path: &RemotePath,
        ) -> impl Future<Output = SshResult<()>> + Send {
            future::ready(Err(SshError::new("not supported")))
        }

        fn exec(
            &self,
            command: &RemoteCommand,
        ) -> impl Future<Output = SshResult<ExecResult>> + Send {
            self.exec_calls.lock().unwrap().push(command.clone());
            let key = {
                let args = command
                    .args()
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{} {args}", command.program())
            };
            let result = self
                .exec_results
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_else(|| {
                    ExecResult::new(Vec::new(), format!("no mock for {key}").into_bytes(), 1)
                });
            future::ready(Ok(result))
        }

        fn disconnect(self) -> impl Future<Output = SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    struct MockBackend {
        session: Option<MockSession>,
        connect_error: Option<&'static str>,
    }

    impl SshBackend for MockBackend {
        type Session = MockSession;

        fn connect(
            &self,
            _request: &ConnectRequest,
        ) -> impl Future<Output = SshResult<Self::Session>> + Send {
            if let Some(message) = self.connect_error {
                return future::ready(Err(SshError::new(message)));
            }
            future::ready(Ok(self
                .session
                .clone()
                .expect("mock session configured")))
        }
    }

    fn profile() -> StoredConnectionProfile {
        StoredConnectionProfile {
            profile_name: "test".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 22,
            username: "admin".to_owned(),
            auth_method: AuthMethod::Password,
            private_key_path: String::new(),
        }
    }

    fn secrets() -> ConnectionSecrets {
        let mut secrets = ConnectionSecrets::new();
        secrets.set_password("secret".to_owned());
        secrets
    }

    fn sample_installation(init: InitSystemKind, service: Option<&str>) -> XrayInstallation {
        XrayInstallation {
            operating_system: "Linux".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: init,
            binary_path: None,
            version: Some("1.0".to_owned()),
            service_name: service.map(str::to_owned),
            service_state: Some(ServiceState::Running),
            exec_start: None,
            config_source: ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        }
    }

    #[tokio::test]
    async fn start_service_refreshes_state() {
        let session = MockSession::new()
            .with_result(
                "systemctl start -- xray.service",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                "systemctl is-active -- xray.service",
                ExecResult::new(b"active\n".to_vec(), Vec::new(), 0),
            );
        let backend = MockBackend {
            session: Some(session),
            connect_error: None,
        };
        let outcome = run_service_operation(
            &backend,
            &profile(),
            &secrets(),
            &SystemdManager::new(),
            "xray.service",
            ServiceOperation::Start,
        )
        .await;

        assert!(outcome.result.is_ok());
        assert_eq!(outcome.refreshed_state, Some(ServiceState::Running));
    }

    #[tokio::test]
    async fn stop_service_refreshes_even_when_inactive() {
        let session = MockSession::new()
            .with_result(
                "systemctl stop -- xray.service",
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                "systemctl is-active -- xray.service",
                ExecResult::new(b"inactive\n".to_vec(), Vec::new(), 3),
            );
        let backend = MockBackend {
            session: Some(session),
            connect_error: None,
        };
        let outcome = run_service_operation(
            &backend,
            &profile(),
            &secrets(),
            &SystemdManager::new(),
            "xray.service",
            ServiceOperation::Stop,
        )
        .await;

        assert!(outcome.result.is_ok());
        assert_eq!(outcome.refreshed_state, Some(ServiceState::Inactive));
    }

    #[tokio::test]
    async fn ssh_connect_failure_is_classified() {
        let backend = MockBackend {
            session: None,
            connect_error: Some("SSH connection refused"),
        };
        let outcome = run_service_operation(
            &backend,
            &profile(),
            &secrets(),
            &SystemdManager::new(),
            "xray.service",
            ServiceOperation::Restart,
        )
        .await;

        let error = outcome.result.expect_err("should fail");
        assert_eq!(
            error.kind(),
            ServiceOperationErrorKind::SshConnectionFailed
        );
        assert!(outcome.refreshed_state.is_none());
    }

    #[tokio::test]
    async fn permission_denied_is_classified() {
        let session = MockSession::new()
            .with_result(
                "systemctl disable -- xray.service",
                ExecResult::new(
                    Vec::new(),
                    b"Failed to disable unit: Interactive authentication required.\n".to_vec(),
                    1,
                ),
            )
            .with_result(
                "systemctl is-active -- xray.service",
                ExecResult::new(b"active\n".to_vec(), Vec::new(), 0),
            );
        let backend = MockBackend {
            session: Some(session),
            connect_error: None,
        };
        let outcome = run_service_operation(
            &backend,
            &profile(),
            &secrets(),
            &SystemdManager::new(),
            "xray.service",
            ServiceOperation::Disable,
        )
        .await;

        let error = outcome.result.expect_err("should fail");
        assert_eq!(error.kind(), ServiceOperationErrorKind::PermissionDenied);
        assert_eq!(outcome.refreshed_state, Some(ServiceState::Running));
    }

    #[tokio::test]
    async fn service_not_found_is_classified() {
        let session = MockSession::new()
            .with_result(
                "systemctl start -- missing.service",
                ExecResult::new(
                    Vec::new(),
                    b"Unit missing.service could not be found.\n".to_vec(),
                    5,
                ),
            )
            .with_result(
                "systemctl is-active -- missing.service",
                ExecResult::new(b"unknown\n".to_vec(), Vec::new(), 4),
            );
        let backend = MockBackend {
            session: Some(session),
            connect_error: None,
        };
        let outcome = run_service_operation(
            &backend,
            &profile(),
            &secrets(),
            &SystemdManager::new(),
            "missing.service",
            ServiceOperation::Start,
        )
        .await;

        let error = outcome.result.expect_err("should fail");
        assert_eq!(error.kind(), ServiceOperationErrorKind::ServiceNotFound);
    }

    #[test]
    fn page_model_blocks_unsupported_init() {
        let discovery = DiscoveryState::Succeeded(sample_installation(InitSystemKind::OpenRC, None));
        let model = build_service_page_model(&discovery, &ServiceControlState::Idle, None);
        assert!(!model.management_allowed);
        assert_eq!(
            model.blocked_reason,
            Some("Do not attempt service management.")
        );
    }

    #[test]
    fn page_model_allows_systemd_with_unit() {
        let discovery =
            DiscoveryState::Succeeded(sample_installation(InitSystemKind::Systemd, Some("xray.service")));
        let model = build_service_page_model(&discovery, &ServiceControlState::Idle, None);
        assert!(model.management_allowed);
        assert_eq!(model.service_name.as_deref(), Some("xray.service"));
        assert_eq!(model.state, Some(ServiceState::Running));
    }

    #[test]
    fn page_model_requires_discovery() {
        let model = build_service_page_model(
            &DiscoveryState::Idle,
            &ServiceControlState::Idle,
            None,
        );
        assert!(!model.discovery_ready);
        assert_eq!(
            model.blocked_reason,
            Some("Run discovery on the Connection page first.")
        );
    }

    #[test]
    fn confirmation_only_for_destructive_ops() {
        assert!(ServiceOperation::Start.confirmation_prompt().is_none());
        assert!(ServiceOperation::Reload.confirmation_prompt().is_none());
        assert!(ServiceOperation::Enable.confirmation_prompt().is_none());
        assert_eq!(
            ServiceOperation::Stop.confirmation_prompt(),
            Some("Stop Xray?")
        );
        assert_eq!(
            ServiceOperation::Restart.confirmation_prompt(),
            Some("Restart Xray?")
        );
        assert_eq!(
            ServiceOperation::Disable.confirmation_prompt(),
            Some("Disable Xray startup?")
        );
    }
}
