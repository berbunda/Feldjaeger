//! Init system manager trait and shared types.

use std::future::Future;

use feldjaeger_ssh::SshSession;

use super::error::ServiceControlResult;

/// Service lifecycle state reported by an init system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is running or activating.
    Running,
    /// Service is stopped or deactivating.
    Stopped,
    /// Service entered a failed state.
    Failed,
    /// Service is inactive (loaded but not running).
    Inactive,
    /// Service state could not be determined.
    Unknown,
}

impl ServiceState {
    /// Human-readable label for UI summaries.
    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Inactive => "inactive",
            Self::Unknown => "unknown",
        }
    }
}

/// Abstraction over OS init systems for remote service control.
///
/// MVP provides only [`super::SystemdManager`]; other backends will be added later.
/// All operations run on the remote host through an SSH session.
pub trait InitSystemManager: Send + Sync {
    /// Returns the current state of the named service.
    fn service_state<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<ServiceState>> + Send;

    /// Starts the named service.
    fn start_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send;

    /// Stops the named service.
    fn stop_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send;

    /// Restarts the named service.
    fn restart_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send;

    /// Reloads the named service configuration without a full restart.
    fn reload_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send;

    /// Enables the named service to start on boot.
    fn enable_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send;

    /// Disables the named service from starting on boot.
    fn disable_service<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> impl Future<Output = ServiceControlResult<()>> + Send;
}
