//! Application status exposed to the GUI Status Bar.
//!
//! Status values are owned by [`super::ApplicationService`].
//! The GUI reads this snapshot and must not query SSH or Xray directly.

/// Progress of a long-running operation shown in the Status Bar.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OperationProgress {
    /// No progress indicator (idle or message-only).
    None,
    /// Determinate progress in the range `0.0..=1.0`.
    Determinate(f32),
    /// Indeterminate progress (spinner).
    Indeterminate,
}

impl OperationProgress {
    /// Clamps a determinate fraction into `0.0..=1.0`.
    pub fn determinate(fraction: f32) -> Self {
        Self::Determinate(fraction.clamp(0.0, 1.0))
    }
}

/// Transient operation currently running in the application.
///
/// Returns to [`CurrentOperation::Ready`] when the operation completes.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum CurrentOperation {
    /// No operation is running; the application is idle.
    #[default]
    Ready,
    /// Short-lived informational message (for example after saving a profile).
    Message {
        /// Text shown in the Current Operation area.
        text: String,
    },
    /// Connecting to a remote host over SSH (`host:port`).
    Connecting {
        /// Remote endpoint in `host:port` form.
        endpoint: String,
    },
    /// Uploading configuration to the remote server.
    UploadingConfig {
        /// Upload progress, if known.
        progress: OperationProgress,
    },
    /// Restarting the remote Xray service.
    RestartingXray {
        /// Restart progress; typically indeterminate.
        progress: OperationProgress,
    },
    /// Creating a remote configuration backup.
    CreatingBackup {
        /// Backup progress, if known.
        progress: OperationProgress,
    },
    /// Discovering an existing remote Xray installation (read-only).
    DiscoveringXray,
    /// Adding a VLESS user to the remote configuration.
    AddingUser,
    /// Updating a VLESS user in the remote configuration.
    UpdatingUser,
    /// Deleting a VLESS user from the remote configuration.
    DeletingUser,
    /// Updating inbound General fields (tag / listen / port).
    UpdatingInboundGeneral,
    /// Updating inbound sniffing settings.
    UpdatingInboundSniffing,
    /// Unified Shell Save (General + Protocol + Sniffing + Security).
    UpdatingInboundShell,
    /// Adding a new inbound.
    AddingInbound,
    /// Deleting an inbound.
    DeletingInbound,
    /// Duplicating an inbound.
    DuplicatingInbound,
    /// Adding a new outbound (Freedom shell; Roadmap §2.4:94).
    AddingOutbound,
    /// Saving an outbound Shell edit (Freedom; Roadmap §2.4:94).
    UpdatingOutboundShell,
    /// Deleting an outbound.
    DeletingOutbound,
    /// Duplicating a shell-editable outbound (Roadmap §2.4:98).
    DuplicatingOutbound,
    /// Renaming an outbound's tag (Roadmap §2.4:99).
    RenamingOutboundTag,
    /// Adding a new confdir file (Roadmap §2.5:107).
    AddingConfdirFile,
    /// Removing an empty confdir file (Roadmap §2.5:107).
    RemovingConfdirFile,
    /// Generating x25519 key pair for Reality.
    GeneratingX25519,
    /// Generating mldsa65 seed/verify for Reality.
    GeneratingMldsa65,
    /// Generating VLESS decryption/encryption via `xray vlessenc`.
    GeneratingVlessEnc,
    /// Fetching a TLS certificate's SHA-256 pin for Hysteria2 `pinSHA256` (Roadmap §3:121).
    FetchingCertPin,
    /// Replacing an inbound's entire JSON object (raw JSON escape hatch, Roadmap §3:125).
    ReplacingInboundRawJson,
    /// Replacing an outbound's entire JSON object (raw JSON escape hatch, Roadmap §3:125).
    ReplacingOutboundRawJson,
    /// Managing the remote Xray systemd service (start/stop/…).
    ManagingXrayService {
        /// Status Bar text for the in-flight operation.
        text: String,
    },
    /// Installing, updating, or removing remote Xray.
    ManagingXrayLifecycle {
        /// Status Bar text for the in-flight operation.
        text: String,
    },
    /// Refreshing or updating remote GeoData databases.
    ManagingGeoData {
        /// Status Bar text for the in-flight operation.
        text: String,
    },
    /// Discovering or mutating Cloudflare WARP integration.
    ManagingWarp {
        /// Status Bar text for the in-flight operation.
        text: String,
    },
    /// Reading or following remote Xray runtime logs.
    ManagingXrayLogs {
        /// Status Bar text for the in-flight operation.
        text: String,
    },
    /// Validating / saving Xray top-level log settings.
    SavingLogSettings,
    /// Validating Xray log settings before save.
    ValidatingLogSettings,
    /// Validating / saving Xray top-level `api` settings (Roadmap §2.1:54).
    SavingApiSettings,
    /// Validating / saving Xray top-level `dns` settings (Roadmap §2.1:46).
    SavingDnsSettings,
    /// Validating / saving Xray top-level `fakedns` settings (Roadmap §2.1:47).
    SavingFakeDnsSettings,
    /// Validating / saving Xray top-level `routing` settings (Roadmap §2.1:48).
    SavingRoutingSettings,
    /// Validating / saving Xray top-level `policy` settings (Roadmap §2.1:49).
    SavingPolicySettings,
    /// Validating / saving Xray top-level `observatory` settings (Roadmap §2.1:50).
    SavingObservatorySettings,
    /// Validating / saving Xray top-level `burstObservatory` settings (Roadmap §2.1:51).
    SavingBurstObservatorySettings,
    /// Validating / saving Xray top-level `stats` settings (Roadmap §2.1:52).
    SavingStatsSettings,
    /// Validating / saving Xray top-level `metrics` settings (Roadmap §2.1:53).
    SavingMetricsSettings,
    /// Validating / saving Xray top-level `env` settings (Roadmap §2.1:55).
    SavingEnvSettings,
    /// Validating / saving Xray top-level `version` settings (Roadmap §2.1:56).
    SavingVersionSettings,
    /// Validating / saving Xray top-level `geodata` settings (Roadmap §2.1:57).
    SavingGeodataSettings,
    /// Restoring a config source file from a previously created backup (Roadmap §3:127).
    RestoringBackup,
    /// Running a live `xray api` gRPC operation (Roadmap §3:128) — affects only the running
    /// Xray process, never the configuration file.
    ManagingLiveApi {
        /// Status Bar text for the in-flight call (e.g. "Adding live inbound(s)...").
        text: String,
    },
}

impl CurrentOperation {
    /// Human-readable label for the Status Bar.
    pub fn label(&self) -> String {
        match self {
            Self::Ready => "Ready".to_owned(),
            Self::Message { text } => text.clone(),
            Self::Connecting { endpoint } => format!("Connecting {endpoint} ..."),
            Self::UploadingConfig { .. } => "Uploading config...".to_owned(),
            Self::RestartingXray { .. } => "Restarting Xray...".to_owned(),
            Self::CreatingBackup { .. } => "Creating backup...".to_owned(),
            Self::DiscoveringXray => "Discovering Xray installation...".to_owned(),
            Self::AddingUser => "Adding user...".to_owned(),
            Self::UpdatingUser => "Updating user...".to_owned(),
            Self::DeletingUser => "Deleting user...".to_owned(),
            Self::UpdatingInboundGeneral => "Updating inbound...".to_owned(),
            Self::UpdatingInboundSniffing => "Updating sniffing...".to_owned(),
            Self::UpdatingInboundShell => "Saving inbound...".to_owned(),
            Self::AddingInbound => "Adding inbound...".to_owned(),
            Self::DeletingInbound => "Deleting inbound...".to_owned(),
            Self::DuplicatingInbound => "Duplicating inbound...".to_owned(),
            Self::AddingOutbound => "Adding outbound...".to_owned(),
            Self::UpdatingOutboundShell => "Saving outbound...".to_owned(),
            Self::DeletingOutbound => "Deleting outbound...".to_owned(),
            Self::DuplicatingOutbound => "Duplicating outbound...".to_owned(),
            Self::RenamingOutboundTag => "Renaming outbound tag...".to_owned(),
            Self::AddingConfdirFile => "Adding confdir file...".to_owned(),
            Self::RemovingConfdirFile => "Removing confdir file...".to_owned(),
            Self::GeneratingX25519 => "Generating x25519 key pair...".to_owned(),
            Self::GeneratingMldsa65 => "Generating mldsa65 key pair...".to_owned(),
            Self::GeneratingVlessEnc => "Generating VLESS encryption...".to_owned(),
            Self::FetchingCertPin => "Fetching certificate pin...".to_owned(),
            Self::ReplacingInboundRawJson => "Saving inbound raw JSON...".to_owned(),
            Self::ReplacingOutboundRawJson => "Saving outbound raw JSON...".to_owned(),
            Self::ManagingXrayService { text } => text.clone(),
            Self::ManagingXrayLifecycle { text } => text.clone(),
            Self::ManagingGeoData { text } => text.clone(),
            Self::ManagingWarp { text } => text.clone(),
            Self::ManagingXrayLogs { text } => text.clone(),
            Self::SavingLogSettings => "Saving log settings...".to_owned(),
            Self::ValidatingLogSettings => "Validating log settings...".to_owned(),
            Self::RestoringBackup => "Restoring backup...".to_owned(),
            Self::ManagingLiveApi { text } => text.clone(),
            Self::SavingApiSettings => "Saving API settings...".to_owned(),
            Self::SavingDnsSettings => "Saving DNS settings...".to_owned(),
            Self::SavingFakeDnsSettings => "Saving FakeDNS settings...".to_owned(),
            Self::SavingRoutingSettings => "Saving routing settings...".to_owned(),
            Self::SavingPolicySettings => "Saving policy settings...".to_owned(),
            Self::SavingObservatorySettings => "Saving Observatory settings...".to_owned(),
            Self::SavingBurstObservatorySettings => "Saving BurstObservatory settings...".to_owned(),
            Self::SavingStatsSettings => "Saving stats settings...".to_owned(),
            Self::SavingMetricsSettings => "Saving metrics settings...".to_owned(),
            Self::SavingEnvSettings => "Saving env settings...".to_owned(),
            Self::SavingVersionSettings => "Saving version settings...".to_owned(),
            Self::SavingGeodataSettings => "Saving geodata settings...".to_owned(),
        }
    }

    /// Progress associated with this operation, if any.
    pub fn progress(&self) -> OperationProgress {
        match self {
            Self::Ready | Self::Message { .. } | Self::Connecting { .. } => OperationProgress::None,
            Self::DiscoveringXray
            | Self::AddingUser
            | Self::UpdatingUser
            | Self::DeletingUser
            | Self::UpdatingInboundGeneral
            | Self::UpdatingInboundSniffing
            | Self::UpdatingInboundShell
            | Self::AddingInbound
            | Self::DeletingInbound
            | Self::DuplicatingInbound
            | Self::AddingOutbound
            | Self::UpdatingOutboundShell
            | Self::DeletingOutbound
            | Self::DuplicatingOutbound
            | Self::RenamingOutboundTag
            | Self::AddingConfdirFile
            | Self::RemovingConfdirFile
            | Self::GeneratingX25519
            | Self::GeneratingMldsa65
            | Self::GeneratingVlessEnc
            | Self::FetchingCertPin
            | Self::ReplacingInboundRawJson
            | Self::ReplacingOutboundRawJson
            | Self::ManagingXrayService { .. }
            | Self::ManagingXrayLifecycle { .. }
            | Self::ManagingGeoData { .. }
            | Self::ManagingWarp { .. }
            | Self::ManagingXrayLogs { .. }
            | Self::SavingLogSettings
            | Self::ValidatingLogSettings
            | Self::RestoringBackup
            | Self::ManagingLiveApi { .. }
            | Self::SavingApiSettings
            | Self::SavingDnsSettings
            | Self::SavingFakeDnsSettings
            | Self::SavingRoutingSettings
            | Self::SavingPolicySettings
            | Self::SavingObservatorySettings
            | Self::SavingBurstObservatorySettings
            | Self::SavingStatsSettings
            | Self::SavingMetricsSettings
            | Self::SavingEnvSettings
            | Self::SavingVersionSettings
            | Self::SavingGeodataSettings => OperationProgress::Indeterminate,
            Self::UploadingConfig { progress }
            | Self::RestartingXray { progress }
            | Self::CreatingBackup { progress } => *progress,
        }
    }

    /// Returns `true` when an operation is in progress.
    pub fn is_busy(&self) -> bool {
        !matches!(self, Self::Ready | Self::Message { .. })
    }
}

/// Persistent SSH connection state for the Status Bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SshStatus {
    /// No active SSH session.
    #[default]
    Disconnected,
    /// SSH handshake or authentication is in progress.
    Connecting,
    /// SSH session is established.
    Connected,
    /// Authentication was rejected by the server.
    AuthenticationFailed,
    /// Too many authentication attempts were rejected.
    TooManyAuthFailures,
    /// The remote host refused the TCP connection.
    ConnectionRefused,
    /// The connection attempt timed out.
    TimedOut,
    /// Host key is unknown or does not match known_hosts.
    HostKeyVerificationFailed,
    /// The remote host name could not be resolved.
    HostNotFound,
    /// The connection was closed unexpectedly.
    ConnectionClosed,
    /// An unclassified SSH error occurred.
    UnknownError,
}

impl SshStatus {
    /// Human-readable label for the Status Bar.
    pub fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::AuthenticationFailed => "Authentication failed",
            Self::TooManyAuthFailures => "Too many authentication failures",
            Self::ConnectionRefused => "Connection refused",
            Self::TimedOut => "Connection timed out",
            Self::HostKeyVerificationFailed => "Host key verification failed",
            Self::HostNotFound => "Host not found",
            Self::ConnectionClosed => "Connection closed",
            Self::UnknownError => "Unknown SSH error",
        }
    }

    /// Semantic severity used for Status Bar coloring.
    pub fn severity(self) -> StatusSeverity {
        match self {
            Self::Connected => StatusSeverity::Healthy,
            Self::Connecting => StatusSeverity::Warning,
            Self::Disconnected => StatusSeverity::Unknown,
            Self::AuthenticationFailed
            | Self::TooManyAuthFailures
            | Self::ConnectionRefused
            | Self::TimedOut
            | Self::HostKeyVerificationFailed
            | Self::HostNotFound
            | Self::ConnectionClosed
            | Self::UnknownError => StatusSeverity::Error,
        }
    }
}

/// Persistent Xray service state for the Status Bar.
///
/// Supports arbitrary status messages; common examples include
/// `"Xray: Running"` and `"Xray: Inactive"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayStatus {
    message: String,
    severity: StatusSeverity,
}

impl XrayStatus {
    /// Creates an Xray status with an arbitrary message and severity.
    pub fn new(message: impl Into<String>, severity: StatusSeverity) -> Self {
        Self {
            message: message.into(),
            severity,
        }
    }

    /// Convenience constructor for a running remote Xray service.
    pub fn running() -> Self {
        Self::new("Xray: Running", StatusSeverity::Healthy)
    }

    /// Convenience constructor for an inactive remote Xray service.
    pub fn inactive() -> Self {
        Self::new("Xray: Inactive", StatusSeverity::Warning)
    }

    /// Convenience constructor for a stopped remote Xray service.
    pub fn stopped() -> Self {
        Self::new("Xray: Stopped", StatusSeverity::Warning)
    }

    /// Convenience constructor for a failed remote Xray service.
    pub fn failed() -> Self {
        Self::new("Xray: Failed", StatusSeverity::Error)
    }

    /// Convenience constructor for an unknown Xray state.
    pub fn unknown() -> Self {
        Self::new("Xray: Unknown", StatusSeverity::Unknown)
    }

    /// Maps a [`crate::init::ServiceState`] into a Status Bar Xray status.
    pub fn from_service_state(state: crate::init::ServiceState) -> Self {
        use crate::init::ServiceState;
        match state {
            ServiceState::Running => Self::running(),
            ServiceState::Stopped => Self::stopped(),
            ServiceState::Inactive => Self::inactive(),
            ServiceState::Failed => Self::failed(),
            ServiceState::Unknown => Self::unknown(),
        }
    }

    /// Status text shown in the Status Bar.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Semantic severity used for Status Bar coloring.
    pub fn severity(&self) -> StatusSeverity {
        self.severity
    }
}

impl Default for XrayStatus {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Semantic severity for status coloring in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusSeverity {
    /// Healthy / success state (green).
    Healthy,
    /// Warning / in-progress state (yellow).
    Warning,
    /// Error / failed state (red).
    Error,
    /// Unknown / idle state (gray).
    #[default]
    Unknown,
}

/// Immutable snapshot of Status Bar state.
///
/// Produced by [`super::ApplicationService`] for the GUI layer.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusSnapshot {
    /// Transient current operation.
    pub operation: CurrentOperation,
    /// Persistent SSH connection state.
    pub ssh: SshStatus,
    /// Persistent Xray service state.
    pub xray: XrayStatus,
}

impl Default for StatusSnapshot {
    fn default() -> Self {
        Self {
            operation: CurrentOperation::Ready,
            ssh: SshStatus::Disconnected,
            xray: XrayStatus::unknown(),
        }
    }
}
