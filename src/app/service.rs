//! Application service facade for upper layers.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use feldjaeger_ssh::{HostKeyPolicy, RusshClient, RusshClientOptions, SshBackend, SshSession};
use tracing::{error, info, warn};

use crate::init::{ServiceName, ServiceState, SystemdManager};
use crate::remote::RemoteAdmin;
use crate::storage::{
    AppConfig, ConfigManager, ConnectionDraft, ConnectionValidationErrors, StoredConnectionProfile,
    ThemeMode, UiConfig, WindowPosition, WindowSize,
};
use crate::xray::{DefaultConfigValidator, XrayManager};

use super::burst_observatory::{BurstObservatoryPageModel, build_burst_observatory_page_model};
use super::connection_secrets::ConnectionSecrets;
use super::connection_test::{
    ConnectionTestOutcome, ConnectionTestState, build_connect_request, classify_ssh_error,
    run_connection_test, validate_for_connection_test,
};
use super::discovery::{DiscoveryOutcome, run_discovery};
use super::dns::{DnsPageModel, build_dns_page_model};
use super::fakedns::{FakeDnsPageModel, build_fakedns_page_model};
use super::geodata::{
    GeoDataOperation, GeoDataOutcome, GeoDataPageModel, GeoDataUiState,
    build_geodata_page_model, hints_from_discovery, run_geodata_operation,
    user_facing_geodata_error,
};
use super::warp::{
    WarpOperation, WarpOutcome, WarpOutcomePayload, WarpPageModel, WarpPendingConfirm,
    WarpUiState, WarpWorkerContext, build_warp_page_model, default_preferred_tag,
    run_warp_operation, user_facing_warp_error,
};
    use super::inbound_ops::{
    InboundEditorSession, InboundMutationKind, InboundMutationOutcome, InboundMutationSuccess,
    InboundShellDrafts, InboundShellMutationKind, InboundShellMutationOutcome, Mldsa65Result,
    X25519Result, VlessEncResult, run_add_inbound, run_delete_inbound, run_duplicate_inbound,
    run_generate_mldsa65, run_generate_vlessenc, run_generate_x25519,
    run_update_inbound_general, run_update_inbound_shell, run_update_inbound_sniffing,
};
use super::inbounds::{
    InboundsPageModel, InboundsSort, InboundsSortColumn, LoadedConfigSnapshot,
    build_inbounds_page_model,
};
use super::log_settings::{LogSettingsPageModel, build_log_settings_page_model};
use super::log_settings_ops::{LogSettingsMutationOutcome, run_update_log_settings};
use super::observatory::{ObservatoryPageModel, build_observatory_page_model};
use super::outbounds::{
    OutboundsPageModel, OutboundsSort, OutboundsSortColumn, build_outbounds_page_model,
};
use super::policy::{PolicyPageModel, PolicySort, PolicySortColumn, build_policy_page_model};
use super::routing::{RoutingPageModel, RoutingSort, RoutingSortColumn, build_routing_page_model};
use super::service_control::{
    ServiceControlState, ServiceOperation, ServiceOperationOutcome, ServicePageModel,
    UnitApplyOutcome, UnitApplyRequest, build_service_page_model, run_service_operation,
    run_unit_apply, user_facing_service_error, user_facing_unit_error,
};
use super::status::{CurrentOperation, OperationProgress, SshStatus, StatusSnapshot, XrayStatus};
use super::user_ops::{
    UserMutationKind, UserMutationOutcome, run_add_user, run_delete_user, run_update_user,
};
use super::users::{UsersPageModel, UsersSort, UsersSortColumn, build_users_page_model};
use super::xray_management::{
    XrayLifecycleOperation, XrayLifecycleOutcome, XrayLifecycleState, XrayManagementPageModel,
    VersionCheckOutcome, build_xray_management_page_model, lifecycle_snapshot_from_discovery,
    run_version_check, run_xray_lifecycle, user_facing_installer_error,
};
use super::xray_logs::{
    XrayLogsPageModel, XrayLogsRuntime, XrayLogsUiState, apply_xray_log_event,
    build_xray_logs_page_model, spawn_xray_log_follow, spawn_xray_log_probe, spawn_xray_log_read,
    xray_log_event_channel, xray_log_probe_channel,
};
use crate::xray::{
    AddInboundRequest, AddOutboundShellRequest, AddUserRequest, AvailableVersions,
    BurstObservatorySummary, DeleteInboundRequest, DeleteUserRequest, DiscoveryState, DnsSummary,
    DuplicateInboundRequest, EditableXrayConfig, FakeDnsSummary, InboundClientProtocol,
    InboundGeneral, InboundProtocolDraft, InboundRef, InboundSecurityDraft, InboundSecurityMode,
    InboundStreamDraft, InboundSummary, InstallChannel, LogSettings, ObservatorySummary,
    OutboundGeneral, OutboundRef, OutboundSettingsDraft, OutboundSummary, PolicySummary,
    RoutingSummary, SniffingSettings, StreamMethod, UpdateInboundGeneralRequest,
    UpdateInboundShellRequest, UpdateInboundSniffingRequest, UpdateLogSettingsRequest,
    UpdateOutboundShellRequest, UpdateUserRequest, UserSummary, VlessClientSummary, XrayInstaller,
    XrayLogLineLimit, XrayLogService, XrayLogSourceKind, add_inbound, is_shell_editable_protocol,
    parse_inbound_general, parse_inbound_protocol, parse_inbound_security, parse_inbound_stream,
    parse_outbound_general, parse_outbound_settings, parse_sniffing_settings,
    port_is_shell_editable, update_inbound_shell, validate_log_settings,
};

/// How long a transient Status Bar message remains visible.
const STATUS_MESSAGE_DURATION: Duration = Duration::from_secs(3);

/// Internal request payload for the user-mutation worker (VLESS + Trojan + Hysteria).
enum UserMutationRequest {
    Add(AddUserRequest),
    Update(UpdateUserRequest),
    Delete(DeleteUserRequest),
    /// Add Trojan client (IB-L1).
    AddTrojan {
        inbound_index: usize,
        email: String,
        password: crate::xray::SecretString,
        level: u32,
    },
    /// Update Trojan client (email + password draft).
    UpdateTrojan {
        inbound_index: usize,
        client_index: usize,
        email: String,
        password: crate::xray::SecretFieldDraft,
        level: u32,
        expected_fingerprint: Option<String>,
    },
    /// Add Hysteria user (Wave A).
    AddHysteria {
        inbound_index: usize,
        email: String,
        auth: crate::xray::SecretString,
        level: u32,
    },
    /// Update Hysteria user (email + auth draft).
    UpdateHysteria {
        inbound_index: usize,
        client_index: usize,
        email: String,
        auth: crate::xray::SecretFieldDraft,
        level: u32,
        expected_fingerprint: Option<String>,
    },
}

/// Internal request payload for inbound shell mutation worker.
enum InboundShellMutationRequest {
    General(UpdateInboundGeneralRequest),
    Sniffing(UpdateInboundSniffingRequest),
}

/// Top-level application service exposed to the GUI.
///
/// Hides SSH, init-system, Xray, and config-file wiring from presentation code.
/// Owns Status Bar state, local UI preferences, and the connection profile draft.
/// The GUI never touches `config.json` or SSH directly.
pub struct ApplicationService {
    remote: RemoteAdmin,
    xray: XrayManager,
    init: SystemdManager,
    validator: DefaultConfigValidator,
    config: ConfigManager,
    ssh_client: RusshClient,
    connection_draft: ConnectionDraft,
    connection_secrets: ConnectionSecrets,
    connection_errors: ConnectionValidationErrors,
    connection_test: ConnectionTestState,
    connection_test_rx: Option<Receiver<ConnectionTestOutcome>>,
    discovery: DiscoveryState,
    discovery_rx: Option<Receiver<DiscoveryOutcome>>,
    loaded_config: LoadedConfigSnapshot,
    inbounds_sort: InboundsSort,
    outbounds_sort: OutboundsSort,
    outbounds_status_announced: bool,
    dns_status_announced: bool,
    fakedns_status_announced: bool,
    observatory_status_announced: bool,
    burst_observatory_status_announced: bool,
    routing_sort: RoutingSort,
    routing_status_announced: bool,
    policy_sort: PolicySort,
    policy_status_announced: bool,
    selected_users_inbound_index: Option<usize>,
    users_sort: UsersSort,
    user_mutation_rx: Option<Receiver<UserMutationOutcome>>,
    inbound_shell_drafts: Option<InboundShellDrafts>,
    inbound_shell_rx: Option<Receiver<InboundShellMutationOutcome>>,
    /// IB-L1 unified editor session (Shell Save / Add / Keygen).
    inbound_editor_session: Option<InboundEditorSession>,
    /// Reality PublicKey / vlessenc client encryption retained for Share URI.
    share_materials: super::share_material::ShareMaterialStore,
    /// In-flight unified inbound mutation (Shell / Add / GenerateX25519).
    inbound_mutation_rx: Option<Receiver<InboundMutationOutcome>>,
    /// In-flight outbound mutation (Add / Update / Delete).
    outbound_mutation_rx: Option<Receiver<super::outbound_ops::OutboundMutationOutcome>>,
    /// Outbound Shell editor session (Freedom only today; Roadmap §2.4:94).
    outbound_editor_session: Option<super::outbound_ops::OutboundEditorSession>,
    log_settings_draft: Option<LogSettings>,
    log_settings_error: Option<String>,
    log_settings_saved_flash: bool,
    log_settings_rx: Option<Receiver<LogSettingsMutationOutcome>>,
    service_control: ServiceControlState,
    service_control_rx: Option<Receiver<ServiceOperationOutcome>>,
    service_state: Option<ServiceState>,
    unit_host_probe: Option<crate::init::UnitHostProbe>,
    unit_probe_rx: Option<Receiver<crate::init::UnitHostProbe>>,
    unit_apply_rx: Option<Receiver<UnitApplyOutcome>>,
    unit_apply_busy: bool,
    unit_apply_needs_restart_prompt: bool,
    xray_lifecycle: XrayLifecycleState,
    xray_lifecycle_rx: Option<Receiver<XrayLifecycleOutcome>>,
    install_channel: InstallChannel,
    available_versions: AvailableVersions,
    version_check_rx: Option<Receiver<VersionCheckOutcome>>,
    version_check_busy: bool,
    geodata_summary: Option<crate::xray::GeoDataSummary>,
    geodata_ui: GeoDataUiState,
    geodata_rx: Option<Receiver<GeoDataOutcome>>,
    warp_summary: Option<crate::xray::WarpSummary>,
    warp_ui: WarpUiState,
    warp_rx: Option<Receiver<WarpOutcome>>,
    warp_generation: u64,
    warp_preferred_tag: String,
    warp_pending_confirm: Option<WarpPendingConfirm>,
    warp_proposed: Option<crate::xray::WarpProposedChange>,
    warp_routing_notice: Option<String>,
    warp_ownership: Option<crate::xray::WarpOwnershipRecord>,
    xray_logs: XrayLogsRuntime,
    operation: CurrentOperation,
    status_message_until: Option<Instant>,
    ssh_status: SshStatus,
    xray_status: XrayStatus,
}

impl std::fmt::Debug for ApplicationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationService")
            .field("remote", &self.remote)
            .field("xray", &self.xray)
            .field("init", &self.init)
            .field("validator", &self.validator)
            .field("config", &self.config)
            .field("ssh_client", &self.ssh_client)
            .field("connection_draft", &self.connection_draft)
            .field("connection_secrets", &self.connection_secrets)
            .field("connection_errors", &self.connection_errors)
            .field("connection_test", &self.connection_test)
            .field(
                "connection_test_rx",
                &self.connection_test_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field("discovery", &self.discovery)
            .field(
                "discovery_rx",
                &self.discovery_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field("loaded_config", &self.loaded_config)
            .field("inbounds_sort", &self.inbounds_sort)
            .field("outbounds_sort", &self.outbounds_sort)
            .field(
                "outbounds_status_announced",
                &self.outbounds_status_announced,
            )
            .field("dns_status_announced", &self.dns_status_announced)
            .field("fakedns_status_announced", &self.fakedns_status_announced)
            .field(
                "observatory_status_announced",
                &self.observatory_status_announced,
            )
            .field(
                "burst_observatory_status_announced",
                &self.burst_observatory_status_announced,
            )
            .field("routing_sort", &self.routing_sort)
            .field("routing_status_announced", &self.routing_status_announced)
            .field("policy_sort", &self.policy_sort)
            .field("policy_status_announced", &self.policy_status_announced)
            .field(
                "selected_users_inbound_index",
                &self.selected_users_inbound_index,
            )
            .field("users_sort", &self.users_sort)
            .field(
                "user_mutation_rx",
                &self.user_mutation_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field(
                "inbound_shell_drafts",
                &self
                    .inbound_shell_drafts
                    .as_ref()
                    .map(|d| format!("Some(inbound={})", d.inbound_index)),
            )
            .field(
                "inbound_shell_rx",
                &self.inbound_shell_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field(
                "inbound_editor_session",
                &self.inbound_editor_session.as_ref().map(|s| {
                    if s.is_add {
                        "Some(Add)".to_owned()
                    } else {
                        format!("Some(Edit inbound={})", s.inbound_index)
                    }
                }),
            )
            .field(
                "inbound_mutation_rx",
                &self.inbound_mutation_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field(
                "outbound_mutation_rx",
                &self.outbound_mutation_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field(
                "log_settings_draft",
                &self.log_settings_draft.as_ref().map(|_| "Some(LogSettings)"),
            )
            .field("log_settings_error", &self.log_settings_error)
            .field("log_settings_saved_flash", &self.log_settings_saved_flash)
            .field(
                "log_settings_rx",
                &self.log_settings_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field("service_control", &self.service_control)
            .field(
                "service_control_rx",
                &self.service_control_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field("service_state", &self.service_state)
            .field("xray_lifecycle", &self.xray_lifecycle)
            .field(
                "xray_lifecycle_rx",
                &self.xray_lifecycle_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field("install_channel", &self.install_channel)
            .field("available_versions", &self.available_versions)
            .field(
                "version_check_rx",
                &self.version_check_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field("version_check_busy", &self.version_check_busy)
            .field("geodata_summary", &self.geodata_summary)
            .field("geodata_ui", &self.geodata_ui)
            .field(
                "geodata_rx",
                &self.geodata_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field("warp_summary", &self.warp_summary)
            .field("warp_ui", &self.warp_ui)
            .field(
                "warp_rx",
                &self.warp_rx.as_ref().map(|_| "Some(Receiver)"),
            )
            .field("warp_generation", &self.warp_generation)
            .field("warp_preferred_tag", &self.warp_preferred_tag)
            .field("warp_pending_confirm", &self.warp_pending_confirm)
            .field("warp_proposed", &self.warp_proposed)
            .field("warp_routing_notice", &self.warp_routing_notice)
            .field("warp_ownership", &self.warp_ownership)
            .field("xray_logs_selected", &self.xray_logs.selected)
            .field("xray_logs_ui", &self.xray_logs.ui_state)
            .field("operation", &self.operation)
            .field("status_message_until", &self.status_message_until)
            .field("ssh_status", &self.ssh_status)
            .field("xray_status", &self.xray_status)
            .finish()
    }
}

impl ApplicationService {
    /// Creates a new application service with default MVP components.
    ///
    /// Loads `config.json` through [`ConfigManager`]. On load failure the
    /// service continues with in-memory defaults and logs the problem.
    ///
    /// The SSH client uses [`HostKeyPolicy::KnownHostsFile`] (never `AcceptAny`)
    /// and a 10-second connect timeout.
    pub fn new() -> Self {
        let config = match ConfigManager::load() {
            Ok(manager) => manager,
            Err(error) => {
                warn!(
                    target: "config",
                    error = %crate::logging::redact::sanitize_detail(&error.to_string()),
                    "failed to load application config; using defaults"
                );
                let path = ConfigManager::default_config_path().unwrap_or_else(|_| {
                    std::env::temp_dir().join("feldjaeger-fallback-config.json")
                });
                ConfigManager::with_defaults(path)
            }
        };

        let connection_draft = ConnectionDraft::from_stored(&config.config().connection);
        let ssh_client = RusshClient::with_options(RusshClientOptions {
            host_key_policy: HostKeyPolicy::KnownHostsFile(
                HostKeyPolicy::default_known_hosts_path(),
            ),
            connect_timeout: Duration::from_secs(10),
        });

        let service = Self {
            remote: RemoteAdmin::new(),
            xray: XrayManager::new("xray"),
            init: SystemdManager::new(),
            validator: DefaultConfigValidator::new(),
            config,
            ssh_client,
            connection_draft,
            connection_secrets: ConnectionSecrets::new(),
            connection_errors: ConnectionValidationErrors::default(),
            connection_test: ConnectionTestState::Idle,
            connection_test_rx: None,
            discovery: DiscoveryState::Idle,
            discovery_rx: None,
            loaded_config: LoadedConfigSnapshot::None,
            inbounds_sort: InboundsSort::by_index(),
            outbounds_sort: OutboundsSort::by_index(),
            outbounds_status_announced: false,
            dns_status_announced: false,
            fakedns_status_announced: false,
            observatory_status_announced: false,
            burst_observatory_status_announced: false,
            routing_sort: RoutingSort::by_index(),
            routing_status_announced: false,
            policy_sort: PolicySort::by_level(),
            policy_status_announced: false,
            selected_users_inbound_index: None,
            users_sort: UsersSort::by_index(),
            user_mutation_rx: None,
            inbound_shell_drafts: None,
            inbound_shell_rx: None,
            inbound_editor_session: None,
            share_materials: super::share_material::ShareMaterialStore::new(),
            inbound_mutation_rx: None,
            outbound_mutation_rx: None,
            outbound_editor_session: None,
            log_settings_draft: None,
            log_settings_error: None,
            log_settings_saved_flash: false,
            log_settings_rx: None,
            service_control: ServiceControlState::Idle,
            service_control_rx: None,
            service_state: None,
            unit_host_probe: None,
            unit_probe_rx: None,
            unit_apply_rx: None,
            unit_apply_busy: false,
            unit_apply_needs_restart_prompt: false,
            xray_lifecycle: XrayLifecycleState::Idle,
            xray_lifecycle_rx: None,
            install_channel: InstallChannel::Stable,
            available_versions: AvailableVersions::default(),
            version_check_rx: None,
            version_check_busy: false,
            geodata_summary: None,
            geodata_ui: GeoDataUiState::Idle,
            geodata_rx: None,
            warp_summary: None,
            warp_ui: WarpUiState::Idle,
            warp_rx: None,
            warp_generation: 0,
            warp_preferred_tag: default_preferred_tag(),
            warp_pending_confirm: None,
            warp_proposed: None,
            warp_routing_notice: None,
            warp_ownership: None,
            xray_logs: XrayLogsRuntime::default(),
            operation: CurrentOperation::Ready,
            status_message_until: None,
            ssh_status: SshStatus::Disconnected,
            xray_status: XrayStatus::unknown(),
        };
        service
    }

    /// Returns the remote administration facade.
    pub fn remote(&self) -> &RemoteAdmin {
        &self.remote
    }

    /// Hint for post-write `xray run -test` from the last successful discovery.
    fn config_validate_hint(&self) -> super::config_write::RemoteConfigValidateHint {
        match &self.discovery {
            DiscoveryState::Succeeded(installation) => {
                super::config_write::RemoteConfigValidateHint::from_installation(
                    installation.binary_path.as_ref(),
                    &installation.config_source,
                )
            }
            _ => super::config_write::RemoteConfigValidateHint::skip(),
        }
    }

    /// Returns the Xray manager.
    pub fn xray(&self) -> &XrayManager {
        &self.xray
    }

    /// Returns the init-system manager.
    pub fn init(&self) -> &SystemdManager {
        &self.init
    }

    /// Returns the configuration validator.
    pub fn validator(&self) -> &DefaultConfigValidator {
        &self.validator
    }

    /// Returns the loaded application configuration.
    pub fn app_config(&self) -> &AppConfig {
        self.config.config()
    }

    /// Returns UI preferences from the application configuration.
    pub fn ui_config(&self) -> &UiConfig {
        &self.config.config().ui
    }

    /// Returns the last saved non-secret connection profile.
    pub fn saved_connection_profile(&self) -> &StoredConnectionProfile {
        &self.config.config().connection
    }

    /// Returns the editable connection draft (non-secret fields).
    pub fn connection_draft(&self) -> &ConnectionDraft {
        &self.connection_draft
    }

    /// Returns a mutable connection draft for UI binding.
    pub fn connection_draft_mut(&mut self) -> &mut ConnectionDraft {
        &mut self.connection_draft
    }

    /// Returns in-memory connection secrets (never persisted).
    pub fn connection_secrets(&self) -> &ConnectionSecrets {
        &self.connection_secrets
    }

    /// Returns mutable connection secrets for UI binding.
    pub fn connection_secrets_mut(&mut self) -> &mut ConnectionSecrets {
        &mut self.connection_secrets
    }

    /// Returns the latest connection form validation errors.
    pub fn connection_errors(&self) -> &ConnectionValidationErrors {
        &self.connection_errors
    }

    /// Returns the connection test lifecycle state.
    pub fn connection_test_state(&self) -> &ConnectionTestState {
        &self.connection_test
    }

    /// Returns the Xray discovery lifecycle state.
    pub fn discovery_state(&self) -> &DiscoveryState {
        &self.discovery
    }

    /// Returns the last loaded remote configuration snapshot (read-only).
    pub fn loaded_config(&self) -> &LoadedConfigSnapshot {
        &self.loaded_config
    }

    /// Returns inbound summaries from the loaded configuration (may be empty).
    pub fn inbound_summaries(&self) -> &[InboundSummary] {
        self.loaded_config.inbounds()
    }

    /// Returns outbound summaries from the loaded configuration (may be empty).
    pub fn outbound_summaries(&self) -> &[OutboundSummary] {
        self.loaded_config.outbounds()
    }

    /// Returns the DNS summary from the loaded configuration, when present.
    pub fn dns_summary(&self) -> Option<&DnsSummary> {
        self.loaded_config.dns()
    }

    /// Returns the FakeDNS summary from the loaded configuration, when present.
    pub fn fakedns_summary(&self) -> Option<&FakeDnsSummary> {
        self.loaded_config.fakedns()
    }

    /// Returns the Observatory summary from the loaded configuration, when present.
    pub fn observatory_summary(&self) -> Option<&ObservatorySummary> {
        self.loaded_config.observatory()
    }

    /// Returns the Burst Observatory summary when present.
    pub fn burst_observatory_summary(&self) -> Option<&BurstObservatorySummary> {
        self.loaded_config.burst_observatory()
    }

    /// Returns the routing summary from the loaded configuration, when present.
    pub fn routing_summary(&self) -> Option<&RoutingSummary> {
        self.loaded_config.routing()
    }

    /// Returns the policy summary from the loaded configuration, when present.
    pub fn policy_summary(&self) -> Option<&PolicySummary> {
        self.loaded_config.policy()
    }

    /// Returns VLESS / user summaries from the loaded configuration.
    pub fn vless_client_summaries(&self) -> &[VlessClientSummary] {
        self.loaded_config.vless_clients()
    }

    /// Alias for [`Self::vless_client_summaries`].
    pub fn user_summaries(&self) -> &[UserSummary] {
        self.vless_client_summaries()
    }

    /// Builds the read-only Inbounds page model for the GUI.
    pub fn inbounds_page_model(&self) -> InboundsPageModel {
        build_inbounds_page_model(
            self.ssh_status,
            &self.discovery,
            &self.loaded_config,
            self.inbounds_sort,
        )
    }

    /// Builds the read-only Outbounds page model for the GUI.
    pub fn outbounds_page_model(&self) -> OutboundsPageModel {
        build_outbounds_page_model(
            self.ssh_status,
            &self.discovery,
            &self.loaded_config,
            self.outbounds_sort,
        )
    }

    /// Builds the read-only DNS page model for the GUI.
    pub fn dns_page_model(&self) -> DnsPageModel {
        build_dns_page_model(self.ssh_status, &self.discovery, &self.loaded_config)
    }

    /// Builds the read-only FakeDNS page model for the GUI.
    pub fn fakedns_page_model(&self) -> FakeDnsPageModel {
        build_fakedns_page_model(self.ssh_status, &self.discovery, &self.loaded_config)
    }

    /// Builds the read-only Observatory page model for the GUI.
    pub fn observatory_page_model(&self) -> ObservatoryPageModel {
        build_observatory_page_model(self.ssh_status, &self.discovery, &self.loaded_config)
    }

    /// Builds the read-only Burst Observatory page model.
    pub fn burst_observatory_page_model(&self) -> BurstObservatoryPageModel {
        build_burst_observatory_page_model(self.ssh_status, &self.discovery, &self.loaded_config)
    }

    /// Builds the read-only Routing page model for the GUI.
    pub fn routing_page_model(&self) -> RoutingPageModel {
        build_routing_page_model(
            self.ssh_status,
            &self.discovery,
            &self.loaded_config,
            self.routing_sort,
        )
    }

    /// Builds the read-only Policy page model for the GUI.
    pub fn policy_page_model(&self) -> PolicyPageModel {
        build_policy_page_model(
            self.ssh_status,
            &self.discovery,
            &self.loaded_config,
            self.policy_sort,
        )
    }

    /// Builds the read-only Users page model for the GUI.
    pub fn users_page_model(&self) -> UsersPageModel {
        build_users_page_model(
            self.ssh_status,
            &self.discovery,
            &self.loaded_config,
            self.selected_users_inbound_index,
            self.users_sort,
        )
    }

    /// Selects which inbound the Inbounds detail / Users tab should display.
    pub fn set_selected_users_inbound(&mut self, inbound_index: usize) {
        if self.selected_users_inbound_index != Some(inbound_index) {
            self.clear_shell_drafts();
        }
        self.selected_users_inbound_index = Some(inbound_index);
    }

    /// Currently selected inbound index for the Inbounds Users tab, if any.
    pub fn selected_users_inbound(&self) -> Option<usize> {
        self.selected_users_inbound_index
    }

    /// Clears General/Sniffing shell drafts (selection change, mutate success, conflict).
    pub fn clear_shell_drafts(&mut self) {
        self.inbound_shell_drafts = None;
        self.inbound_editor_session = None;
    }

    /// Borrowed shell edit drafts, if any.
    pub fn inbound_shell_drafts(&self) -> Option<&InboundShellDrafts> {
        self.inbound_shell_drafts.as_ref()
    }

    /// Mutable shell edit drafts (General/Sniffing forms).
    pub fn inbound_shell_drafts_mut(&mut self) -> Option<&mut InboundShellDrafts> {
        self.inbound_shell_drafts.as_mut()
    }

    // ─── IB-L1 editor session accessors ──────────────────────────────────────

    /// Borrowed IB-L1 editor session, if any.
    pub fn inbound_editor_session(&self) -> Option<&InboundEditorSession> {
        self.inbound_editor_session.as_ref()
    }

    /// Mutable IB-L1 editor session for direct form binding.
    pub fn inbound_editor_session_mut(&mut self) -> Option<&mut InboundEditorSession> {
        self.inbound_editor_session.as_mut()
    }

    /// Returns `true` when the editor session has unsaved dirty state that blocks Users.
    pub fn users_blocked_by_dirty_shell(&self) -> Option<&'static str> {
        match &self.inbound_editor_session {
            Some(s) if !s.is_add && s.dirty => {
                Some("Save or cancel the inbound shell edits before managing users.")
            }
            _ => None,
        }
    }

    /// Opens an IB-L1 edit session for an existing inbound (Shell Save flow).
    pub fn begin_edit_inbound_shell(&mut self, inbound_index: usize) -> Result<(), String> {
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let inbound_ref = self.build_inbound_ref(inbound_index)?;
        let protocol = inbound_ref.protocol;
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?;
        let inbound_value = editable
            .sections()
            .inbounds()
            .get(inbound_index)
            .ok_or_else(|| "Inbound not found.".to_owned())?
            .value()
            .clone();
        let general = parse_inbound_general(&inbound_value);
        let proto_draft = parse_inbound_protocol(&inbound_value)
            .ok_or_else(|| "Protocol not supported for shell edit.".to_owned())?;
        let stream = parse_inbound_stream(&inbound_value);
        let sniffing = parse_sniffing_settings(&inbound_value);
        let security = match protocol {
            InboundClientProtocol::Vless
            | InboundClientProtocol::Trojan
            | InboundClientProtocol::Hysteria => Some(parse_inbound_security(&inbound_value)),
            InboundClientProtocol::Tunnel => None,
        };
        let vision_active = crate::xray::vision_active_from_inbound(&inbound_value);
        let material = self
            .share_materials
            .get(general.tag.as_deref(), inbound_index)
            .cloned();
        self.inbound_editor_session = Some(InboundEditorSession {
            inbound_index,
            inbound_ref: Some(inbound_ref),
            general,
            protocol: proto_draft,
            stream,
            sniffing,
            security,
            is_add: false,
            ephemeral_public_key: material.as_ref().and_then(|m| m.public_key.clone()),
            ephemeral_mldsa65_verify: material.as_ref().and_then(|m| m.mldsa65_verify.clone()),
            ephemeral_client_encryption: material.and_then(|m| m.client_encryption),
            vlessenc_auth: crate::xray::VlessEncAuthKind::default(),
            dirty: false,
            diff_preview: None,
            vision_active,
        });
        Ok(())
    }

    /// Opens an IB-L1 session for adding a new inbound.
    pub fn begin_add_inbound(&mut self, protocol: InboundClientProtocol) -> Result<(), String> {
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let proto_draft = match protocol {
            InboundClientProtocol::Vless => InboundProtocolDraft::vless_default(),
            InboundClientProtocol::Trojan => InboundProtocolDraft::trojan_default(),
            InboundClientProtocol::Hysteria => InboundProtocolDraft::hysteria_default(),
            InboundClientProtocol::Tunnel => InboundProtocolDraft::tunnel_default(),
        };
        let security = match protocol {
            InboundClientProtocol::Vless => Some(InboundSecurityDraft {
                mode: InboundSecurityMode::None,
                ..Default::default()
            }),
            InboundClientProtocol::Trojan => Some(InboundSecurityDraft {
                mode: InboundSecurityMode::Reality,
                ..Default::default()
            }),
            InboundClientProtocol::Hysteria => Some(InboundSecurityDraft {
                mode: InboundSecurityMode::Tls,
                ..Default::default()
            }),
            InboundClientProtocol::Tunnel => None,
        };
        let stream = match protocol {
            InboundClientProtocol::Hysteria => InboundStreamDraft {
                method: Some(StreamMethod::Hysteria),
                hysteria: crate::xray::config::HysteriaStreamSettings {
                    version: Some(2),
                    ..Default::default()
                },
                ..Default::default()
            },
            InboundClientProtocol::Tunnel => InboundStreamDraft {
                method: Some(StreamMethod::Tcp),
                ..Default::default()
            },
            _ => InboundStreamDraft::default(),
        };
        self.inbound_editor_session = Some(InboundEditorSession {
            inbound_index: usize::MAX,
            inbound_ref: None,
            general: InboundGeneral {
                tag: None,
                listen: Some("0.0.0.0".to_owned()),
                port: None,
            },
            protocol: proto_draft,
            stream,
            sniffing: SniffingSettings::default(),
            security,
            is_add: true,
            ephemeral_public_key: None,
            ephemeral_mldsa65_verify: None,
            ephemeral_client_encryption: None,
            vlessenc_auth: crate::xray::VlessEncAuthKind::default(),
            dirty: false,
            diff_preview: None,
            vision_active: false,
        });
        Ok(())
    }

    /// Cancels the IB-L1 editor session.
    pub fn cancel_inbound_editor_session(&mut self) {
        self.retain_share_material_from_session();
        self.schedule_share_material_persist();
        self.inbound_editor_session = None;
    }

    /// Persists ephemeral PublicKey / client encryption before session clear.
    fn retain_share_material_from_session(&mut self) {
        let Some(session) = &self.inbound_editor_session else {
            return;
        };
        if session.is_add {
            return;
        }
        let tag = session.general.tag.as_deref();
        self.share_materials.retain_from_session(
            tag,
            session.inbound_index,
            session.ephemeral_public_key.as_deref(),
            session.ephemeral_client_encryption.as_deref(),
            session.ephemeral_mldsa65_verify.as_deref(),
        );
    }

    /// Fire-and-forget remote write of the share-material sidecar.
    fn schedule_share_material_persist(&mut self) {
        let Some(path) = (match &self.discovery {
            DiscoveryState::Succeeded(installation) => {
                super::share_material::share_sidecar_path(&installation.config_source)
            }
            _ => None,
        }) else {
            return;
        };
        let bytes = match self.share_materials.to_json_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(
                    target: "app",
                    detail = %crate::logging::redact::sanitize_detail(&error),
                    "share material serialize failed"
                );
                return;
            }
        };
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => profile,
                Err(_) => return,
            };
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let store_len = self.share_materials.len();
        let path_str = path.as_str().to_owned();
        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => return,
            };
            runtime.block_on(async {
                let request = build_connect_request(&profile, &secrets);
                let session = match client.connect(&request).await {
                    Ok(session) => session,
                    Err(error) => {
                        warn!(
                            target: "app",
                            detail = %crate::logging::redact::sanitize_detail(error.message()),
                            "share material persist connect failed"
                        );
                        return;
                    }
                };
                let write_result = session.write_file_atomic(&path, &bytes).await;
                let _ = session.disconnect().await;
                match write_result {
                    Ok(()) => {
                        info!(
                            target: "app",
                            path = %path_str,
                            entries = store_len,
                            "share material sidecar written"
                        );
                    }
                    Err(error) => {
                        warn!(
                            target: "app",
                            path = %path_str,
                            detail = %crate::logging::redact::sanitize_detail(error.message()),
                            "share material sidecar write failed"
                        );
                    }
                }
            });
        });
    }

    /// Retained client-side crypto for an inbound (PublicKey, encryption, mldsa65Verify).
    pub fn inbound_share_material(
        &self,
        tag: Option<&str>,
        inbound_index: usize,
    ) -> Option<&super::share_material::InboundShareMaterial> {
        self.share_materials.get(tag, inbound_index)
    }

    /// Dry-runs Shell Save / Add and stores a redacted JSON diff preview (IB-L5).
    pub fn preview_inbound_shell_diff(&mut self) -> Result<(), String> {
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?
            .clone();
        let session = self
            .inbound_editor_session
            .as_ref()
            .ok_or_else(|| "Not editing an inbound.".to_owned())?;

        let outcome = if session.is_add {
            let protocol = match &session.protocol {
                InboundProtocolDraft::Vless { .. } => InboundClientProtocol::Vless,
                InboundProtocolDraft::Trojan { .. } => InboundClientProtocol::Trojan,
                InboundProtocolDraft::Hysteria { .. } => InboundClientProtocol::Hysteria,
                InboundProtocolDraft::Tunnel { .. } => InboundClientProtocol::Tunnel,
            };
            let request = AddInboundRequest {
                protocol,
                general: session.general.clone(),
                protocol_draft: session.protocol.clone(),
                stream: session.stream.clone(),
                sniffing: session.sniffing.clone(),
                security: session.security.clone(),
                preferred_source_file: None,
            };
            let mut editable = editable;
            add_inbound(&mut editable, request).map_err(|e| e.message())?
        } else {
            let inbound_ref = session
                .inbound_ref
                .clone()
                .ok_or_else(|| "Missing inbound ref.".to_owned())?;
            let request = UpdateInboundShellRequest {
                inbound_ref,
                general: session.general.clone(),
                protocol: session.protocol.clone(),
                stream: session.stream.clone(),
                sniffing: session.sniffing.clone(),
                security: session.security.clone(),
            };
            let mut editable = editable;
            let (outcome, _) =
                update_inbound_shell(&mut editable, request).map_err(|e| e.message())?;
            outcome
        };

        let entries = crate::xray::redacted_json_diff_bytes(
            &outcome.original_serialized,
            &outcome.serialized,
        );
        if let Some(session) = &mut self.inbound_editor_session {
            session.diff_preview = Some(entries);
        }
        Ok(())
    }

    /// Builds a `vless://` / `trojan://` share URI for one client (clipboard-ready).
    ///
    /// Reality PublicKey is taken from Generate ephemerals / retained store, or
    /// derived locally from `realitySettings.privateKey`. VLESS client encryption
    /// still requires Generate when inbound `decryption` is not `none`.
    pub fn build_client_share_uri(
        &mut self,
        inbound_index: usize,
        client_index: usize,
    ) -> Result<String, String> {
        use crate::xray::{
            ShareProtocol, ShareSecurity, ShareTransport, ShareUriRequest, StreamMethod,
            build_share_uri, parse_inbound_protocol, parse_inbound_security, parse_inbound_stream,
            public_key_from_private_key,
        };

        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?;
        let inbound = editable
            .sections()
            .inbounds()
            .get(inbound_index)
            .ok_or_else(|| "Inbound not found.".to_owned())?;
        let inbound_value = inbound.value();
        let protocol = inbound_value
            .get("protocol")
            .and_then(|v| v.as_str())
            .and_then(InboundClientProtocol::from_wire)
            .ok_or_else(|| "Unsupported inbound protocol for share URI.".to_owned())?;

        let client = editable
            .client_object(inbound_index, client_index)
            .map_err(|e| e.message())?;

        let (share_protocol, user_id, flow) = match protocol {
            InboundClientProtocol::Vless => {
                let id = client
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "Client UUID is empty.".to_owned())?
                    .to_owned();
                let flow = client
                    .get("flow")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned);
                (ShareProtocol::Vless, id, flow)
            }
            InboundClientProtocol::Trojan => {
                let password = client
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "Client password is empty.".to_owned())?
                    .to_owned();
                (ShareProtocol::Trojan, password, None)
            }
            InboundClientProtocol::Hysteria => {
                let auth = client
                    .get("auth")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "Hysteria auth is empty.".to_owned())?
                    .to_owned();
                (ShareProtocol::Hysteria, auth, None)
            }
            InboundClientProtocol::Tunnel => {
                return Err("Share URI is not available for Tunnel inbounds.".to_owned());
            }
        };

        let address = self.connection_draft.host.trim().to_owned();
        if address.is_empty() {
            return Err("Connection host is empty.".to_owned());
        }

        let port = self
            .loaded_config
            .inbounds()
            .get(inbound_index)
            .and_then(|row| row.port)
            .or_else(|| {
                self.inbound_editor_session
                    .as_ref()
                    .filter(|s| !s.is_add && s.inbound_index == inbound_index)
                    .and_then(|s| s.general.port)
            })
            .ok_or_else(|| "Inbound port is missing.".to_owned())?;

        let remark = client
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                inbound_value
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            });

        // Prefer live editor drafts when editing this inbound.
        let (security_draft, stream_draft, protocol_draft, session_pk, session_enc, session_pqv) =
            if let Some(session) = self
                .inbound_editor_session
                .as_ref()
                .filter(|s| !s.is_add && s.inbound_index == inbound_index)
            {
                (
                    session.security.clone(),
                    session.stream.clone(),
                    Some(session.protocol.clone()),
                    session.ephemeral_public_key.clone(),
                    session.ephemeral_client_encryption.clone(),
                    session.ephemeral_mldsa65_verify.clone(),
                )
            } else {
                (
                    Some(parse_inbound_security(inbound_value)),
                    parse_inbound_stream(inbound_value),
                    parse_inbound_protocol(inbound_value),
                    None,
                    None,
                    None,
                )
            };

        let tag = inbound_value
            .get("tag")
            .and_then(|v| v.as_str())
            .or_else(|| {
                self.inbound_editor_session
                    .as_ref()
                    .and_then(|s| s.general.tag.as_deref())
            });
        let stored = self.share_materials.get(tag, inbound_index);
        let mut public_key = session_pk
            .or_else(|| stored.and_then(|m| m.public_key.clone()))
            .filter(|s| !s.trim().is_empty());
        let client_encryption = session_enc
            .or_else(|| stored.and_then(|m| m.client_encryption.clone()))
            .filter(|s| !s.trim().is_empty());
        let mldsa65_verify = session_pqv
            .or_else(|| stored.and_then(|m| m.mldsa65_verify.clone()))
            .filter(|s| !s.trim().is_empty());

        if public_key.is_none() {
            if let Some(private_key) = security_draft
                .as_ref()
                .map(|s| s.reality.private_key.trim())
                .filter(|s| !s.is_empty())
            {
                match public_key_from_private_key(private_key) {
                    Ok(derived) => {
                        self.share_materials.merge(
                            tag,
                            inbound_index,
                            Some(derived.clone()),
                            None,
                            None,
                        );
                        public_key = Some(derived);
                    }
                    Err(detail) => return Err(detail),
                }
            }
        }

        let mode = security_draft
            .as_ref()
            .map(|s| s.mode)
            .unwrap_or(InboundSecurityMode::None);
        let security = match mode {
            InboundSecurityMode::Reality => {
                let reality = &security_draft
                    .as_ref()
                    .ok_or_else(|| "Reality settings missing.".to_owned())?
                    .reality;
                let pbk = public_key.ok_or_else(|| {
                    "Reality PublicKey is missing. Generate x25519 on the Security tab first."
                        .to_owned()
                })?;
                let short_id = if let Some(sid) = reality
                    .short_ids
                    .iter()
                    .map(|s| s.trim())
                    .find(|s| !s.is_empty())
                {
                    sid.to_owned()
                } else if !reality.short_ids.is_empty() {
                    String::new()
                } else {
                    return Err("Reality shortIds is empty.".to_owned());
                };
                let server_name = reality
                    .server_names
                    .iter()
                    .map(|s| s.trim())
                    .find(|s| !s.is_empty())
                    .ok_or_else(|| "Reality serverNames is empty.".to_owned())?
                    .to_owned();
                ShareSecurity::Reality {
                    public_key: pbk,
                    short_id,
                    server_name,
                    fingerprint: "chrome".to_owned(),
                    spider_x: "/".to_owned(),
                    mldsa65_verify,
                }
            }
            InboundSecurityMode::Tls => {
                let server_name = security_draft.as_ref().and_then(|s| {
                    let name = s.tls.server_name.trim();
                    if name.is_empty() {
                        None
                    } else {
                        Some(name.to_owned())
                    }
                });
                ShareSecurity::Tls {
                    server_name,
                    insecure: false,
                }
            }
            InboundSecurityMode::None => {
                if matches!(
                    protocol,
                    InboundClientProtocol::Trojan | InboundClientProtocol::Hysteria
                ) {
                    return Err(
                        "Share URI requires TLS or Reality. Configure Security first.".to_owned(),
                    );
                }
                ShareSecurity::None
            }
        };

        if matches!(
            stream_draft.method,
            Some(StreamMethod::Ws) | Some(StreamMethod::Mkcp)
        ) && !matches!(mode, InboundSecurityMode::Tls)
        {
            return Err(match stream_draft.method {
                Some(StreamMethod::Mkcp) => {
                    "mKCP share requires TLS. Configure Security → tls first.".to_owned()
                }
                _ => "WebSocket share requires TLS. Configure Security → tls first.".to_owned(),
            });
        }

        let transport = match stream_draft.method {
            Some(StreamMethod::Tcp) => ShareTransport::Tcp,
            Some(StreamMethod::Xhttp) => {
                use crate::xray::xhttp_extra_json;
                let path = {
                    let path = stream_draft.xhttp.path().trim();
                    if path.is_empty() {
                        "/".to_owned()
                    } else {
                        path.to_owned()
                    }
                };
                let host = {
                    let host = stream_draft.xhttp.host().trim();
                    if host.is_empty() {
                        None
                    } else {
                        Some(host.to_owned())
                    }
                };
                let mode = {
                    let mode = stream_draft.xhttp.mode().trim();
                    if mode.is_empty() {
                        None
                    } else {
                        Some(mode.to_owned())
                    }
                };
                ShareTransport::Xhttp {
                    path,
                    host,
                    mode,
                    extra: xhttp_extra_json(&stream_draft.xhttp),
                }
            }
            Some(StreamMethod::Grpc) => ShareTransport::Grpc {
                service_name: stream_draft.grpc.service_name.clone(),
            },
            Some(StreamMethod::Ws) => {
                use crate::xray::join_ws_path_and_ed;
                let path = join_ws_path_and_ed(&stream_draft.ws.path, stream_draft.ws.ed);
                let path = if path.is_empty() {
                    "/".to_owned()
                } else {
                    path
                };
                let host = {
                    let host = stream_draft.ws.host.trim();
                    if host.is_empty() {
                        None
                    } else {
                        Some(host.to_owned())
                    }
                };
                ShareTransport::Ws { path, host }
            }
            Some(StreamMethod::Mkcp) => ShareTransport::Kcp,
            Some(StreamMethod::Hysteria) => ShareTransport::Tcp, // unused for hy2 builder
            None if stream_draft.other_method.is_none() => ShareTransport::Tcp,
            None => {
                return Err(format!(
                    "Share URI does not support stream method '{}'.",
                    stream_draft.other_method.as_deref().unwrap_or("unknown")
                ));
            }
        };

        let encryption = match protocol {
            InboundClientProtocol::Vless => {
                let decryption = match &protocol_draft {
                    Some(InboundProtocolDraft::Vless { decryption, .. }) => decryption.trim(),
                    _ => "none",
                };
                if decryption.is_empty() || decryption == "none" {
                    "none".to_owned()
                } else {
                    client_encryption.ok_or_else(|| {
                        "VLESS client encryption is missing. Generate vlessenc on the Protocol tab first."
                            .to_owned()
                    })?
                }
            }
            _ => "none".to_owned(),
        };

        let request = ShareUriRequest {
            protocol: share_protocol,
            user_id,
            address,
            port,
            remark,
            flow,
            encryption,
            security,
            transport,
        };
        build_share_uri(&request).map_err(|e| e.detail().to_owned())
    }

    /// Refreshes the fingerprint in the editor session after a users mutation.
    ///
    /// Must NOT clear the session. Called after successful user Add/Update/Delete.
    pub fn refresh_editor_fingerprint(&mut self) {
        let Some(session) = &self.inbound_editor_session else {
            return;
        };
        if session.is_add {
            return;
        }
        let inbound_index = session.inbound_index;
        match self.build_inbound_ref(inbound_index) {
            Ok(new_ref) => {
                if let Some(s) = &mut self.inbound_editor_session {
                    s.inbound_ref = Some(new_ref);
                }
            }
            Err(_) => {
                // Inbound no longer findable — discard session to avoid stale fingerprint.
                self.inbound_editor_session = None;
            }
        }
    }

    /// Saves the IB-L1 editor session via unified Shell Save.
    pub fn start_save_inbound_shell(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let (inbound_ref, general, protocol, stream, sniffing, security) = {
            let session = self
                .inbound_editor_session
                .as_ref()
                .ok_or_else(|| "Not editing an inbound.".to_owned())?;
            if session.is_add {
                return Err("Use start_add_inbound for Add mode.".to_owned());
            }
            let inbound_ref = session
                .inbound_ref
                .clone()
                .ok_or_else(|| "Missing inbound ref.".to_owned())?;
            (
                inbound_ref,
                session.general.clone(),
                session.protocol.clone(),
                session.stream.clone(),
                session.sniffing.clone(),
                session.security.clone(),
            )
        };
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?
            .clone();
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let request = UpdateInboundShellRequest {
            inbound_ref,
            general,
            protocol,
            stream,
            sniffing,
            security,
        };
        let (tx, rx) = mpsc::channel();
        self.inbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::UpdatingInboundShell;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();
        info!(target: "app", "starting inbound shell save");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime.block_on(run_update_inbound_shell(
                &client,
                &profile,
                &secrets,
                &remote,
                editable,
                request,
                validate_hint,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Submits an Add Inbound request from the editor session.
    pub fn start_add_inbound(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let (protocol, general, protocol_draft, stream, sniffing, security) = {
            let session = self
                .inbound_editor_session
                .as_ref()
                .ok_or_else(|| "No Add session active.".to_owned())?;
            if !session.is_add {
                return Err("Use start_save_inbound_shell for Edit mode.".to_owned());
            }
            let protocol = match &session.protocol {
                InboundProtocolDraft::Vless { .. } => InboundClientProtocol::Vless,
                InboundProtocolDraft::Trojan { .. } => InboundClientProtocol::Trojan,
                InboundProtocolDraft::Hysteria { .. } => InboundClientProtocol::Hysteria,
                InboundProtocolDraft::Tunnel { .. } => InboundClientProtocol::Tunnel,
            };
            (
                protocol,
                session.general.clone(),
                session.protocol.clone(),
                session.stream.clone(),
                session.sniffing.clone(),
                session.security.clone(),
            )
        };
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?
            .clone();
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let preferred_source_file = editable.primary_source_file().map(str::to_owned);
        let request = AddInboundRequest {
            protocol,
            general,
            protocol_draft,
            stream,
            sniffing,
            security,
            preferred_source_file,
        };
        let (tx, rx) = mpsc::channel();
        self.inbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::AddingInbound;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();
        info!(target: "app", "starting add inbound");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime.block_on(run_add_inbound(
                &client,
                &profile,
                &secrets,
                &remote,
                editable,
                request,
                validate_hint,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Deletes an inbound by merged index (any protocol; fingerprint + routing refs).
    pub fn start_delete_inbound(&mut self, inbound_index: usize) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?
            .clone();
        let _ = editable
            .locate_inbound(inbound_index)
            .map_err(|error| error.message())?;
        let expected_fingerprint = editable
            .inbound_object_fingerprint(inbound_index)
            .map_err(|error| error.message())?;
        let request = DeleteInboundRequest {
            inbound_index,
            expected_fingerprint: Some(expected_fingerprint),
        };
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let (tx, rx) = mpsc::channel();
        self.inbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::DeletingInbound;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();
        info!(target: "app", inbound_index, "starting delete inbound");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime.block_on(run_delete_inbound(
                &client,
                &profile,
                &secrets,
                &remote,
                editable,
                request,
                validate_hint,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Deletes an outbound by merged index (any protocol; fingerprint + routing refs).
    pub fn start_delete_outbound(&mut self, outbound_index: usize) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?
            .clone();
        let _ = editable
            .locate_outbound(outbound_index)
            .map_err(|error| error.message())?;
        let expected_fingerprint = editable
            .outbound_object_fingerprint(outbound_index)
            .map_err(|error| error.message())?;
        let request = crate::xray::DeleteOutboundRequest {
            outbound_index,
            expected_fingerprint: Some(expected_fingerprint),
        };
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let (tx, rx) = mpsc::channel();
        self.outbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::DeletingOutbound;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();
        info!(target: "app", outbound_index, "starting delete outbound");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime.block_on(super::outbound_ops::run_delete_outbound(
                &client,
                &profile,
                &secrets,
                &remote,
                editable,
                request,
                validate_hint,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    // ─── Outbound Shell (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95) ───────

    /// Returns the current outbound editor session, if any.
    pub fn outbound_editor_session(&self) -> Option<&super::outbound_ops::OutboundEditorSession> {
        self.outbound_editor_session.as_ref()
    }

    /// Returns the current outbound editor session, mutably.
    pub fn outbound_editor_session_mut(
        &mut self,
    ) -> Option<&mut super::outbound_ops::OutboundEditorSession> {
        self.outbound_editor_session.as_mut()
    }

    /// Cancels the outbound editor session.
    pub fn cancel_outbound_editor_session(&mut self) {
        self.outbound_editor_session = None;
    }

    /// Opens an Add session for a new Freedom outbound.
    pub fn begin_add_outbound_freedom(&mut self) -> Result<(), String> {
        self.begin_add_outbound(OutboundSettingsDraft::freedom_default())
    }

    /// Opens an Add session for a new Blackhole outbound.
    pub fn begin_add_outbound_blackhole(&mut self) -> Result<(), String> {
        self.begin_add_outbound(OutboundSettingsDraft::blackhole_default())
    }

    fn begin_add_outbound(&mut self, settings: OutboundSettingsDraft) -> Result<(), String> {
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        self.outbound_editor_session = Some(super::outbound_ops::OutboundEditorSession {
            outbound_index: usize::MAX,
            outbound_ref: None,
            general: OutboundGeneral {
                tag: None,
                send_through: None,
            },
            settings,
            is_add: true,
        });
        Ok(())
    }

    /// Opens a Shell Save session for an existing shell-editable outbound (Freedom, Blackhole).
    pub fn begin_edit_outbound_shell(&mut self, outbound_index: usize) -> Result<(), String> {
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let outbound_ref = self.build_outbound_ref(outbound_index)?;
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?;
        let outbound_value = editable
            .sections()
            .outbounds()
            .get(outbound_index)
            .ok_or_else(|| "Outbound not found.".to_owned())?
            .value()
            .clone();
        let settings = parse_outbound_settings(&outbound_value)
            .ok_or_else(|| "Protocol not supported for shell edit.".to_owned())?;
        let general = parse_outbound_general(&outbound_value);
        self.outbound_editor_session = Some(super::outbound_ops::OutboundEditorSession {
            outbound_index,
            outbound_ref: Some(outbound_ref),
            general,
            settings,
            is_add: false,
        });
        Ok(())
    }

    fn build_outbound_ref(&self, outbound_index: usize) -> Result<OutboundRef, String> {
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?;
        let _ = editable
            .locate_outbound(outbound_index)
            .map_err(|error| error.message())?;
        let protocol = editable
            .sections()
            .outbounds()
            .get(outbound_index)
            .and_then(|outbound| outbound.value().get("protocol"))
            .and_then(|value| value.as_str())
            .map(str::to_ascii_lowercase);
        if !protocol.as_deref().is_some_and(is_shell_editable_protocol) {
            return Err("Shell editing is not supported for this outbound protocol.".to_owned());
        }
        let expected_fingerprint = editable
            .outbound_object_fingerprint(outbound_index)
            .map_err(|error| error.message())?;
        Ok(OutboundRef {
            outbound_index,
            expected_fingerprint,
        })
    }

    /// Submits an Add Outbound request from the editor session.
    pub fn start_add_outbound_shell(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let (general, settings) = {
            let session = self
                .outbound_editor_session
                .as_ref()
                .ok_or_else(|| "No Add session active.".to_owned())?;
            if !session.is_add {
                return Err("Use start_save_outbound_shell for Edit mode.".to_owned());
            }
            (session.general.clone(), session.settings.clone())
        };
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?
            .clone();
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let preferred_source_file = editable.primary_source_file().map(str::to_owned);
        let request = AddOutboundShellRequest {
            general,
            settings,
            preferred_source_file,
        };
        let (tx, rx) = mpsc::channel();
        self.outbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::AddingOutbound;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();
        info!(target: "app", "starting add outbound");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime.block_on(super::outbound_ops::run_add_outbound_shell(
                &client,
                &profile,
                &secrets,
                &remote,
                editable,
                request,
                validate_hint,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Submits a Shell Save request from the editor session.
    pub fn start_save_outbound_shell(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let (outbound_ref, general, settings) = {
            let session = self
                .outbound_editor_session
                .as_ref()
                .ok_or_else(|| "Not editing an outbound.".to_owned())?;
            if session.is_add {
                return Err("Use start_add_outbound_shell for Add mode.".to_owned());
            }
            let outbound_ref = session
                .outbound_ref
                .clone()
                .ok_or_else(|| "Missing outbound ref.".to_owned())?;
            (outbound_ref, session.general.clone(), session.settings.clone())
        };
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?
            .clone();
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let request = UpdateOutboundShellRequest {
            outbound_ref,
            general,
            settings,
        };
        let (tx, rx) = mpsc::channel();
        self.outbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::UpdatingOutboundShell;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();
        info!(target: "app", "starting outbound shell save");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime.block_on(super::outbound_ops::run_update_outbound_shell(
                &client,
                &profile,
                &secrets,
                &remote,
                editable,
                request,
                validate_hint,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Duplicates a shell-editable inbound (unique tag, same source file).
    pub fn start_duplicate_inbound(&mut self, inbound_index: usize) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        if !self.inbound_shell_edit_enabled(inbound_index) {
            return Err(
                "Duplicate is available for VLESS, Trojan, Hysteria, and Tunnel only."
                    .to_owned(),
            );
        }
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?
            .clone();
        let request = DuplicateInboundRequest { inbound_index };
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let (tx, rx) = mpsc::channel();
        self.inbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::DuplicatingInbound;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();
        info!(target: "app", inbound_index, "starting duplicate inbound");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime.block_on(run_duplicate_inbound(
                &client,
                &profile,
                &secrets,
                &remote,
                editable,
                request,
                validate_hint,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Starts remote x25519 keygen for the active Reality editor session.
    pub fn start_generate_x25519(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let binary_path = match &self.discovery {
            DiscoveryState::Succeeded(installation) => installation
                .binary_path
                .as_ref()
                .map(|p| p.as_str())
                .unwrap_or("/usr/local/bin/xray")
                .to_owned(),
            _ => return Err("Xray not discovered; cannot run keygen.".to_owned()),
        };
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let (tx, rx) = mpsc::channel();
        self.inbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::GeneratingX25519;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        info!(target: "app", "starting x25519 keygen");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime
                .block_on(run_generate_x25519(&client, &profile, &secrets, binary_path));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Starts remote mldsa65 keygen for the active Reality editor session.
    pub fn start_generate_mldsa65(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let binary_path = match &self.discovery {
            DiscoveryState::Succeeded(installation) => installation
                .binary_path
                .as_ref()
                .map(|p| p.as_str())
                .unwrap_or("/usr/local/bin/xray")
                .to_owned(),
            _ => return Err("Xray not discovered; cannot run keygen.".to_owned()),
        };
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let (tx, rx) = mpsc::channel();
        self.inbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::GeneratingMldsa65;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        info!(target: "app", "starting mldsa65 keygen");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime
                .block_on(run_generate_mldsa65(&client, &profile, &secrets, binary_path));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Starts remote `xray vlessenc` for the active VLESS Protocol draft.
    pub fn start_generate_vlessenc(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let session = self
            .inbound_editor_session
            .as_ref()
            .ok_or_else(|| "No inbound editor session.".to_owned())?;
        if !matches!(session.protocol, InboundProtocolDraft::Vless { .. }) {
            return Err("vlessenc is only available for VLESS.".to_owned());
        }
        let auth = session.vlessenc_auth;
        let binary_path = match &self.discovery {
            DiscoveryState::Succeeded(installation) => installation
                .binary_path
                .as_ref()
                .map(|p| p.as_str())
                .unwrap_or("/usr/local/bin/xray")
                .to_owned(),
            _ => return Err("Xray not discovered; cannot run vlessenc.".to_owned()),
        };
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(p) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    p
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };
        let (tx, rx) = mpsc::channel();
        self.inbound_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = CurrentOperation::GeneratingVlessEnc;
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        info!(target: "app", "starting vlessenc");
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let outcome = runtime.block_on(run_generate_vlessenc(
                &client,
                &profile,
                &secrets,
                binary_path,
                auth,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Polls for a completed IB-L1 mutation (Shell / Add / GenerateX25519 / Mldsa65 / VlessEnc).
    pub fn poll_inbound_mutation(&mut self) {
        let Some(rx) = &self.inbound_mutation_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(outcome) => {
                self.inbound_mutation_rx = None;
                self.operation = CurrentOperation::Ready;
                match outcome.result {
                    Ok(InboundMutationSuccess::Shell { editable, wrote_remote }) => {
                        self.retain_share_material_from_session();
                        self.schedule_share_material_persist();
                        self.replace_loaded_editable(editable);
                        self.inbound_editor_session = None;
                        if wrote_remote {
                            self.show_status_message(
                                "Inbound saved. Configuration updated. Xray restart required.",
                            );
                        } else {
                            self.show_status_message("Inbound saved (no remote change required).");
                        }
                    }
                    Ok(InboundMutationSuccess::Add { editable }) => {
                        let captured = self.inbound_editor_session.as_ref().map(|s| {
                            (
                                s.general.tag.clone(),
                                s.ephemeral_public_key.clone(),
                                s.ephemeral_client_encryption.clone(),
                                s.ephemeral_mldsa65_verify.clone(),
                            )
                        });
                        self.replace_loaded_editable(editable);
                        if let Some((tag, pk, enc, verify)) = captured {
                            let inbounds = self.loaded_config.inbounds();
                            let index = inbounds
                                .iter()
                                .rposition(|row| row.tag == tag)
                                .unwrap_or_else(|| inbounds.len().saturating_sub(1));
                            self.share_materials.merge(
                                tag.as_deref(),
                                index,
                                pk,
                                enc,
                                verify,
                            );
                            self.schedule_share_material_persist();
                        }
                        self.inbound_editor_session = None;
                        self.show_status_message(
                            "Inbound added. Configuration updated. Xray restart required.",
                        );
                    }
                    Ok(InboundMutationSuccess::Delete {
                        editable,
                        deleted_index,
                    }) => {
                        self.retain_share_material_from_session();
                        if self
                            .inbound_editor_session
                            .as_ref()
                            .is_some_and(|s| !s.is_add && s.inbound_index == deleted_index)
                        {
                            self.inbound_editor_session = None;
                        }
                        if self
                            .inbound_shell_drafts
                            .as_ref()
                            .is_some_and(|d| d.inbound_index == deleted_index)
                        {
                            self.inbound_shell_drafts = None;
                        }
                        match self.selected_users_inbound_index {
                            Some(selected) if selected == deleted_index => {
                                self.selected_users_inbound_index = None;
                            }
                            Some(selected) if selected > deleted_index => {
                                self.selected_users_inbound_index = Some(selected - 1);
                            }
                            _ => {}
                        }
                        self.replace_loaded_editable(editable);
                        self.show_status_message(
                            "Inbound deleted. Configuration updated. Xray restart required.",
                        );
                    }
                    Ok(InboundMutationSuccess::Duplicate {
                        editable,
                        new_index,
                    }) => {
                        self.retain_share_material_from_session();
                        self.replace_loaded_editable(editable);
                        self.set_selected_users_inbound(new_index);
                        self.show_status_message(
                            "Inbound duplicated. Configuration updated. Xray restart required.",
                        );
                    }
                    Ok(InboundMutationSuccess::X25519(X25519Result {
                        private_key,
                        public_key,
                    })) => {
                        let mut retain: Option<(Option<String>, usize)> = None;
                        if let Some(session) = &mut self.inbound_editor_session {
                            if let Some(security) = &mut session.security {
                                security.reality.private_key = private_key;
                            }
                            session.ephemeral_public_key = Some(public_key.clone());
                            session.dirty = true;
                            if !session.is_add {
                                retain = Some((session.general.tag.clone(), session.inbound_index));
                            }
                        }
                        let merged_to_store = retain.is_some();
                        if let Some((tag, index)) = retain {
                            self.share_materials.merge(
                                tag.as_deref(),
                                index,
                                Some(public_key),
                                None,
                                None,
                            );
                        }
                        self.show_status_message("x25519 key pair generated.");
                        if merged_to_store {
                            self.schedule_share_material_persist();
                        }
                    }
                    Ok(InboundMutationSuccess::Mldsa65(Mldsa65Result { seed, verify })) => {
                        let mut retain: Option<(Option<String>, usize)> = None;
                        if let Some(session) = &mut self.inbound_editor_session {
                            if let Some(security) = &mut session.security {
                                security.reality.mldsa65_seed = Some(seed);
                            }
                            session.ephemeral_mldsa65_verify = Some(verify.clone());
                            session.dirty = true;
                            if !session.is_add {
                                retain = Some((session.general.tag.clone(), session.inbound_index));
                            }
                        }
                        let merged_to_store = retain.is_some();
                        if let Some((tag, index)) = retain {
                            self.share_materials.merge(
                                tag.as_deref(),
                                index,
                                None,
                                None,
                                Some(verify),
                            );
                        }
                        self.show_status_message("mldsa65 key pair generated.");
                        if merged_to_store {
                            self.schedule_share_material_persist();
                        }
                    }
                    Ok(InboundMutationSuccess::VlessEnc(VlessEncResult {
                        decryption,
                        encryption,
                        auth,
                    })) => {
                        let mut retain: Option<(Option<String>, usize)> = None;
                        if let Some(session) = &mut self.inbound_editor_session {
                            if let InboundProtocolDraft::Vless {
                                decryption: draft_dec,
                                ..
                            } = &mut session.protocol
                            {
                                *draft_dec = decryption;
                            }
                            session.ephemeral_client_encryption = Some(encryption.clone());
                            session.vlessenc_auth = auth;
                            session.dirty = true;
                            if !session.is_add {
                                retain = Some((session.general.tag.clone(), session.inbound_index));
                            }
                        }
                        let merged_to_store = retain.is_some();
                        if let Some((tag, index)) = retain {
                            self.share_materials.merge(
                                tag.as_deref(),
                                index,
                                None,
                                Some(encryption),
                                None,
                            );
                        }
                        self.show_status_message(format!(
                            "VLESS encryption generated ({})",
                            auth.label()
                        ));
                        if merged_to_store {
                            self.schedule_share_material_persist();
                        }
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.message().as_str());
                        tracing::error!(
                            target: "app",
                            kind = ?outcome.kind,
                            detail = %technical,
                            "inbound mutation failed"
                        );
                        let user_message = if error.kind()
                            == crate::xray::ConfigModifyErrorKind::FingerprintMismatch
                        {
                            format!("{} — session reset.", error.kind().label())
                        } else {
                            crate::logging::redact::user_message_see_log(
                                "Unable to complete inbound operation.",
                            )
                        };
                        if matches!(
                            outcome.kind,
                            InboundMutationKind::Shell
                                | InboundMutationKind::Add
                                | InboundMutationKind::Delete
                                | InboundMutationKind::Duplicate
                        ) {
                            self.inbound_editor_session = None;
                        }
                        self.show_status_message(user_message);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.inbound_mutation_rx = None;
                self.operation = CurrentOperation::Ready;
                self.show_status_message("Inbound operation failed: worker ended unexpectedly");
            }
        }
    }

    /// Polls for a completed outbound mutation (Delete).
    pub fn poll_outbound_mutation(&mut self) {
        let Some(rx) = &self.outbound_mutation_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(outcome) => {
                self.outbound_mutation_rx = None;
                self.operation = CurrentOperation::Ready;
                match outcome.result {
                    Ok(super::outbound_ops::OutboundMutationSuccess::Delete {
                        editable,
                        deleted_index: _,
                    }) => {
                        self.replace_loaded_editable(editable);
                        self.show_status_message(
                            "Outbound deleted. Configuration updated. Xray restart required.",
                        );
                    }
                    Ok(super::outbound_ops::OutboundMutationSuccess::Add { editable }) => {
                        self.replace_loaded_editable(editable);
                        self.outbound_editor_session = None;
                        self.show_status_message(
                            "Outbound added. Configuration updated. Xray restart required.",
                        );
                    }
                    Ok(super::outbound_ops::OutboundMutationSuccess::Update { editable }) => {
                        self.replace_loaded_editable(editable);
                        self.outbound_editor_session = None;
                        self.show_status_message(
                            "Outbound saved. Configuration updated. Xray restart required.",
                        );
                    }
                    Err(error) => {
                        let user_message = if error.message().is_empty() {
                            crate::logging::redact::user_message_see_log(
                                "Unable to modify outbound.",
                            )
                        } else {
                            error.message().to_owned()
                        };
                        self.show_status_message(user_message);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.outbound_mutation_rx = None;
                self.operation = CurrentOperation::Ready;
                self.show_status_message("Outbound operation failed: worker ended unexpectedly");
            }
        }
    }

    /// Returns true when an outbound Add / Shell Save / Delete is in flight.
    pub fn is_outbound_mutation_busy(&self) -> bool {
        self.outbound_mutation_rx.is_some()
            || matches!(
                self.operation,
                CurrentOperation::AddingOutbound
                    | CurrentOperation::UpdatingOutboundShell
                    | CurrentOperation::DeletingOutbound
            )
    }

    /// Returns true when inbound shell Save is in flight.
    pub fn is_inbound_shell_mutation_busy(&self) -> bool {
        self.inbound_shell_rx.is_some()
            || self.inbound_mutation_rx.is_some()
            || matches!(
                self.operation,
                CurrentOperation::UpdatingInboundGeneral
                    | CurrentOperation::UpdatingInboundSniffing
                    | CurrentOperation::UpdatingInboundShell
                    | CurrentOperation::AddingInbound
                    | CurrentOperation::DeletingInbound
                    | CurrentOperation::DuplicatingInbound
                    | CurrentOperation::GeneratingX25519
                    | CurrentOperation::GeneratingMldsa65
                    | CurrentOperation::GeneratingVlessEnc
            )
    }

    /// Returns `true` when a keygen is in flight.
    pub fn is_keygen_busy(&self) -> bool {
        matches!(
            self.operation,
            CurrentOperation::GeneratingX25519
                | CurrentOperation::GeneratingMldsa65
                | CurrentOperation::GeneratingVlessEnc
        )
            || self
                .inbound_mutation_rx
                .as_ref()
                .is_some_and(|_| {
                    matches!(
                        self.operation,
                        CurrentOperation::GeneratingX25519
                            | CurrentOperation::GeneratingMldsa65
                            | CurrentOperation::GeneratingVlessEnc
                    )
                })
    }

    /// Whether shell edit (General/Sniffing) is allowed for the selected inbound.
    pub fn inbound_shell_edit_enabled(&self, inbound_index: usize) -> bool {
        let Some(editable) = self.loaded_config.editable() else {
            return false;
        };
        editable
            .require_shell_editable_inbound(inbound_index)
            .is_ok()
    }

    /// Whether the port field is editable for the selected inbound (scalar only).
    pub fn inbound_port_shell_editable(&self, inbound_index: usize) -> bool {
        let Some(editable) = self.loaded_config.editable() else {
            return false;
        };
        let Some(inbound) = editable.sections().inbounds().get(inbound_index) else {
            return false;
        };
        port_is_shell_editable(inbound.value())
    }

    /// Parsed General view values from the loaded config (not drafts).
    pub fn inbound_general_view(&self, inbound_index: usize) -> Option<InboundGeneral> {
        let editable = self.loaded_config.editable()?;
        let inbound = editable.sections().inbounds().get(inbound_index)?;
        Some(parse_inbound_general(inbound.value()))
    }

    /// Parsed Sniffing view values from the loaded config (not drafts).
    pub fn inbound_sniffing_view(&self, inbound_index: usize) -> Option<SniffingSettings> {
        let editable = self.loaded_config.editable()?;
        let inbound = editable.sections().inbounds().get(inbound_index)?;
        Some(parse_sniffing_settings(inbound.value()))
    }

    fn ensure_shell_session(&mut self, inbound_index: usize) -> Result<(), String> {
        if let Some(drafts) = &self.inbound_shell_drafts
            && drafts.inbound_index == inbound_index
        {
            return Ok(());
        }
        let inbound_ref = self.build_inbound_ref(inbound_index)?;
        self.inbound_shell_drafts = Some(InboundShellDrafts {
            inbound_index,
            inbound_ref,
            general: None,
            sniffing: None,
        });
        Ok(())
    }

    fn build_inbound_ref(&self, inbound_index: usize) -> Result<InboundRef, String> {
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?;
        let location = editable
            .locate_inbound(inbound_index)
            .map_err(|error| error.message())?;
        let protocol = editable
            .sections()
            .inbounds()
            .get(inbound_index)
            .and_then(|inbound| inbound.value().get("protocol"))
            .and_then(|value| value.as_str())
            .and_then(InboundClientProtocol::from_wire)
            .ok_or_else(|| "Shell editing is not supported for this inbound protocol.".to_owned())?;
        protocol
            .require_shell_edit_enabled()
            .map_err(|error| error.message())?;
        let expected_fingerprint = editable
            .inbound_object_fingerprint(inbound_index)
            .map_err(|error| error.message())?;
        Ok(InboundRef {
            location,
            protocol,
            expected_fingerprint,
        })
    }

    /// Enters General edit mode for the selected inbound (captures fingerprint).
    pub fn begin_edit_inbound_general(&mut self, inbound_index: usize) -> Result<(), String> {
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        self.ensure_shell_session(inbound_index)?;
        let general = self
            .inbound_general_view(inbound_index)
            .ok_or_else(|| "Inbound not found.".to_owned())?;
        if let Some(drafts) = &mut self.inbound_shell_drafts {
            drafts.general = Some(general);
        }
        Ok(())
    }

    /// Enters Sniffing edit mode for the selected inbound (captures fingerprint).
    pub fn begin_edit_inbound_sniffing(&mut self, inbound_index: usize) -> Result<(), String> {
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        self.ensure_shell_session(inbound_index)?;
        let sniffing = self
            .inbound_sniffing_view(inbound_index)
            .ok_or_else(|| "Inbound not found.".to_owned())?;
        if let Some(drafts) = &mut self.inbound_shell_drafts {
            drafts.sniffing = Some(sniffing);
        }
        Ok(())
    }

    /// Cancels General edit draft; clears session when both drafts empty.
    pub fn cancel_edit_inbound_general(&mut self) {
        if let Some(drafts) = &mut self.inbound_shell_drafts {
            drafts.general = None;
            if !drafts.is_editing() {
                self.inbound_shell_drafts = None;
            }
        }
    }

    /// Cancels Sniffing edit draft; clears session when both drafts empty.
    pub fn cancel_edit_inbound_sniffing(&mut self) {
        if let Some(drafts) = &mut self.inbound_shell_drafts {
            drafts.sniffing = None;
            if !drafts.is_editing() {
                self.inbound_shell_drafts = None;
            }
        }
    }

    /// Focuses General edit for context-menu Edit (creates draft if needed).
    pub fn focus_inbound_general_edit(&mut self, inbound_index: usize) -> Result<(), String> {
        self.set_selected_users_inbound(inbound_index);
        self.begin_edit_inbound_general(inbound_index)
    }

    /// Saves General draft for the active shell session.
    pub fn start_save_inbound_general(&mut self) -> Result<(), String> {
        let (inbound_ref, general) = {
            let drafts = self
                .inbound_shell_drafts
                .as_ref()
                .ok_or_else(|| "Not editing inbound General.".to_owned())?;
            let general = drafts
                .general
                .clone()
                .ok_or_else(|| "Not editing inbound General.".to_owned())?;
            (drafts.inbound_ref.clone(), general)
        };
        self.start_inbound_shell_mutation(InboundShellMutationRequest::General(
            UpdateInboundGeneralRequest {
                inbound_ref,
                general,
            },
        ))
    }

    /// Saves Sniffing draft for the active shell session.
    pub fn start_save_inbound_sniffing(&mut self) -> Result<(), String> {
        let (inbound_ref, sniffing) = {
            let drafts = self
                .inbound_shell_drafts
                .as_ref()
                .ok_or_else(|| "Not editing inbound Sniffing.".to_owned())?;
            let sniffing = drafts
                .sniffing
                .clone()
                .ok_or_else(|| "Not editing inbound Sniffing.".to_owned())?;
            (drafts.inbound_ref.clone(), sniffing)
        };
        self.start_inbound_shell_mutation(InboundShellMutationRequest::Sniffing(
            UpdateInboundSniffingRequest {
                inbound_ref,
                sniffing,
            },
        ))
    }

    fn start_inbound_shell_mutation(
        &mut self,
        request: InboundShellMutationRequest,
    ) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }

        let editable = match self.loaded_config.editable() {
            Some(editable) => editable.clone(),
            None => return Err("Configuration not loaded for editing.".to_owned()),
        };

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let kind = match &request {
            InboundShellMutationRequest::General(_) => InboundShellMutationKind::General,
            InboundShellMutationRequest::Sniffing(_) => InboundShellMutationKind::Sniffing,
        };

        let (tx, rx) = mpsc::channel();
        self.inbound_shell_rx = Some(rx);
        self.status_message_until = None;
        self.operation = match kind {
            InboundShellMutationKind::General => CurrentOperation::UpdatingInboundGeneral,
            InboundShellMutationKind::Sniffing => CurrentOperation::UpdatingInboundSniffing,
        };

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();

        info!(target: "app", kind = ?kind, "starting inbound shell mutation");

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(InboundShellMutationOutcome {
                        kind,
                        result: Err(crate::xray::ConfigModifyError::new(
                            crate::xray::ConfigModifyErrorKind::UploadFailed,
                            format!("failed to start async runtime: {error}"),
                        )),
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(async {
                match request {
                    InboundShellMutationRequest::General(request) => {
                        run_update_inbound_general(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            request,
                            validate_hint.clone(),
                        )
                        .await
                    }
                    InboundShellMutationRequest::Sniffing(request) => {
                        run_update_inbound_sniffing(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            request,
                            validate_hint,
                        )
                        .await
                    }
                }
            });
            let _ = tx.send(outcome);
        });

        Ok(())
    }

    /// Polls for a completed inbound General/Sniffing Save.
    pub fn poll_inbound_shell_mutation(&mut self) {
        let Some(rx) = &self.inbound_shell_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.inbound_shell_rx = None;
                match outcome.result {
                    Ok(success) => {
                        self.replace_loaded_editable(success.editable);
                        self.clear_shell_drafts();
                        if success.wrote_remote {
                            self.show_status_message(
                                "Inbound updated. Configuration updated. Xray restart required.",
                            );
                        } else {
                            self.show_status_message(
                                "No sniffing changes to write. Inbound drafts reset.",
                            );
                        }
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.message().as_str());
                        error!(
                            target: "app",
                            kind = ?outcome.kind,
                            detail = %technical,
                            "inbound shell mutation failed"
                        );
                        self.clear_shell_drafts();
                        let user_message = if error.kind()
                            == crate::xray::ConfigModifyErrorKind::FingerprintMismatch
                        {
                            format!("{} — drafts reset.", error.kind().label())
                        } else {
                            crate::logging::redact::user_message_see_log(
                                "Unable to update inbound configuration.",
                            )
                        };
                        self.show_status_message(user_message);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.inbound_shell_rx = None;
                if matches!(
                    self.operation,
                    CurrentOperation::UpdatingInboundGeneral
                        | CurrentOperation::UpdatingInboundSniffing
                ) {
                    self.show_status_message("Upload failed: worker ended unexpectedly");
                }
            }
        }
    }

    /// SHA-256 fingerprint of a client for edit/delete intent, when editable config is loaded.
    pub fn client_fingerprint(
        &self,
        inbound_index: usize,
        client_index: usize,
    ) -> Result<String, String> {
        let editable = self
            .loaded_config
            .editable()
            .ok_or_else(|| "Configuration not loaded.".to_owned())?;
        editable
            .client_fingerprint(inbound_index, client_index)
            .map_err(|error| error.message())
    }

    /// Returns the current Users table sort settings.
    pub fn users_sort(&self) -> UsersSort {
        self.users_sort
    }

    /// Toggles or switches Users table sorting for a column.
    pub fn set_users_sort_column(&mut self, column: UsersSortColumn) {
        if self.users_sort.column == column {
            self.users_sort.ascending = !self.users_sort.ascending;
        } else {
            self.users_sort = UsersSort {
                column,
                ascending: true,
            };
        }
    }

    /// Returns the current Inbounds table sort settings.
    pub fn inbounds_sort(&self) -> InboundsSort {
        self.inbounds_sort
    }

    /// Toggles or switches Inbounds table sorting for a column.
    pub fn set_inbounds_sort_column(&mut self, column: InboundsSortColumn) {
        if self.inbounds_sort.column == column {
            self.inbounds_sort.ascending = !self.inbounds_sort.ascending;
        } else {
            self.inbounds_sort = InboundsSort {
                column,
                ascending: true,
            };
        }
    }

    /// Returns the current Outbounds table sort settings.
    pub fn outbounds_sort(&self) -> OutboundsSort {
        self.outbounds_sort
    }

    /// Toggles or switches Outbounds table sorting for a column.
    pub fn set_outbounds_sort_column(&mut self, column: OutboundsSortColumn) {
        if self.outbounds_sort.column == column {
            self.outbounds_sort.ascending = !self.outbounds_sort.ascending;
        } else {
            self.outbounds_sort = OutboundsSort {
                column,
                ascending: true,
            };
        }
    }

    /// Updates Status Bar while the Outbounds page is visible.
    ///
    /// During discovery shows a loading message. After a successful load,
    /// announces the outbound count once, then returns to Ready.
    pub fn tick_outbounds_page_status(&mut self) {
        if matches!(self.discovery, DiscoveryState::Discovering) {
            self.operation = CurrentOperation::Message {
                text: "Loading outbounds...".to_owned(),
            };
            self.status_message_until = None;
            return;
        }

        if self.outbounds_status_announced || !self.loaded_config.is_loaded() {
            return;
        }

        let count = self.loaded_config.outbounds().len();
        self.outbounds_status_announced = true;
        self.show_status_message(format!("Loaded {count} outbound(s)"));
    }

    /// Updates Status Bar while the DNS page is visible.
    pub fn tick_dns_page_status(&mut self) {
        if matches!(self.discovery, DiscoveryState::Discovering) {
            self.operation = CurrentOperation::Message {
                text: "Loading DNS...".to_owned(),
            };
            self.status_message_until = None;
            return;
        }

        if self.dns_status_announced || !self.loaded_config.is_loaded() {
            return;
        }

        self.dns_status_announced = true;
        self.show_status_message("DNS configuration loaded.");
    }

    /// Updates Status Bar while the FakeDNS page is visible.
    pub fn tick_fakedns_page_status(&mut self) {
        if matches!(self.discovery, DiscoveryState::Discovering) {
            self.operation = CurrentOperation::Message {
                text: "Loading FakeDNS...".to_owned(),
            };
            self.status_message_until = None;
            return;
        }

        if self.fakedns_status_announced || !self.loaded_config.is_loaded() {
            return;
        }

        self.fakedns_status_announced = true;
        if self.loaded_config.fakedns().is_some() {
            self.show_status_message("FakeDNS configuration loaded.");
        } else {
            self.show_status_message("FakeDNS is not configured.");
        }
    }

    /// Updates Status Bar while the Observatory page is visible.
    pub fn tick_observatory_page_status(&mut self) {
        if matches!(self.discovery, DiscoveryState::Discovering) {
            self.operation = CurrentOperation::Message {
                text: "Loading Observatory...".to_owned(),
            };
            self.status_message_until = None;
            return;
        }

        if self.observatory_status_announced || !self.loaded_config.is_loaded() {
            return;
        }

        self.observatory_status_announced = true;
        self.show_status_message("Observatory configuration loaded.");
    }

    /// Updates Status Bar while the Burst Observatory page is visible.
    pub fn tick_burst_observatory_page_status(&mut self) {
        if matches!(self.discovery, DiscoveryState::Discovering) {
            self.operation = CurrentOperation::Message {
                text: "Loading BurstObservatory...".to_owned(),
            };
            self.status_message_until = None;
            return;
        }

        if self.burst_observatory_status_announced || !self.loaded_config.is_loaded() {
            return;
        }

        self.burst_observatory_status_announced = true;
        self.show_status_message("BurstObservatory configuration loaded.");
    }

    /// Returns the current Routing table sort settings.
    pub fn routing_sort(&self) -> RoutingSort {
        self.routing_sort
    }

    /// Toggles or switches Routing table sorting for a column.
    pub fn set_routing_sort_column(&mut self, column: RoutingSortColumn) {
        if self.routing_sort.column == column {
            self.routing_sort.ascending = !self.routing_sort.ascending;
        } else {
            self.routing_sort = RoutingSort {
                column,
                ascending: true,
            };
        }
    }

    /// Updates Status Bar while the Routing page is visible.
    ///
    /// During discovery shows a loading message. After a successful load,
    /// announces the rule count once, then returns to Ready.
    pub fn tick_routing_page_status(&mut self) {
        if matches!(self.discovery, DiscoveryState::Discovering) {
            self.operation = CurrentOperation::Message {
                text: "Loading routing...".to_owned(),
            };
            self.status_message_until = None;
            return;
        }

        if self.routing_status_announced || !self.loaded_config.is_loaded() {
            return;
        }

        let count = self
            .loaded_config
            .routing()
            .map(|routing| routing.rule_count)
            .unwrap_or(0);
        self.routing_status_announced = true;
        self.show_status_message(format!("Loaded {count} routing rule(s)."));
    }

    /// Returns the current Policy table sort settings.
    pub fn policy_sort(&self) -> PolicySort {
        self.policy_sort
    }

    /// Toggles or switches Policy table sorting for a column.
    pub fn set_policy_sort_column(&mut self, column: PolicySortColumn) {
        if self.policy_sort.column == column {
            self.policy_sort.ascending = !self.policy_sort.ascending;
        } else {
            self.policy_sort = PolicySort {
                column,
                ascending: true,
            };
        }
    }

    /// Updates Status Bar while the Policy page is visible.
    ///
    /// During discovery shows a loading message. After a successful load,
    /// announces the user-level count once, then returns to Ready.
    pub fn tick_policy_page_status(&mut self) {
        if matches!(self.discovery, DiscoveryState::Discovering) {
            self.operation = CurrentOperation::Message {
                text: "Loading policy...".to_owned(),
            };
            self.status_message_until = None;
            return;
        }

        if self.policy_status_announced || !self.loaded_config.is_loaded() {
            return;
        }

        let count = self
            .loaded_config
            .policy()
            .map(|policy| policy.user_levels.len())
            .unwrap_or(0);
        self.policy_status_announced = true;
        self.show_status_message(format!("Loaded {count} policy level(s)."));
    }

    /// Returns `true` when discovery may be started (active SSH + not already discovering
    /// + no other exclusive remote operation in flight).
    pub fn can_start_discovery(&self) -> bool {
        self.ssh_status == SshStatus::Connected
            && !self.discovery.is_discovering()
            && !self.is_service_control_busy()
            && !self.is_xray_lifecycle_busy()
            && !self.is_user_mutation_busy()
            && !self.version_check_busy
            && !self.warp_ui.is_busy()
            && !self.geodata_ui.is_busy()
            && !self.is_log_settings_mutation_busy()
    }

    /// Returns `true` when the draft differs from the last saved profile.
    pub fn connection_has_unsaved_changes(&self) -> bool {
        self.connection_draft
            .differs_from(self.saved_connection_profile())
    }

    /// Validates and persists the non-secret connection profile.
    ///
    /// On success, shows a short Status Bar message and clears field errors.
    /// Secrets remain in memory only and are never written to disk.
    pub fn save_connection_profile(&mut self) -> bool {
        match self.connection_draft.validate() {
            Ok(profile) => {
                self.connection_errors = ConnectionValidationErrors::default();
                self.config.config_mut().connection = profile;
                self.connection_draft =
                    ConnectionDraft::from_stored(&self.config.config().connection);
                self.save_config();
                self.show_status_message("Connection profile saved");
                true
            }
            Err(errors) => {
                self.connection_errors = errors;
                false
            }
        }
    }

    /// Restores the draft from the last saved non-secret profile.
    ///
    /// In-memory secrets are cleared so the form matches a freshly loaded session.
    pub fn reset_connection_profile(&mut self) {
        self.connection_draft = ConnectionDraft::from_stored(self.saved_connection_profile());
        self.connection_secrets.clear();
        self.connection_errors = ConnectionValidationErrors::default();
    }

    /// Starts an asynchronous SSH connection test.
    ///
    /// Returns `false` when validation fails or a test is already running.
    /// Does not block the UI thread.
    pub fn start_connection_test(&mut self) -> bool {
        if self.connection_test.is_connecting() {
            return false;
        }

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return false;
                }
            };

        let request = build_connect_request(&profile, &self.connection_secrets);
        let endpoint = format!("{}:{}", profile.host, profile.port);

        let (tx, rx) = mpsc::channel();
        self.connection_test_rx = Some(rx);
        self.connection_test = ConnectionTestState::Connecting;
        self.status_message_until = None;
        self.operation = CurrentOperation::Connecting {
            endpoint: endpoint.clone(),
        };
        self.ssh_status = SshStatus::Connecting;

        let client = self.ssh_client.clone();
        info!(
            target: "app",
            endpoint = %endpoint,
            "starting SSH connection test"
        );

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let failure = classify_ssh_error(&feldjaeger_ssh::SshError::new(format!(
                        "failed to start async runtime: {error}"
                    )));
                    let _ = tx.send(ConnectionTestOutcome {
                        result: Err(failure),
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(async {
                match run_connection_test(&client, &request).await {
                    Ok(()) => ConnectionTestOutcome { result: Ok(()) },
                    Err(error) => {
                        let technical = classify_ssh_error(&error);
                        error!(
                            target: "ssh",
                            error_kind = ?technical.summary,
                            detail = %technical.detail,
                            "SSH connection failed"
                        );
                        ConnectionTestOutcome {
                            result: Err(
                                crate::app::connection_test::user_facing_connection_failure(
                                    &technical,
                                ),
                            ),
                        }
                    }
                }
            });

            let _ = tx.send(outcome);
        });

        true
    }

    /// Polls for a completed connection test and updates Status Bar state.
    pub fn poll_connection_test(&mut self) {
        let Some(rx) = &self.connection_test_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.connection_test_rx = None;
                match outcome.result {
                    Ok(()) => {
                        info!(target: "app", "SSH connection test succeeded");
                        self.connection_test = ConnectionTestState::Succeeded;
                        self.ssh_status = SshStatus::Connected;
                        self.show_status_message("SSH connection test succeeded");
                    }
                    Err(failure) => {
                        let ssh_status = failure.summary;
                        self.connection_test = ConnectionTestState::Failed {
                            summary: ssh_status.label().to_owned(),
                            detail: failure.detail,
                        };
                        self.ssh_status = ssh_status;
                        self.operation = CurrentOperation::Ready;
                        self.status_message_until = None;
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.connection_test_rx = None;
                if self.connection_test.is_connecting() {
                    self.connection_test = ConnectionTestState::Failed {
                        summary: SshStatus::UnknownError.label().to_owned(),
                        detail: "Connection test worker ended unexpectedly.".to_owned(),
                    };
                    self.ssh_status = SshStatus::UnknownError;
                    self.operation = CurrentOperation::Ready;
                    self.status_message_until = None;
                }
            }
        }
    }

    /// Starts asynchronous read-only Xray discovery on the remote host.
    ///
    /// Requires a successful prior SSH connection (`SshStatus::Connected`).
    /// Returns `false` when discovery cannot start (not connected, already running,
    /// or invalid credentials for reconnect).
    pub fn start_discovery(&mut self) -> bool {
        if !self.can_start_discovery() {
            return false;
        }

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return false;
                }
            };

        let (tx, rx) = mpsc::channel();
        self.discovery_rx = Some(rx);
        self.discovery = DiscoveryState::Discovering;
        self.loaded_config = LoadedConfigSnapshot::None;
        self.selected_users_inbound_index = None;
        self.clear_shell_drafts();
        self.log_settings_draft = None;
        self.log_settings_error = None;
        self.log_settings_saved_flash = false;
        self.outbounds_status_announced = false;
        self.dns_status_announced = false;
        self.fakedns_status_announced = false;
        self.observatory_status_announced = false;
        self.burst_observatory_status_announced = false;
        self.routing_status_announced = false;
        self.policy_status_announced = false;
        self.service_control = ServiceControlState::Idle;
        self.service_control_rx = None;
        self.service_state = None;
        self.xray_lifecycle = XrayLifecycleState::Idle;
        self.xray_lifecycle_rx = None;
        self.install_channel = InstallChannel::Stable;
        self.available_versions = AvailableVersions::default();
        self.version_check_rx = None;
        self.version_check_busy = false;
        self.geodata_summary = None;
        self.geodata_ui = GeoDataUiState::Idle;
        self.geodata_rx = None;
        self.clear_warp_state();
        self.xray_logs.reset();
        self.status_message_until = None;
        self.operation = CurrentOperation::DiscoveringXray;
        self.ssh_status = SshStatus::Connected;

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let init = self.init.clone();

        info!(
            target: "app",
            host = %profile.host,
            port = profile.port,
            "starting Xray discovery"
        );

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(DiscoveryOutcome {
                        state: DiscoveryState::Failed {
                            kind: crate::xray::DiscoveryErrorKind::Unexpected,
                            detail: format!("failed to start async runtime: {error}"),
                        },
                        config: LoadedConfigSnapshot::None,
                        share_materials: super::share_material::ShareMaterialStore::new(),
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(run_discovery(&client, &profile, &secrets, &init));
            let _ = tx.send(outcome);
        });

        true
    }

    /// Polls for a completed discovery and updates Status Bar / discovery state.
    pub fn poll_discovery(&mut self) {
        let Some(rx) = &self.discovery_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.discovery_rx = None;
                self.discovery = outcome.state;
                self.loaded_config = outcome.config;
                self.share_materials = outcome.share_materials;
                match &self.discovery {
                    DiscoveryState::Succeeded(installation) => {
                        self.service_state = installation.service_state;
                        if let Some(state) = installation.service_state {
                            self.xray_status = XrayStatus::from_service_state(state);
                        } else if let Some(version) = &installation.version {
                            self.xray_status = XrayStatus::new(
                                format!("Xray: {version}"),
                                crate::app::StatusSeverity::Healthy,
                            );
                        } else {
                            self.xray_status = XrayStatus::unknown();
                        }
                        self.ssh_status = SshStatus::Connected;
                        self.seed_xray_log_sources();
                        if self.loaded_config.is_loaded() {
                            let count = self.loaded_config.vless_clients().len();
                            self.show_status_message(format!("Loaded {count} user(s)"));
                        } else {
                            self.show_status_message("Xray discovery completed");
                        }
                    }
                    DiscoveryState::NotFound { .. } => {
                        self.service_state = None;
                        self.xray_status =
                            XrayStatus::new("Xray: Not found", crate::app::StatusSeverity::Warning);
                        self.ssh_status = SshStatus::Connected;
                        self.show_status_message("Xray installation not found");
                    }
                    DiscoveryState::Failed { kind, detail } => {
                        if *kind == crate::xray::DiscoveryErrorKind::SshConnectionLost {
                            self.ssh_status = SshStatus::ConnectionClosed;
                        }
                        self.operation = CurrentOperation::Ready;
                        self.status_message_until = None;
                        warn!(
                            target: "app",
                            detail = %detail,
                            "Xray discovery failed"
                        );
                    }
                    DiscoveryState::Idle | DiscoveryState::Discovering => {}
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.discovery_rx = None;
                if self.discovery.is_discovering() {
                    self.discovery = DiscoveryState::Failed {
                        kind: crate::xray::DiscoveryErrorKind::Unexpected,
                        detail: "Discovery worker ended unexpectedly.".to_owned(),
                    };
                    self.operation = CurrentOperation::Ready;
                    self.status_message_until = None;
                }
            }
        }
    }

    /// Persists the current application configuration to disk.
    pub fn save_config(&self) {
        if let Err(error) = self.config.save() {
            warn!(
                target: "config",
                error = %crate::logging::redact::sanitize_detail(&error.to_string()),
                "failed to save application config"
            );
        }
    }

    /// Updates sidebar width and saves when the value changed.
    pub fn set_sidebar_width(&mut self, width: f32) {
        let width = width.clamp(120.0, 480.0);
        if (self.config.config().ui.sidebar_width - width).abs() < 0.5 {
            return;
        }
        self.config.config_mut().ui.sidebar_width = width;
        self.save_config();
    }

    /// Updates the last selected page and saves when the value changed.
    pub fn set_last_page(&mut self, page: impl Into<String>) {
        let page = page.into();
        if self.config.config().ui.last_page == page {
            return;
        }
        self.config.config_mut().ui.last_page = page;
        self.save_config();
    }

    /// Updates window size and saves when the value changed.
    pub fn set_window_size(&mut self, size: WindowSize) {
        let size = WindowSize {
            width: size.width.max(400.0),
            height: size.height.max(300.0),
        };
        let current = self.config.config().ui.window_size;
        if (current.width - size.width).abs() < 0.5 && (current.height - size.height).abs() < 0.5 {
            return;
        }
        self.config.config_mut().ui.window_size = size;
        self.save_config();
    }

    /// Updates window position and saves when the value changed.
    pub fn set_window_position(&mut self, position: WindowPosition) {
        if let Some(current) = self.config.config().ui.window_position
            && (current.x - position.x).abs() < 0.5
            && (current.y - position.y).abs() < 0.5
        {
            return;
        }
        self.config.config_mut().ui.window_position = Some(position);
        self.save_config();
    }

    /// Updates theme preference and saves when the value changed.
    ///
    /// MVP always renders with the system theme; this stores the preference only.
    pub fn set_theme_mode(&mut self, theme: ThemeMode) {
        if self.config.config().ui.theme == theme {
            return;
        }
        self.config.config_mut().ui.theme = theme;
        self.save_config();
    }

    /// Returns an immutable Status Bar snapshot for the GUI.
    pub fn status_snapshot(&self) -> StatusSnapshot {
        StatusSnapshot {
            operation: self.operation.clone(),
            ssh: self.ssh_status,
            xray: self.xray_status.clone(),
        }
    }

    /// Returns `true` when a user mutation (add/update/delete) is in progress.
    pub fn is_user_mutation_busy(&self) -> bool {
        self.user_mutation_rx.is_some()
            || matches!(
                self.operation,
                CurrentOperation::AddingUser
                    | CurrentOperation::UpdatingUser
                    | CurrentOperation::DeletingUser
            )
    }

    /// Returns `true` when a remote service lifecycle operation is in progress.
    pub fn is_service_control_busy(&self) -> bool {
        self.service_control.is_busy()
            || matches!(self.operation, CurrentOperation::ManagingXrayService { .. })
    }

    /// Returns `true` when install/update/remove is in progress.
    pub fn is_xray_lifecycle_busy(&self) -> bool {
        self.xray_lifecycle.is_busy()
            || matches!(self.operation, CurrentOperation::ManagingXrayLifecycle { .. })
    }

    /// Returns `true` when any exclusive remote operation is running.
    fn is_any_remote_busy(&self) -> bool {
        self.is_service_control_busy()
            || self.is_xray_lifecycle_busy()
            || self.is_user_mutation_busy()
            || self.is_inbound_shell_mutation_busy()
            || self.is_log_settings_mutation_busy()
            || self.discovery.is_discovering()
            || self.version_check_busy
            || self.geodata_ui.is_busy()
            || self.warp_ui.is_busy()
            || self.xray_logs.ui_state.is_busy()
            || self.unit_apply_busy
            || self.unit_probe_rx.is_some()
            || self.inbound_mutation_rx.is_some()
            || self.outbound_mutation_rx.is_some()
    }

    /// Returns `true` while a log-settings save is in flight.
    pub fn is_log_settings_mutation_busy(&self) -> bool {
        self.log_settings_rx.is_some()
    }

    /// Read-only model for the Service page.
    pub fn service_page_model(&self) -> ServicePageModel {
        build_service_page_model(
            &self.discovery,
            &self.service_control,
            self.service_state,
            self.unit_host_probe,
        )
    }

    /// Whether a unit Apply is in flight.
    pub fn unit_apply_busy(&self) -> bool {
        self.unit_apply_busy
    }

    /// After Apply, GUI should offer Restart when this is true.
    pub fn take_unit_apply_restart_prompt(&mut self) -> bool {
        let v = self.unit_apply_needs_restart_prompt;
        self.unit_apply_needs_restart_prompt = false;
        v
    }

    /// Prefill a UnitSpec from discovery for Create or Edit.
    pub fn unit_spec_from_discovery(&self, create: bool) -> Result<crate::init::UnitSpec, String> {
        use crate::init::UnitSpec;
        use crate::xray::ConfigSource;

        match &self.discovery {
            DiscoveryState::Succeeded(installation) => UnitSpec::from_discovery(
                installation.service_name.as_deref(),
                installation.binary_path.as_ref(),
                &installation.config_source,
                create,
            )
            .map_err(|e| e.message()),
            DiscoveryState::NotFound { .. } => UnitSpec::from_discovery(
                None,
                None,
                &ConfigSource::NotFound,
                true,
            )
            .map_err(|e| e.message()),
            _ => Err("Run discovery on the Connection page first.".to_owned()),
        }
    }

    /// Starts a background probe of `/etc/systemd/system` for Create/Edit gating.
    pub fn start_unit_host_probe(&mut self, unit_name: &str) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.unit_probe_rx.is_some() {
            return Ok(());
        }
        let name = ServiceName::new(unit_name).map_err(|e| e.message().to_owned())?;
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => profile,
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let (ptx, prx) = mpsc::channel();
        self.unit_probe_rx = Some(prx);
        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            let _ = rt.block_on(async move {
                let connect = build_connect_request(&profile, &secrets);
                let Ok(session) = client.connect(&connect).await else {
                    return;
                };
                if let Ok(probe) = crate::init::probe_unit_host(&session, &name).await {
                    let _ = ptx.send(probe);
                }
                let _ = session.disconnect().await;
            });
        });
        Ok(())
    }

    /// Applies a unit Create/Edit on a background worker.
    pub fn start_unit_apply(&mut self, mut request: UnitApplyRequest) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() || self.unit_apply_busy {
            return Err("Another operation is already running.".to_owned());
        }
        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let was_running = matches!(self.service_state, Some(ServiceState::Running));
        let (tx, rx) = mpsc::channel();
        self.unit_apply_rx = Some(rx);
        self.unit_apply_busy = true;
        self.status_message_until = None;
        self.operation = CurrentOperation::ManagingXrayService {
            text: "Applying unit file...".to_owned(),
        };

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        // Move password out — never log
        let password = request.sudo_password.take();
        request.sudo_password = password;

        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = tx.send(UnitApplyOutcome {
                        service_name: request.spec.unit_name.as_str().to_owned(),
                        result: Err(crate::init::UnitFileError::new(
                            crate::init::UnitFileErrorKind::CommandFailed,
                            format!("runtime: {err}"),
                        )),
                        enable_and_start: request.enable_and_start,
                        was_running,
                    });
                    return;
                }
            };
            let outcome = rt.block_on(run_unit_apply(
                &client, &profile, &secrets, request, was_running,
            ));
            let _ = tx.send(outcome);
        });
        Ok(())
    }

    /// Read-only model for the Xray Management page.
    pub fn xray_management_page_model(&self) -> XrayManagementPageModel {
        build_xray_management_page_model(
            &self.discovery,
            &self.xray_lifecycle,
            self.install_channel,
            &self.available_versions,
            self.version_check_busy,
        )
    }

    /// Session-only Stable/Beta preference for Xray Management.
    pub fn set_install_channel(&mut self, channel: InstallChannel) {
        self.install_channel = channel;
    }

    /// Current session install channel.
    pub fn install_channel(&self) -> InstallChannel {
        self.install_channel
    }

    /// Starts a remote Xray service lifecycle operation (start/stop/…).
    ///
    /// The service name always comes from the discovery result; it is never
    /// taken from user input. Only systemd is supported.
    pub fn start_service_operation(&mut self, operation: ServiceOperation) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }

        let DiscoveryState::Succeeded(installation) = &self.discovery else {
            return Err("Run discovery on the Connection page first.".to_owned());
        };

        if !installation.service_control_supported() {
            return Err("Unsupported init system.".to_owned());
        }

        let service_name = match &installation.service_name {
            Some(name) => name.clone(),
            None => return Err("Service not found.".to_owned()),
        };

        if let Err(error) = ServiceName::new(&service_name) {
            return Err(error.message().to_owned());
        }

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let (tx, rx) = mpsc::channel();
        self.service_control_rx = Some(rx);
        self.service_control = ServiceControlState::Busy(operation);
        self.status_message_until = None;
        self.operation = CurrentOperation::ManagingXrayService {
            text: operation.status_message().to_owned(),
        };

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let init = self.init.clone();

        info!(
            target: "app",
            "{} Xray service {}",
            operation.log_gerund(),
            service_name
        );

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(ServiceOperationOutcome {
                        operation,
                        service_name,
                        result: Err(crate::init::ServiceControlError::new(
                            crate::init::ServiceOperationErrorKind::CommandFailed,
                            format!("failed to start async runtime: {error}"),
                        )),
                        refreshed_state: None,
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(run_service_operation(
                &client,
                &profile,
                &secrets,
                &init,
                &service_name,
                operation,
            ));
            let _ = tx.send(outcome);
        });

        Ok(())
    }

    /// Polls for a completed service lifecycle operation.
    pub fn poll_service_operation(&mut self) {
        let Some(rx) = &self.service_control_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.service_control_rx = None;
                if let Some(state) = outcome.refreshed_state {
                    self.apply_refreshed_service_state(state);
                }

                match outcome.result {
                    Ok(()) => {
                        self.service_control = ServiceControlState::Idle;
                        self.show_status_message("Xray service updated.");
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.detail());
                        error!(
                            target: "app",
                            kind = ?error.kind(),
                            detail = %technical,
                            "Failed to {} Xray service",
                            outcome.operation.log_past()
                        );
                        let detail = user_facing_service_error(&error);
                        self.service_control = ServiceControlState::Failed {
                            kind: error.kind(),
                            detail: detail.clone(),
                        };
                        self.show_status_message(detail);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.service_control_rx = None;
                if self.service_control.is_busy() {
                    self.service_control = ServiceControlState::Failed {
                        kind: crate::init::ServiceOperationErrorKind::CommandFailed,
                        detail: "Service operation worker ended unexpectedly.".to_owned(),
                    };
                    self.show_status_message("Service operation failed unexpectedly.");
                }
            }
        }
    }

    /// Polls unit host probe and Apply workers.
    pub fn poll_unit_operations(&mut self) {
        if let Some(rx) = &self.unit_probe_rx {
            match rx.try_recv() {
                Ok(probe) => {
                    self.unit_probe_rx = None;
                    self.unit_host_probe = Some(probe);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.unit_probe_rx = None;
                }
            }
        }

        let Some(rx) = &self.unit_apply_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(outcome) => {
                self.unit_apply_rx = None;
                self.unit_apply_busy = false;
                match outcome.result {
                    Ok(()) => {
                        self.show_status_message("Unit file applied.");
                        self.unit_apply_needs_restart_prompt =
                            outcome.was_running && !outcome.enable_and_start;
                        self.unit_host_probe = Some(crate::init::UnitHostProbe {
                            etc_unit_exists: true,
                            can_write_unit_dir: self
                                .unit_host_probe
                                .map(|p| p.can_write_unit_dir)
                                .unwrap_or(true),
                        });
                        // Refresh discovery so lifecycle sees the unit.
                        let _ = self.start_discovery();
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.detail());
                        error!(
                            target: "app",
                            kind = ?error.kind(),
                            detail = %technical,
                            "Failed to apply unit file"
                        );
                        self.show_status_message(user_facing_unit_error(&error));
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.unit_apply_rx = None;
                if self.unit_apply_busy {
                    self.unit_apply_busy = false;
                    self.show_status_message("Unit apply failed unexpectedly.");
                }
            }
        }
    }

    fn apply_refreshed_service_state(&mut self, state: ServiceState) {
        self.service_state = Some(state);
        self.xray_status = XrayStatus::from_service_state(state);
        if let DiscoveryState::Succeeded(installation) = &mut self.discovery {
            installation.service_state = Some(state);
        }
    }

    /// Starts remote Xray install / update / remove.
    pub fn start_xray_lifecycle(
        &mut self,
        operation: XrayLifecycleOperation,
    ) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }

        let snapshot = match lifecycle_snapshot_from_discovery(&self.discovery) {
            Some(snapshot) => snapshot,
            None => return Err("Run discovery on the Connection page first.".to_owned()),
        };

        if !snapshot.init_system.supports_service_control() {
            return Err("Unsupported system.".to_owned());
        }

        match operation {
            XrayLifecycleOperation::Install if snapshot.installed => {
                return Err("Xray is already installed.".to_owned());
            }
            XrayLifecycleOperation::Update | XrayLifecycleOperation::Remove
                if !snapshot.installed =>
            {
                return Err("Xray is not installed.".to_owned());
            }
            _ => {}
        }

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let (tx, rx) = mpsc::channel();
        self.xray_lifecycle_rx = Some(rx);
        self.xray_lifecycle = XrayLifecycleState::Busy(operation);
        self.status_message_until = None;
        self.operation = CurrentOperation::ManagingXrayLifecycle {
            text: operation.status_message().to_owned(),
        };

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let installer = XrayInstaller::new();
        let channel = self.install_channel;

        info!(
            target: "app",
            operation = ?operation,
            channel = ?channel,
            "starting Xray lifecycle operation"
        );

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(XrayLifecycleOutcome {
                        operation,
                        result: Err(crate::xray::InstallerError::new(
                            crate::xray::InstallerErrorKind::CommandFailed,
                            format!("failed to start async runtime: {error}"),
                        )),
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(run_xray_lifecycle(
                &client,
                &profile,
                &secrets,
                &installer,
                &snapshot,
                operation,
                channel,
            ));
            let _ = tx.send(outcome);
        });

        Ok(())
    }

    /// Polls for a completed install/update/remove and triggers rediscovery on success.
    pub fn poll_xray_lifecycle(&mut self) {
        let Some(rx) = &self.xray_lifecycle_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.xray_lifecycle_rx = None;
                match outcome.result {
                    Ok(()) => {
                        self.xray_lifecycle = XrayLifecycleState::Idle;
                        self.show_status_message("Xray operation completed.");
                        let _ = self.start_discovery();
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.detail());
                        error!(
                            target: "app",
                            kind = ?error.kind(),
                            detail = %technical,
                            "Xray installation failed"
                        );
                        let detail = user_facing_installer_error(&error);
                        self.xray_lifecycle = XrayLifecycleState::Failed {
                            kind: error.kind(),
                            detail: detail.clone(),
                        };
                        self.show_status_message(detail);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.xray_lifecycle_rx = None;
                if self.xray_lifecycle.is_busy() {
                    self.xray_lifecycle = XrayLifecycleState::Failed {
                        kind: crate::xray::InstallerErrorKind::CommandFailed,
                        detail: "Xray lifecycle worker ended unexpectedly.".to_owned(),
                    };
                    self.show_status_message("Xray operation failed unexpectedly.");
                }
            }
        }
    }

    /// Starts a background check for the latest Xray-core release version.
    pub fn start_version_check(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        if lifecycle_snapshot_from_discovery(&self.discovery).is_none() {
            return Err("Run discovery on the Connection page first.".to_owned());
        }

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let (tx, rx) = mpsc::channel();
        self.version_check_rx = Some(rx);
        self.version_check_busy = true;
        self.show_status_message("Checking available Xray version...");

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let installer = XrayInstaller::new();

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(VersionCheckOutcome {
                        result: Err(crate::xray::InstallerError::new(
                            crate::xray::InstallerErrorKind::CommandFailed,
                            format!("failed to start async runtime: {error}"),
                        )),
                    });
                    return;
                }
            };

            let outcome =
                runtime.block_on(run_version_check(&client, &profile, &secrets, &installer));
            let _ = tx.send(outcome);
        });

        Ok(())
    }

    /// Polls for a completed available-version check.
    pub fn poll_version_check(&mut self) {
        let Some(rx) = &self.version_check_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.version_check_rx = None;
                self.version_check_busy = false;
                match outcome.result {
                    Ok(versions) => {
                        if let Some(tag) = versions.stable {
                            self.available_versions.stable = Some(tag);
                            self.available_versions.stable_error = None;
                        } else if let Some(err) = versions.stable_error {
                            self.available_versions.stable_error = Some(err);
                        }

                        if let Some(tag) = versions.beta {
                            self.available_versions.beta = Some(tag);
                            self.available_versions.beta_error = None;
                        } else if let Some(err) = versions.beta_error {
                            self.available_versions.beta_error = Some(err);
                        } else {
                            // Successful probe with no candidate — clear stale beta tag.
                            self.available_versions.beta = None;
                            self.available_versions.beta_error = None;
                        }

                        let msg = match (
                            self.available_versions.stable_error.as_ref(),
                            self.available_versions.beta_error.as_ref(),
                        ) {
                            (None, None) => "Available versions updated.".to_owned(),
                            (Some(_), None) => {
                                "Stable version check failed; beta updated.".to_owned()
                            }
                            (None, Some(_)) => {
                                "Beta version check failed; stable may be updated.".to_owned()
                            }
                            (Some(_), Some(_)) => {
                                "Version check reported errors — see Management page.".to_owned()
                            }
                        };
                        self.show_status_message(msg);
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.detail());
                        warn!(
                            target: "app",
                            kind = ?error.kind(),
                            detail = %technical,
                            "available version check failed"
                        );
                        self.show_status_message(user_facing_installer_error(&error));
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.version_check_rx = None;
                self.version_check_busy = false;
                self.show_status_message("Version check failed unexpectedly.");
            }
        }
    }

    /// Read-only model for the GeoData page.
    pub fn geodata_page_model(&self) -> GeoDataPageModel {
        build_geodata_page_model(
            self.ssh_status,
            &self.discovery,
            self.geodata_summary.as_ref(),
            &self.geodata_ui,
            self.is_any_remote_busy(),
        )
    }

    /// Starts a background GeoData status refresh (read-only).
    pub fn start_geodata_refresh(&mut self) -> Result<(), String> {
        self.start_geodata_operation(GeoDataOperation::Refresh)
    }

    /// Starts a background GeoData download / update.
    pub fn start_geodata_update(&mut self) -> Result<(), String> {
        self.start_geodata_operation(GeoDataOperation::Update)
    }

    fn start_geodata_operation(&mut self, operation: GeoDataOperation) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }

        let hints = match hints_from_discovery(&self.discovery) {
            Some(hints) => hints,
            None => return Err("Run discovery on the Connection page first.".to_owned()),
        };

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let (tx, rx) = mpsc::channel();
        self.geodata_rx = Some(rx);
        self.geodata_ui = GeoDataUiState::Busy(operation);
        self.status_message_until = None;
        self.operation = CurrentOperation::ManagingGeoData {
            text: operation.status_message().to_owned(),
        };

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();

        info!(
            target: "app",
            operation = ?operation,
            "starting GeoData operation"
        );

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(GeoDataOutcome {
                        operation,
                        result: Err(crate::xray::GeoDataError::new(
                            crate::xray::GeoDataErrorKind::CommandFailed,
                            format!("failed to start async runtime: {error}"),
                        )),
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(run_geodata_operation(
                &client, &profile, &secrets, hints, operation,
            ));
            let _ = tx.send(outcome);
        });

        Ok(())
    }

    /// Polls for a completed GeoData refresh / update.
    pub fn poll_geodata(&mut self) {
        let Some(rx) = &self.geodata_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.geodata_rx = None;
                match outcome.result {
                    Ok(summary) => {
                        self.geodata_summary = Some(summary);
                        self.geodata_ui = GeoDataUiState::Idle;
                        let message = match outcome.operation {
                            GeoDataOperation::Update => "GeoData updated successfully.",
                            GeoDataOperation::Refresh => "GeoData refreshed.",
                        };
                        self.show_status_message(message);
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.detail());
                        error!(
                            target: "app",
                            kind = ?error.kind(),
                            detail = %technical,
                            "GeoData operation failed"
                        );
                        let detail = user_facing_geodata_error(&error);
                        self.geodata_ui = GeoDataUiState::Failed {
                            kind: error.kind(),
                            detail: detail.clone(),
                        };
                        self.show_status_message(detail);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.geodata_rx = None;
                if self.geodata_ui.is_busy() {
                    self.geodata_ui = GeoDataUiState::Failed {
                        kind: crate::xray::GeoDataErrorKind::CommandFailed,
                        detail: "GeoData worker ended unexpectedly.".to_owned(),
                    };
                    self.show_status_message("GeoData operation failed unexpectedly.");
                }
            }
        }
    }

    /// Read-only model for the Cloudflare WARP page.
    pub fn warp_page_model(&self) -> WarpPageModel {
        build_warp_page_model(
            self.ssh_status,
            &self.discovery,
            self.loaded_config.editable().is_some(),
            self.warp_summary.as_ref(),
            &self.warp_ui,
            self.warp_pending_confirm.as_ref(),
            &self.warp_preferred_tag,
            self.warp_proposed.as_ref(),
            self.is_any_remote_busy(),
            self.warp_routing_notice.as_deref(),
        )
    }

    /// Updates the draft preferred outbound tag used for managed setup.
    pub fn set_warp_preferred_tag(&mut self, tag: String) {
        self.warp_preferred_tag = tag;
    }

    /// Starts a background WARP discovery refresh (read-only remote probe).
    pub fn request_warp_discover(&mut self) -> Result<(), String> {
        self.start_warp_operation(WarpOperation::Discover, None, None)
    }

    /// Queues confirmation for installing / updating the approved WARP helper.
    pub fn request_warp_install_helper(&mut self) -> Result<(), String> {
        self.require_warp_can_queue()?;
        self.warp_pending_confirm = Some(WarpPendingConfirm::InstallHelper);
        Ok(())
    }

    /// Confirms the pending WARP dialog and starts the matching operation.
    pub fn confirm_warp_pending(&mut self) -> Result<(), String> {
        let Some(pending) = self.warp_pending_confirm.take() else {
            return Err("No pending WARP confirmation.".to_owned());
        };

        match pending {
            WarpPendingConfirm::InstallHelper => {
                self.start_warp_operation(WarpOperation::InstallHelper, None, None)
            }
            WarpPendingConfirm::Setup { preferred_tag } => {
                let tag = if preferred_tag.trim().is_empty() {
                    self.warp_preferred_tag.clone()
                } else {
                    preferred_tag
                };
                self.start_warp_operation(WarpOperation::Setup, Some(tag), None)
            }
            WarpPendingConfirm::Adopt { outbound_tag, .. } => {
                self.start_warp_operation(WarpOperation::Adopt, None, Some(outbound_tag))
            }
            WarpPendingConfirm::Regenerate => {
                self.start_warp_operation(WarpOperation::Regenerate, None, None)
            }
            WarpPendingConfirm::RemoveIntegration { .. } => {
                self.start_warp_operation(WarpOperation::RemoveIntegration, None, None)
            }
            WarpPendingConfirm::RemoveHelper => {
                self.start_warp_operation(WarpOperation::RemoveHelper, None, None)
            }
            WarpPendingConfirm::RestartXray => {
                self.start_service_operation(ServiceOperation::Restart)
            }
        }
    }

    /// Cancels a pending WARP confirmation dialog without starting work.
    pub fn cancel_warp_pending(&mut self) {
        self.warp_pending_confirm = None;
    }

    /// Queues confirmation for full managed WARP setup.
    pub fn request_warp_setup(&mut self) -> Result<(), String> {
        self.require_warp_can_queue()?;
        self.warp_pending_confirm = Some(WarpPendingConfirm::Setup {
            preferred_tag: self.warp_preferred_tag.clone(),
        });
        Ok(())
    }

    /// Queues confirmation for adopting a Possible WARP outbound.
    pub fn request_warp_adopt(&mut self) -> Result<(), String> {
        self.require_warp_can_queue()?;
        let tag = self
            .warp_summary
            .as_ref()
            .and_then(|summary| summary.outbound_tag.clone())
            .ok_or_else(|| "No WARP outbound available to adopt.".to_owned())?;
        let summary_line = format!("Adopt outbound `{tag}` as managed WARP.");
        self.warp_pending_confirm = Some(WarpPendingConfirm::Adopt {
            outbound_tag: tag,
            summary_line,
        });
        Ok(())
    }

    /// Starts a background WARP connectivity probe.
    pub fn request_warp_test(&mut self) -> Result<(), String> {
        self.start_warp_operation(WarpOperation::TestConnectivity, None, None)
    }

    /// Queues confirmation for regenerating managed WARP credentials.
    pub fn request_warp_regenerate(&mut self) -> Result<(), String> {
        self.require_warp_can_queue()?;
        self.warp_pending_confirm = Some(WarpPendingConfirm::Regenerate);
        Ok(())
    }

    /// Queues confirmation for removing the managed WARP outbound.
    pub fn request_warp_remove_integration(&mut self) -> Result<(), String> {
        self.require_warp_can_queue()?;
        let summary = self
            .warp_summary
            .as_ref()
            .ok_or_else(|| "Refresh WARP status first.".to_owned())?;
        let outbound_tag = summary
            .outbound_tag
            .clone()
            .ok_or_else(|| "No managed WARP outbound to remove.".to_owned())?;
        let blocking_references = summary.routing_references.clone();
        self.warp_pending_confirm = Some(WarpPendingConfirm::RemoveIntegration {
            outbound_tag,
            blocking_references,
        });
        Ok(())
    }

    /// Queues confirmation for removing only the managed WARP helper.
    pub fn request_warp_remove_helper(&mut self) -> Result<(), String> {
        self.require_warp_can_queue()?;
        self.warp_pending_confirm = Some(WarpPendingConfirm::RemoveHelper);
        Ok(())
    }

    /// Polls for a completed WARP worker outcome.
    pub fn poll_warp(&mut self) {
        let Some(rx) = &self.warp_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.warp_rx = None;
                if outcome.generation != self.warp_generation {
                    // Stale after disconnect or a superseded generation — release
                    // exclusivity without applying the payload.
                    if self.warp_ui.is_busy() {
                        self.warp_ui = WarpUiState::Idle;
                    } else {
                        self.show_status_message("Stale WARP result discarded.");
                    }
                    return;
                }

                match outcome.result {
                    Ok(payload) => self.apply_warp_success(outcome.operation, payload),
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.detail());
                        error!(
                            target: "app",
                            kind = ?error.kind(),
                            detail = %technical,
                            "WARP operation failed"
                        );
                        let detail = user_facing_warp_error(&error);
                        self.warp_ui = WarpUiState::Failed {
                            kind: error.kind(),
                            detail: detail.clone(),
                        };
                        self.show_status_message(detail);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.warp_rx = None;
                if self.warp_ui.is_busy() {
                    self.warp_ui = WarpUiState::Failed {
                        kind: crate::xray::WarpErrorKind::CommandFailed,
                        detail: "WARP worker ended unexpectedly.".to_owned(),
                    };
                    self.show_status_message("WARP operation failed unexpectedly.");
                }
            }
        }
    }

    fn require_warp_can_queue(&self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if !matches!(self.discovery, DiscoveryState::Succeeded(_)) {
            return Err("Run discovery on the Connection page first.".to_owned());
        }
        if self.loaded_config.editable().is_none() {
            return Err(
                "Configuration not loaded. Discover Xray again after the config becomes readable."
                    .to_owned(),
            );
        }
        if self.warp_ui.is_busy() {
            return Err("Another WARP operation is already running.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        Ok(())
    }

    fn start_warp_operation(
        &mut self,
        operation: WarpOperation,
        preferred_tag: Option<String>,
        adopt_tag: Option<String>,
    ) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        let DiscoveryState::Succeeded(installation) = &self.discovery else {
            return Err("Run discovery on the Connection page first.".to_owned());
        };
        if self.loaded_config.editable().is_none() {
            return Err(
                "Configuration not loaded. Discover Xray again after the config becomes readable."
                    .to_owned(),
            );
        }
        if self.warp_ui.is_busy() {
            return Err("Another WARP operation is already running.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let preferred_tag = preferred_tag.unwrap_or_else(|| self.warp_preferred_tag.clone());
        let adopt_tag = adopt_tag.or_else(|| {
            self.warp_summary
                .as_ref()
                .and_then(|summary| summary.outbound_tag.clone())
        });
        let existing_tags = self
            .loaded_config
            .outbounds()
            .iter()
            .filter_map(|outbound| outbound.tag.clone())
            .collect::<Vec<_>>();
        let context = WarpWorkerContext {
            preferred_tag,
            adopt_tag,
            editable: self.loaded_config.editable().cloned(),
            xray_version: installation.version.clone(),
            existing_tags,
            validate_hint: self.config_validate_hint(),
        };

        self.warp_generation = self.warp_generation.saturating_add(1);
        let generation = self.warp_generation;

        let (tx, rx) = mpsc::channel();
        self.warp_rx = Some(rx);
        self.warp_ui = WarpUiState::Busy(operation);
        self.status_message_until = None;
        self.operation = CurrentOperation::ManagingWarp {
            text: operation.status_message().to_owned(),
        };

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();

        info!(
            target: "app",
            operation = ?operation,
            generation,
            "starting WARP operation"
        );

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(WarpOutcome {
                        operation,
                        generation,
                        result: Err(crate::xray::WarpError::new(
                            crate::xray::WarpErrorKind::CommandFailed,
                            format!("failed to start async runtime: {error}"),
                        )),
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(run_warp_operation(
                &client, &profile, &secrets, &remote, operation, generation, context,
            ));
            let _ = tx.send(outcome);
        });

        Ok(())
    }

    fn apply_warp_success(&mut self, operation: WarpOperation, payload: WarpOutcomePayload) {
        self.warp_ui = WarpUiState::Idle;
        match payload {
            WarpOutcomePayload::Summary(summary) => {
                self.warp_summary = Some(summary);
                let message = match operation {
                    WarpOperation::Discover => "WARP status refreshed.",
                    WarpOperation::InstallHelper => "WARP helper installed.",
                    _ => "WARP operation completed.",
                };
                self.show_status_message(message);
            }
            WarpOutcomePayload::Setup {
                summary,
                editable,
                ownership,
                proposed,
            } => {
                self.replace_loaded_editable(editable);
                self.warp_summary = Some(summary);
                self.warp_ownership = Some(ownership);
                self.warp_proposed = Some(proposed);
                self.warp_routing_notice = Some(
                    "WARP outbound was added successfully.\nNo routing rules were changed."
                        .to_owned(),
                );
                self.warp_pending_confirm = Some(WarpPendingConfirm::RestartXray);
                self.show_status_message(
                    "Xray configuration was updated.\nRestart Xray to apply the change.",
                );
            }
            WarpOutcomePayload::Adopted {
                summary,
                ownership,
            } => {
                self.warp_summary = Some(summary);
                self.warp_ownership = Some(ownership);
                self.show_status_message("WARP outbound adopted.");
            }
            WarpOutcomePayload::Connectivity { summary, result } => {
                self.warp_summary = Some(summary);
                let message = if result.available && result.warp_active == Some(true) {
                    "WARP connectivity test succeeded."
                } else if !result.available {
                    "WARP connectivity test unavailable."
                } else {
                    "WARP connectivity test completed."
                };
                self.show_status_message(message);
            }
            WarpOutcomePayload::Regenerated {
                summary,
                editable,
                proposed,
            } => {
                self.replace_loaded_editable(editable);
                self.warp_summary = Some(summary);
                self.warp_proposed = Some(proposed);
                self.warp_pending_confirm = Some(WarpPendingConfirm::RestartXray);
                self.show_status_message(
                    "Xray configuration was updated.\nRestart Xray to apply the change.",
                );
            }
            WarpOutcomePayload::Removed {
                summary,
                editable,
            } => {
                self.replace_loaded_editable(editable);
                self.warp_summary = Some(summary);
                self.warp_ownership = None;
                self.warp_proposed = None;
                self.warp_routing_notice = None;
                self.warp_pending_confirm = Some(WarpPendingConfirm::RestartXray);
                self.show_status_message(
                    "Xray configuration was updated.\nRestart Xray to apply the change.",
                );
            }
            WarpOutcomePayload::HelperRemoved { summary } => {
                self.warp_summary = Some(summary);
                self.show_status_message("WARP helper removed.");
            }
        }
    }

    fn replace_loaded_editable(&mut self, editable: EditableXrayConfig) {
        let inbounds = editable.inbound_summaries();
        let outbounds = editable.outbound_summaries();
        let dns = editable.dns_summary();
        let fakedns = editable.fakedns_summary();
        let observatory = editable.observatory_summary();
        let burst_observatory = editable.burst_observatory_summary();
        let routing = editable.routing_summary();
        let policy = editable.policy_summary();
        let vless_clients = editable.vless_clients();
        let warnings = self.loaded_config.warnings().to_vec();
        self.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds,
            outbounds,
            dns,
            fakedns,
            observatory,
            burst_observatory,
            routing,
            policy,
            vless_clients,
            warnings,
            editable: Some(editable),
        };
    }

    fn clear_warp_state(&mut self) {
        self.warp_summary = None;
        self.warp_ui = WarpUiState::Idle;
        self.warp_rx = None;
        self.warp_generation = 0;
        self.warp_preferred_tag = default_preferred_tag();
        self.warp_pending_confirm = None;
        self.warp_proposed = None;
        self.warp_routing_notice = None;
        self.warp_ownership = None;
    }

    /// Invalidates in-flight WARP UI state on disconnect without releasing
    /// remote exclusivity until the worker channel drains.
    fn invalidate_warp_on_disconnect(&mut self) {
        self.warp_summary = None;
        self.warp_preferred_tag = default_preferred_tag();
        self.warp_pending_confirm = None;
        self.warp_proposed = None;
        self.warp_routing_notice = None;
        self.warp_ownership = None;
        if self.warp_rx.is_some() || self.warp_ui.is_busy() {
            // Keep Busy + rx so is_any_remote_busy stays true while the worker
            // may still mutate the remote host. Bump generation so the result
            // is discarded when it arrives.
            self.warp_generation = self.warp_generation.saturating_add(1);
            if !self.warp_ui.is_busy() {
                self.warp_ui = WarpUiState::Busy(WarpOperation::Discover);
            }
        } else {
            self.warp_ui = WarpUiState::Idle;
            self.warp_generation = 0;
        }
    }

    /// Application action: AddUser.
    pub fn start_add_user(&mut self, request: AddUserRequest) -> Result<(), String> {
        self.start_user_mutation(UserMutationKind::Add, UserMutationRequest::Add(request))
    }

    /// Application action: UpdateUser.
    pub fn start_update_user(&mut self, request: UpdateUserRequest) -> Result<(), String> {
        self.start_user_mutation(
            UserMutationKind::Update,
            UserMutationRequest::Update(request),
        )
    }

    /// Application action: DeleteUser.
    pub fn start_delete_user(&mut self, request: DeleteUserRequest) -> Result<(), String> {
        self.start_user_mutation(
            UserMutationKind::Delete,
            UserMutationRequest::Delete(request),
        )
    }

    /// Application action: Add Trojan client (IB-L1).
    pub fn start_add_trojan_client(
        &mut self,
        inbound_index: usize,
        email: String,
        password: crate::xray::SecretString,
        level: u32,
    ) -> Result<(), String> {
        self.start_user_mutation(
            UserMutationKind::Add,
            UserMutationRequest::AddTrojan {
                inbound_index,
                email,
                password,
                level,
            },
        )
    }

    /// Application action: Update Trojan client (IB-L1).
    pub fn start_update_trojan_client(
        &mut self,
        inbound_index: usize,
        client_index: usize,
        email: String,
        password: crate::xray::SecretFieldDraft,
        level: u32,
        expected_fingerprint: Option<String>,
    ) -> Result<(), String> {
        self.start_user_mutation(
            UserMutationKind::Update,
            UserMutationRequest::UpdateTrojan {
                inbound_index,
                client_index,
                email,
                password,
                level,
                expected_fingerprint,
            },
        )
    }

    /// Application action: Delete Trojan client (same request as VLESS).
    pub fn start_delete_trojan_client(
        &mut self,
        request: DeleteUserRequest,
    ) -> Result<(), String> {
        self.start_user_mutation(UserMutationKind::Delete, UserMutationRequest::Delete(request))
    }

    /// Application action: Add Hysteria user (Wave A).
    pub fn start_add_hysteria_client(
        &mut self,
        inbound_index: usize,
        email: String,
        auth: crate::xray::SecretString,
        level: u32,
    ) -> Result<(), String> {
        self.start_user_mutation(
            UserMutationKind::Add,
            UserMutationRequest::AddHysteria {
                inbound_index,
                email,
                auth,
                level,
            },
        )
    }

    /// Application action: Update Hysteria user (Wave A).
    pub fn start_update_hysteria_client(
        &mut self,
        inbound_index: usize,
        client_index: usize,
        email: String,
        auth: crate::xray::SecretFieldDraft,
        level: u32,
        expected_fingerprint: Option<String>,
    ) -> Result<(), String> {
        self.start_user_mutation(
            UserMutationKind::Update,
            UserMutationRequest::UpdateHysteria {
                inbound_index,
                client_index,
                email,
                auth,
                level,
                expected_fingerprint,
            },
        )
    }

    /// Application action: Delete Hysteria user (same request as VLESS/Trojan).
    pub fn start_delete_hysteria_client(
        &mut self,
        request: DeleteUserRequest,
    ) -> Result<(), String> {
        self.start_user_mutation(UserMutationKind::Delete, UserMutationRequest::Delete(request))
    }

    fn start_user_mutation(
        &mut self,
        kind: UserMutationKind,
        request: UserMutationRequest,
    ) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }

        let editable = match self.loaded_config.editable() {
            Some(editable) => editable.clone(),
            None => return Err("Configuration not loaded for editing.".to_owned()),
        };

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let (tx, rx) = mpsc::channel();
        self.user_mutation_rx = Some(rx);
        self.status_message_until = None;
        self.operation = match kind {
            UserMutationKind::Add => CurrentOperation::AddingUser,
            UserMutationKind::Update => CurrentOperation::UpdatingUser,
            UserMutationKind::Delete => CurrentOperation::DeletingUser,
        };

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let validate_hint = self.config_validate_hint();

        info!(target: "app", kind = ?kind, "starting user mutation");

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(UserMutationOutcome {
                        kind,
                        result: Err(crate::xray::ConfigModifyError::new(
                            crate::xray::ConfigModifyErrorKind::UploadFailed,
                            format!("failed to start async runtime: {error}"),
                        )),
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(async {
                match request {
                    UserMutationRequest::Add(request) => {
                        run_add_user(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            request,
                            validate_hint.clone(),
                        )
                        .await
                    }
                    UserMutationRequest::Update(request) => {
                        run_update_user(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            request,
                            validate_hint.clone(),
                        )
                        .await
                    }
                    UserMutationRequest::Delete(request) => {
                        run_delete_user(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            request,
                            validate_hint.clone(),
                        )
                        .await
                    }
                    UserMutationRequest::AddTrojan {
                        inbound_index,
                        email,
                        password,
                        level,
                    } => {
                        let req = crate::xray::AddInboundClientRequest::Trojan {
                            inbound_index,
                            email,
                            password,
                            level,
                        };
                        super::user_ops::run_add_inbound_client(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            req,
                            validate_hint.clone(),
                        )
                        .await
                    }
                    UserMutationRequest::UpdateTrojan {
                        inbound_index,
                        client_index,
                        email,
                        password,
                        level,
                        expected_fingerprint,
                    } => {
                        let req = crate::xray::UpdateInboundClientRequest::Trojan {
                            inbound_index,
                            client_index,
                            email,
                            password,
                            level,
                            expected_fingerprint,
                        };
                        super::user_ops::run_update_inbound_client(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            req,
                            validate_hint,
                        )
                        .await
                    }
                    UserMutationRequest::AddHysteria {
                        inbound_index,
                        email,
                        auth,
                        level,
                    } => {
                        let req = crate::xray::AddInboundClientRequest::Hysteria {
                            inbound_index,
                            email,
                            auth,
                            level,
                        };
                        super::user_ops::run_add_inbound_client(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            req,
                            validate_hint,
                        )
                        .await
                    }
                    UserMutationRequest::UpdateHysteria {
                        inbound_index,
                        client_index,
                        email,
                        auth,
                        level,
                        expected_fingerprint,
                    } => {
                        let req = crate::xray::UpdateInboundClientRequest::Hysteria {
                            inbound_index,
                            client_index,
                            email,
                            auth,
                            level,
                            expected_fingerprint,
                        };
                        super::user_ops::run_update_inbound_client(
                            &client,
                            &profile,
                            &secrets,
                            &remote,
                            editable,
                            req,
                            validate_hint,
                        )
                        .await
                    }
                }
            });
            let _ = tx.send(outcome);
        });

        Ok(())
    }

    /// Polls for a completed Add/Update/Delete user operation.
    pub fn poll_user_mutation(&mut self) {
        let Some(rx) = &self.user_mutation_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.user_mutation_rx = None;
                match outcome.result {
                    Ok(success) => {
                        let inbound_index = self
                            .inbound_editor_session
                            .as_ref()
                            .map(|s| s.inbound_index);
                        let vision_active = inbound_index.and_then(|idx| {
                            success
                                .editable
                                .sections()
                                .inbounds()
                                .get(idx)
                                .map(|inbound| {
                                    crate::xray::vision_active_from_inbound(inbound.value())
                                })
                        });
                        let inbounds = success.editable.inbound_summaries();
                        let outbounds = success.editable.outbound_summaries();
                        let dns = success.editable.dns_summary();
                        let fakedns = success.editable.fakedns_summary();
                        let observatory = success.editable.observatory_summary();
                        let burst_observatory = success.editable.burst_observatory_summary();
                        let routing = success.editable.routing_summary();
                        let policy = success.editable.policy_summary();
                        let vless_clients = success.editable.vless_clients();
                        let warnings = self.loaded_config.warnings().to_vec();
                        self.loaded_config = LoadedConfigSnapshot::Loaded {
                            inbounds,
                            outbounds,
                            dns,
                            fakedns,
                            observatory,
                            burst_observatory,
                            routing,
                            policy,
                            vless_clients,
                            warnings,
                            editable: Some(success.editable),
                        };
                        if let (Some(vision), Some(session)) =
                            (vision_active, self.inbound_editor_session.as_mut())
                        {
                            session.vision_active = vision;
                        }
                        self.refresh_editor_fingerprint();
                        self.show_status_message(
                            "User updated. Configuration updated. Xray restart required.",
                        );
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.message().as_str());
                        error!(
                            target: "app",
                            kind = ?outcome.kind,
                            detail = %technical,
                            "user mutation failed"
                        );
                        self.show_status_message(crate::logging::redact::user_message_see_log(
                            "Unable to update user configuration.",
                        ));
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.user_mutation_rx = None;
                if matches!(
                    self.operation,
                    CurrentOperation::AddingUser
                        | CurrentOperation::UpdatingUser
                        | CurrentOperation::DeletingUser
                ) {
                    self.show_status_message("Upload failed: worker ended unexpectedly");
                }
            }
        }
    }

    /// Read-only / edit model for the Log Settings page.
    pub fn log_settings_page_model(&self) -> LogSettingsPageModel {
        build_log_settings_page_model(
            self.ssh_status,
            &self.discovery,
            &self.loaded_config,
            self.log_settings_draft.as_ref(),
            self.is_log_settings_mutation_busy(),
            self.log_settings_error.clone(),
            self.log_settings_saved_flash,
        )
    }

    /// Enters edit mode with an in-memory draft cloned from the loaded config.
    pub fn begin_edit_log_settings(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if !matches!(self.discovery, DiscoveryState::Succeeded(_)) {
            return Err("Xray not discovered.".to_owned());
        }
        let settings = {
            let Some(editable) = self.loaded_config.editable() else {
                return Err("Configuration not loaded.".to_owned());
            };
            editable.log_settings()
        };
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        self.show_status_message("Loading log settings...");
        self.log_settings_draft = Some(settings);
        self.log_settings_error = None;
        self.log_settings_saved_flash = false;
        self.clear_current_operation();
        Ok(())
    }

    /// Discards the in-memory draft and returns to view mode.
    pub fn cancel_edit_log_settings(&mut self) {
        self.log_settings_draft = None;
        self.log_settings_error = None;
        self.log_settings_saved_flash = false;
        self.clear_current_operation();
    }

    /// Mutable access to the log-settings draft (edit mode only).
    pub fn log_settings_draft_mut(&mut self) -> Option<&mut LogSettings> {
        self.log_settings_draft.as_mut()
    }

    /// Borrowed log-settings draft.
    pub fn log_settings_draft(&self) -> Option<&LogSettings> {
        self.log_settings_draft.as_ref()
    }

    /// Validates the draft and starts the remote save workflow.
    pub fn start_save_log_settings(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if !matches!(self.discovery, DiscoveryState::Succeeded(_)) {
            return Err("Xray not discovered.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }

        let draft = match &self.log_settings_draft {
            Some(draft) => draft.clone(),
            None => return Err("Not in edit mode.".to_owned()),
        };

        self.show_status_message("Validating log settings...");
        if let Err(error) = validate_log_settings(&draft) {
            self.log_settings_error = Some(error.message());
            return Err(error.message());
        }

        let editable = match self.loaded_config.editable() {
            Some(editable) => editable.clone(),
            None => return Err("Configuration not loaded.".to_owned()),
        };

        let profile =
            match validate_for_connection_test(&self.connection_draft, &self.connection_secrets) {
                Ok(profile) => {
                    self.connection_errors = ConnectionValidationErrors::default();
                    profile
                }
                Err(errors) => {
                    self.connection_errors = errors;
                    return Err("Connection profile is incomplete.".to_owned());
                }
            };

        let (tx, rx) = mpsc::channel();
        self.log_settings_rx = Some(rx);
        self.log_settings_error = None;
        self.log_settings_saved_flash = false;
        self.status_message_until = None;
        self.operation = CurrentOperation::SavingLogSettings;
        self.show_status_message("Saving log settings...");

        let client = self.ssh_client.clone();
        let secrets = self.connection_secrets.clone();
        let remote = self.remote.clone();
        let request = UpdateLogSettingsRequest { settings: draft };
        let validate_hint = self.config_validate_hint();

        info!(target: "app", "starting log settings mutation");

        thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(LogSettingsMutationOutcome {
                        result: Err(crate::xray::ConfigModifyError::new(
                            crate::xray::ConfigModifyErrorKind::UploadFailed,
                            format!("failed to start async runtime: {error}"),
                        )),
                    });
                    return;
                }
            };

            let outcome = runtime.block_on(run_update_log_settings(
                &client,
                &profile,
                &secrets,
                &remote,
                editable,
                request,
                validate_hint,
            ));
            let _ = tx.send(outcome);
        });

        Ok(())
    }

    /// Polls for a completed log-settings save.
    pub fn poll_log_settings_mutation(&mut self) {
        let Some(rx) = &self.log_settings_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(outcome) => {
                self.log_settings_rx = None;
                match outcome.result {
                    Ok(success) => {
                        let inbounds = success.editable.inbound_summaries();
                        let outbounds = success.editable.outbound_summaries();
                        let dns = success.editable.dns_summary();
                        let fakedns = success.editable.fakedns_summary();
                        let observatory = success.editable.observatory_summary();
                        let burst_observatory = success.editable.burst_observatory_summary();
                        let routing = success.editable.routing_summary();
                        let policy = success.editable.policy_summary();
                        let vless_clients = success.editable.vless_clients();
                        let warnings = self.loaded_config.warnings().to_vec();
                        self.loaded_config = LoadedConfigSnapshot::Loaded {
                            inbounds,
                            outbounds,
                            dns,
                            fakedns,
                            observatory,
                            burst_observatory,
                            routing,
                            policy,
                            vless_clients,
                            warnings,
                            editable: Some(success.editable),
                        };
                        self.log_settings_draft = None;
                        self.log_settings_error = None;
                        self.log_settings_saved_flash = true;
                        self.stop_xray_log_follow();
                        self.xray_logs.entries.clear();
                        self.xray_logs.generation = self.xray_logs.generation.saturating_add(1);
                        self.seed_xray_log_sources();
                        self.show_status_message(
                            "Log settings were updated. Restart or reload Xray to apply the changes.",
                        );
                    }
                    Err(error) => {
                        let technical =
                            crate::logging::redact::sanitize_detail(error.message().as_str());
                        error!(
                            target: "app",
                            detail = %technical,
                            "Xray log settings validation failed"
                        );
                        let user_message = user_facing_log_settings_error(&error);
                        self.log_settings_error = Some(user_message.clone());
                        self.show_status_message(user_message);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.log_settings_rx = None;
                if matches!(self.operation, CurrentOperation::SavingLogSettings) {
                    self.log_settings_error =
                        Some("Remote write failed: worker ended unexpectedly".to_owned());
                    self.show_status_message("Remote write failed: worker ended unexpectedly");
                }
            }
        }
    }

    /// Read-only model for the Xray Logs page.
    pub fn xray_logs_page_model(&self) -> XrayLogsPageModel {
        build_xray_logs_page_model(
            self.ssh_status,
            &self.discovery,
            &self.xray_logs,
            self.is_any_remote_busy() && !self.xray_logs.ui_state.is_busy(),
        )
    }

    /// Returns `true` while Xray log follow is active (for GUI repaint).
    pub fn is_xray_log_following(&self) -> bool {
        self.xray_logs.ui_state.is_following()
    }

    /// Stops follow when leaving the Xray Logs page.
    pub fn leave_xray_logs_page(&mut self) {
        if self.xray_logs.ui_state.is_following() {
            self.stop_xray_log_follow();
        }
    }

    fn seed_xray_log_sources(&mut self) {
        let editable = self.loaded_config.editable().cloned();
        let installation = match &self.discovery {
            DiscoveryState::Succeeded(installation) => Some(installation),
            _ => None,
        };
        self.xray_logs.sources =
            XrayLogService::new().resolve_sources(installation, editable.as_ref());
        self.xray_logs.sources_probed = false;
        // Prefer Error Log when available, else first readable source.
        if let Some(preferred) = self
            .xray_logs
            .sources
            .iter()
            .find(|s| s.kind == XrayLogSourceKind::ErrorFile && s.availability.is_readable())
            .or_else(|| {
                self.xray_logs
                    .sources
                    .iter()
                    .find(|s| s.availability.is_readable())
            })
        {
            self.xray_logs.selected = preferred.kind;
        }
    }

    /// Starts a source probe once after discovery (or when opening Xray Logs).
    pub fn ensure_xray_log_sources_probed(&mut self) {
        if self.xray_logs.sources_probed || self.xray_logs.ui_state.is_busy() {
            return;
        }
        if self.ssh_status != SshStatus::Connected {
            return;
        }
        if !matches!(self.discovery, DiscoveryState::Succeeded(_)) {
            return;
        }
        let _ = self.start_xray_log_source_probe();
    }

    /// Selects a log source; stops any active follow session.
    pub fn select_xray_log_source(&mut self, kind: XrayLogSourceKind) {
        if self.xray_logs.selected == kind {
            return;
        }
        self.stop_xray_log_follow();
        self.xray_logs.selected = kind;
        self.xray_logs.entries.clear();
        self.xray_logs.search = Default::default();
        self.xray_logs.generation = self.xray_logs.generation.saturating_add(1);
        self.xray_logs.last_error = None;
        self.xray_logs.ui_state = XrayLogsUiState::Idle;
        self.xray_logs.event_rx = None;
    }

    /// Sets the line limit for subsequent reads.
    pub fn set_xray_log_line_limit(&mut self, limit: XrayLogLineLimit) {
        self.xray_logs.line_limit = limit;
    }

    /// Updates local search over currently loaded entries (no remote calls).
    pub fn set_xray_log_search_query(&mut self, query: &str) {
        self.xray_logs
            .search
            .recompute(&self.xray_logs.entries, query);
    }

    /// Moves to the next local search match.
    pub fn xray_log_search_next(&mut self) -> Option<usize> {
        self.xray_logs.search.next()
    }

    /// Moves to the previous local search match.
    pub fn xray_log_search_previous(&mut self) -> Option<usize> {
        self.xray_logs.search.previous()
    }

    /// Probes remote availability of log sources.
    pub fn start_xray_log_source_probe(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let DiscoveryState::Succeeded(installation) = &self.discovery else {
            return Err("Xray not discovered.".to_owned());
        };
        let installation = installation.clone();
        let profile =
            validate_for_connection_test(&self.connection_draft, &self.connection_secrets)
                .map_err(|_| "Invalid connection profile.".to_owned())?;

        self.stop_xray_log_follow();
        self.xray_logs.generation = self.xray_logs.generation.saturating_add(1);
        let generation = self.xray_logs.generation;
        let (tx, rx) = xray_log_probe_channel();
        self.xray_logs.probe_rx = Some(rx);
        self.xray_logs.ui_state = XrayLogsUiState::Loading;
        self.operation = CurrentOperation::ManagingXrayLogs {
            text: "Loading Xray logs...".to_owned(),
        };

        spawn_xray_log_probe(
            self.ssh_client.clone(),
            profile,
            self.connection_secrets.clone(),
            installation,
            self.loaded_config.editable().cloned(),
            generation,
            tx,
        );
        Ok(())
    }

    /// Refreshes the selected source (last N lines).
    pub fn start_xray_log_refresh(&mut self) -> Result<(), String> {
        self.start_xray_log_read("Loading Xray logs...")
    }

    fn start_xray_log_read(&mut self, status: &str) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() && !self.xray_logs.ui_state.is_following() {
            return Err("Another operation is already running.".to_owned());
        }
        if self.xray_logs.ui_state.is_following() {
            return Err("Stop follow before refreshing.".to_owned());
        }
        let DiscoveryState::Succeeded(installation) = &self.discovery else {
            return Err("Xray not discovered.".to_owned());
        };
        let installation = installation.clone();
        let profile =
            validate_for_connection_test(&self.connection_draft, &self.connection_secrets)
                .map_err(|_| "Invalid connection profile.".to_owned())?;

        self.xray_logs.generation = self.xray_logs.generation.saturating_add(1);
        let generation = self.xray_logs.generation;
        let kind = self.xray_logs.selected;
        let limit = self.xray_logs.line_limit;
        let (tx, rx) = xray_log_event_channel();
        self.xray_logs.event_rx = Some(rx);
        self.xray_logs.ui_state = XrayLogsUiState::Loading;
        self.xray_logs.last_error = None;
        self.operation = CurrentOperation::ManagingXrayLogs {
            text: status.to_owned(),
        };

        spawn_xray_log_read(
            self.ssh_client.clone(),
            profile,
            self.connection_secrets.clone(),
            installation,
            self.loaded_config.editable().cloned(),
            kind,
            limit,
            generation,
            tx,
        );
        Ok(())
    }

    /// Starts follow mode for the selected source.
    pub fn start_xray_log_follow(&mut self) -> Result<(), String> {
        if self.ssh_status != SshStatus::Connected {
            return Err("No SSH connection.".to_owned());
        }
        if self.is_any_remote_busy() {
            return Err("Another operation is already running.".to_owned());
        }
        let DiscoveryState::Succeeded(installation) = &self.discovery else {
            return Err("Xray not discovered.".to_owned());
        };
        let installation = installation.clone();
        let profile =
            validate_for_connection_test(&self.connection_draft, &self.connection_secrets)
                .map_err(|_| "Invalid connection profile.".to_owned())?;

        self.stop_xray_log_follow();
        self.xray_logs.generation = self.xray_logs.generation.saturating_add(1);
        let generation = self.xray_logs.generation;
        let kind = self.xray_logs.selected;
        let limit = self.xray_logs.line_limit;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.xray_logs.follow_stop = Some(std::sync::Arc::clone(&stop));
        let (tx, rx) = xray_log_event_channel();
        self.xray_logs.event_rx = Some(rx);
        self.xray_logs.ui_state = XrayLogsUiState::Following;
        self.xray_logs.last_error = None;
        self.operation = CurrentOperation::ManagingXrayLogs {
            text: format!(
                "Following Xray {}...",
                kind.display_name().to_ascii_lowercase()
            ),
        };

        spawn_xray_log_follow(
            self.ssh_client.clone(),
            profile,
            self.connection_secrets.clone(),
            installation,
            self.loaded_config.editable().cloned(),
            kind,
            limit,
            generation,
            stop,
            tx,
        );
        Ok(())
    }

    /// Stops the active follow session.
    pub fn stop_xray_log_follow(&mut self) {
        let was_following = self.xray_logs.ui_state.is_following();
        self.xray_logs.stop_follow();
        if was_following {
            self.show_status_message("Xray log follow stopped.");
        }
    }

    /// Polls probe and stream workers for the Xray Logs page.
    pub fn poll_xray_logs(&mut self) {
        if self.xray_logs.probe_rx.is_some() {
            let next = self
                .xray_logs
                .probe_rx
                .as_ref()
                .map(|rx| rx.try_recv());
            match next {
                Some(Ok(outcome)) => {
                    self.xray_logs.probe_rx = None;
                    if outcome.generation == self.xray_logs.generation {
                        match outcome.result {
                            Ok(sources) => {
                                self.xray_logs.sources = sources;
                                self.xray_logs.sources_probed = true;
                                if matches!(self.xray_logs.ui_state, XrayLogsUiState::Loading)
                                    && self.xray_logs.event_rx.is_none()
                                {
                                    self.xray_logs.ui_state = XrayLogsUiState::Idle;
                                    self.show_status_message("Xray logs loaded.");
                                    // First successful probe: load selected source content.
                                    if self.xray_logs.entries.is_empty() {
                                        let _ = self.start_xray_log_refresh();
                                    }
                                }
                            }
                            Err(error) => {
                                self.xray_logs.sources_probed = true;
                                self.xray_logs.last_error = Some(error.clone());
                                self.xray_logs.ui_state = XrayLogsUiState::Failed {
                                    kind: error.kind,
                                    detail: error.detail.clone(),
                                };
                                self.show_status_message(error.kind.label().to_owned());
                            }
                        }
                    }
                }
                Some(Err(TryRecvError::Empty)) => {}
                Some(Err(TryRecvError::Disconnected)) | None => {
                    self.xray_logs.probe_rx = None;
                }
            }
        }

        loop {
            let next = self
                .xray_logs
                .event_rx
                .as_ref()
                .map(|rx| rx.try_recv());
            let event = match next {
                None => break,
                Some(Ok(event)) => event,
                Some(Err(TryRecvError::Empty)) => break,
                Some(Err(TryRecvError::Disconnected)) => {
                    self.xray_logs.event_rx = None;
                    if self.xray_logs.ui_state.is_following() {
                        self.xray_logs.ui_state = XrayLogsUiState::Failed {
                            kind: crate::xray::XrayLogErrorKind::FollowSessionInterrupted,
                            detail: "Follow worker ended unexpectedly.".to_owned(),
                        };
                        self.xray_logs.follow_stop = None;
                        self.show_status_message("Xray log follow stopped.");
                    } else if matches!(self.xray_logs.ui_state, XrayLogsUiState::Loading) {
                        self.xray_logs.ui_state = XrayLogsUiState::Failed {
                            kind: crate::xray::XrayLogErrorKind::RemoteReadFailed,
                            detail: "Log worker ended unexpectedly.".to_owned(),
                        };
                        self.show_status_message("Remote read failed");
                    }
                    break;
                }
            };

            let was_follow_stop =
                matches!(event, crate::xray::XrayLogStreamEvent::FollowStopped { .. });
            let was_failed = matches!(event, crate::xray::XrayLogStreamEvent::Failed { .. });
            let was_replace = matches!(event, crate::xray::XrayLogStreamEvent::Replace { .. });
            apply_xray_log_event(&mut self.xray_logs, event);

            if was_failed || was_follow_stop {
                self.xray_logs.event_rx = None;
                if was_follow_stop && matches!(self.xray_logs.ui_state, XrayLogsUiState::Idle) {
                    self.show_status_message("Xray log follow stopped.");
                } else if let XrayLogsUiState::Failed { kind, .. } = &self.xray_logs.ui_state {
                    self.show_status_message(kind.label().to_owned());
                }
            } else if was_replace && !self.xray_logs.ui_state.is_following() {
                self.xray_logs.event_rx = None;
                self.show_status_message("Xray logs loaded.");
            } else if self.xray_logs.ui_state.is_following() {
                self.operation = CurrentOperation::ManagingXrayLogs {
                    text: format!(
                        "Following Xray {}...",
                        self.xray_logs.selected.display_name().to_ascii_lowercase()
                    ),
                };
            }
        }
    }

    /// Clears expired transient Status Bar messages and polls async work.
    pub fn tick_status(&mut self) {
        self.poll_connection_test();
        self.poll_discovery();
        self.poll_user_mutation();
        self.poll_inbound_shell_mutation();
        self.poll_inbound_mutation();
        self.poll_outbound_mutation();
        self.poll_log_settings_mutation();
        self.poll_service_operation();
        self.poll_unit_operations();
        self.poll_xray_lifecycle();
        self.poll_version_check();
        self.poll_geodata();
        self.poll_warp();
        self.poll_xray_logs();

        if let Some(until) = self.status_message_until
            && Instant::now() >= until
        {
            self.status_message_until = None;
            if matches!(self.operation, CurrentOperation::Message { .. }) {
                self.operation = CurrentOperation::Ready;
            }
        }
    }

    /// Shows a short-lived Status Bar message, then returns to [`CurrentOperation::Ready`].
    pub fn show_status_message(&mut self, text: impl Into<String>) {
        self.operation = CurrentOperation::Message { text: text.into() };
        self.status_message_until = Some(Instant::now() + STATUS_MESSAGE_DURATION);
    }

    /// Sets the transient current operation shown in the Status Bar.
    pub fn set_current_operation(&mut self, operation: CurrentOperation) {
        self.status_message_until = None;
        self.operation = operation;
    }

    /// Marks the application as idle (`Ready`).
    pub fn clear_current_operation(&mut self) {
        self.status_message_until = None;
        self.operation = CurrentOperation::Ready;
    }

    /// Updates progress for the current operation when it supports progress.
    pub fn set_operation_progress(&mut self, progress: OperationProgress) {
        match &mut self.operation {
            CurrentOperation::UploadingConfig { progress: current }
            | CurrentOperation::RestartingXray { progress: current }
            | CurrentOperation::CreatingBackup { progress: current } => {
                *current = progress;
            }
            CurrentOperation::Ready
            | CurrentOperation::Message { .. }
            | CurrentOperation::Connecting { .. }
            | CurrentOperation::DiscoveringXray
            | CurrentOperation::AddingUser
            | CurrentOperation::UpdatingUser
            | CurrentOperation::DeletingUser
            | CurrentOperation::UpdatingInboundGeneral
            | CurrentOperation::UpdatingInboundSniffing
            | CurrentOperation::ManagingXrayService { .. }
            | CurrentOperation::ManagingXrayLifecycle { .. }
            | CurrentOperation::ManagingGeoData { .. }
            | CurrentOperation::ManagingWarp { .. }
            | CurrentOperation::ManagingXrayLogs { .. }
            | CurrentOperation::SavingLogSettings
            | CurrentOperation::ValidatingLogSettings
            | CurrentOperation::UpdatingInboundShell
            | CurrentOperation::AddingInbound
            | CurrentOperation::DeletingInbound
            | CurrentOperation::DuplicatingInbound
            | CurrentOperation::AddingOutbound
            | CurrentOperation::UpdatingOutboundShell
            | CurrentOperation::DeletingOutbound
            | CurrentOperation::GeneratingX25519
            | CurrentOperation::GeneratingMldsa65
            | CurrentOperation::GeneratingVlessEnc => {}
        }
    }

    /// Sets the persistent SSH connection status.
    pub fn set_ssh_status(&mut self, status: SshStatus) {
        if status != SshStatus::Connected {
            self.xray_logs.stop_follow();
            self.invalidate_warp_on_disconnect();
        }
        self.ssh_status = status;
    }

    /// Sets the persistent Xray service status.
    pub fn set_xray_status(&mut self, status: XrayStatus) {
        self.xray_status = status;
    }
}

impl Default for ApplicationService {
    fn default() -> Self {
        Self::new()
    }
}

fn user_facing_log_settings_error(error: &crate::xray::ConfigModifyError) -> String {
    use crate::xray::ConfigModifyErrorKind;
    match error.kind() {
        ConfigModifyErrorKind::BackupFailed => {
            if error.detail().is_empty() {
                "Backup failed".to_owned()
            } else {
                format!("Backup failed: {}", error.detail())
            }
        }
        ConfigModifyErrorKind::PermissionDenied => {
            if error.detail().is_empty() {
                "Permission denied".to_owned()
            } else {
                format!("Permission denied: {}", error.detail())
            }
        }
        ConfigModifyErrorKind::ConnectionLost => "No SSH connection".to_owned(),
        ConfigModifyErrorKind::ConfigurationChangedRemotely => {
            "Configuration changed remotely".to_owned()
        }
        ConfigModifyErrorKind::XrayValidationFailed => {
            "Xray configuration validation failed".to_owned()
        }
        ConfigModifyErrorKind::MalformedLogObject => "Malformed log object".to_owned(),
        ConfigModifyErrorKind::UnsupportedLogValue => {
            if error.detail().is_empty() {
                "Unsupported log value".to_owned()
            } else {
                format!("Unsupported log value: {}", error.detail())
            }
        }
        ConfigModifyErrorKind::InvalidFilePath => {
            if error.detail().is_empty() {
                "Invalid file path".to_owned()
            } else {
                format!("Invalid file path: {}", error.detail())
            }
        }
        ConfigModifyErrorKind::InvalidMaskFormat => {
            if error.detail().is_empty() {
                "Invalid mask format".to_owned()
            } else {
                format!("Invalid mask format: {}", error.detail())
            }
        }
        ConfigModifyErrorKind::UploadFailed => {
            if error.detail().is_empty() {
                "Remote write failed".to_owned()
            } else {
                format!("Remote write failed: {}", error.detail())
            }
        }
        ConfigModifyErrorKind::ValidationFailed | ConfigModifyErrorKind::SerializationFailed => {
            error.message()
        }
        _ => error.message(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{CONFIG_FILE_NAME, ConfigManager};
    use crate::xray::DiscoveryState;
    use feldjaeger_ssh::AuthMethod;
    use std::fs;

    fn service_with_temp_config(name: &str) -> ApplicationService {
        let dir = std::env::temp_dir().join(format!(
            "feldjaeger-conn-service-{}-{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(CONFIG_FILE_NAME);
        let config = ConfigManager::load_from(path).expect("config");
        let mut service = ApplicationService::new();
        service.config = config;
        service.connection_draft = ConnectionDraft::from_stored(service.saved_connection_profile());
        service
    }

    fn fill_valid_password_profile(service: &mut ApplicationService) {
        {
            let draft = service.connection_draft_mut();
            draft.profile_name = "vm".to_owned();
            draft.host = "192.0.2.10".to_owned();
            draft.port = "22".to_owned();
            draft.username = "root".to_owned();
            draft.auth_method = AuthMethod::Password;
        }
        service.connection_secrets_mut().set_password("secret");
    }

    #[test]
    fn save_and_reload_non_secret_fields() {
        let mut service = service_with_temp_config("save-reload");
        {
            let draft = service.connection_draft_mut();
            draft.profile_name = "edge".to_owned();
            draft.host = "203.0.113.5".to_owned();
            draft.port = "2222".to_owned();
            draft.username = "ops".to_owned();
            draft.auth_method = AuthMethod::PrivateKey;
            draft.private_key_path = "C:\\keys\\id_ed25519".to_owned();
        }
        service
            .connection_secrets_mut()
            .set_password("must-not-persist");
        service
            .connection_secrets_mut()
            .set_passphrase("must-not-persist-either");

        assert!(service.save_connection_profile());

        let path = service.config.path().to_path_buf();
        let json = fs::read_to_string(&path).expect("read config");
        assert!(!json.contains("must-not-persist"));
        assert!(!json.contains("password"));
        assert!(!json.contains("passphrase"));

        let reloaded = ConfigManager::load_from(path.clone()).expect("reload");
        let connection = &reloaded.config().connection;
        assert_eq!(connection.profile_name, "edge");
        assert_eq!(connection.host, "203.0.113.5");
        assert_eq!(connection.port, 2222);
        assert_eq!(connection.username, "ops");
        assert_eq!(connection.auth_method, AuthMethod::PrivateKey);
        assert_eq!(connection.private_key_path, "C:\\keys\\id_ed25519");

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn reset_restores_saved_profile() {
        let mut service = service_with_temp_config("reset");
        {
            let draft = service.connection_draft_mut();
            draft.profile_name = "saved".to_owned();
            draft.host = "10.0.0.1".to_owned();
            draft.port = "22".to_owned();
            draft.username = "root".to_owned();
        }
        assert!(service.save_connection_profile());

        service.connection_draft_mut().host = "changed".to_owned();
        service.connection_secrets_mut().set_password("temp");
        assert!(service.connection_has_unsaved_changes());

        service.reset_connection_profile();
        assert_eq!(service.connection_draft().host, "10.0.0.1");
        assert!(service.connection_secrets().password().is_empty());
        assert!(!service.connection_has_unsaved_changes());

        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn connection_test_rejects_invalid_profile() {
        let mut service = service_with_temp_config("test-invalid");
        service.connection_draft_mut().host.clear();
        assert!(!service.start_connection_test());
        assert!(matches!(
            service.connection_test_state(),
            ConnectionTestState::Idle
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn connection_test_rejects_empty_password() {
        let mut service = service_with_temp_config("test-empty-pw");
        fill_valid_password_profile(&mut service);
        service.connection_secrets_mut().set_password("");
        assert!(!service.start_connection_test());
        assert!(service.connection_errors().password.is_some());
        assert!(matches!(
            service.connection_test_state(),
            ConnectionTestState::Idle
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn connection_test_cannot_restart_while_connecting() {
        let mut service = service_with_temp_config("test-busy");
        fill_valid_password_profile(&mut service);
        // Force connecting state without spawning a real network call.
        service.connection_test = ConnectionTestState::Connecting;
        assert!(!service.start_connection_test());
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn connection_test_success_updates_status_bar() {
        let mut service = service_with_temp_config("test-success-status");
        service.connection_test = ConnectionTestState::Connecting;
        service.operation = CurrentOperation::Connecting {
            endpoint: "192.0.2.10:22".to_owned(),
        };
        service.ssh_status = SshStatus::Connecting;

        let (tx, rx) = mpsc::channel();
        service.connection_test_rx = Some(rx);
        tx.send(ConnectionTestOutcome { result: Ok(()) })
            .expect("send");
        service.poll_connection_test();

        assert!(matches!(
            service.connection_test_state(),
            ConnectionTestState::Succeeded
        ));
        assert_eq!(service.status_snapshot().ssh, SshStatus::Connected);
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "SSH connection test succeeded"
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn connection_test_failure_updates_status_bar() {
        let mut service = service_with_temp_config("test-fail-status");
        service.connection_test = ConnectionTestState::Connecting;
        service.ssh_status = SshStatus::Connecting;

        let (tx, rx) = mpsc::channel();
        service.connection_test_rx = Some(rx);
        tx.send(ConnectionTestOutcome {
            result: Err(crate::app::connection_test::ConnectionTestFailure {
                summary: SshStatus::AuthenticationFailed,
                detail: "SSH authentication failed".to_owned(),
            }),
        })
        .expect("send");
        service.poll_connection_test();

        assert!(matches!(
            service.connection_test_state(),
            ConnectionTestState::Failed { .. }
        ));
        assert_eq!(
            service.status_snapshot().ssh,
            SshStatus::AuthenticationFailed
        );
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Ready
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn discovery_requires_connected_ssh() {
        let mut service = service_with_temp_config("discover-need-ssh");
        fill_valid_password_profile(&mut service);
        assert!(!service.can_start_discovery());
        assert!(!service.start_discovery());
        assert!(matches!(service.discovery_state(), DiscoveryState::Idle));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn discovery_cannot_restart_while_discovering() {
        let mut service = service_with_temp_config("discover-busy");
        fill_valid_password_profile(&mut service);
        service.set_ssh_status(SshStatus::Connected);
        service.discovery = DiscoveryState::Discovering;
        assert!(!service.start_discovery());
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn discovery_blocked_while_service_control_busy() {
        let mut service = service_with_temp_config("discover-svc-busy");
        fill_valid_password_profile(&mut service);
        service.set_ssh_status(SshStatus::Connected);
        service.service_control = ServiceControlState::Busy(ServiceOperation::Start);
        assert!(!service.can_start_discovery());
        assert!(!service.start_discovery());
        assert!(matches!(service.discovery_state(), DiscoveryState::Idle));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn geodata_requires_connected_ssh() {
        let mut service = service_with_temp_config("geodata-need-ssh");
        fill_valid_password_profile(&mut service);
        assert!(service.start_geodata_refresh().is_err());
        assert!(service.start_geodata_update().is_err());
        assert!(matches!(service.geodata_ui, GeoDataUiState::Idle));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn geodata_requires_discovery() {
        let mut service = service_with_temp_config("geodata-need-discovery");
        fill_valid_password_profile(&mut service);
        service.set_ssh_status(SshStatus::Connected);
        assert!(matches!(service.discovery_state(), DiscoveryState::Idle));
        assert!(service.start_geodata_refresh().is_err());
        assert!(matches!(service.geodata_ui, GeoDataUiState::Idle));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn geodata_blocked_while_busy() {
        let mut service = service_with_temp_config("geodata-busy");
        fill_valid_password_profile(&mut service);
        service.set_ssh_status(SshStatus::Connected);
        service.discovery = DiscoveryState::Succeeded(crate::xray::XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: crate::xray::InitSystemKind::Systemd,
            binary_path: Some(
                feldjaeger_ssh::RemotePath::new("/usr/local/bin/xray").expect("path"),
            ),
            version: Some("25.7.1".to_owned()),
            service_name: Some("xray.service".to_owned()),
            service_state: Some(crate::init::ServiceState::Running),
            exec_start: None,
            config_source: crate::xray::ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        });
        service.service_control = ServiceControlState::Busy(ServiceOperation::Start);
        assert!(service.start_geodata_refresh().is_err());
        assert!(matches!(service.geodata_ui, GeoDataUiState::Idle));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn discovery_success_updates_status_bar() {
        let mut service = service_with_temp_config("discover-success-status");
        service.discovery = DiscoveryState::Discovering;
        service.operation = CurrentOperation::DiscoveringXray;
        service.ssh_status = SshStatus::Connected;

        let installation = crate::xray::XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: crate::xray::InitSystemKind::Systemd,
            binary_path: Some(
                feldjaeger_ssh::RemotePath::new("/usr/local/bin/xray").expect("path"),
            ),
            version: Some("25.7.1".to_owned()),
            service_name: Some("xray.service".to_owned()),
            service_state: Some(crate::init::ServiceState::Running),
            exec_start: None,
            config_source: crate::xray::ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        };

        let (tx, rx) = mpsc::channel();
        service.discovery_rx = Some(rx);
        tx.send(crate::app::discovery::DiscoveryOutcome {
            state: DiscoveryState::Succeeded(installation),
            config: crate::app::LoadedConfigSnapshot::NotLoaded,
            share_materials: crate::app::share_material::ShareMaterialStore::new(),
        })
        .expect("send");
        service.poll_discovery();

        assert!(matches!(
            service.discovery_state(),
            DiscoveryState::Succeeded(_)
        ));
        assert_eq!(service.status_snapshot().ssh, SshStatus::Connected);
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Xray discovery completed"
        ));
        assert!(matches!(
            service.loaded_config(),
            crate::app::LoadedConfigSnapshot::NotLoaded
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn dns_page_status_reports_loading() {
        let mut service = service_with_temp_config("dns-loading-status");
        service.discovery = DiscoveryState::Discovering;
        service.tick_dns_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Loading DNS..."
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn fakedns_page_status_reports_loading() {
        let mut service = service_with_temp_config("fakedns-loading-status");
        service.discovery = DiscoveryState::Discovering;
        service.tick_fakedns_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Loading FakeDNS..."
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn fakedns_page_status_announces_loaded_then_ready() {
        let mut service = service_with_temp_config("fakedns-loaded-status");
        service.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: Some(crate::xray::FakeDnsSummary {
                pools: vec![crate::xray::FakeDnsPoolSummary {
                    ip_pool: Some("198.18.0.0/15".to_owned()),
                    pool_size: Some(65535),
                    address_family: crate::xray::FakeDnsAddressFamily::Ipv4,
                }],
                source_file: "/etc/xray/config.json".to_owned(),
                warnings: Vec::new(),
            }),
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };

        service.tick_fakedns_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "FakeDNS configuration loaded."
        ));

        service.status_message_until = Some(Instant::now() - Duration::from_millis(1));
        service.tick_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Ready
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn fakedns_page_status_announces_missing_then_ready() {
        let mut service = service_with_temp_config("fakedns-missing-status");
        service.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };

        service.tick_fakedns_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "FakeDNS is not configured."
        ));

        service.status_message_until = Some(Instant::now() - Duration::from_millis(1));
        service.tick_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Ready
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn dns_page_status_announces_loaded_then_ready() {
        let mut service = service_with_temp_config("dns-loaded-status");
        service.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };

        service.tick_dns_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "DNS configuration loaded."
        ));

        service.status_message_until = Some(Instant::now() - Duration::from_millis(1));
        service.tick_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Ready
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn routing_page_status_reports_loading() {
        let mut service = service_with_temp_config("routing-loading-status");
        service.discovery = DiscoveryState::Discovering;
        service.tick_routing_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Loading routing..."
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn routing_page_status_announces_loaded_then_ready() {
        let mut service = service_with_temp_config("routing-loaded-status");
        service.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: Some(crate::xray::RoutingSummary {
                domain_strategy: None,
                domain_matcher: None,
                rule_count: 2,
                rules: Vec::new(),
                source_file: "/etc/xray/config.json".to_owned(),
            }),
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };

        service.tick_routing_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Loaded 2 routing rule(s)."
        ));

        service.status_message_until = Some(Instant::now() - Duration::from_millis(1));
        service.tick_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Ready
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn policy_page_status_reports_loading() {
        let mut service = service_with_temp_config("policy-loading-status");
        service.discovery = DiscoveryState::Discovering;
        service.tick_policy_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Loading policy..."
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn policy_page_status_announces_loaded_then_ready() {
        let mut service = service_with_temp_config("policy-loaded-status");
        service.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: Some(crate::xray::PolicySummary {
                user_policy_count: Some(2),
                user_levels: vec![
                    crate::xray::UserPolicySummary {
                        level: "0".to_owned(),
                        handshake: None,
                        conn_idle: None,
                        uplink_only: None,
                        downlink_only: None,
                        buffer_size: None,
                        stats_user_uplink: None,
                        stats_user_downlink: None,
                        stats_user_online: None,
                        source_file: "/etc/xray/config.json".to_owned(),
                    },
                    crate::xray::UserPolicySummary {
                        level: "1".to_owned(),
                        handshake: None,
                        conn_idle: None,
                        uplink_only: None,
                        downlink_only: None,
                        buffer_size: None,
                        stats_user_uplink: None,
                        stats_user_downlink: None,
                        stats_user_online: None,
                        source_file: "/etc/xray/config.json".to_owned(),
                    },
                ],
                system_policy: None,
                source_file: "/etc/xray/config.json".to_owned(),
            }),
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };

        service.tick_policy_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Loaded 2 policy level(s)."
        ));

        service.status_message_until = Some(Instant::now() - Duration::from_millis(1));
        service.tick_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Ready
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn observatory_page_status_reports_loading() {
        let mut service = service_with_temp_config("observatory-loading-status");
        service.discovery = DiscoveryState::Discovering;
        service.tick_observatory_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Loading Observatory..."
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn observatory_page_status_announces_loaded_then_ready() {
        let mut service = service_with_temp_config("observatory-loaded-status");
        service.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: Some(crate::xray::ObservatorySummary {
                probe_url: Some("https://www.google.com/generate_204".to_owned()),
                probe_interval: Some("10s".to_owned()),
                subject_selectors: vec!["proxy".to_owned()],
                source_file: "/etc/xray/config.json".to_owned(),
                warnings: Vec::new(),
            }),
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };

        service.tick_observatory_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Observatory configuration loaded."
        ));

        service.status_message_until = Some(Instant::now() - Duration::from_millis(1));
        service.tick_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Ready
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn burst_observatory_page_status_reports_loading() {
        let mut service = service_with_temp_config("burst-observatory-loading-status");
        service.discovery = DiscoveryState::Discovering;
        service.tick_burst_observatory_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text } if text == "Loading BurstObservatory..."
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn burst_observatory_page_status_announces_loaded_then_ready() {
        let mut service = service_with_temp_config("burst-observatory-loaded-status");
        service.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: Some(crate::xray::BurstObservatorySummary {
                subject_selectors: vec!["proxy".to_owned()],
                ping_config: Some(crate::xray::BurstPingConfigSummary {
                    destination: Some("https://example.com/generate_204".to_owned()),
                    connectivity: None,
                    interval: Some("30s".to_owned()),
                    sampling: Some(10),
                    timeout: Some("5s".to_owned()),
                    http_method: Some("HEAD".to_owned()),
                    summary: "Example probe".to_owned(),
                }),
                source_file: "/etc/xray/config.json".to_owned(),
                warnings: Vec::new(),
            }),
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };

        service.tick_burst_observatory_page_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Message { ref text }
                if text == "BurstObservatory configuration loaded."
        ));
        service.status_message_until = Some(Instant::now() - Duration::from_millis(1));
        service.tick_status();
        assert!(matches!(
            service.status_snapshot().operation,
            CurrentOperation::Ready
        ));
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn production_client_does_not_use_accept_any() {
        let service = service_with_temp_config("no-accept-any");
        assert!(matches!(
            service.ssh_client.options().host_key_policy,
            HostKeyPolicy::KnownHostsFile(_)
        ));
        assert_ne!(
            service.ssh_client.options().host_key_policy,
            HostKeyPolicy::AcceptAny
        );
        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }

    #[test]
    fn vless_share_uri_derives_pbk_from_private_key_without_ephemeral() {
        use crate::xray::{InboundSummary, XrayConfigParser};

        let mut service = service_with_temp_config("share-uri-derive-pbk");
        service.connection_draft_mut().host = "203.0.113.10".to_owned();

        let json = r#"{
            "inbounds":[{
                "tag":"vless-in",
                "protocol":"vless",
                "port":443,
                "listen":"0.0.0.0",
                "settings":{
                    "clients":[{
                        "id":"11111111-1111-1111-1111-111111111111",
                        "email":"user@example.com",
                        "flow":"xtls-rprx-vision"
                    }],
                    "decryption":"none"
                },
                "streamSettings":{
                    "network":"tcp",
                    "security":"reality",
                    "realitySettings":{
                        "show":false,
                        "target":"www.example.com:443",
                        "serverNames":["www.example.com"],
                        "privateKey":"0EiEonMUwJyuyI4Q8tdGIRvjV_aaOfeFC7TSsohh5mk",
                        "shortIds":["abcd"]
                    }
                }
            }]
        }"#;
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file("/etc/xray/config.json", json);
        assert!(outcome.is_success(), "{:?}", outcome.errors());
        let root: serde_json::Value = serde_json::from_str(json).expect("json");
        let editable = EditableXrayConfig::from_single_file(
            "/etc/xray/config.json",
            root,
            outcome.into_sections(),
        );
        let inbounds = editable.inbound_summaries();
        assert_eq!(inbounds.len(), 1);
        let InboundSummary { port, .. } = &inbounds[0];
        assert_eq!(*port, Some(443));

        service.loaded_config = LoadedConfigSnapshot::Loaded {
            inbounds,
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: editable.vless_clients(),
            warnings: Vec::new(),
            editable: Some(editable),
        };

        let uri = service
            .build_client_share_uri(0, 0)
            .expect("share uri without ephemeral Generate");
        assert!(uri.starts_with(
            "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?"
        ));
        assert!(uri.contains("security=reality"));
        assert!(uri.contains("pbk=RGhjWSrEM-rYV-nrfeDNswssqctjn8GFalDEuEcII1c"));
        assert!(uri.contains("sid=abcd"));
        assert!(uri.contains("sni=www.example.com"));
        assert!(uri.contains("fp=chrome"));
        assert!(uri.contains("type=tcp"));
        assert!(uri.contains("encryption=none"));
        assert!(uri.contains("flow=xtls-rprx-vision"));
        assert!(uri.contains("#user%40example.com") || uri.ends_with("#user@example.com"));

        // Derived key is cached for subsequent calls.
        assert_eq!(
            service
                .share_materials
                .get(Some("vless-in"), 0)
                .and_then(|m| m.public_key.as_deref()),
            Some("RGhjWSrEM-rYV-nrfeDNswssqctjn8GFalDEuEcII1c")
        );

        let _ = fs::remove_dir_all(service.config.path().parent().unwrap());
    }
}
