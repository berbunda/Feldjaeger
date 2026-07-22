//! Application service facade for upper layers.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use feldjaeger_ssh::{HostKeyPolicy, RusshClient, RusshClientOptions};
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
use super::inbounds::{
    InboundsPageModel, InboundsSort, InboundsSortColumn, LoadedConfigSnapshot,
    build_inbounds_page_model,
};
use super::observatory::{ObservatoryPageModel, build_observatory_page_model};
use super::outbounds::{
    OutboundsPageModel, OutboundsSort, OutboundsSortColumn, build_outbounds_page_model,
};
use super::policy::{PolicyPageModel, PolicySort, PolicySortColumn, build_policy_page_model};
use super::routing::{RoutingPageModel, RoutingSort, RoutingSortColumn, build_routing_page_model};
use super::service_control::{
    ServiceControlState, ServiceOperation, ServiceOperationOutcome, ServicePageModel,
    build_service_page_model, run_service_operation, user_facing_service_error,
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
    AddUserRequest, BurstObservatorySummary, DeleteUserRequest, DiscoveryState, DnsSummary,
    FakeDnsSummary, InboundSummary, ObservatorySummary, PolicySummary, OutboundSummary,
    RoutingSummary, UpdateUserRequest, UserSummary, VlessClientSummary, XrayInstaller,
    XrayLogLineLimit, XrayLogService, XrayLogSourceKind,
};

/// How long a transient Status Bar message remains visible.
const STATUS_MESSAGE_DURATION: Duration = Duration::from_secs(3);

/// Internal request payload for the user-mutation worker.
enum UserMutationRequest {
    Add(AddUserRequest),
    Update(UpdateUserRequest),
    Delete(DeleteUserRequest),
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
    service_control: ServiceControlState,
    service_control_rx: Option<Receiver<ServiceOperationOutcome>>,
    service_state: Option<ServiceState>,
    xray_lifecycle: XrayLifecycleState,
    xray_lifecycle_rx: Option<Receiver<XrayLifecycleOutcome>>,
    available_version: Option<String>,
    version_check_rx: Option<Receiver<VersionCheckOutcome>>,
    version_check_busy: bool,
    geodata_summary: Option<crate::xray::GeoDataSummary>,
    geodata_ui: GeoDataUiState,
    geodata_rx: Option<Receiver<GeoDataOutcome>>,
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
            .field("available_version", &self.available_version)
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

        Self {
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
            service_control: ServiceControlState::Idle,
            service_control_rx: None,
            service_state: None,
            xray_lifecycle: XrayLifecycleState::Idle,
            xray_lifecycle_rx: None,
            available_version: None,
            version_check_rx: None,
            version_check_busy: false,
            geodata_summary: None,
            geodata_ui: GeoDataUiState::Idle,
            geodata_rx: None,
            xray_logs: XrayLogsRuntime::default(),
            operation: CurrentOperation::Ready,
            status_message_until: None,
            ssh_status: SshStatus::Disconnected,
            xray_status: XrayStatus::unknown(),
        }
    }

    /// Returns the remote administration facade.
    pub fn remote(&self) -> &RemoteAdmin {
        &self.remote
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

    /// Selects which supported inbound the Users page should display.
    pub fn set_selected_users_inbound(&mut self, inbound_index: usize) {
        self.selected_users_inbound_index = Some(inbound_index);
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
        self.available_version = None;
        self.version_check_rx = None;
        self.version_check_busy = false;
        self.geodata_summary = None;
        self.geodata_ui = GeoDataUiState::Idle;
        self.geodata_rx = None;
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
            || self.discovery.is_discovering()
            || self.version_check_busy
            || self.geodata_ui.is_busy()
            || self.xray_logs.ui_state.is_busy()
    }

    /// Read-only model for the Service page.
    pub fn service_page_model(&self) -> ServicePageModel {
        build_service_page_model(&self.discovery, &self.service_control, self.service_state)
    }

    /// Read-only model for the Xray Management page.
    pub fn xray_management_page_model(&self) -> XrayManagementPageModel {
        build_xray_management_page_model(
            &self.discovery,
            &self.xray_lifecycle,
            self.available_version.as_deref(),
            self.version_check_busy,
        )
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

        info!(
            target: "app",
            operation = ?operation,
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
                    Ok(version) => {
                        self.available_version = Some(version);
                        self.show_status_message("Available version updated.");
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
                        run_add_user(&client, &profile, &secrets, &remote, editable, request).await
                    }
                    UserMutationRequest::Update(request) => {
                        run_update_user(&client, &profile, &secrets, &remote, editable, request)
                            .await
                    }
                    UserMutationRequest::Delete(request) => {
                        run_delete_user(&client, &profile, &secrets, &remote, editable, request)
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
        self.poll_service_operation();
        self.poll_xray_lifecycle();
        self.poll_version_check();
        self.poll_geodata();
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
            | CurrentOperation::ManagingXrayService { .. }
            | CurrentOperation::ManagingXrayLifecycle { .. }
            | CurrentOperation::ManagingGeoData { .. }
            | CurrentOperation::ManagingXrayLogs { .. } => {}
        }
    }

    /// Sets the persistent SSH connection status.
    pub fn set_ssh_status(&mut self, status: SshStatus) {
        if status != SshStatus::Connected {
            self.xray_logs.stop_follow();
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
}
