//! Application facade.
//!
//! Provides a single entry point for the GUI and CLI, wiring together
//! remote administration, Xray management, and init-system control.

mod api_console;
mod api_ops;
mod api_settings;
mod api_settings_ops;
mod backup_ops;
mod backups;
mod burst_observatory;
mod burst_observatory_settings_ops;
mod confdir_files;
mod confdir_ops;
pub(crate) mod config_write;
mod connection_secrets;
mod connection_test;
mod discovery;
mod dns;
mod dns_settings_ops;
mod env_settings;
mod env_settings_ops;
mod fakedns;
mod fakedns_settings_ops;
mod geodata;
mod geodata_settings;
mod geodata_settings_ops;
mod inbound_import;
mod inbound_ops;
mod inbounds;
mod log_settings;
mod log_settings_ops;
mod metrics_console;
mod metrics_ops;
mod metrics_settings;
mod metrics_settings_ops;
mod observatory;
mod observatory_settings_ops;
mod outbound_ops;
mod outbounds;
mod policy;
mod policy_settings_ops;
mod routing;
mod routing_settings_ops;
mod service;
mod service_control;
pub(crate) mod share_material;
mod stats_console;
mod stats_settings;
mod stats_settings_ops;
mod status;
mod target_lookup;
mod target_scan_ops;
mod user_ops;
mod users;
mod version_settings;
mod version_settings_ops;
mod warp;
mod warp_ops;
mod xray_logs;
mod xray_management;

pub use crate::remote::ConfigBackup;
pub use crate::xray::{
    AddInboundRequest, AddUserRequest, ApiSettings, BLACKHOLE_RESPONSE_TYPES, DNS_REWRITE_NETWORKS,
    DNS_RULE_ACTIONS, DeleteInboundRequest,
    DeleteUserRequest, DOMAIN_STRATEGIES, DnsRuleDraft,
    DiscoveryState, DuplicateInboundRequest, FREEDOM_NOISE_TYPES, FragmentDraft,
    InboundClientProtocol, InboundClientSummary, InboundGeneral, InboundProtocolDraft,
    InboundSecurityDraft, InboundSecurityMode, InboundStreamDraft, KNOWN_DEST_OVERRIDE, LogLevel,
    LogOutput, LogSettings, MaskAddress, NoiseDraft, OutboundGeneral, OutboundKind,
    OutboundSettingsDraft, ProxySettingsDraft, RealitySettingsDraft, ReverseSniffingDraft,
    ReverseTagDraft, SecretFieldDraft, SecretString, SniffingSettings,
    StreamMethod, TrojanClientSummary, UpdateInboundGeneralRequest, UpdateInboundShellRequest,
    UpdateInboundSniffingRequest, UpdateLogSettingsRequest, UpdateUserRequest,
    allowed_security_modes, allowed_stream_methods, coerce_display_stream_method,
    coerce_security_mode_for_transport, generate_client_auth, generate_client_uuid,
    parse_inbound_stream, port_is_shell_editable, selectable_stream_methods,
    vision_active_from_inbound,
};
pub use api_console::{
    ApiConsolePageModel, ApiConsolePageState, build_api_console_page_model,
    derive_api_console_page_state, resolve_api_listen, resolve_api_services,
};
pub use api_ops::{
    ApiCallOutcome, ApiCallRequest, add_inbound_users_request, add_inbounds_request,
    add_outbounds_request, add_rules_request, balancer_info_request, balancer_override_request,
    inbound_user_count_request, inbound_users_request, list_inbounds_request,
    list_outbounds_request, list_rules_request, remove_inbound_users_request,
    remove_inbounds_request, remove_outbounds_request, remove_rules_request,
    restart_logger_request, source_ip_block_request, stats_query_all_request,
    stats_sys_request,
};
pub use api_settings::{ApiSettingsPageModel, ApiSettingsPageState, build_api_settings_page_model};
pub use api_settings_ops::{ApiSettingsMutationOutcome, ApiSettingsMutationSuccess};
pub use backup_ops::{BackupContentOutcome, BackupListOutcome, BackupRestoreOutcome};
pub use backups::{
    BackupFileRow, BackupsPageModel, BackupsPageState, build_backups_page_model,
    derive_backups_page_state, format_backup_timestamp,
};
pub use burst_observatory::{
    BurstObservatoryGeneralDisplay, BurstObservatoryPageModel, BurstObservatoryPageState,
    BurstPingConfigDisplay, build_burst_observatory_page_model, burst_observatory_general_display,
    burst_ping_config_display, derive_burst_observatory_page_state,
};
pub use burst_observatory_settings_ops::{
    BurstObservatorySettingsMutationOutcome, BurstObservatorySettingsMutationSuccess,
};
pub use confdir_files::{
    ConfdirFileRow, ConfdirFilesPageModel, ConfdirFilesPageState, build_confdir_files_page_model,
    derive_confdir_files_page_state,
};
pub use confdir_ops::{ConfdirFileMutationKind, ConfdirFileMutationSuccess};
pub use connection_secrets::ConnectionSecrets;
pub use connection_test::ConnectionTestState;
pub use discovery::{format_installation_summary, format_not_found_summary};
pub use dns::{DnsPageModel, DnsPageState, build_dns_page_model};
pub use dns_settings_ops::{DnsSettingsMutationOutcome, DnsSettingsMutationSuccess};
pub use env_settings::{EnvSettingsPageModel, EnvSettingsPageState, build_env_settings_page_model};
pub use env_settings_ops::{EnvSettingsMutationOutcome, EnvSettingsMutationSuccess};
pub use fakedns::{FakeDnsPageModel, FakeDnsPageState, build_fakedns_page_model};
pub use fakedns_settings_ops::{FakeDnsSettingsMutationOutcome, FakeDnsSettingsMutationSuccess};
pub use geodata::{
    GeoDataOperation, GeoDataPageModel, GeoDataPageState, GeoDataRowDisplay, GeoDataUiState,
    build_geodata_page_model, format_size, format_unix_date, user_facing_geodata_error,
};
pub use geodata_settings::{
    GeodataSettingsPageModel, GeodataSettingsPageState, build_geodata_settings_page_model,
};
pub use geodata_settings_ops::{GeodataSettingsMutationOutcome, GeodataSettingsMutationSuccess};
pub use inbound_import::{ImportPreview, build_import_preview};
pub use inbound_ops::{
    InboundEditorSession, InboundMutationKind, InboundShellDrafts, InboundShellMutationKind,
};
pub use inbounds::{
    InboundRowDisplay, InboundsPageModel, InboundsPageState, InboundsSort, InboundsSortColumn,
    LoadedConfigSnapshot, MISSING_FIELD, build_inbounds_page_model, derive_inbounds_page_state,
    display_clients_count, display_optional_port, display_optional_str, display_source_file,
    inbound_row_display, sort_inbound_summaries,
};
pub use log_settings::{
    LogSettingsPageModel, LogSettingsPageState, build_log_settings_page_model, log_level_display,
    log_output_display, mask_address_display, settings_from_snapshot,
};
pub use log_settings_ops::{LogSettingsMutationOutcome, run_update_log_settings};
pub use metrics_console::{
    MemStatsDisplay, MetricsPageModel, MetricsPageState, MetricsScrapeSnapshot,
    ObservatoryRowDisplay, build_metrics_page_model, derive_metrics_page_state,
    resolve_metrics_listen,
};
pub use metrics_ops::{MetricsScrapeOutcome, run_metrics_scrape_op};
pub use metrics_settings::{
    MetricsSettingsPageModel, MetricsSettingsPageState, build_metrics_settings_page_model,
};
pub use metrics_settings_ops::{MetricsSettingsMutationOutcome, MetricsSettingsMutationSuccess};
pub use observatory::{
    ObservatoryGeneralDisplay, ObservatoryPageModel, ObservatoryPageState,
    build_observatory_page_model, derive_observatory_page_state, observatory_general_display,
};
pub use observatory_settings_ops::{
    ObservatorySettingsMutationOutcome, ObservatorySettingsMutationSuccess,
};
pub use outbound_ops::{OutboundEditorSession, OutboundMutationKind, OutboundMutationSuccess};
pub use outbounds::{
    OutboundRowDisplay, OutboundsPageModel, OutboundsPageState, OutboundsSort, OutboundsSortColumn,
    build_outbounds_page_model, derive_outbounds_page_state, outbound_row_display,
    sort_outbound_summaries,
};
pub use policy::{
    PolicyGeneralDisplay, PolicyPageModel, PolicyPageState, PolicySort, PolicySortColumn,
    SystemPolicyDisplay, UserPolicyRowDisplay, build_policy_page_model, derive_policy_page_state,
    display_enabled_flag, format_timeout_values, policy_general_display,
    sort_user_policy_summaries, system_policy_display, user_policy_row_display,
};
pub use policy_settings_ops::{PolicySettingsMutationOutcome, PolicySettingsMutationSuccess};
pub use routing::{
    RoutingGeneralDisplay, RoutingPageModel, RoutingPageState, RoutingRuleRowDisplay, RoutingSort,
    RoutingSortColumn, build_routing_page_model, derive_routing_page_state, display_routing_list,
    routing_general_display, routing_rule_row_display, sort_routing_rule_summaries,
};
pub use share_material::InboundShareMaterial;
pub use service::ApplicationService;
pub use stats_console::{
    StatDirection, StatsPageModel, StatsQuerySnapshot, StatsSysSnapshot, SysStatsDisplay,
    TrafficCategory, TrafficSeriesDisplay, build_stats_page_model, missing_stats_service_warning,
    record_stats_sample, sys_stats_display, traffic_counter_name,
};
pub use stats_settings::{
    StatsSettingsPageModel, StatsSettingsPageState, build_stats_settings_page_model,
};
pub use stats_settings_ops::{StatsSettingsMutationOutcome, StatsSettingsMutationSuccess};
pub use service_control::{
    ServiceControlState, ServiceOperation, ServicePageModel, UnitApplyRequest,
    build_service_page_model,
};
pub use status::{
    CurrentOperation, OperationProgress, SshStatus, StatusSeverity, StatusSnapshot, XrayStatus,
};
pub use target_lookup::{
    TargetLookupPageModel, TargetLookupResultDisplay, TargetLookupSnapshot, TargetScanPageModel,
    TargetScanSnapshot, ScanRowDisplay, build_target_lookup_page_model, build_target_scan_page_model,
    target_lookup_result_display,
};
pub use target_scan_ops::{DEFAULT_SCAN_THREADS, PROBE_PAUSE, ScanEvent, run_target_scan};
pub use user_ops::UserMutationKind;
pub use users::{
    HysteriaRowDisplay, TrojanRowDisplay, UserRowDisplay, UsersPageModel,
    UsersPageState, UsersProtocolUi, UsersSort, UsersSortColumn, build_users_page_model,
    derive_users_page_state, display_optional_client_field, hysteria_row_display,
    resolve_selected_inbound_index, selected_users_protocol,
    sort_user_summaries, trojan_row_display, user_row_display,
};
pub use version_settings::{
    VersionSettingsPageModel, VersionSettingsPageState, build_version_settings_page_model,
};
pub use version_settings_ops::{VersionSettingsMutationOutcome, VersionSettingsMutationSuccess};
pub use warp::{
    WarpOperation, WarpPageModel, WarpPageState, WarpPendingConfirm, WarpUiState,
    build_warp_page_model, default_preferred_tag, user_facing_warp_error,
};
pub use xray_logs::{
    XrayLogsPageModel, XrayLogsPageState, XrayLogsRuntime, XrayLogsUiState,
    build_xray_logs_page_model,
};
pub use xray_management::{
    InstallationStatus, XrayLifecycleOperation, XrayLifecycleState, XrayManagementPageModel,
    build_xray_management_page_model,
};
