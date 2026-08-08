//! Application facade.
//!
//! Provides a single entry point for the GUI and CLI, wiring together
//! remote administration, Xray management, and init-system control.

mod burst_observatory;
pub(crate) mod config_write;
mod connection_secrets;
mod connection_test;
mod discovery;
mod dns;
mod fakedns;
mod geodata;
mod inbound_ops;
mod inbounds;
mod log_settings;
mod log_settings_ops;
mod observatory;
mod outbound_ops;
mod outbounds;
mod policy;
mod routing;
mod service;
mod service_control;
pub(crate) mod share_material;
mod status;
mod user_ops;
mod users;
mod warp;
mod warp_ops;
mod xray_logs;
mod xray_management;

pub use crate::xray::{
    AddInboundRequest, AddUserRequest, DeleteInboundRequest, DeleteUserRequest,
    DiscoveryState, DuplicateInboundRequest, InboundClientProtocol,
    InboundClientSummary, InboundGeneral, InboundProtocolDraft, InboundSecurityDraft,
    InboundSecurityMode, InboundStreamDraft, KNOWN_DEST_OVERRIDE, LogLevel, LogOutput, LogSettings,
    MaskAddress, RealitySettingsDraft, SecretFieldDraft, SecretString, SniffingSettings,
    StreamMethod, TrojanClientSummary, UpdateInboundGeneralRequest, UpdateInboundShellRequest,
    UpdateInboundSniffingRequest, UpdateLogSettingsRequest, UpdateUserRequest,
    allowed_security_modes, allowed_stream_methods, coerce_display_stream_method,
    coerce_security_mode_for_transport, generate_client_auth, generate_client_uuid,
    parse_inbound_stream, port_is_shell_editable, selectable_stream_methods,
    vision_active_from_inbound,
};
pub use burst_observatory::{
    BurstObservatoryGeneralDisplay, BurstObservatoryPageModel, BurstObservatoryPageState,
    BurstPingConfigDisplay, build_burst_observatory_page_model, burst_observatory_general_display,
    burst_ping_config_display, derive_burst_observatory_page_state,
};
pub use connection_secrets::ConnectionSecrets;
pub use connection_test::ConnectionTestState;
pub use discovery::{format_installation_summary, format_not_found_summary};
pub use dns::{
    DnsGeneralDisplay, DnsHostRowDisplay, DnsPageModel, DnsPageState, DnsServerRowDisplay,
    build_dns_page_model, derive_dns_page_state, display_optional_bool, display_string_list,
    dns_general_display, dns_host_row_display, dns_server_row_display,
};
pub use fakedns::{
    FakeDnsPageModel, FakeDnsPageState, FakeDnsPoolDisplay, build_fakedns_page_model,
    derive_fakedns_page_state, display_address_family, fakedns_pool_display,
};
pub use geodata::{
    GeoDataOperation, GeoDataPageModel, GeoDataPageState, GeoDataRowDisplay, GeoDataUiState,
    build_geodata_page_model, format_size, format_unix_date, user_facing_geodata_error,
};
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
pub use observatory::{
    ObservatoryGeneralDisplay, ObservatoryPageModel, ObservatoryPageState,
    build_observatory_page_model, derive_observatory_page_state, observatory_general_display,
};
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
pub use routing::{
    RoutingGeneralDisplay, RoutingPageModel, RoutingPageState, RoutingRuleRowDisplay, RoutingSort,
    RoutingSortColumn, build_routing_page_model, derive_routing_page_state, display_routing_list,
    routing_general_display, routing_rule_row_display, sort_routing_rule_summaries,
};
pub use share_material::InboundShareMaterial;
pub use service::ApplicationService;
pub use service_control::{
    ServiceControlState, ServiceOperation, ServicePageModel, UnitApplyRequest,
    build_service_page_model,
};
pub use status::{
    CurrentOperation, OperationProgress, SshStatus, StatusSeverity, StatusSnapshot, XrayStatus,
};
pub use user_ops::UserMutationKind;
pub use users::{
    HysteriaRowDisplay, TrojanRowDisplay, UserRowDisplay, UsersPageModel,
    UsersPageState, UsersProtocolUi, UsersSort, UsersSortColumn, build_users_page_model,
    derive_users_page_state, display_optional_client_field, hysteria_row_display,
    resolve_selected_inbound_index, selected_users_protocol,
    sort_user_summaries, trojan_row_display, user_row_display,
};
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
