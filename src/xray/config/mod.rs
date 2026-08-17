//! Internal Xray configuration model and lossless parser.
//!
//! This module replaces the previous flat `XrayConfig` / `XrayConfigParser`
//! pair with a sourced section model suitable for single-file and directory
//! configs, while keeping unknown data for future write-back.

mod api_settings;
mod compatibility;
mod dns_settings;
mod editable;
mod env_settings;
mod errors;
mod fakedns_settings;
mod geodata_settings;
mod inbound_clients;
mod inbound_edit;
mod inbound_fallbacks;
mod inbound_protocol;
mod inbound_security;
mod inbound_stream;
mod json_diff;
mod log_settings;
mod modify;
mod modify_error;
mod outbound_edit;
mod outbound_protocol;
mod burst_observatory_settings;
mod metrics_settings;
mod observatory_settings;
mod parser;
mod policy_settings;
mod reverse_proxy;
mod routing_settings;
mod sections;
mod stats_settings;
mod serialize;
mod sourced_section;
mod summary;
mod tag_refs;
mod users;
mod version_settings;
mod wiring;

pub use api_settings::{
    ApiSettings, KNOWN_API_SERVICES, api_settings_change_summary, api_settings_from_section,
    api_settings_to_new_value, apply_api_settings_to_value, validate_api_settings,
};
pub use burst_observatory_settings::{
    BurstObservatorySettings, BurstPingConfigEntry, apply_burst_observatory_settings_to_value,
    burst_observatory_settings_change_summary, burst_observatory_settings_from_section,
    burst_observatory_settings_to_new_value, validate_burst_observatory_settings,
};
pub use compatibility::{
    CompatibilityGateId, allowed_security_modes, allowed_stream_methods, check_inbound_compatibility,
    coerce_display_stream_method, coerce_security_mode_for_transport, effective_security,
    first_failing_gate, g10_hysteria_requires_tls, g11_shadowsocks_tcp_only,
    g9_hysteria_protocol_transport_ok, inbound_has_vision_flow, matrix_transport, normalized_method,
    selectable_stream_methods, transport_security_allowed, vision_active_from_inbound,
};
pub use dns_settings::{
    DnsHostEntry, DnsServerEntry, DnsSettings, QueryStrategy, apply_dns_settings_to_value,
    dns_settings_change_summary, dns_settings_from_section, dns_settings_to_new_value,
    validate_dns_settings,
};
pub use editable::{EditableXrayConfig, InboundLocation, OutboundLocation, parse_file_roots};
pub use env_settings::{
    EnvSettings, EnvVarEntry, KNOWN_ENV_VARS, apply_env_settings_to_value,
    env_settings_change_summary, env_settings_from_section, env_settings_to_new_value,
    validate_env_settings,
};
pub use errors::{ConfigError, ConfigErrorKind};
pub use geodata_settings::{
    GeodataAssetEntry, GeodataSettings, apply_geodata_settings_to_value,
    geodata_settings_change_summary, geodata_settings_from_section, geodata_settings_to_new_value,
    validate_geodata_settings,
};
pub use fakedns_settings::{
    FakeDnsPoolEntry, FakeDnsSettings, apply_fakedns_settings_to_value,
    fakedns_settings_change_summary, fakedns_settings_from_section, fakedns_settings_to_new_value,
    validate_fakedns_settings,
};
pub use inbound_clients::{
    ClientRef, ClientsArrayKey, HysteriaClient, InboundClient, InboundClientProtocol,
    SecretFieldDraft, TrojanClient, VlessClient, apply_secret_draft, client_fingerprint,
    inbound_fingerprint, json_value_fingerprint, parse_inbound_client,
    resolve_clients_array_key, resolve_or_create_clients_array_key, verify_client_fingerprint,
    verify_inbound_fingerprint, verify_json_fingerprint, write_inbound_client,
};
pub use inbound_edit::{
    InboundGeneral, InboundRef, KNOWN_DEST_OVERRIDE, SniffingSettings, SniffingWriteOutcome,
    apply_inbound_general, apply_inbound_sniffing, first_hop_port, parse_inbound_general,
    parse_sniffing_settings, port_hop_syntax, port_is_shell_editable, raw_port_display,
    sniffing_is_absent_defaults, validate_listen_address,
};
pub use inbound_fallbacks::{
    FallbackDest, FallbackDestKind, FallbackObject, apply_fallbacks, fallbacks_compatible_on_inbound,
    fallbacks_transport_compatible, parse_fallbacks, reconcile_inbound_fallbacks, validate_fallbacks,
};
pub use inbound_protocol::{
    InboundProtocolDraft, TUNNEL_NETWORKS, apply_inbound_protocol, parse_inbound_protocol,
    validate_port_map_target,
};
pub use inbound_security::{
    ALPN_PRESETS, CERT_USAGE_PRESETS, CURVE_PRESETS, CertificateDraft, FINGERPRINT_PRESETS,
    InboundSecurityDraft, InboundSecurityMode, RealityDestinationKey,
    RealityLimitFallbackDraft, RealitySettingsDraft, TLS_VERSION_PRESETS, TlsSettingsDraft,
    apply_inbound_security, parse_inbound_security, trojan_reality_stream_settings,
};
pub use inbound_stream::{
    ADDRESS_PORT_STRATEGIES, DOMAIN_STRATEGIES, FinalMaskLayerDraft, GrpcStreamSettings,
    HappyEyeballsDraft, HysteriaStreamSettings, InboundStreamDraft, KCP_DEFAULT_DOWNLINK,
    KCP_DEFAULT_MTU, KCP_DEFAULT_READ_BUFFER, KCP_DEFAULT_TTI, KCP_DEFAULT_UPLINK,
    KCP_DEFAULT_WRITE_BUFFER, KCP_MTU_MAX, KCP_MTU_MIN, KCP_TTI_MAX, KCP_TTI_MIN,
    KcpStreamSettings, QuicParamsDraft, SockoptDraft, StreamMethod, StreamMethodKey,
    TCP_CONGESTION_PRESETS, TCP_FINALMASK_TYPES, TPROXY_MODES, TcpFastOpenDraft, TcpNestedKey,
    TcpStreamSettings, UDP_FINALMASK_TYPES, XHTTP_DEFAULT_PADDING_FROM, XHTTP_DEFAULT_PADDING_TO,
    XHTTP_DEFAULT_SC_MAX_BUFFERED_POSTS, XHTTP_DEFAULT_SC_MAX_EACH_POST,
    XHTTP_DEFAULT_SC_MIN_POSTS_INTERVAL_MS, XHTTP_DEFAULT_SC_STREAM_UP_FROM,
    XHTTP_DEFAULT_SC_STREAM_UP_TO, XHTTP_DEFAULT_SERVER_MAX_HEADER_BYTES,
    XHTTP_DOWNLOAD_SECURITIES, XHTTP_MODES, XHTTP_MODE_DEFAULT, XHTTP_PADDING_METHODS,
    XHTTP_PATH_DEFAULT, XHTTP_PLACEMENTS, XHTTP_SESSION_ID_TABLES, XHTTP_UPLINK_METHODS,
    WsStreamSettings, XhttpCoreSettings, XhttpDownloadDraft, XhttpRange, XhttpStreamSettings,
    XmuxDraft, apply_inbound_stream, apply_tunnel_sockopt, finalmask_layers_to_value, join_ws_path_and_ed,
    hysteria_salamander_obfs_password, parse_finalmask_layers, parse_inbound_stream, parse_sockopt,
    sockopt_to_value, split_ws_path_and_ed, validate_finalmask_layers, validate_kcp_settings,
    validate_sockopt, validate_xhttp_settings, xhttp_extra_json, xhttp_extra_object, xhttp_to_object,
};
pub use json_diff::{
    JsonDiffEntry, JsonDiffKind, redacted_json_diff, redacted_json_diff_bytes,
    redacted_json_diff_lines,
};
pub use log_settings::{
    LogLevel, LogOutput, LogSettings, MaskAddress, apply_log_settings_to_value,
    is_custom_mask_format, log_settings_change_summary, log_settings_from_section,
    log_settings_to_new_value, validate_custom_mask_format, validate_log_settings,
};
pub use modify::{
    AddConfdirFileRequest, AddInboundClientRequest, AddInboundRequest, AddOutboundRequest,
    AddOutboundShellRequest, AddUserRequest, DeleteInboundClientRequest, DeleteInboundRequest,
    DeleteOutboundRequest, DeleteUserRequest, DuplicateInboundRequest, DuplicateOutboundRequest,
    ModifyConfigOutcome, ModifyUserOutcome, RemoveConfdirFileRequest, RemoveOutboundRequest,
    RenameOutboundOutcome, RenameOutboundTagRequest, ReplaceInboundRawJsonRequest,
    ReplaceOutboundRawJsonRequest, ReplaceOutboundRequest,
    UpdateApiSettingsRequest, UpdateDnsSettingsRequest, UpdateFakeDnsSettingsRequest,
    UpdateInboundClientRequest,
    UpdateInboundGeneralRequest, UpdateInboundShellRequest, UpdateInboundSniffingRequest,
    UpdateBurstObservatorySettingsRequest, UpdateEnvSettingsRequest, UpdateGeodataSettingsRequest,
    UpdateLogSettingsRequest, UpdateMetricsSettingsRequest, UpdateObservatorySettingsRequest,
    UpdateOutboundShellRequest,
    UpdatePolicySettingsRequest,
    UpdateRoutingSettingsRequest, UpdateStatsSettingsRequest, UpdateVersionSettingsRequest,
    UpdateUserRequest, add_confdir_file, add_inbound, add_inbound_client, add_outbound,
    add_outbound_shell, add_user, delete_inbound, delete_inbound_client, delete_outbound,
    delete_user, duplicate_inbound, duplicate_outbound, generate_client_auth,
    generate_client_uuid, remove_confdir_file, remove_outbound, rename_outbound_tag,
    replace_inbound_raw_json, replace_outbound, replace_outbound_raw_json, update_api_settings,
    update_burst_observatory_settings,
    update_dns_settings, update_env_settings, update_fakedns_settings, update_geodata_settings,
    update_inbound_client,
    update_inbound_general,
    update_inbound_shell,
    update_inbound_sniffing, update_log_settings, update_metrics_settings,
    update_observatory_settings,
    update_outbound_shell, update_policy_settings,
    update_routing_settings, update_stats_settings, update_version_settings,
    update_user,
};
pub use metrics_settings::{
    MetricsSettings, apply_metrics_settings_to_value, metrics_settings_change_summary,
    metrics_settings_from_section, metrics_settings_to_new_value, validate_metrics_settings,
};
pub use version_settings::{
    VersionSettings, apply_version_settings_to_value, validate_version_settings,
    version_settings_change_summary, version_settings_from_section, version_settings_to_new_value,
};
pub use modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
pub use observatory_settings::{
    ObservatorySettings, apply_observatory_settings_to_value, observatory_settings_change_summary,
    observatory_settings_from_section, observatory_settings_to_new_value,
    validate_observatory_settings,
};
pub use outbound_edit::{
    OutboundGeneral, OutboundRef, ProxySettingsDraft, apply_outbound_general, parse_outbound_general,
};
pub use outbound_protocol::{
    BLACKHOLE_RESPONSE_TYPES, DNS_REWRITE_NETWORKS, DNS_RULE_ACTIONS, DnsRuleDraft,
    FREEDOM_NOISE_TYPES, FragmentDraft, NoiseDraft, OutboundSettingsDraft,
    apply_outbound_settings, is_shell_editable_protocol, parse_outbound_settings,
};
pub use parser::{ConfigParseOutcome, XrayConfigParser};
pub use stats_settings::{
    StatsSettings, stats_settings_change_summary, stats_settings_from_section,
    stats_settings_to_value, validate_stats_settings,
};
pub use policy_settings::{
    PolicyLevelEntry, PolicySettings, SystemPolicyEntry, apply_policy_settings_to_value,
    policy_settings_change_summary, policy_settings_from_section, policy_settings_to_new_value,
    validate_policy_settings,
};
pub use reverse_proxy::{
    ReverseSniffingDraft, ReverseTagDraft, parse_reverse, reverse_to_value, validate_reverse,
};
pub use routing_settings::{
    BalancerEntry, BalancerStrategyType, CostEntry, DomainStrategy, NetworkKind, RoutingRuleEntry,
    RoutingSettings, StrategyEntry, StrategySettingsEntry, WebhookEntry,
    apply_routing_settings_to_value, routing_settings_change_summary, routing_settings_from_section,
    routing_settings_to_new_value, validate_routing_settings,
};
pub use sections::{KNOWN_SECTION_NAMES, XrayConfig, XrayConfigSections};
pub use sourced_section::SourcedSection;
pub use summary::{
    BurstObservatorySummary, BurstPingConfigSummary, DnsHostSummary, DnsServerSummary, DnsSummary,
    FakeDnsAddressFamily, FakeDnsPoolSummary, FakeDnsSummary, InboundSummary, ObservatorySummary,
    OutboundKind, OutboundSummary, PolicySummary, RoutingRuleSummary, RoutingSummary,
    SystemPolicySummary, UserPolicySummary, burst_observatory_summary, cmp_policy_level,
    dns_summary, fakedns_summary, inbound_summaries, observatory_summary, outbound_summaries,
    policy_summary, routing_summary,
};
pub use tag_refs::{
    format_tag_reference_block, inbound_tag_references, outbound_tag_references,
};
pub use users::{
    HysteriaClientSummary, InboundClientSummary, SUPPORTED_USER_PROTOCOL,
    SupportedUserInbound, TrojanClientSummary, UserSummary, VlessClientSummary, clients_for_inbound,
    extract_inbound_clients, extract_vless_clients, supported_user_inbounds,
    supported_vless_user_inbounds, vless_clients_for_inbound,
};
pub use wiring::{routing_wiring_warnings, stats_wiring_warnings};

#[cfg(test)]
mod modify_tests;
#[cfg(test)]
mod tests;
