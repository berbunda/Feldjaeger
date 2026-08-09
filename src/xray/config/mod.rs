//! Internal Xray configuration model and lossless parser.
//!
//! This module replaces the previous flat `XrayConfig` / `XrayConfigParser`
//! pair with a sourced section model suitable for single-file and directory
//! configs, while keeping unknown data for future write-back.

mod compatibility;
mod editable;
mod errors;
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
mod parser;
mod sections;
mod serialize;
mod sourced_section;
mod summary;
mod tag_refs;
mod users;

pub use compatibility::{
    CompatibilityGateId, allowed_security_modes, allowed_stream_methods, check_inbound_compatibility,
    coerce_display_stream_method, coerce_security_mode_for_transport, effective_security,
    first_failing_gate, g10_hysteria_requires_tls, g11_shadowsocks_tcp_only,
    g9_hysteria_protocol_transport_ok, inbound_has_vision_flow, matrix_transport, normalized_method,
    selectable_stream_methods, transport_security_allowed, vision_active_from_inbound,
};
pub use editable::{EditableXrayConfig, InboundLocation, OutboundLocation, parse_file_roots};
pub use errors::{ConfigError, ConfigErrorKind};
pub use inbound_clients::{
    ClientRef, ClientsArrayKey, HysteriaClient, InboundClient, InboundClientProtocol,
    SecretFieldDraft, TrojanClient, VlessClient, apply_secret_draft, client_fingerprint,
    inbound_fingerprint, json_value_fingerprint, parse_inbound_client,
    resolve_clients_array_key, resolve_or_create_clients_array_key, verify_client_fingerprint,
    verify_inbound_fingerprint, verify_json_fingerprint, write_inbound_client,
};
pub use inbound_edit::{
    InboundGeneral, InboundRef, KNOWN_DEST_OVERRIDE, SniffingSettings, SniffingWriteOutcome,
    apply_inbound_general, apply_inbound_sniffing, parse_inbound_general, parse_sniffing_settings,
    port_is_shell_editable, sniffing_is_absent_defaults, validate_listen_address,
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
    parse_finalmask_layers, parse_inbound_stream, parse_sockopt, sockopt_to_value,
    split_ws_path_and_ed, validate_finalmask_layers, validate_kcp_settings, validate_sockopt,
    validate_xhttp_settings, xhttp_extra_json, xhttp_extra_object, xhttp_to_object,
};
pub use json_diff::{JsonDiffEntry, JsonDiffKind, redacted_json_diff, redacted_json_diff_bytes};
pub use log_settings::{
    LogLevel, LogOutput, LogSettings, MaskAddress, apply_log_settings_to_value,
    is_custom_mask_format, log_settings_change_summary, log_settings_from_section,
    log_settings_to_new_value, validate_custom_mask_format, validate_log_settings,
};
pub use modify::{
    AddInboundClientRequest, AddInboundRequest, AddOutboundRequest, AddUserRequest,
    DeleteInboundClientRequest, DeleteInboundRequest, DeleteOutboundRequest, DeleteUserRequest,
    DuplicateInboundRequest, ModifyConfigOutcome, ModifyUserOutcome, RemoveOutboundRequest,
    ReplaceOutboundRequest, UpdateInboundClientRequest, UpdateInboundGeneralRequest,
    UpdateInboundShellRequest, UpdateInboundSniffingRequest, UpdateLogSettingsRequest,
    UpdateUserRequest, add_inbound, add_inbound_client, add_outbound, add_user, delete_inbound,
    delete_inbound_client, delete_outbound, delete_user, duplicate_inbound, generate_client_auth,
    generate_client_uuid, remove_outbound, replace_outbound, update_inbound_client,
    update_inbound_general, update_inbound_shell, update_inbound_sniffing, update_log_settings,
    update_user,
};
pub use modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
pub use parser::{ConfigParseOutcome, XrayConfigParser};
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

#[cfg(test)]
mod modify_tests;
#[cfg(test)]
mod tests;
