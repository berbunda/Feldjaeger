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
mod outbound_stream;
mod burst_observatory_settings;
mod metrics_settings;
mod observatory_settings;
mod parser;
mod policy_settings;
mod reverse_proxy;
mod routing_settings;
mod sections;
mod stats_settings;
mod stream;
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
    CompatibilityWarning, CompatibilityWarningId, WarningSeverity, inbound_warnings, outbound_warnings,
    with_warning_suffix, CORE_FEATURES, CoreFeature, XrayCoreVersion,
    CompatibilityGateId, allowed_security_modes, allowed_stream_methods, check_inbound_compatibility,
    check_outbound_compatibility, coerce_display_stream_method, coerce_security_mode_for_transport,
    effective_security, first_failing_gate, first_failing_outbound_gate, g10_hysteria_requires_tls, g11_shadowsocks_tcp_only,
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
    KCP_CWND_MULTIPLIER_MIN, KCP_DEFAULT_CWND_MULTIPLIER, KCP_DEFAULT_MAX_SENDING_WINDOW,
    KCP_DEFAULT_MTU, KCP_DEFAULT_TTI, KCP_DEFAULT_UPLINK, KCP_IGNORED_FIELDS,
    KCP_LEGACY_OBFUSCATION_FIELDS,
    KCP_MTU_MIN, KCP_TTI_MAX, KCP_TTI_MIN,
    KcpStreamSettings, QuicParamsDraft, SockoptDraft, StreamMethod, StreamMethodKey,
    TCP_CONGESTION_PRESETS, TCP_FINALMASK_TYPES, TPROXY_MODES, TcpFastOpenDraft, TcpNestedKey,
    TcpStreamSettings, UDP_FINALMASK_TYPES, XHTTP_DEFAULT_PADDING_FROM, XHTTP_DEFAULT_PADDING_TO,
    XHTTP_DEFAULT_SC_MAX_BUFFERED_POSTS, XHTTP_DEFAULT_SC_MAX_EACH_POST,
    XHTTP_DEFAULT_SC_MIN_POSTS_INTERVAL_MS, XHTTP_DEFAULT_SC_STREAM_UP_FROM,
    XHTTP_DEFAULT_SC_STREAM_UP_TO, XHTTP_DEFAULT_SERVER_MAX_HEADER_BYTES,
    XHTTP_DOWNLOAD_SECURITIES, XHTTP_MODES, XHTTP_MODE_DEFAULT, XHTTP_PADDING_METHODS,
    XHTTP_PATH_DEFAULT, XHTTP_PLACEMENTS, XHTTP_SESSION_ID_TABLES, XHTTP_UPLINK_METHODS,
    WsStreamSettings, XhttpCoreSettings, XhttpDownloadDraft, XhttpRange, XhttpStreamSettings,
    XmuxDraft, apply_inbound_stream, apply_tunnel_stream, finalmask_layers_to_value, join_ws_path_and_ed,
    ClientFinalMask, ServerFinalMaskImport, client_finalmask, server_finalmask_from_client,
    hy2_share_obfs, parse_finalmask_layers, parse_inbound_stream, parse_sockopt,
    sockopt_to_value, split_ws_path_and_ed, validate_finalmask_layers, validate_kcp_settings,
    validate_sockopt, validate_xhttp_settings, xhttp_extra_json, xhttp_extra_object, xhttp_to_object,
    FragmentMaskSettings, NoiseMaskItem, NoiseMaskSettings, RealmSettings, SalamanderSettings,
    SudokuSettings, UdpHopSettings, XdnsSettings, XicmpSettings, fragment_mask_settings_to_value,
    noise_mask_settings_to_value, parse_fragment_mask_settings, parse_noise_mask_settings,
    parse_realm_settings, parse_salamander_settings, parse_sudoku_settings, parse_udphop_settings,
    parse_xdns_settings, parse_xicmp_settings, realm_settings_to_value,
    salamander_settings_to_value, sudoku_settings_to_value, udphop_settings_to_value,
    xdns_settings_to_value, xicmp_settings_to_value, PacketValue, PortListValue, RangeValue,
    parse_range_values, range_values_from_lines, range_values_to_lines,
};
pub use stream::{
    QuicTransport, XHTTP3_CONGESTION_MODES, alpn_selects_http3, quic_transport_of,
    validate_quic_params_for_transport, validate_stream_quic_params,
    DIAL_HANDLING_UDP_FINALMASK_TYPES, LEGACY_UDP_HOP_MODE, LegacyUdpHopMigration,
    QUIC_PARAMS_LEGACY_UDP_HOP_KEY, migrate_legacy_udp_hop, udphop_layer_from_legacy_udp_hop,
    INBOUND_ONLY_QUIC_PARAMS_FIELDS, OUTBOUND_ONLY_QUIC_PARAMS_FIELDS, QUIC_BBR_PROFILES,
    QUIC_CONGESTION_MODES, QUIC_KEEP_ALIVE_PERIOD_RANGE, QUIC_MAX_IDLE_TIMEOUT_RANGE,
    QUIC_MIN_BRUTAL_BYTES_PER_SEC, QUIC_MIN_INCOMING_STREAMS, QUIC_MIN_RECEIVE_WINDOW,
    parse_quic_params, quic_bandwidth_bytes_per_sec, quic_params_field_applies, validate_quic_params,
    CLIENT_ONLY_UDP_FINALMASK_TYPES, FinalMaskChain, INBOUND_ONLY_SOCKOPT_FIELDS,
    OUTBOUND_ONLY_SOCKOPT_FIELDS, StreamDirection, UDPHOP_DEFAULT_INTERVAL_SECS,
    UDPHOP_LEGACY_SOCKOPT_KEY, UDPHOP_MIN_INTERVAL_SECS, UdpHopModes,
    finalmask_layer_type_applies, finalmask_tcp_layer_faces_probes, parse_realm_url, parse_udphop_mode, sockopt_field_applies,
    validate_udphop_settings, REALM_DEFAULT_PORT_MAP_LIFETIME_SECS,
    REALM_DEFAULT_PORT_MAP_TIMEOUT_SECS, REALM_IP_MODES, RealmPortMapping, RealmScheme, RealmUrl,
    realm_ip_mode_is_known, validate_realm_settings,
    validate_finalmask_layer, MKCP_LEGACY_HEADERS, HEADER_CUSTOM_UDP_MODES,
    MKCP_LEGACY_DEFAULT_DNS_DOMAIN, MkcpLegacyMode, MkcpLegacySettings, mkcp_legacy_settings_to_value,
    parse_mkcp_legacy_settings, validate_mkcp_legacy_settings,
    XMC_LEGACY_DEFAULT_USERNAME, XMC_MAX_PASSWORD_BYTES, XmcProfile,
    XmcSettings, migrate_legacy_xmc_usernames, parse_xmc_settings, xmc_settings_to_value,
    xmc_username_is_valid,
    HeaderCustomItem, HeaderCustomItemKind, HeaderCustomSequences, HeaderCustomTcpGroup,
    HeaderCustomTcpSettings, header_custom_tcp_settings_to_value, parse_header_custom_tcp_settings,
    HEADER_CUSTOM_UDP_DEFAULT_MODE, HeaderCustomItems, HeaderCustomUdpGroup, HeaderCustomUdpSettings,
    header_custom_udp_settings_to_value, parse_header_custom_udp_settings,
    escape_packet_text, unescape_packet_text,
    FRAGMENT_PACKETS_TLSHELLO, FragmentPackets, fragment_packets_mode, NoiseItemPayload, SALAMANDER_MIN_PASSWORD_BYTES,
    SUDOKU_ASCII_MODES, SUDOKU_MAX_PADDING, validate_sudoku_custom_table, validate_sudoku_settings,
    NOISE_EXP_KIND,
    XDNS_DEFAULT_LABEL_LIMIT, XDNS_DEFAULT_LEN_LIMIT, XDNS_RECORD_TYPES, XDNS_RESOLVER_KINDS,
    XdnsDomain, XdnsResolver, migrate_legacy_xdns_settings, xdns_has_legacy_fields,
    xdns_record_type_name,
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
    update_inbound_shell, compose_inbound_shell, build_add_inbound_value,
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
    LegacyProxySettings, OutboundGeneral, OutboundRef, ProxySettingsMigration, apply_outbound_general,
    parse_outbound_general, validate_send_through,
};
pub use outbound_protocol::{
    BLACKHOLE_RESPONSE_TYPES, DNS_REWRITE_NETWORKS, DNS_RULE_ACTIONS, DnsRuleDraft,
    FREEDOM_DEFAULT_BLOCK_DELAY, FREEDOM_FINAL_RULE_ACTIONS, FREEDOM_FINAL_RULE_NETWORKS,
    FREEDOM_LEGACY_STRATEGY_KEYS, FREEDOM_NOISE_TYPES, FREEDOM_PROXY_PROTOCOL_VERSIONS,
    FragmentDraft, FreedomFinalRuleDraft, FreedomSettingsDraft, LegacyDomainStrategyMigration, LoopbackRouting, LoopbackSettingsDraft, loopback_routing,
    NoiseDraft, OutboundSettingsDraft,
    apply_outbound_settings, is_shell_editable_protocol, legacy_vnext_blocker, parse_outbound_settings,
};
pub use outbound_stream::{
    DialerProxyProblem, GrpcClientSettings, HYSTERIA_TRANSPORT_VERSION, HttpUpgradeClientSettings,
    HysteriaClientSettings, OutboundSecurityDraft, OutboundStreamDraft, OutboundTransport,
    REALITY_REFUSED_FINGERPRINTS, RawClientSettings, RealityClientDraft, RealityPublicKeyField,
    TLS_KNOWN_FINGERPRINTS, TlsClientDraft, WsClientSettings, apply_outbound_stream, dialer_proxy_problem,
    outbound_protocol_has_transport, outbound_protocol_uses_sockopt, outbound_transports_for_protocol, parse_outbound_stream,
    validate_outbound_stream,
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
