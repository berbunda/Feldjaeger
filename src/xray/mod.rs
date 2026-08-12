//! Xray configuration and lifecycle management.
//!
//! Uses [`crate::init::InitSystemManager`] for service control and
//! [`crate::remote::RemoteAdmin`] for configuration I/O.
//! Does not depend on SSH library APIs directly.

pub mod config;
mod discovery;
mod geodata;
mod installation;
mod installer;
pub mod logs;
mod manager;
pub mod remote_cli;
pub mod secret;
pub mod share_uri;
mod validator;
pub mod warp;
mod x25519_local;

pub use config::{
    AddInboundClientRequest, AddInboundRequest, AddOutboundRequest, AddOutboundShellRequest,
    AddUserRequest, BLACKHOLE_RESPONSE_TYPES, DNS_REWRITE_NETWORKS, DNS_RULE_ACTIONS, DnsRuleDraft,
    FREEDOM_NOISE_TYPES, FragmentDraft, NoiseDraft,
    OutboundGeneral, OutboundRef, OutboundSettingsDraft, UpdateOutboundShellRequest,
    add_outbound_shell, apply_outbound_general, apply_outbound_settings, is_shell_editable_protocol,
    parse_outbound_general, parse_outbound_settings, update_outbound_shell,
    ALPN_PRESETS, BurstObservatorySummary, BurstPingConfigSummary, CERT_USAGE_PRESETS,
    CompatibilityGateId, ConfigError, ConfigErrorKind, ConfigModifyError, ConfigModifyErrorKind,
    ConfigModifyResult, ConfigParseOutcome, CURVE_PRESETS, DeleteInboundClientRequest,
    DeleteInboundRequest, DeleteOutboundRequest, DeleteUserRequest, DnsHostSummary,
    DuplicateInboundRequest, DnsServerSummary, DnsSummary, EditableXrayConfig, FINGERPRINT_PRESETS,
    FakeDnsAddressFamily, FakeDnsPoolSummary, FakeDnsSummary, FallbackDest, FallbackDestKind,
    FallbackObject, FinalMaskLayerDraft, InboundClientProtocol, InboundClientSummary,
    InboundGeneral, InboundLocation,
    InboundProtocolDraft, InboundRef, InboundSecurityDraft, InboundSecurityMode, InboundStreamDraft,
    InboundSummary, JsonDiffEntry, JsonDiffKind, KNOWN_DEST_OVERRIDE, KNOWN_SECTION_NAMES,
    KCP_DEFAULT_DOWNLINK, KCP_DEFAULT_MTU, KCP_DEFAULT_READ_BUFFER, KCP_DEFAULT_TTI,
    KCP_DEFAULT_UPLINK, KCP_DEFAULT_WRITE_BUFFER, KCP_MTU_MAX, KCP_MTU_MIN, KCP_TTI_MAX,
    KCP_TTI_MIN, KcpStreamSettings, LogLevel, LogOutput, LogSettings, MaskAddress,
    ADDRESS_PORT_STRATEGIES, DOMAIN_STRATEGIES, HappyEyeballsDraft, SockoptDraft,
    TCP_CONGESTION_PRESETS, TPROXY_MODES, TcpFastOpenDraft,
    XHTTP_DOWNLOAD_SECURITIES, XHTTP_MODES, XHTTP_MODE_DEFAULT, XHTTP_PADDING_METHODS,
    XHTTP_PATH_DEFAULT, XHTTP_PLACEMENTS, XHTTP_SESSION_ID_TABLES, XHTTP_UPLINK_METHODS,
    XhttpCoreSettings, XhttpDownloadDraft, XhttpRange, XhttpStreamSettings, XmuxDraft,
    ModifyConfigOutcome, ModifyUserOutcome, ObservatorySummary, OutboundKind, OutboundLocation,
    OutboundSummary, PolicySummary, RealityDestinationKey, RealityLimitFallbackDraft,
    RealitySettingsDraft,
    RemoveOutboundRequest, ReplaceOutboundRequest, RoutingRuleSummary, RoutingSummary,
    SUPPORTED_USER_PROTOCOL, SecretFieldDraft, SniffingSettings, SniffingWriteOutcome,
    SourcedSection, StreamMethod, StreamMethodKey, SupportedUserInbound, SystemPolicySummary,
    TCP_FINALMASK_TYPES, TLS_VERSION_PRESETS, TUNNEL_NETWORKS, UDP_FINALMASK_TYPES,
    CertificateDraft, TlsSettingsDraft, TrojanClientSummary,
    HysteriaClientSummary, UpdateInboundClientRequest, UpdateInboundGeneralRequest,
    UpdateInboundShellRequest, UpdateInboundSniffingRequest, UpdateLogSettingsRequest,
    UpdateUserRequest, UserPolicySummary, UserSummary, VlessClientSummary, XrayConfig,
    XrayConfigParser, XrayConfigSections, add_inbound, add_inbound_client, add_outbound, add_user,
    apply_fallbacks, apply_inbound_general, apply_inbound_protocol, apply_inbound_security,
    apply_inbound_sniffing, apply_inbound_stream, apply_tunnel_sockopt, allowed_security_modes, allowed_stream_methods,
    apply_log_settings_to_value, burst_observatory_summary, check_inbound_compatibility,
    clients_for_inbound, coerce_display_stream_method, coerce_security_mode_for_transport,
    cmp_policy_level, delete_inbound, delete_inbound_client, delete_outbound, delete_user,
    dns_summary, duplicate_inbound, effective_security, extract_inbound_clients,
    extract_vless_clients, fakedns_summary, fallbacks_compatible_on_inbound,
    fallbacks_transport_compatible, first_failing_gate, format_tag_reference_block,
    g10_hysteria_requires_tls, g11_shadowsocks_tcp_only, g9_hysteria_protocol_transport_ok,
    finalmask_layers_to_value, generate_client_auth, generate_client_uuid, inbound_fingerprint,
    inbound_has_vision_flow,
    inbound_summaries, inbound_tag_references, is_custom_mask_format, join_ws_path_and_ed,
    log_settings_change_summary, log_settings_from_section, log_settings_to_new_value,
    matrix_transport, normalized_method, observatory_summary, outbound_summaries,
    outbound_tag_references, parse_fallbacks, parse_file_roots, parse_finalmask_layers,
    parse_inbound_general,
    parse_inbound_protocol, parse_inbound_security, parse_inbound_stream, parse_sniffing_settings,
    parse_sockopt, sockopt_to_value,
    policy_summary, port_is_shell_editable, reconcile_inbound_fallbacks, redacted_json_diff,
    redacted_json_diff_bytes, remove_outbound, replace_outbound, routing_summary,
    selectable_stream_methods, sniffing_is_absent_defaults, split_ws_path_and_ed,
    supported_user_inbounds, supported_vless_user_inbounds, transport_security_allowed,
    trojan_reality_stream_settings, update_inbound_client, update_inbound_general,
    update_inbound_shell, update_inbound_sniffing, update_log_settings, update_user,
    validate_custom_mask_format, validate_fallbacks, validate_finalmask_layers,
    validate_kcp_settings, validate_listen_address, validate_sockopt,
    validate_log_settings, validate_port_map_target, validate_xhttp_settings,
    vision_active_from_inbound, vless_clients_for_inbound, xhttp_extra_json,
};
pub use remote_cli::{
    ConfigTestTarget, Mldsa65KeyPair, RemoteCliError, RemoteCliErrorKind, RemoteCliResult,
    VlessEncAuthKind, VlessEncOutput, VlessEncPair, X25519KeyPair, parse_mldsa65_stdout,
    parse_vlessenc_stdout, parse_x25519_stdout, run_config_test, run_mldsa65, run_vlessenc,
    run_x25519,
};
pub use discovery::{DiscoveryResult, XrayDiscoveryService};
pub use geodata::{
    GeoDataDatabaseSummary, GeoDataError, GeoDataErrorKind, GeoDataManager, GeoDataResolveHints,
    GeoDataResult, GeoDataSummary, parse_asset_dir_from_environment,
};
pub use installation::{
    ConfigSource, DiscoveryErrorKind, DiscoveryState, DiscoveryWarning, InitSystemKind,
    XrayInstallation,
};
pub use installer::{
    AvailableVersions, InstallChannel, InstallerError, InstallerErrorKind, InstallerResult,
    XrayInstaller, normalize_version_tag, parse_beta_tag, parse_latest_tag, version_gt,
};
pub use logs::{
    XrayLogAvailability, XrayLogConfigView, XrayLogDestination, XrayLogEntry, XrayLogError,
    XrayLogErrorKind, XrayLogLineLimit, XrayLogResult, XrayLogSearch, XrayLogService,
    XrayLogSourceKind, XrayLogSourceSummary, XrayLogStreamEvent, log_config_view,
};
pub use manager::XrayManager;
pub use secret::SecretString;
pub use share_uri::{
    ShareProtocol, ShareSecurity, ShareTransport, ShareUriError, ShareUriRequest, build_share_uri,
    pct_encode,
};
pub use validator::{ConfigValidator, DefaultConfigValidator};
pub use x25519_local::public_key_from_private_key;
pub use warp::{
    outbound_value_with_tag, WarpAdoptionOutcome, WarpConnectivityResult, WarpCredentials,
    WarpError, WarpErrorKind, WarpIntegrationState, WarpManager, WarpOutboundClassification,
    WarpOwnershipRecord, WarpProposedChange, WarpRemovalPlan, WarpResult, WarpSummary,
    DEFAULT_WARP_OUTBOUND_TAG,
};
