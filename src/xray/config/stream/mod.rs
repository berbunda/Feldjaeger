//! Direction-aware `streamSettings` building blocks shared by inbounds and outbounds
//! (Roadmap §2.6 stage 0.4).
//!
//! `streamSettings` has the same wire shape on both sides of a connection, but some fields only
//! mean something on one side: `sockopt.acceptProxyProtocol` configures a listening socket
//! (inbound), `sockopt.dialerProxy` a dialing one (outbound); later, FinalMask client-only
//! fields (`xicmp.dgram`, `xdns.resolvers`, …) get the same treatment (stage 7). The typed
//! models here are direction-neutral and lossless — an inapplicable field is still parsed and
//! written back unchanged; [`StreamDirection`] only decides what an editor offers.
//!
//! Contents:
//! - [`finalmask`] — `finalmask.tcp[]` / `finalmask.udp[]` layer chains;
//! - [`finalmask_client`] — the client chain of an inbound's chains (share `fm`, stage 6.1);
//! - [`finalmask_layers`] — typed `settings` of individual layer types (`realm`, `xdns`,
//!   `mkcp-legacy`, `header-custom` and `xmc` in their own modules);
//! - [`values`] — shape-preserving `Int32Range` / `PortList` / `packet` values;
//! - [`quic_params`] — `finalmask.quicParams`;
//! - [`sockopt`] — `sockopt` plus per-direction field applicability.
//!
//! Transport-method settings (`tcpSettings`, `xhttpSettings`, …) still live in
//! `inbound_stream` and move here with the Outbound `streamSettings` editor (Tier 4 §4.2).

pub mod finalmask;
pub mod finalmask_client;
#[cfg(test)]
mod finalmask_fixtures;
#[cfg(test)]
mod finalmask_interop;
pub mod finalmask_header_custom;
pub mod finalmask_layers;
pub mod finalmask_mkcp;
pub mod finalmask_raw;
pub mod finalmask_realm;
pub mod finalmask_xdns;
pub mod finalmask_xmc;
pub mod quic_params;
pub mod sockopt;
pub mod values;

pub use finalmask::{
    CLIENT_ONLY_UDP_FINALMASK_TYPES, FinalMaskChain, FinalMaskLayerDraft,
    TCP_FINALMASK_TYPES, finalmask_tcp_layer_faces_probes,
    UDP_FINALMASK_TYPES, finalmask_layer_type_applies, finalmask_layers_to_value,
    validate_finalmask_layer, hy2_share_obfs, parse_finalmask_layers,
    validate_finalmask_layers,
};
pub use finalmask_client::{
    ClientFinalMask, ServerFinalMaskImport, client_finalmask, server_finalmask_from_client,
};
pub use finalmask_layers::{
    FRAGMENT_PACKETS_TLSHELLO, FragmentPackets, fragment_packets_mode, NoiseItemPayload, SALAMANDER_MIN_PASSWORD_BYTES,
    SUDOKU_ASCII_MODES, SUDOKU_MAX_PADDING, validate_sudoku_custom_table, validate_sudoku_settings,
    FragmentMaskSettings, NoiseMaskItem, NoiseMaskSettings, REALM_DEFAULT_PORT_MAP_LIFETIME_SECS,
    REALM_DEFAULT_PORT_MAP_TIMEOUT_SECS, REALM_IP_MODES, RealmPortMapping, RealmScheme,
    RealmSettings, RealmUrl, SalamanderSettings,
    SudokuSettings, UDPHOP_DEFAULT_INTERVAL_SECS, UDPHOP_LEGACY_SOCKOPT_KEY,
    UDPHOP_MIN_INTERVAL_SECS, UdpHopModes, UdpHopSettings, XdnsSettings, XicmpSettings,
    fragment_mask_settings_to_value,
    noise_mask_settings_to_value, parse_fragment_mask_settings, parse_noise_mask_settings,
    parse_realm_settings, parse_realm_url, parse_salamander_settings, parse_sudoku_settings,
    parse_udphop_mode, parse_udphop_settings, parse_xdns_settings, parse_xicmp_settings,
    realm_ip_mode_is_known, realm_settings_to_value, salamander_settings_to_value,
    sudoku_settings_to_value, udphop_settings_to_value, validate_realm_settings,
    validate_udphop_settings, xdns_settings_to_value, xicmp_settings_to_value,
    NOISE_EXP_KIND, XDNS_DEFAULT_LABEL_LIMIT, XDNS_DEFAULT_LEN_LIMIT, XDNS_RECORD_TYPES,
    XDNS_RESOLVER_KINDS, XdnsDomain, XdnsResolver, migrate_legacy_xdns_settings,
    xdns_has_legacy_fields, xdns_record_type_name,
};
pub use finalmask_header_custom::{
    HEADER_CUSTOM_UDP_DEFAULT_MODE, HeaderCustomItem, HeaderCustomItemKind, HeaderCustomItems,
    HeaderCustomSequences, HeaderCustomTcpGroup, HeaderCustomTcpSettings, HeaderCustomUdpGroup,
    HeaderCustomUdpSettings, header_custom_tcp_settings_to_value,
    header_custom_udp_settings_to_value, parse_header_custom_tcp_settings,
    parse_header_custom_udp_settings,
};
pub use finalmask_mkcp::{
    MKCP_LEGACY_DEFAULT_DNS_DOMAIN, MKCP_LEGACY_HEADERS, MkcpLegacyMode, MkcpLegacySettings,
    mkcp_legacy_layers_from_kcp, mkcp_legacy_settings_to_value, parse_mkcp_legacy_settings,
    validate_mkcp_legacy_settings,
};
pub use finalmask_raw::HEADER_CUSTOM_UDP_MODES;
pub use finalmask_xmc::{
    XMC_LEGACY_DEFAULT_USERNAME, XMC_MAX_PASSWORD_BYTES, XmcProfile, XmcSettings,
    migrate_legacy_xmc_usernames, parse_xmc_settings, xmc_has_legacy_usernames, xmc_settings_to_value,
    xmc_username_is_valid,
};
pub use quic_params::{
    QuicTransport, XHTTP3_CONGESTION_MODES, alpn_selects_http3, quic_transport_of,
    validate_quic_params_for_transport, validate_stream_quic_params,
    DIAL_HANDLING_UDP_FINALMASK_TYPES, LEGACY_UDP_HOP_MODE, LegacyUdpHopMigration,
    QUIC_PARAMS_LEGACY_UDP_HOP_KEY, migrate_legacy_udp_hop, udphop_layer_from_legacy_udp_hop,
    INBOUND_ONLY_QUIC_PARAMS_FIELDS, OUTBOUND_ONLY_QUIC_PARAMS_FIELDS, QUIC_BBR_PROFILES,
    QUIC_CONGESTION_MODES, QUIC_KEEP_ALIVE_PERIOD_RANGE, QUIC_MAX_IDLE_TIMEOUT_RANGE,
    QUIC_MIN_BRUTAL_BYTES_PER_SEC, QUIC_MIN_INCOMING_STREAMS, QUIC_MIN_RECEIVE_WINDOW,
    quic_bandwidth_bytes_per_sec, quic_params_field_applies, validate_quic_params,
    QuicParamsDraft, parse_quic_params, quic_params_to_value,
};
pub use sockopt::{
    ADDRESS_PORT_STRATEGIES, DOMAIN_STRATEGIES, HappyEyeballsDraft, INBOUND_ONLY_SOCKOPT_FIELDS,
    OUTBOUND_ONLY_SOCKOPT_FIELDS, SockoptDraft, TCP_CONGESTION_PRESETS, TPROXY_MODES,
    TcpFastOpenDraft, parse_sockopt, sockopt_field_applies, sockopt_to_value, validate_sockopt,
};
pub use values::{
    PacketValue, PortListValue, RangeValue, escape_packet_text, parse_range_values,
    range_values_from_lines, range_values_to_lines, unescape_packet_text,
};

/// Which side of a connection a `streamSettings` block configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamDirection {
    /// `inbounds[].streamSettings` — the listening (server) side.
    Inbound,
    /// `outbounds[].streamSettings` — the dialing (client) side.
    Outbound,
}

impl StreamDirection {
    /// Lower-case name for UI text and log fields (`"inbound"` / `"outbound"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}
