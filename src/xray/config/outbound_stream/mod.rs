//! Outbound `streamSettings` editor model — the client side of a transport and its security
//! (Roadmap §4.2 "Outbound `streamSettings` editor").
//!
//! Verified against `XTLS/Xray-core@main` (`infra/conf/transport_internet.go`,
//! `transport_method.go`, `transport_security.go`). One `StreamConfig` serves inbounds and
//! outbounds; the client reads different fields than the server:
//!
//! - RAW: only the legacy HTTP `header` obfuscation (kept as raw JSON); `acceptProxyProtocol` is
//!   server-only.
//! - XHTTP: the shared [`XhttpStreamSettings`] model already carries the client fields (`xmux`,
//!   `downloadSettings`, headers, padding/placement).
//! - gRPC: `authority`, `serviceName`, `multiMode`, `user_agent`, `idle_timeout`,
//!   `health_check_timeout`, `permit_without_stream`, `initial_windows_size` (`int32`).
//! - WebSocket: `host`, `path` (`?ed=` Early Data), `headers`, `heartbeatPeriod` (`uint32`); a
//!   `Host` entry in `headers` is deprecated in favour of `host`.
//! - HTTPUpgrade: `host`, `path`, `headers` — a `Host` header is refused.
//! - mKCP: the shared [`KcpStreamSettings`] (both sides read the same fields).
//! - Hysteria: `version` (must be 2), `auth`, `udpIdleTimeout` (0 or 2–600).
//!
//! The core reads `method` over `network` when both are set, `rawSettings` over `tcpSettings` and
//! `xhttpSettings` over `splithttpSettings`; the parser follows the same precedence and the writer
//! keeps the spelling found on disk. Nothing is written unless the user changed the Stream or
//! Security part ([`OutboundStreamDraft::write`]), so a Protocol-only Save leaves
//! `streamSettings` byte-for-byte as it was. Keys this model does not own (`address`, `port`,
//! unknown keys) are never touched.
//!
//! `sockopt` (Roadmap §4.2 "Outbound `sockopt` editor") is merged rather than rewritten: only the
//! keys whose typed value differs between the snapshot read from disk and the draft are set or
//! removed ([`OutboundStreamDraft::sockopt_changed`]). Another writer of the same object in one
//! Save — the `proxySettings` → `dialerProxy` migration of the General tab — keeps its key unless
//! the user edited that very key, and untouched keys keep their on-disk form.
//!
//! FinalMask (Roadmap §2.6 stage 7.1) is the client side of the shared direction-aware stream
//! module: `finalmask.tcp` / `finalmask.udp` layers validated for [`StreamDirection::Outbound`]
//! (client-only masks such as `udphop` are allowed here) and `finalmask.quicParams` for the QUIC
//! transports (Hysteria, XHTTP over HTTP/3). Each chain and `quicParams` is written only when it
//! was edited; other `finalmask` keys stay as they are, and a `finalmask` that is not an object
//! or a chain the typed model cannot read is never overwritten.

use serde_json::{Map, Value};

use crate::xray::config::compatibility::transport_security_allowed;
use crate::xray::config::inbound_security::InboundSecurityMode;
use crate::xray::config::inbound_stream::{
    KcpStreamSettings, StreamMethodKey, XhttpStreamSettings, join_ws_path_and_ed,
    kcp_settings_to_object, parse_kcp, parse_xhttp, split_ws_path_and_ed, validate_kcp_settings,
    validate_xhttp_settings, xhttp_to_object,
};
use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::config::stream::{
    FinalMaskChain, FinalMaskLayerDraft, LegacyUdpHopMigration, QuicParamsDraft, QuicTransport,
    StreamDirection, alpn_selects_http3, finalmask_layers_to_value, migrate_legacy_udp_hop,
    parse_finalmask_layers, parse_quic_params, quic_params_to_value, validate_finalmask_layers,
    SockoptDraft, TCP_CONGESTION_KEY, parse_sockopt, sockopt_to_value, validate_quic_params,
    validate_quic_params_for_transport, validate_sockopt, validate_stream_quic_params,
};

#[cfg(test)]
mod parity;
mod security;

pub use security::{
    OutboundSecurityDraft, REALITY_REFUSED_FINGERPRINTS, RealityClientDraft, RealityPublicKeyField,
    TLS_KNOWN_FINGERPRINTS, TlsClientDraft,
};
use security::{
    append_extras, apply_outbound_security, bool_field, extras_without, insert_non_empty,
    insert_true, parse_outbound_security, string_field, validate_outbound_security,
};

/// Default Hysteria transport `version` (the only one Xray-core accepts).
pub const HYSTERIA_TRANSPORT_VERSION: u64 = 2;

/// Transports the outbound Stream editor writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundTransport {
    /// RAW (`tcp` / `raw`).
    Raw,
    /// XHTTP (`xhttp` / `splithttp`).
    Xhttp,
    /// gRPC.
    Grpc,
    /// WebSocket (`websocket` / `ws`).
    WebSocket,
    /// HTTPUpgrade.
    HttpUpgrade,
    /// mKCP (`mkcp` / `kcp`).
    Mkcp,
    /// Hysteria (QUIC; only the Hysteria protocol uses it).
    Hysteria,
}

impl OutboundTransport {
    /// Every transport, in GUI order.
    pub const ALL: [Self; 7] = [
        Self::Raw,
        Self::Xhttp,
        Self::Grpc,
        Self::WebSocket,
        Self::HttpUpgrade,
        Self::Mkcp,
        Self::Hysteria,
    ];

    /// Wire value written for a new transport (same spellings as the inbound editor).
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Raw => "tcp",
            Self::Xhttp => "xhttp",
            Self::Grpc => "grpc",
            Self::WebSocket => "websocket",
            Self::HttpUpgrade => "httpupgrade",
            Self::Mkcp => "mkcp",
            Self::Hysteria => "hysteria",
        }
    }

    /// GUI label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Raw => "raw / tcp",
            Self::Xhttp => "xhttp",
            Self::Grpc => "grpc",
            Self::WebSocket => "websocket",
            Self::HttpUpgrade => "httpupgrade",
            Self::Mkcp => "mkcp",
            Self::Hysteria => "hysteria",
        }
    }

    /// Parses a wire value case-insensitively, like `TransportProtocol.Build()`.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" | "raw" => Some(Self::Raw),
            "xhttp" | "splithttp" => Some(Self::Xhttp),
            "grpc" => Some(Self::Grpc),
            "ws" | "websocket" => Some(Self::WebSocket),
            "httpupgrade" => Some(Self::HttpUpgrade),
            "kcp" | "mkcp" => Some(Self::Mkcp),
            "hysteria" => Some(Self::Hysteria),
            _ => None,
        }
    }

    /// The `*Settings` keys of this transport, preferred key first (the one the core reads when
    /// both are present).
    fn settings_keys(self) -> &'static [&'static str] {
        match self {
            Self::Raw => &["rawSettings", "tcpSettings"],
            Self::Xhttp => &["xhttpSettings", "splithttpSettings"],
            Self::Grpc => &["grpcSettings"],
            Self::WebSocket => &["wsSettings"],
            Self::HttpUpgrade => &["httpupgradeSettings"],
            Self::Mkcp => &["kcpSettings"],
            Self::Hysteria => &["hysteriaSettings"],
        }
    }
}

/// Whether an outbound protocol dials through `streamSettings` transports (and so gets the
/// Stream / Security editor). Freedom, Blackhole, DNS, Loopback and WireGuard do not.
pub fn outbound_protocol_has_transport(protocol: &str) -> bool {
    matches!(
        protocol.trim().to_ascii_lowercase().as_str(),
        "vless" | "vmess" | "trojan" | "shadowsocks" | "socks" | "http" | "hysteria"
    )
}

/// Whether `streamSettings.sockopt` has an effect on an outbound of `protocol`: every protocol
/// that opens a socket — the transport protocols, Freedom, DNS (its upstream queries) and
/// WireGuard. Blackhole and Loopback never dial.
pub fn outbound_protocol_uses_sockopt(protocol: &str) -> bool {
    !matches!(protocol.trim().to_ascii_lowercase().as_str(), "blackhole" | "loopback")
}

/// Transports offered for an outbound protocol: Hysteria only with its own transport, every
/// other proxy protocol with all the rest.
pub fn outbound_transports_for_protocol(protocol: &str) -> Vec<OutboundTransport> {
    let hysteria = protocol.trim().eq_ignore_ascii_case("hysteria");
    OutboundTransport::ALL
        .into_iter()
        .filter(|transport| (*transport == OutboundTransport::Hysteria) == hysteria)
        .collect()
}

/// RAW client settings: nothing typed — the legacy HTTP `header` obfuscation (and the
/// server-only `acceptProxyProtocol`) are kept as they are.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawClientSettings {
    /// The whole nested object, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// gRPC client settings (`GRPCConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrpcClientSettings {
    /// `authority` (HTTP/2 `:authority`); empty = the address.
    pub authority: String,
    /// `serviceName`.
    pub service_name: String,
    /// `multiMode`.
    pub multi_mode: bool,
    /// `user_agent`; empty = gRPC default.
    pub user_agent: String,
    /// `idle_timeout` seconds; `None` = disabled.
    pub idle_timeout: Option<i64>,
    /// `health_check_timeout` seconds; `None` = default.
    pub health_check_timeout: Option<i64>,
    /// `permit_without_stream`.
    pub permit_without_stream: bool,
    /// `initial_windows_size` bytes; `None` = default.
    pub initial_windows_size: Option<i64>,
    /// Other keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// WebSocket client settings (`WebSocketConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WsClientSettings {
    /// `host` — HTTP Host header; empty = `serverName`, then the address.
    pub host: String,
    /// `path` without the `ed` query.
    pub path: String,
    /// Early Data size from `path?ed=N`.
    pub ed: Option<u64>,
    /// `headers` (string → string).
    pub headers: Vec<(String, String)>,
    /// `heartbeatPeriod` seconds; `None` = off.
    pub heartbeat_period: Option<u64>,
    /// Other keys (incl. `headers` when it is not a string map), preserved verbatim.
    pub extras: Map<String, Value>,
}

/// HTTPUpgrade client settings (`HttpUpgradeConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpUpgradeClientSettings {
    /// `host`; empty = `serverName`, then the address.
    pub host: String,
    /// `path` without the `ed` query.
    pub path: String,
    /// Early Data size from `path?ed=N`.
    pub ed: Option<u64>,
    /// `headers` (string → string; `Host` refused by the core).
    pub headers: Vec<(String, String)>,
    /// Other keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// Hysteria transport client settings (`HysteriaConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaClientSettings {
    /// `version` (must be 2).
    pub version: Option<u64>,
    /// `auth` — the server's user password (secret; never logged).
    pub auth: String,
    /// `udpIdleTimeout` seconds; `None` = default 60.
    pub udp_idle_timeout: Option<u64>,
    /// Other keys (`masquerade` is server-only), preserved verbatim.
    pub extras: Map<String, Value>,
}

impl Default for HysteriaClientSettings {
    fn default() -> Self {
        Self {
            version: Some(HYSTERIA_TRANSPORT_VERSION),
            auth: String::new(),
            udp_idle_timeout: None,
            extras: Map::new(),
        }
    }
}

/// Outbound Stream + Security draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundStreamDraft {
    /// Selected transport; `None` with [`Self::other_transport`] = one this editor does not
    /// write (`masque`, `xdrive`, unknown) — then `streamSettings` stays untouched.
    pub transport: Option<OutboundTransport>,
    /// Wire value of a transport this editor does not write.
    pub other_transport: Option<String>,
    /// Which key holds the transport (`network` / `method`).
    pub method_key: StreamMethodKey,
    /// Transport on disk when the draft was read (`Raw` when absent — the core default).
    pub disk_transport: OutboundTransport,
    /// Spelling on disk, kept while the transport is unchanged.
    pub disk_wire: Option<String>,
    /// `*Settings` key found on disk for the transport, per transport (alias spelling).
    pub disk_settings_key: Option<&'static str>,
    /// RAW settings.
    pub raw: RawClientSettings,
    /// XHTTP settings (shared client/server model).
    pub xhttp: XhttpStreamSettings,
    /// gRPC settings.
    pub grpc: GrpcClientSettings,
    /// WebSocket settings.
    pub ws: WsClientSettings,
    /// HTTPUpgrade settings.
    pub httpupgrade: HttpUpgradeClientSettings,
    /// mKCP settings (shared model).
    pub kcp: KcpStreamSettings,
    /// Hysteria transport settings.
    pub hysteria: HysteriaClientSettings,
    /// Security (`none` / client TLS / client REALITY).
    pub security: OutboundSecurityDraft,
    /// The user changed the transport or Security part; only then are they written.
    pub write: bool,
    /// Typed `finalmask.tcp` layers (Roadmap §2.6 stage 7.1).
    pub finalmask_tcp: Vec<FinalMaskLayerDraft>,
    /// Write `finalmask.tcp` from [`Self::finalmask_tcp`] (set when edited).
    pub write_finalmask_tcp: bool,
    /// Typed `finalmask.udp` layers.
    pub finalmask_udp: Vec<FinalMaskLayerDraft>,
    /// Write `finalmask.udp` from [`Self::finalmask_udp`] (set when edited).
    pub write_finalmask_udp: bool,
    /// Typed `finalmask.quicParams`.
    pub quic_params: QuicParamsDraft,
    /// Write `finalmask.quicParams` from [`Self::quic_params`] (set when edited).
    pub write_quic_params: bool,
    /// `finalmask` on disk is neither an object nor `null`: not owned, never written.
    pub finalmask_foreign: bool,
    /// Chains present on disk that the typed model cannot read (not an array of `{type, …}`
    /// objects); their editor is unavailable and they are never overwritten.
    pub finalmask_unreadable: Vec<FinalMaskChain>,
    /// Typed `sockopt` as edited (Roadmap §4.2).
    pub sockopt: SockoptDraft,
    /// `sockopt` as read from disk; Save writes only the keys that differ from it.
    pub disk_sockopt: SockoptDraft,
    /// `sockopt` (or `streamSettings`) on disk is neither an object nor `null`: not owned, never
    /// written, and its editor is unavailable.
    pub sockopt_foreign: bool,
}

impl Default for OutboundStreamDraft {
    fn default() -> Self {
        Self {
            transport: Some(OutboundTransport::Raw),
            other_transport: None,
            method_key: StreamMethodKey::Network,
            disk_transport: OutboundTransport::Raw,
            disk_wire: None,
            disk_settings_key: None,
            raw: RawClientSettings::default(),
            xhttp: XhttpStreamSettings::default(),
            grpc: GrpcClientSettings::default(),
            ws: WsClientSettings::default(),
            httpupgrade: HttpUpgradeClientSettings::default(),
            kcp: KcpStreamSettings::default(),
            hysteria: HysteriaClientSettings::default(),
            security: OutboundSecurityDraft::default(),
            write: false,
            finalmask_tcp: Vec::new(),
            write_finalmask_tcp: false,
            finalmask_udp: Vec::new(),
            write_finalmask_udp: false,
            quic_params: QuicParamsDraft::default(),
            write_quic_params: false,
            finalmask_foreign: false,
            finalmask_unreadable: Vec::new(),
            sockopt: SockoptDraft::default(),
            disk_sockopt: SockoptDraft::default(),
            sockopt_foreign: false,
        }
    }
}

impl OutboundStreamDraft {
    /// Whether the transport part can be edited.
    pub fn is_editable(&self) -> bool {
        self.transport.is_some()
    }

    /// Default draft for a new outbound of `protocol` (Hysteria starts on its own transport and
    /// TLS, which it requires).
    pub fn default_for_protocol(protocol: &str) -> Self {
        let mut draft = Self::default();
        if protocol.trim().eq_ignore_ascii_case("hysteria") {
            draft.transport = Some(OutboundTransport::Hysteria);
            draft.disk_transport = OutboundTransport::Hysteria;
            draft.security.mode = InboundSecurityMode::Tls;
            // Written even untouched: without the hysteria transport Xray-core does not start
            // ("not hysteria transport"), without TLS no connection works (Roadmap §4.2).
            draft.write = true;
        }
        draft
    }

    /// Switches the transport (GUI); a transport entered for the first time starts from its
    /// defaults.
    pub fn select_transport(&mut self, transport: OutboundTransport) {
        if self.transport == Some(transport) {
            return;
        }
        match transport {
            OutboundTransport::Xhttp => self.xhttp = XhttpStreamSettings::default(),
            OutboundTransport::Mkcp => self.kcp = KcpStreamSettings::default(),
            OutboundTransport::Hysteria => self.hysteria = HysteriaClientSettings::default(),
            _ => {}
        }
        self.transport = Some(transport);
        self.other_transport = None;
        self.write = true;
    }

    /// The QUIC transport this draft configures — the one that reads `finalmask.quicParams`:
    /// Hysteria, or XHTTP with TLS and ALPN exactly `["h3"]` (Roadmap §2.6 stage 3.3).
    pub fn quic_transport(&self) -> Option<QuicTransport> {
        match self.transport? {
            OutboundTransport::Hysteria => Some(QuicTransport::Hysteria),
            OutboundTransport::Xhttp
                if self.security.is_editable()
                    && self.security.mode == InboundSecurityMode::Tls
                    && alpn_selects_http3(&self.security.tls.alpn) =>
            {
                Some(QuicTransport::XhttpH3)
            }
            _ => None,
        }
    }

    /// The FinalMask chain this outbound's transport dials through: `udp` for mKCP, Hysteria and
    /// XHTTP/3, `tcp` for the others (`transport/internet/*/dialer.go`; a proxy protocol such as
    /// VLESS carries its UDP inside the stream).
    pub fn dial_chain(&self) -> Option<FinalMaskChain> {
        match self.transport? {
            OutboundTransport::Mkcp | OutboundTransport::Hysteria => Some(FinalMaskChain::Udp),
            OutboundTransport::Xhttp if self.quic_transport().is_some() => Some(FinalMaskChain::Udp),
            _ => Some(FinalMaskChain::Tcp),
        }
    }

    /// Whether applying the draft writes into `finalmask`.
    pub fn writes_finalmask(&self) -> bool {
        self.write_finalmask_tcp || self.write_finalmask_udp || self.write_quic_params
    }

    /// Whether the `chain` editor is available (`finalmask` owned and the chain readable).
    pub fn finalmask_chain_editable(&self, chain: FinalMaskChain) -> bool {
        !self.finalmask_foreign && !self.finalmask_unreadable.contains(&chain)
    }

    /// Whether the user changed `sockopt` (only then is it written).
    pub fn sockopt_changed(&self) -> bool {
        self.sockopt != self.disk_sockopt
    }

    /// Clears `sockopt.addressPortStrategy` in the draft — the explicit fix for gate G14 (Freedom
    /// refuses the key from Xray-core v26.9.8). Returns the removed value, or `None` when it is
    /// already empty. Save removes the key.
    pub fn remove_address_port_strategy(&mut self) -> Option<String> {
        if self.sockopt.address_port_strategy.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut self.sockopt.address_port_strategy))
    }

    /// Moves the removed `quicParams.udpHop` (XTLS/Xray-core#6327) into the equivalent `udphop`
    /// layer at `finalmask.udp[0]` — the explicit migration action of Roadmap §2.6 stage 3.2 on
    /// the client side, where the old key was read. On error nothing changes. The caller checks
    /// the installed core (the `udphop` mask needs v26.9.9).
    pub fn migrate_legacy_udp_hop(&mut self) -> Result<LegacyUdpHopMigration, String> {
        if !self.finalmask_chain_editable(FinalMaskChain::Udp) {
            return Err("streamSettings.finalmask.udp can't be read by the editor; fix it on the \
                        Raw JSON tab first"
                .to_owned());
        }
        let migration =
            migrate_legacy_udp_hop(&mut self.quic_params, &mut self.finalmask_udp, StreamDirection::Outbound)?;
        self.write_quic_params = true;
        if matches!(migration, LegacyUdpHopMigration::Migrated { .. }) {
            self.write_finalmask_udp = true;
        }
        Ok(migration)
    }
}

/// Reads the Stream draft from an outbound object (absent `streamSettings` → RAW / `none`).
pub fn parse_outbound_stream(outbound: &Value) -> OutboundStreamDraft {
    let mut draft = OutboundStreamDraft::default();
    let stream = match outbound.get("streamSettings") {
        None | Some(Value::Null) => return draft,
        Some(Value::Object(stream)) => stream,
        Some(_) => {
            draft.sockopt_foreign = true;
            return draft;
        }
    };
    match stream.get("sockopt") {
        None | Some(Value::Null) => {}
        Some(Value::Object(sockopt)) => {
            draft.sockopt = parse_sockopt(sockopt);
            draft.disk_sockopt = draft.sockopt.clone();
        }
        Some(_) => draft.sockopt_foreign = true,
    }

    // `StreamConfig.Build()`: `method`, when present, replaces `network`.
    let (wire_value, method_key) = match (stream.get("method"), stream.get("network")) {
        (Some(method), _) if !method.is_null() => (Some(method), StreamMethodKey::Method),
        (_, Some(network)) if !network.is_null() => (Some(network), StreamMethodKey::Network),
        _ => (None, StreamMethodKey::Network),
    };
    draft.method_key = method_key;
    match wire_value {
        None => {}
        Some(Value::String(wire)) => match OutboundTransport::from_wire(wire) {
            Some(transport) => {
                draft.transport = Some(transport);
                draft.disk_transport = transport;
                draft.disk_wire = Some(wire.clone());
            }
            None => {
                draft.transport = None;
                draft.other_transport = Some(wire.trim().to_owned());
            }
        },
        Some(other) => {
            draft.transport = None;
            draft.other_transport = Some(other.to_string());
        }
    }

    let nested = |transport: OutboundTransport| -> Option<(&'static str, &Map<String, Value>)> {
        transport
            .settings_keys()
            .iter()
            .find_map(|key| stream.get(*key).and_then(Value::as_object).map(|object| (*key, object)))
    };
    if let Some(transport) = draft.transport {
        draft.disk_settings_key = nested(transport).map(|(key, _)| key);
    }
    if let Some((_, object)) = nested(OutboundTransport::Raw) {
        draft.raw = RawClientSettings { extras: object.clone() };
    }
    if let Some((_, object)) = nested(OutboundTransport::Xhttp) {
        draft.xhttp = parse_xhttp(object);
    }
    if let Some((_, object)) = nested(OutboundTransport::Grpc) {
        draft.grpc = parse_grpc_client(object);
    }
    if let Some((_, object)) = nested(OutboundTransport::WebSocket) {
        draft.ws = parse_ws_client(object);
    }
    if let Some((_, object)) = nested(OutboundTransport::HttpUpgrade) {
        draft.httpupgrade = parse_httpupgrade_client(object);
    }
    if let Some((_, object)) = nested(OutboundTransport::Mkcp) {
        draft.kcp = parse_kcp(object);
    }
    if let Some((_, object)) = nested(OutboundTransport::Hysteria) {
        draft.hysteria = parse_hysteria_client(object);
    }
    draft.security = parse_outbound_security(stream);

    match stream.get("finalmask") {
        None | Some(Value::Null) => {}
        Some(Value::Object(finalmask)) => {
            for chain in [FinalMaskChain::Tcp, FinalMaskChain::Udp] {
                let layers = match finalmask.get(chain.key()) {
                    None | Some(Value::Null) => Some(Vec::new()),
                    Some(Value::Array(array)) => parse_finalmask_layers(array),
                    Some(_) => None,
                };
                match (layers, chain) {
                    (Some(layers), FinalMaskChain::Tcp) => draft.finalmask_tcp = layers,
                    (Some(layers), FinalMaskChain::Udp) => draft.finalmask_udp = layers,
                    (None, _) => draft.finalmask_unreadable.push(chain),
                }
            }
            if let Some(quic_params) = finalmask.get("quicParams").and_then(Value::as_object) {
                draft.quic_params = parse_quic_params(quic_params);
            }
        }
        Some(_) => draft.finalmask_foreign = true,
    }
    draft
}

const GRPC_CLIENT_KEYS: &[&str] = &[
    "authority",
    "serviceName",
    "multiMode",
    "user_agent",
    "idle_timeout",
    "health_check_timeout",
    "permit_without_stream",
    "initial_windows_size",
];

fn parse_grpc_client(object: &Map<String, Value>) -> GrpcClientSettings {
    // Integers that are not JSON integers stay in extras instead of being dropped.
    let int = |key: &str| object.get(key).and_then(Value::as_i64);
    let mut extras = extras_without(object, GRPC_CLIENT_KEYS);
    for key in ["idle_timeout", "health_check_timeout", "initial_windows_size"] {
        if let Some(value) = object.get(key)
            && int(key).is_none()
        {
            extras.insert(key.to_owned(), value.clone());
        }
    }
    GrpcClientSettings {
        authority: string_field(object.get("authority")),
        service_name: string_field(object.get("serviceName")),
        multi_mode: bool_field(object.get("multiMode")),
        user_agent: string_field(object.get("user_agent")),
        idle_timeout: int("idle_timeout"),
        health_check_timeout: int("health_check_timeout"),
        permit_without_stream: bool_field(object.get("permit_without_stream")),
        initial_windows_size: int("initial_windows_size"),
        extras,
    }
}

/// `headers` as string pairs, or `None` when it is not an object of strings (then it is kept
/// as raw JSON).
fn parse_headers(value: Option<&Value>) -> Option<Vec<(String, String)>> {
    let object = value?.as_object()?;
    object
        .iter()
        .map(|(key, value)| value.as_str().map(|text| (key.clone(), text.to_owned())))
        .collect()
}

fn parse_ws_client(object: &Map<String, Value>) -> WsClientSettings {
    let (path, ed) = split_ws_path_and_ed(&string_field(object.get("path")));
    let headers = parse_headers(object.get("headers"));
    let heartbeat_period = object.get("heartbeatPeriod").and_then(Value::as_u64);
    let mut extras = extras_without(object, &["host", "path", "headers", "heartbeatPeriod"]);
    if headers.is_none()
        && let Some(raw) = object.get("headers")
    {
        extras.insert("headers".to_owned(), raw.clone());
    }
    if heartbeat_period.is_none()
        && let Some(raw) = object.get("heartbeatPeriod")
    {
        extras.insert("heartbeatPeriod".to_owned(), raw.clone());
    }
    WsClientSettings {
        host: string_field(object.get("host")),
        path,
        ed,
        headers: headers.unwrap_or_default(),
        heartbeat_period,
        extras,
    }
}

fn parse_httpupgrade_client(object: &Map<String, Value>) -> HttpUpgradeClientSettings {
    let (path, ed) = split_ws_path_and_ed(&string_field(object.get("path")));
    let headers = parse_headers(object.get("headers"));
    let mut extras = extras_without(object, &["host", "path", "headers"]);
    if headers.is_none()
        && let Some(raw) = object.get("headers")
    {
        extras.insert("headers".to_owned(), raw.clone());
    }
    HttpUpgradeClientSettings {
        host: string_field(object.get("host")),
        path,
        ed,
        headers: headers.unwrap_or_default(),
        extras,
    }
}

fn parse_hysteria_client(object: &Map<String, Value>) -> HysteriaClientSettings {
    let version = object.get("version").and_then(Value::as_u64);
    let udp_idle_timeout = object.get("udpIdleTimeout").and_then(Value::as_u64);
    let mut extras = extras_without(object, &["version", "auth", "udpIdleTimeout"]);
    for (key, typed) in [("version", version.is_some()), ("udpIdleTimeout", udp_idle_timeout.is_some())] {
        if !typed && let Some(raw) = object.get(key) {
            extras.insert(key.to_owned(), raw.clone());
        }
    }
    HysteriaClientSettings {
        version,
        auth: object.get("auth").and_then(Value::as_str).unwrap_or("").to_owned(),
        udp_idle_timeout,
        extras,
    }
}

/// Validates the draft the way the core's `Build()` would, without touching the outbound.
pub fn validate_outbound_stream(draft: &OutboundStreamDraft) -> ConfigModifyResult<()> {
    let Some(transport) = draft.transport else {
        return Ok(());
    };
    if draft.security.is_editable()
        && !transport_security_allowed(transport.as_wire(), draft.security.mode.as_wire())
    {
        return invalid(format!(
            "security \"{}\" cannot be used with the {} transport (Xray-core: REALITY only with \
             RAW, XHTTP and gRPC; Hysteria only with TLS)",
            draft.security.mode.as_wire(),
            transport.label()
        ));
    }
    match transport {
        OutboundTransport::Raw => {}
        OutboundTransport::Xhttp => validate_xhttp_settings(&draft.xhttp)?,
        OutboundTransport::Grpc => {
            for (key, value) in [
                ("idle_timeout", draft.grpc.idle_timeout),
                ("health_check_timeout", draft.grpc.health_check_timeout),
                ("initial_windows_size", draft.grpc.initial_windows_size),
            ] {
                if let Some(value) = value
                    && i32::try_from(value).is_err()
                {
                    return invalid(format!("grpcSettings.{key} must fit a 32-bit integer (got {value})"));
                }
            }
        }
        OutboundTransport::WebSocket => {
            if let Some(period) = draft.ws.heartbeat_period
                && u32::try_from(period).is_err()
            {
                return invalid(format!("wsSettings.heartbeatPeriod must fit a 32-bit unsigned integer (got {period})"));
            }
            validate_header_names("wsSettings", &draft.ws.headers)?;
        }
        OutboundTransport::HttpUpgrade => {
            validate_header_names("httpupgradeSettings", &draft.httpupgrade.headers)?;
            if draft.httpupgrade.headers.iter().any(|(key, _)| key.trim().eq_ignore_ascii_case("host")) {
                return invalid("httpupgradeSettings.headers can't contain \"Host\" (Xray-core); use the host field");
            }
        }
        OutboundTransport::Mkcp => validate_kcp_settings(&draft.kcp)?,
        OutboundTransport::Hysteria => {
            if draft.hysteria.version != Some(HYSTERIA_TRANSPORT_VERSION) {
                return invalid("hysteriaSettings.version must be 2");
            }
            if let Some(timeout) = draft.hysteria.udp_idle_timeout
                && timeout != 0
                && !(2..=600).contains(&timeout)
            {
                return invalid(format!("hysteriaSettings.udpIdleTimeout must be between 2 and 600 seconds (got {timeout})"));
            }
        }
    }
    validate_outbound_security(&draft.security)
}

/// Validates the `finalmask` parts the draft writes: layers for the client side, `quicParams` as
/// `StreamConfig.Build()` does (plus what the QUIC transport refuses, when there is one).
pub fn validate_outbound_finalmask(draft: &OutboundStreamDraft) -> ConfigModifyResult<()> {
    if !draft.writes_finalmask() {
        return Ok(());
    }
    if draft.finalmask_foreign {
        return invalid(
            "streamSettings.finalmask is not a JSON object; Feldjäger leaves it as is — fix or \
             remove it on the Raw JSON tab before editing FinalMask or quicParams",
        );
    }
    for (chain, write, layers) in [
        (FinalMaskChain::Tcp, draft.write_finalmask_tcp, &draft.finalmask_tcp),
        (FinalMaskChain::Udp, draft.write_finalmask_udp, &draft.finalmask_udp),
    ] {
        if !write {
            continue;
        }
        if draft.finalmask_unreadable.contains(&chain) {
            return invalid(format!(
                "streamSettings.finalmask.{} can't be read by the editor; fix it on the Raw JSON tab",
                chain.key()
            ));
        }
        validate_finalmask_layers(layers, chain, StreamDirection::Outbound)?;
    }
    if draft.write_quic_params {
        let checked = match draft.quic_transport() {
            Some(transport) => validate_quic_params_for_transport(&draft.quic_params, transport),
            None => validate_quic_params(&draft.quic_params),
        };
        if let Err(message) = checked {
            return invalid(format!("streamSettings.finalmask.{message}"));
        }
    }
    Ok(())
}

fn validate_header_names(object: &str, headers: &[(String, String)]) -> ConfigModifyResult<()> {
    let mut seen: Vec<String> = Vec::new();
    for (key, _) in headers {
        let key = key.trim();
        if key.is_empty() {
            return invalid(format!("{object}.headers: a header name is empty"));
        }
        if seen.iter().any(|other| other == key) {
            return invalid(format!("{object}.headers: \"{key}\" is listed twice"));
        }
        seen.push(key.to_owned());
    }
    Ok(())
}

/// Applies the Stream draft to an outbound in place. A draft the user did not change
/// ([`OutboundStreamDraft::write`] false) or with a transport this editor does not write leaves
/// the outbound untouched; otherwise the transport key, the transport's `*Settings` object and
/// the security keys are written, and — only when the transport changed — the other
/// transports' `*Settings` objects are dropped (the core builds every one present).
pub fn apply_outbound_stream(outbound: &mut Value, draft: &OutboundStreamDraft) -> ConfigModifyResult<()> {
    let transport = draft.transport.filter(|_| draft.write);
    let writes_finalmask = draft.writes_finalmask();
    let writes_sockopt = draft.sockopt_changed();
    if transport.is_none() && !writes_finalmask && !writes_sockopt {
        return Ok(());
    }
    // Everything is validated before the first mutation, so a rejected draft changes nothing.
    if transport.is_some() {
        validate_outbound_stream(draft)?;
    }
    validate_outbound_finalmask(draft)?;
    if writes_sockopt {
        validate_outbound_sockopt(outbound, draft)?;
    }
    if transport.is_none() && !writes_finalmask {
        return apply_outbound_sockopt(outbound, draft);
    }

    let root = outbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, "outbound must be a JSON object".to_owned())
    })?;
    if root.get("streamSettings").is_none_or(Value::is_null) {
        root.insert("streamSettings".to_owned(), Value::Object(Map::new()));
    }
    let stream = root.get_mut("streamSettings").and_then(Value::as_object_mut).ok_or_else(|| {
        ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, "streamSettings must be a JSON object".to_owned())
    })?;
    let before = stream.clone();
    if let Some(transport) = transport {
        write_transport_and_security(stream, transport, draft);
    }
    if writes_finalmask {
        write_finalmask(stream, draft);
    }
    // `quicParams` written now or kept from disk must suit the transport as composed.
    if let Err(message) = validate_stream_quic_params(&Value::Object(stream.clone())) {
        *stream = before;
        return invalid(message);
    }
    if writes_sockopt {
        apply_outbound_sockopt(outbound, draft)?;
    }
    Ok(())
}

/// Validates the `sockopt` draft as `SocketConfig.Build()` would ([`validate_sockopt`]), plus a
/// `dialerProxy` naming this very outbound: the core accepts it, but every connection would be
/// handed back to the same outbound without end. Checked only when the user changed the value.
pub fn validate_outbound_sockopt(outbound: &Value, draft: &OutboundStreamDraft) -> ConfigModifyResult<()> {
    if draft.sockopt_foreign {
        return invalid(
            "streamSettings.sockopt is not a JSON object; Feldjäger leaves it as is — fix or remove \
             it on the Raw JSON tab before editing socket options",
        );
    }
    validate_sockopt(&draft.sockopt)?;
    let dialer_proxy = draft.sockopt.dialer_proxy.trim();
    if dialer_proxy != draft.disk_sockopt.dialer_proxy.trim()
        && !dialer_proxy.is_empty()
        && outbound.get("tag").and_then(Value::as_str).is_some_and(|tag| tag.trim() == dialer_proxy)
    {
        return invalid(format!(
            "streamSettings.sockopt.dialerProxy \"{dialer_proxy}\" is this outbound's own tag — every \
             connection would be sent back into it; choose another outbound"
        ));
    }
    Ok(())
}

/// What is wrong with a `sockopt.dialerProxy` value — shown under the field. Xray-core loads all
/// of these; they fail at run time (`DialSystem`, `transport/internet/dialer.go`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialerProxyProblem {
    /// The value is the outbound's own tag (Save refuses it, [`validate_outbound_sockopt`]).
    SelfReference,
    /// No outbound has this tag: every connection fails with "there is no outbound handler for
    /// dialerProxy".
    UnknownTag,
    /// Following the other outbounds' `dialerProxy` leads back here; the tags of the loop, from
    /// this outbound to itself.
    Cycle(Vec<String>),
}

/// Checks `dialer_proxy` of the outbound tagged `own_tag` against `others` (every other outbound
/// of the config, as on disk). Empty value → `None`.
pub fn dialer_proxy_problem(own_tag: &str, dialer_proxy: &str, others: &[&Value]) -> Option<DialerProxyProblem> {
    let own_tag = own_tag.trim();
    let target = dialer_proxy.trim();
    if target.is_empty() {
        return None;
    }
    if target == own_tag {
        return Some(DialerProxyProblem::SelfReference);
    }
    let next_hop = |tag: &str| -> Option<Option<String>> {
        let outbound = others.iter().find(|outbound| outbound.get("tag").and_then(Value::as_str).map(str::trim) == Some(tag))?;
        Some(
            outbound
                .get("streamSettings")
                .and_then(|stream| stream.get("sockopt"))
                .and_then(|sockopt| sockopt.get("dialerProxy"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|next| !next.is_empty())
                .map(str::to_owned),
        )
    };
    let mut path = vec![own_tag.to_owned(), target.to_owned()];
    let mut current = target.to_owned();
    loop {
        match next_hop(&current) {
            // Only the first hop is ours to report; a broken link further on is that outbound's.
            None if path.len() == 2 => return Some(DialerProxyProblem::UnknownTag),
            None | Some(None) => return None,
            Some(Some(next)) => {
                if next == own_tag {
                    path.push(next);
                    return Some(DialerProxyProblem::Cycle(path));
                }
                // A loop among the others, not through this outbound.
                if path.contains(&next) {
                    return None;
                }
                path.push(next.clone());
                current = next;
            }
        }
    }
}

/// Merges the `sockopt` edits into the outbound (validated before): every key whose typed value
/// differs between [`OutboundStreamDraft::disk_sockopt`] and [`OutboundStreamDraft::sockopt`] is
/// set or removed; all other keys stay as they are. Containers are created for a new key and
/// dropped only when this merge left them empty.
fn apply_outbound_sockopt(outbound: &mut Value, draft: &OutboundStreamDraft) -> ConfigModifyResult<()> {
    let to_map = |sockopt: &SockoptDraft| match sockopt_to_value(sockopt) {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    let before = to_map(&draft.disk_sockopt);
    let after = to_map(&draft.sockopt);
    let mut changed: Vec<&String> = before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .collect();
    changed.sort();
    changed.dedup();
    if changed.is_empty() {
        return Ok(());
    }

    let root = outbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, "outbound must be a JSON object".to_owned())
    })?;
    let stream = object_entry(root, "streamSettings", "streamSettings")?;
    let sockopt = object_entry(stream, "sockopt", "streamSettings.sockopt")?;
    for key in changed {
        // Go matches keys case-insensitively: a rewritten congestion key replaces every spelling.
        if key.eq_ignore_ascii_case(TCP_CONGESTION_KEY) {
            sockopt.retain(|existing, _| !existing.eq_ignore_ascii_case(TCP_CONGESTION_KEY));
        }
        match after.get(key) {
            Some(value) => {
                sockopt.insert(key.clone(), value.clone());
            }
            None => {
                sockopt.remove(key);
            }
        }
    }
    if sockopt.is_empty() {
        stream.remove("sockopt");
        if stream.is_empty() {
            root.remove("streamSettings");
        }
    }
    Ok(())
}

/// `parent[key]` as an object, created when absent or `null`.
fn object_entry<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
    path: &str,
) -> ConfigModifyResult<&'a mut Map<String, Value>> {
    if parent.get(key).is_none_or(Value::is_null) {
        parent.insert(key.to_owned(), Value::Object(Map::new()));
    }
    parent.get_mut(key).and_then(Value::as_object_mut).ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{path} is not a JSON object; fix or remove it on the Raw JSON tab"),
        )
    })
}

/// The transport key, its `*Settings` object and the security keys (validated before).
fn write_transport_and_security(
    stream: &mut Map<String, Value>,
    transport: OutboundTransport,
    draft: &OutboundStreamDraft,
) {
    let unchanged = transport == draft.disk_transport;
    let wire = match (&draft.disk_wire, unchanged) {
        (Some(disk), true) => disk.clone(),
        _ => transport.as_wire().to_owned(),
    };
    let method_key = match draft.method_key {
        StreamMethodKey::Network => "network",
        StreamMethodKey::Method => "method",
    };
    stream.insert(method_key.to_owned(), Value::String(wire));

    if !unchanged {
        for other in OutboundTransport::ALL {
            for key in other.settings_keys() {
                stream.remove(*key);
            }
        }
    }
    let settings_key = match draft.disk_settings_key {
        Some(key) if unchanged => key,
        _ => transport.settings_keys()[0],
    };
    let settings = transport_settings_object(transport, draft);
    match settings {
        Some(object) => {
            stream.insert(settings_key.to_owned(), Value::Object(object));
        }
        None => {
            stream.remove(settings_key);
        }
    }

    apply_outbound_security(stream, &draft.security);
}

/// The edited `finalmask` parts, keeping every other `finalmask` key (validated before; a
/// foreign `finalmask` was refused).
fn write_finalmask(stream: &mut Map<String, Value>, draft: &OutboundStreamDraft) {
    let mut finalmask = match stream.remove("finalmask") {
        Some(Value::Object(existing)) => existing,
        _ => Map::new(),
    };
    if draft.write_finalmask_tcp {
        finalmask.insert("tcp".to_owned(), finalmask_layers_to_value(&draft.finalmask_tcp));
    }
    if draft.write_finalmask_udp {
        finalmask.insert("udp".to_owned(), finalmask_layers_to_value(&draft.finalmask_udp));
    }
    if draft.write_quic_params {
        finalmask.insert("quicParams".to_owned(), quic_params_to_value(&draft.quic_params));
    }
    stream.insert("finalmask".to_owned(), Value::Object(finalmask));
}

/// The `*Settings` object for the selected transport; `None` = nothing to write (RAW without
/// preserved keys).
fn transport_settings_object(transport: OutboundTransport, draft: &OutboundStreamDraft) -> Option<Map<String, Value>> {
    let object = match transport {
        OutboundTransport::Raw => {
            if draft.raw.extras.is_empty() {
                return None;
            }
            draft.raw.extras.clone()
        }
        OutboundTransport::Xhttp => xhttp_to_object(&draft.xhttp),
        OutboundTransport::Grpc => {
            let grpc = &draft.grpc;
            let mut object = Map::new();
            insert_non_empty(&mut object, "authority", &grpc.authority);
            insert_non_empty(&mut object, "serviceName", &grpc.service_name);
            insert_true(&mut object, "multiMode", grpc.multi_mode);
            insert_non_empty(&mut object, "user_agent", &grpc.user_agent);
            insert_int(&mut object, "idle_timeout", grpc.idle_timeout);
            insert_int(&mut object, "health_check_timeout", grpc.health_check_timeout);
            insert_true(&mut object, "permit_without_stream", grpc.permit_without_stream);
            insert_int(&mut object, "initial_windows_size", grpc.initial_windows_size);
            append_extras(&mut object, &grpc.extras);
            object
        }
        OutboundTransport::WebSocket => {
            let ws = &draft.ws;
            let mut object = Map::new();
            insert_non_empty(&mut object, "host", &ws.host);
            insert_non_empty(&mut object, "path", &join_ws_path_and_ed(&ws.path, ws.ed));
            insert_headers(&mut object, &ws.headers);
            if let Some(period) = ws.heartbeat_period {
                object.insert("heartbeatPeriod".to_owned(), Value::Number(period.into()));
            }
            append_extras(&mut object, &ws.extras);
            object
        }
        OutboundTransport::HttpUpgrade => {
            let hu = &draft.httpupgrade;
            let mut object = Map::new();
            insert_non_empty(&mut object, "host", &hu.host);
            insert_non_empty(&mut object, "path", &join_ws_path_and_ed(&hu.path, hu.ed));
            insert_headers(&mut object, &hu.headers);
            append_extras(&mut object, &hu.extras);
            object
        }
        OutboundTransport::Mkcp => kcp_settings_to_object(&draft.kcp),
        OutboundTransport::Hysteria => {
            let hy = &draft.hysteria;
            let mut object = Map::new();
            if let Some(version) = hy.version {
                object.insert("version".to_owned(), Value::Number(version.into()));
            }
            // The password is written as typed: leading/trailing spaces may be part of it.
            if !hy.auth.is_empty() {
                object.insert("auth".to_owned(), Value::String(hy.auth.clone()));
            }
            if let Some(timeout) = hy.udp_idle_timeout {
                object.insert("udpIdleTimeout".to_owned(), Value::Number(timeout.into()));
            }
            append_extras(&mut object, &hy.extras);
            object
        }
    };
    Some(object)
}

fn insert_int(object: &mut Map<String, Value>, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        object.insert(key.to_owned(), Value::Number(value.into()));
    }
}

fn insert_headers(object: &mut Map<String, Value>, headers: &[(String, String)]) {
    if headers.is_empty() {
        return;
    }
    let map: Map<String, Value> = headers
        .iter()
        .map(|(key, value)| (key.trim().to_owned(), Value::String(value.clone())))
        .collect();
    object.insert("headers".to_owned(), Value::Object(map));
}

fn invalid(message: impl Into<String>) -> ConfigModifyResult<()> {
    Err(ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::config::stream::{HappyEyeballsDraft, TcpFastOpenDraft};
    use serde_json::json;

    const PUBLIC_KEY: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

    #[test]
    fn untouched_draft_writes_nothing() {
        let mut outbound = json!({"protocol": "vless", "settings": {},
            "streamSettings": {"network": "raw", "security": "reality", "sockopt": {"mark": 1}}});
        let before = outbound.clone();
        let draft = parse_outbound_stream(&outbound);
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(outbound, before);

        let mut bare = json!({"protocol": "vless"});
        apply_outbound_stream(&mut bare, &OutboundStreamDraft::default()).unwrap();
        assert!(bare.get("streamSettings").is_none());
    }

    #[test]
    fn method_wins_over_network_like_the_core() {
        let draft = parse_outbound_stream(&json!({"streamSettings": {"network": "ws", "method": "grpc"}}));
        assert_eq!(draft.transport, Some(OutboundTransport::Grpc));
        assert_eq!(draft.method_key, StreamMethodKey::Method);
    }

    #[test]
    fn exotic_transport_is_read_only() {
        let mut outbound = json!({"streamSettings": {"network": "masque", "masqueSettings": {"host": "a"}}});
        let before = outbound.clone();
        let mut draft = parse_outbound_stream(&outbound);
        assert!(!draft.is_editable());
        assert_eq!(draft.other_transport.as_deref(), Some("masque"));
        draft.write = true;
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(outbound, before);
    }

    #[test]
    fn same_transport_keeps_spelling_and_alias_key_and_other_keys() {
        let mut outbound = json!({"streamSettings": {
            "network": "ws", "wsSettings": {"path": "/a?ed=2048", "headers": {"X": "1"}, "future": 1},
            "splithttpSettings": {"path": "/leftover"}, "sockopt": {"mark": 7}, "finalmask": {"tcp": []},
            "security": "tls", "tlsSettings": {"serverName": "a.com"}
        }});
        let mut draft = parse_outbound_stream(&outbound);
        assert_eq!(draft.ws.ed, Some(2048));
        assert_eq!(draft.ws.headers, [("X".to_owned(), "1".to_owned())]);
        draft.ws.host = "cdn.example".to_owned();
        draft.write = true;
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        let stream = &outbound["streamSettings"];
        assert_eq!(stream["network"], "ws");
        assert_eq!(stream["wsSettings"]["host"], "cdn.example");
        assert_eq!(stream["wsSettings"]["path"], "/a?ed=2048");
        assert_eq!(stream["wsSettings"]["future"], 1);
        // Transport unchanged → leftovers of other transports stay; foreign keys stay.
        assert_eq!(stream["splithttpSettings"]["path"], "/leftover");
        assert_eq!(stream["sockopt"]["mark"], 7);
        assert_eq!(stream["finalmask"], json!({"tcp": []}));
    }

    #[test]
    fn switching_transport_drops_other_settings_objects() {
        let mut outbound = json!({"streamSettings": {"network": "tcp", "rawSettings": {"header": {"type": "http"}},
            "kcpSettings": {"mtu": 1350}}});
        let mut draft = parse_outbound_stream(&outbound);
        draft.select_transport(OutboundTransport::Grpc);
        draft.grpc.service_name = "svc".to_owned();
        draft.grpc.authority = "a.example".to_owned();
        draft.grpc.idle_timeout = Some(60);
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        let stream = &outbound["streamSettings"];
        assert_eq!(stream["network"], "grpc");
        assert!(stream.get("rawSettings").is_none());
        assert!(stream.get("kcpSettings").is_none());
        assert_eq!(stream["grpcSettings"], json!({"authority": "a.example", "serviceName": "svc", "idle_timeout": 60}));
        assert_eq!(stream["security"], "none");
    }

    #[test]
    fn raw_header_is_preserved_and_raw_settings_alias_wins() {
        let outbound = json!({"streamSettings": {"network": "raw",
            "rawSettings": {"header": {"type": "http"}}, "tcpSettings": {"header": {"type": "none"}}}});
        let draft = parse_outbound_stream(&outbound);
        assert_eq!(draft.disk_settings_key, Some("rawSettings"));
        assert_eq!(draft.raw.extras["header"]["type"], "http");
    }

    #[test]
    fn reality_is_refused_on_websocket_and_hysteria_needs_tls() {
        let mut draft = OutboundStreamDraft::default();
        draft.select_transport(OutboundTransport::WebSocket);
        draft.security.mode = InboundSecurityMode::Reality;
        draft.security.reality.public_key = PUBLIC_KEY.to_owned();
        assert!(validate_outbound_stream(&draft).is_err());
        draft.select_transport(OutboundTransport::Grpc);
        validate_outbound_stream(&draft).expect("REALITY over gRPC");

        let mut hy = OutboundStreamDraft::default_for_protocol("hysteria");
        hy.hysteria.auth = "pw".to_owned();
        validate_outbound_stream(&hy).expect("hysteria + tls");
        hy.security.mode = InboundSecurityMode::None;
        assert!(validate_outbound_stream(&hy).is_err());
        hy.security.mode = InboundSecurityMode::Tls;
        hy.hysteria.udp_idle_timeout = Some(1);
        assert!(validate_outbound_stream(&hy).is_err());
    }

    #[test]
    fn httpupgrade_refuses_host_header() {
        let mut draft = OutboundStreamDraft::default();
        draft.select_transport(OutboundTransport::HttpUpgrade);
        draft.httpupgrade.headers.push(("host".to_owned(), "x".to_owned()));
        assert!(validate_outbound_stream(&draft).is_err());
        draft.httpupgrade.headers = vec![("User-Agent".to_owned(), "x".to_owned())];
        let mut outbound = json!({"protocol": "vless"});
        draft.httpupgrade.path = "/up".to_owned();
        draft.httpupgrade.ed = Some(2048);
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(
            outbound["streamSettings"],
            json!({"network": "httpupgrade", "security": "none",
                   "httpupgradeSettings": {"path": "/up?ed=2048", "headers": {"User-Agent": "x"}}})
        );
    }

    #[test]
    fn transports_per_protocol() {
        assert_eq!(outbound_transports_for_protocol("hysteria"), [OutboundTransport::Hysteria]);
        let vless = outbound_transports_for_protocol("VLESS");
        assert_eq!(vless.len(), 6);
        assert!(!vless.contains(&OutboundTransport::Hysteria));
        assert!(outbound_protocol_has_transport("vless"));
        assert!(!outbound_protocol_has_transport("freedom"));
    }

    #[test]
    fn xhttp_client_fields_round_trip() {
        let mut outbound = json!({"streamSettings": {"network": "splithttp",
            "splithttpSettings": {"path": "/x", "mode": "packet-up",
                "xmux": {"maxConcurrency": "16-32"},
                "downloadSettings": {"address": "dl.example", "port": 443, "network": "xhttp",
                                     "security": "tls", "tlsSettings": {"serverName": "dl.example"}}}}});
        let mut draft = parse_outbound_stream(&outbound);
        assert_eq!(draft.disk_settings_key, Some("splithttpSettings"));
        assert!(draft.xhttp.download.is_some());
        draft.write = true;
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        let stream = &outbound["streamSettings"];
        assert_eq!(stream["network"], "splithttp");
        assert!(stream.get("xhttpSettings").is_none());
        assert_eq!(stream["splithttpSettings"]["downloadSettings"]["address"], "dl.example");
    }

    fn layer(kind: &str, settings: Value) -> FinalMaskLayerDraft {
        FinalMaskLayerDraft { layer_type: kind.to_owned(), settings }
    }

    /// Roadmap §2.6 stage 7.1: only the edited chain is written; the client-only `udphop` is
    /// allowed; other `finalmask` keys and the untouched transport stay as they are.
    #[test]
    fn finalmask_chain_written_only_when_edited_with_client_layers() {
        let mut outbound = json!({"protocol": "vless", "streamSettings": {
            "network": "mkcp", "kcpSettings": {"mtu": 1200},
            "finalmask": {"tcp": [{"type": "fragment", "settings": {}}], "future": 1}
        }});
        let mut draft = parse_outbound_stream(&outbound);
        assert_eq!(draft.finalmask_tcp.len(), 1);
        assert_eq!(draft.dial_chain(), Some(FinalMaskChain::Udp));
        draft.finalmask_udp.push(layer("udphop", json!({"mode": "intervalRemote"})));
        draft.write_finalmask_udp = true;
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        let stream = &outbound["streamSettings"];
        assert_eq!(stream["finalmask"]["udp"][0]["type"], "udphop");
        assert_eq!(stream["finalmask"]["tcp"][0]["type"], "fragment");
        assert_eq!(stream["finalmask"]["future"], 1);
        // Transport not edited → kcpSettings untouched (not re-serialized with defaults).
        assert_eq!(stream["kcpSettings"], json!({"mtu": 1200}));
        assert!(stream.get("security").is_none());
    }

    #[test]
    fn foreign_or_unreadable_finalmask_is_never_overwritten() {
        let foreign = json!({"streamSettings": {"finalmask": "x"}});
        let mut draft = parse_outbound_stream(&foreign);
        assert!(draft.finalmask_foreign);
        draft.write_finalmask_tcp = true;
        assert!(apply_outbound_stream(&mut foreign.clone(), &draft).is_err());

        let unreadable = json!({"streamSettings": {"finalmask": {"udp": [42]}}});
        let mut draft = parse_outbound_stream(&unreadable);
        assert_eq!(draft.finalmask_unreadable, [FinalMaskChain::Udp]);
        assert!(draft.finalmask_chain_editable(FinalMaskChain::Tcp));
        draft.write_finalmask_udp = true;
        assert!(apply_outbound_stream(&mut unreadable.clone(), &draft).is_err());
        assert!(draft.migrate_legacy_udp_hop().is_err());
    }

    #[test]
    fn quic_params_follow_the_quic_transport() {
        let mut draft = OutboundStreamDraft::default();
        draft.select_transport(OutboundTransport::Xhttp);
        assert_eq!(draft.quic_transport(), None);
        draft.security.mode = InboundSecurityMode::Tls;
        draft.security.tls.alpn = vec!["h3".to_owned()];
        assert_eq!(draft.quic_transport(), Some(QuicTransport::XhttpH3));
        assert_eq!(draft.dial_chain(), Some(FinalMaskChain::Udp));
        draft.quic_params.congestion = "brutal".to_owned();
        draft.write_quic_params = true;
        let error = apply_outbound_stream(&mut json!({"protocol": "vless"}), &draft).unwrap_err();
        assert!(error.message().contains("not supported on XHTTP/3"));
        draft.quic_params.congestion = "bbr".to_owned();
        let mut outbound = json!({"protocol": "vless"});
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(outbound["streamSettings"]["finalmask"]["quicParams"]["congestion"], "bbr");
    }

    /// Roadmap §4.2 "Outbound `sockopt` editor": only the edited keys change; unknown keys, keys
    /// in a form the typed model can't read, and the on-disk spelling of untouched keys stay.
    #[test]
    fn sockopt_merge_writes_only_changed_keys() {
        let original = json!({"protocol": "vless", "tag": "proxy", "streamSettings": {
            "network": "ws", "wsSettings": {"path": "/a"},
            "sockopt": {"mark": "255", "tcpcongestion": "bbr", "tcpFastOpen": true, "future": 1}
        }});
        let mut outbound = original.clone();
        let mut draft = parse_outbound_stream(&outbound);
        assert!(!draft.sockopt_changed());
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(outbound, original, "untouched draft → byte for byte");

        draft.sockopt.dialer_proxy = "tor".to_owned();
        draft.sockopt.domain_strategy = "UseIPv4".to_owned();
        draft.sockopt.tcp_fast_open = TcpFastOpenDraft::Unset;
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(
            outbound["streamSettings"],
            json!({"network": "ws", "wsSettings": {"path": "/a"}, "sockopt": {
                "mark": "255", "tcpcongestion": "bbr", "future": 1,
                "dialerProxy": "tor", "domainStrategy": "UseIPv4"
            }})
        );

        // A rewritten congestion key replaces every spelling with the one the draft holds.
        let mut outbound = original.clone();
        let mut draft = parse_outbound_stream(&outbound);
        draft.sockopt.tcp_congestion = "cubic".to_owned();
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(outbound["streamSettings"]["sockopt"]["tcpcongestion"], "cubic");
        let mut fresh = json!({"protocol": "freedom"});
        let mut draft = parse_outbound_stream(&fresh);
        draft.sockopt.tcp_congestion = "bbr".to_owned();
        apply_outbound_stream(&mut fresh, &draft).unwrap();
        assert_eq!(fresh["streamSettings"], json!({"sockopt": {"tcpCongestion": "bbr"}}));
    }

    #[test]
    fn sockopt_containers_are_created_and_dropped_only_by_the_merge() {
        let mut outbound = json!({"protocol": "freedom", "settings": {}});
        let mut draft = parse_outbound_stream(&outbound);
        draft.sockopt.mark = Some(7);
        draft.sockopt.happy_eyeballs =
            Some(HappyEyeballsDraft { try_delay_ms: Some(250), ..HappyEyeballsDraft::default() });
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(
            outbound["streamSettings"],
            json!({"sockopt": {"mark": 7, "happyEyeballs": {"tryDelayMs": 250}}})
        );

        // Clearing the last keys removes the containers this merge emptied…
        let mut draft = parse_outbound_stream(&outbound);
        draft.sockopt.mark = None;
        draft.sockopt.happy_eyeballs = None;
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert!(outbound.get("streamSettings").is_none());

        // …but not a `streamSettings` that still holds other keys.
        let mut kept = json!({"streamSettings": {"network": "raw", "sockopt": {"interface": "eth1"}}});
        let mut draft = parse_outbound_stream(&kept);
        draft.sockopt.interface.clear();
        apply_outbound_stream(&mut kept, &draft).unwrap();
        assert_eq!(kept["streamSettings"], json!({"network": "raw"}));
    }

    #[test]
    fn sockopt_edit_validates_like_the_core_and_refuses_a_self_loop() {
        let outbound = json!({"protocol": "vless", "tag": "proxy"});
        let mut draft = parse_outbound_stream(&outbound);
        draft.sockopt.domain_strategy = "UseIPv5".to_owned();
        let error = apply_outbound_stream(&mut outbound.clone(), &draft).unwrap_err();
        assert!(error.message().contains("domainStrategy"), "{error}");

        let mut draft = parse_outbound_stream(&outbound);
        draft.sockopt.dialer_proxy = " proxy ".to_owned();
        let error = apply_outbound_stream(&mut outbound.clone(), &draft).unwrap_err();
        assert!(error.message().contains("own tag"), "{error}");

        // A self-loop already on disk is not re-checked when another key changes.
        let looped = json!({"tag": "proxy", "streamSettings": {"sockopt": {"dialerProxy": "proxy"}}});
        let mut draft = parse_outbound_stream(&looped);
        draft.sockopt.mark = Some(1);
        apply_outbound_stream(&mut looped.clone(), &draft).expect("other key edited");
    }

    #[test]
    fn foreign_sockopt_is_never_overwritten() {
        for foreign in [json!({"streamSettings": {"sockopt": "x"}}), json!({"streamSettings": 5})] {
            let mut draft = parse_outbound_stream(&foreign);
            assert!(draft.sockopt_foreign, "{foreign}");
            apply_outbound_stream(&mut foreign.clone(), &draft).expect("untouched");
            draft.sockopt.mark = Some(1);
            assert!(apply_outbound_stream(&mut foreign.clone(), &draft).is_err(), "{foreign}");
        }
    }

    /// Gate G14's explicit fix lives on the stream draft now.
    #[test]
    fn address_port_strategy_removal_keeps_the_other_keys() {
        let mut outbound = json!({"protocol": "freedom",
            "streamSettings": {"sockopt": {"addressPortStrategy": "SrvPortOnly", "mark": 255}}});
        let mut draft = parse_outbound_stream(&outbound);
        assert_eq!(draft.remove_address_port_strategy().as_deref(), Some("SrvPortOnly"));
        assert_eq!(draft.remove_address_port_strategy(), None, "already removed");
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        assert_eq!(outbound["streamSettings"], json!({"sockopt": {"mark": 255}}));
    }

    #[test]
    fn dialer_proxy_problems() {
        let tor = json!({"tag": "tor", "protocol": "socks"});
        let a = json!({"tag": "a", "streamSettings": {"sockopt": {"dialerProxy": "b"}}});
        let b = json!({"tag": "b", "streamSettings": {"sockopt": {"dialerProxy": "me"}}});
        let x = json!({"tag": "x", "streamSettings": {"sockopt": {"dialerProxy": "y"}}});
        let y = json!({"tag": "y", "streamSettings": {"sockopt": {"dialerProxy": "x"}}});
        let others = [&tor, &a, &b, &x, &y];
        assert_eq!(dialer_proxy_problem("me", "", &others), None);
        assert_eq!(dialer_proxy_problem("me", "tor", &others), None);
        assert_eq!(dialer_proxy_problem("me", "me", &others), Some(DialerProxyProblem::SelfReference));
        assert_eq!(dialer_proxy_problem("me", "nope", &others), Some(DialerProxyProblem::UnknownTag));
        assert_eq!(
            dialer_proxy_problem("me", "a", &others),
            Some(DialerProxyProblem::Cycle(vec!["me".into(), "a".into(), "b".into(), "me".into()]))
        );
        // A loop among the others is theirs, not ours.
        assert_eq!(dialer_proxy_problem("me", "x", &others), None);
    }

    #[test]
    fn sockopt_applies_to_every_dialing_protocol() {
        for protocol in ["vless", "Freedom", "dns", "wireguard", "trojan"] {
            assert!(outbound_protocol_uses_sockopt(protocol), "{protocol}");
        }
        for protocol in ["blackhole", "Loopback"] {
            assert!(!outbound_protocol_uses_sockopt(protocol), "{protocol}");
        }
    }

    #[test]
    fn legacy_udp_hop_becomes_a_udphop_layer() {
        let mut outbound = json!({"protocol": "hysteria", "streamSettings": {
            "network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "auth": "pw"},
            "finalmask": {"quicParams": {"congestion": "bbr", "udpHop": {"ports": "20000-30000", "interval": 30}}}
        }});
        let mut draft = parse_outbound_stream(&outbound);
        assert!(draft.quic_params.has_legacy_udp_hop());
        assert!(matches!(draft.migrate_legacy_udp_hop(), Ok(LegacyUdpHopMigration::Migrated { .. })));
        apply_outbound_stream(&mut outbound, &draft).unwrap();
        let finalmask = &outbound["streamSettings"]["finalmask"];
        assert!(finalmask["quicParams"].get("udpHop").is_none());
        assert_eq!(finalmask["quicParams"]["congestion"], "bbr");
        assert_eq!(finalmask["udp"][0]["type"], "udphop");
        assert_eq!(finalmask["udp"][0]["settings"]["mode"], "intervalLocal,intervalRemote");
    }
}
