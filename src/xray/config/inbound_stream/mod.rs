//! Inbound Stream tab (IB-L3): method/network + nested *Settings.
//!
//! **Spike lock (network vs method):**
//! - Read: `network` first, else `method`, else default `tcp`.
//! - Write: prefer the key that already exists on disk; new streamSettings write `network`.
//! - `tcp` ≡ `raw` for gates/UI; when creating new tcp transport, write `network: "tcp"`.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::config::stream::{FinalMaskChain, StreamDirection};

mod xhttp;

// FinalMask, quicParams and sockopt live in the direction-aware `stream` module (Roadmap §2.6
// stage 0.4); re-exported here so the inbound API is unchanged.
pub use crate::xray::config::stream::{
    ADDRESS_PORT_STRATEGIES, DOMAIN_STRATEGIES, FinalMaskLayerDraft, FragmentMaskSettings,
    HappyEyeballsDraft, NoiseMaskItem, NoiseMaskSettings, PacketValue, PortListValue,
    QuicParamsDraft, RangeValue, RealmSettings, SalamanderSettings, SockoptDraft, SudokuSettings,
    TCP_CONGESTION_PRESETS, TCP_FINALMASK_TYPES, TPROXY_MODES, TcpFastOpenDraft,
    UDP_FINALMASK_TYPES, UdpHopSettings, XdnsSettings, XicmpSettings,
    finalmask_layers_to_value, fragment_mask_settings_to_value, hy2_share_obfs,
    noise_mask_settings_to_value, parse_finalmask_layers, parse_fragment_mask_settings,
    parse_noise_mask_settings, parse_quic_params, parse_range_values, parse_realm_settings,
    parse_salamander_settings, parse_sockopt, parse_sudoku_settings, parse_udphop_settings,
    parse_xdns_settings, parse_xicmp_settings, quic_params_to_value, range_values_from_lines,
    range_values_to_lines, realm_settings_to_value, salamander_settings_to_value,
    sockopt_to_value, sudoku_settings_to_value, udphop_settings_to_value,
    validate_finalmask_layers, validate_quic_params, validate_sockopt, xdns_settings_to_value,
    xicmp_settings_to_value,
};
pub use xhttp::{
    XHTTP_DEFAULT_PADDING_FROM, XHTTP_DEFAULT_PADDING_TO, XHTTP_DEFAULT_SC_MAX_BUFFERED_POSTS,
    XHTTP_DEFAULT_SC_MAX_EACH_POST, XHTTP_DEFAULT_SC_MIN_POSTS_INTERVAL_MS,
    XHTTP_DEFAULT_SC_STREAM_UP_FROM, XHTTP_DEFAULT_SC_STREAM_UP_TO,
    XHTTP_DEFAULT_SERVER_MAX_HEADER_BYTES, XHTTP_DOWNLOAD_SECURITIES, XHTTP_MODES,
    XHTTP_MODE_DEFAULT, XHTTP_PADDING_METHODS, XHTTP_PATH_DEFAULT, XHTTP_PLACEMENTS,
    XHTTP_SESSION_ID_TABLES, XHTTP_UPLINK_METHODS, XhttpCoreSettings, XhttpDownloadDraft,
    XhttpRange, XhttpStreamSettings, XmuxDraft, parse_xhttp, validate_xhttp_settings,
    xhttp_extra_json, xhttp_extra_object, xhttp_to_object,
};

/// Transport methods editable in IB-L3 / Wave A / Wave C1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMethod {
    /// Plain TCP / raw (aliases).
    Tcp,
    /// XHTTP.
    Xhttp,
    /// gRPC.
    Grpc,
    /// WebSocket (Wave C1; wire `websocket`, read also `ws`).
    Ws,
    /// mKCP (Wave C1; wire `mkcp`, read also `kcp`).
    Mkcp,
    /// Hysteria QUIC transport (Wave A).
    Hysteria,
}

impl StreamMethod {
    /// Canonical wire value written for new configs (`tcp` not `raw`; `websocket` not `ws`; `mkcp` not `kcp`).
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Xhttp => "xhttp",
            Self::Grpc => "grpc",
            Self::Ws => "websocket",
            Self::Mkcp => "mkcp",
            Self::Hysteria => "hysteria",
        }
    }

    /// UI label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp / raw",
            Self::Xhttp => "xhttp",
            Self::Grpc => "grpc",
            Self::Ws => "websocket",
            Self::Mkcp => "mkcp",
            Self::Hysteria => "hysteria",
        }
    }

    /// Parse from wire (`tcp`/`raw`/`xhttp`/`grpc`/`ws`/`websocket`/`kcp`/`mkcp`/`hysteria`).
    pub fn from_wire(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" | "raw" => Some(Self::Tcp),
            "xhttp" | "splithttp" => Some(Self::Xhttp),
            "grpc" => Some(Self::Grpc),
            "ws" | "websocket" => Some(Self::Ws),
            "kcp" | "mkcp" => Some(Self::Mkcp),
            "hysteria" => Some(Self::Hysteria),
            _ => None,
        }
    }

    /// Nested settings object key for this method.
    pub fn settings_key(self) -> &'static str {
        match self {
            Self::Tcp => "tcpSettings", // also may use rawSettings on disk
            Self::Xhttp => "xhttpSettings",
            Self::Grpc => "grpcSettings",
            Self::Ws => "wsSettings",
            Self::Mkcp => "kcpSettings",
            Self::Hysteria => "hysteriaSettings",
        }
    }
}

// mKCP values mirror Xray-core (Roadmap §2.6 stage 0.6): defaults from
// `transport/internet/kcp/config.go` (`init`), limits from `KCPConfig.Build()` in
// `infra/conf/transport_method.go`. Every numeric field is a `uint32` in the core.

/// Default `mtu` for [`KcpStreamSettings`].
pub const KCP_DEFAULT_MTU: u64 = 1350;
/// Default `tti` (ms).
pub const KCP_DEFAULT_TTI: u64 = 50;
/// Default `uplinkCapacity` (MB/s).
pub const KCP_DEFAULT_UPLINK: u64 = 5;
/// Default `downlinkCapacity` (MB/s).
pub const KCP_DEFAULT_DOWNLINK: u64 = 20;
/// Default `cwndMultiplier`, used by the core when the key is absent.
pub const KCP_DEFAULT_CWND_MULTIPLIER: u64 = 1;
/// Default `maxSendingWindow` in bytes (2 MiB), used by the core when the key is absent.
pub const KCP_DEFAULT_MAX_SENDING_WINDOW: u64 = 2 * 1024 * 1024;
/// Minimum `mtu` ("MTU must be at least 21"). The docs recommend 576–1460, but the core accepts
/// any value from 21, and Feldjäger must not reject a config the core accepts.
pub const KCP_MTU_MIN: u64 = 21;
/// Inclusive `tti` min (ms).
pub const KCP_TTI_MIN: u64 = 10;
/// Inclusive `tti` max (ms); above it `1000 / tti` would be 0 in the core's in-flight sizing.
pub const KCP_TTI_MAX: u64 = 1000;
/// Minimum `cwndMultiplier`.
pub const KCP_CWND_MULTIPLIER_MIN: u64 = 1;

/// `kcpSettings` keys that are not fields of Xray-core's `KCPConfig` any more and are silently
/// ignored. Kept on disk (in [`KcpStreamSettings::extras`]) until the user removes them.
pub const KCP_IGNORED_FIELDS: &[&str] = &["congestion", "readBufferSize", "writeBufferSize"];

/// `kcpSettings` keys still declared in `KCPConfig` but never read by its `Build()` — the legacy
/// mKCP obfuscation, now a `mkcp-legacy` layer in `finalmask.udp` (migration: Roadmap §2.6 5.2).
pub const KCP_LEGACY_OBFUSCATION_FIELDS: &[&str] = &["header", "seed"];

/// Which JSON key holds the transport method on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StreamMethodKey {
    /// Prefer / write `network`.
    #[default]
    Network,
    /// Legacy / docs `method` key present on disk.
    Method,
}

/// Nested fields for tcp/raw (IB-L3 surface).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpStreamSettings {
    /// `acceptProxyProtocol`.
    pub accept_proxy_protocol: bool,
    /// Unknown keys under tcpSettings/rawSettings.
    pub extras: Map<String, Value>,
    /// Which nested key was on disk (`tcpSettings` vs `rawSettings`).
    pub nested_key: TcpNestedKey,
}

/// Nested object name for tcp/raw settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpNestedKey {
    #[default]
    TcpSettings,
    RawSettings,
}

impl TcpNestedKey {
    fn as_str(self) -> &'static str {
        match self {
            Self::TcpSettings => "tcpSettings",
            Self::RawSettings => "rawSettings",
        }
    }
}

/// Nested fields for grpc (IB-L3 surface).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrpcStreamSettings {
    /// gRPC service name.
    pub service_name: String,
    /// multiMode flag.
    pub multi_mode: bool,
    /// Unknown keys.
    pub extras: Map<String, Value>,
}

/// Nested fields for WebSocket `wsSettings` (Wave C1 allowlist + extras).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WsStreamSettings {
    /// HTTP path without Early Data query (`?ed=` stored in [`Self::ed`]).
    pub path: String,
    /// Host header validation value.
    pub host: String,
    /// `acceptProxyProtocol`.
    pub accept_proxy_protocol: bool,
    /// Early Data max size from `path?ed=N` (optional).
    pub ed: Option<u64>,
    /// Unknown keys under wsSettings (including client-only `headers`).
    pub extras: Map<String, Value>,
}

/// Nested fields for mKCP `kcpSettings` — the fields of Xray-core's `KCPConfig` (Wave C1,
/// synced with the core in Roadmap §2.6 stage 0.6) + extras.
///
/// `mtu`/`tti`/`uplinkCapacity`/`downlinkCapacity` hold the core defaults when constructed via
/// [`Default`] and are always written on Save. `cwndMultiplier`/`maxSendingWindow` are written only
/// when set. Keys the core ignores ([`KCP_IGNORED_FIELDS`], [`KCP_LEGACY_OBFUSCATION_FIELDS`]) and
/// unknown keys live in [`Self::extras`] and round-trip unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcpStreamSettings {
    /// Maximum transmission unit (≥ [`KCP_MTU_MIN`]).
    pub mtu: u64,
    /// Transmission time interval in ms ([`KCP_TTI_MIN`]–[`KCP_TTI_MAX`]).
    pub tti: u64,
    /// Uplink capacity MB/s.
    pub uplink_capacity: u64,
    /// Downlink capacity MB/s.
    pub downlink_capacity: u64,
    /// `cwndMultiplier` (≥ 1); `None` = key absent (core default [`KCP_DEFAULT_CWND_MULTIPLIER`]).
    pub cwnd_multiplier: Option<u64>,
    /// `maxSendingWindow` in bytes (≥ `mtu`); `None` = key absent (core default
    /// [`KCP_DEFAULT_MAX_SENDING_WINDOW`]).
    pub max_sending_window: Option<u64>,
    /// Unknown keys under kcpSettings, including the ignored [`KCP_IGNORED_FIELDS`] and legacy
    /// [`KCP_LEGACY_OBFUSCATION_FIELDS`].
    pub extras: Map<String, Value>,
}

impl Default for KcpStreamSettings {
    fn default() -> Self {
        Self {
            mtu: KCP_DEFAULT_MTU,
            tti: KCP_DEFAULT_TTI,
            uplink_capacity: KCP_DEFAULT_UPLINK,
            downlink_capacity: KCP_DEFAULT_DOWNLINK,
            cwnd_multiplier: None,
            max_sending_window: None,
            extras: Map::new(),
        }
    }
}

impl KcpStreamSettings {
    /// True when [`Self::extras`] still holds keys the core ignores ([`KCP_IGNORED_FIELDS`]).
    pub fn has_ignored_fields(&self) -> bool {
        KCP_IGNORED_FIELDS.iter().any(|key| self.extras.contains_key(*key))
    }

    /// Drops the [`KCP_IGNORED_FIELDS`] from [`Self::extras`] (the explicit "remove" action);
    /// returns true when anything was removed. Legacy `header`/`seed` are kept for migration.
    pub fn remove_ignored_fields(&mut self) -> bool {
        let before = self.extras.len();
        self.extras.retain(|key, _| !KCP_IGNORED_FIELDS.contains(&key.as_str()));
        self.extras.len() != before
    }
}

/// Nested fields for `hysteriaSettings` (Wave A allowlist + extras).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HysteriaStreamSettings {
    /// Transport version (usually 2).
    pub version: Option<u64>,
    /// Auth string when present on transport (often unused for inbound protocol users).
    pub auth: String,
    /// UDP idle timeout seconds.
    pub udp_idle_timeout: Option<u64>,
    /// Unknown keys under hysteriaSettings (including masquerade object).
    pub extras: Map<String, Value>,
}

/// Stream tab draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundStreamDraft {
    /// Editable method when `editable`; otherwise read-only preserve.
    pub method: Option<StreamMethod>,
    /// Wire string when method is not in the editable set (preserve-only).
    pub other_method: Option<String>,
    /// Which top-level key to write (`network` / `method`).
    pub method_key: StreamMethodKey,
    /// Nested tcp/raw settings when method is Tcp.
    pub tcp: TcpStreamSettings,
    /// Nested xhttp settings.
    pub xhttp: XhttpStreamSettings,
    /// Nested grpc settings.
    pub grpc: GrpcStreamSettings,
    /// Nested WebSocket settings.
    pub ws: WsStreamSettings,
    /// Nested mKCP settings.
    pub kcp: KcpStreamSettings,
    /// Nested hysteria settings.
    pub hysteria: HysteriaStreamSettings,
    /// Typed quicParams when present / editing Hysteria.
    pub quic_params: QuicParamsDraft,
    /// Whether to write `finalmask.quicParams` from [`Self::quic_params`].
    pub write_quic_params: bool,
    /// Typed `finalmask.tcp` masking layers (VLESS/Trojan; Hysteria never applies them).
    pub finalmask_tcp: Vec<FinalMaskLayerDraft>,
    /// Whether to write `finalmask.tcp` from [`Self::finalmask_tcp`].
    pub write_finalmask_tcp: bool,
    /// Typed `finalmask.udp` masking layers (VLESS/Trojan/Hysteria; Roadmap §2.6 stage 4.1).
    pub finalmask_udp: Vec<FinalMaskLayerDraft>,
    /// Whether to write `finalmask.udp` from [`Self::finalmask_udp`].
    pub write_finalmask_udp: bool,
    /// `streamSettings.finalmask` exists on disk but is neither an object nor `null` (Roadmap §2.6
    /// stage 0.5). Feldjäger does not own such a value: it is left byte-for-byte as it is, the
    /// FinalMask / `quicParams` editors are unavailable, and a draft that would write into it is
    /// rejected by [`apply_inbound_stream`].
    pub finalmask_foreign: bool,
    /// Typed `sockopt` (VLESS/Trojan/Hysteria; method-independent; Roadmap §2.3:87).
    pub sockopt: SockoptDraft,
    /// Whether to write `sockopt` from [`Self::sockopt`] (false ⇒ raw clone-through fallback).
    pub write_sockopt: bool,
    /// Unknown keys under `streamSettings` (excluding security / reality / tls / method keys / *Settings / sockopt we own).
    pub extras: Map<String, Value>,
}

impl Default for InboundStreamDraft {
    fn default() -> Self {
        Self {
            method: Some(StreamMethod::Tcp),
            other_method: None,
            method_key: StreamMethodKey::Network,
            tcp: TcpStreamSettings::default(),
            xhttp: XhttpStreamSettings::default(),
            grpc: GrpcStreamSettings::default(),
            ws: WsStreamSettings::default(),
            kcp: KcpStreamSettings::default(),
            hysteria: HysteriaStreamSettings::default(),
            quic_params: QuicParamsDraft::default(),
            write_quic_params: false,
            finalmask_tcp: Vec::new(),
            write_finalmask_tcp: false,
            finalmask_udp: Vec::new(),
            write_finalmask_udp: false,
            finalmask_foreign: false,
            sockopt: SockoptDraft::default(),
            write_sockopt: false,
            extras: Map::new(),
        }
    }
}

impl InboundStreamDraft {
    /// True when the method can be edited in IB-L3 UI.
    pub fn is_editable(&self) -> bool {
        self.method.is_some()
    }

    /// True when applying the draft writes into `streamSettings.finalmask`
    /// (`quicParams`, `tcp` or `udp`).
    pub fn writes_finalmask(&self) -> bool {
        self.write_quic_params || self.write_finalmask_tcp || self.write_finalmask_udp
    }
}

/// `true` for a `streamSettings.finalmask` value Feldjäger does not own: present, but neither a
/// JSON object (the documented shape) nor `null` (read as "absent").
fn is_foreign_finalmask(value: &Value) -> bool {
    !value.is_object() && !value.is_null()
}

/// JSON type name for user-facing messages (`"a string"`, `"an array"`, …); never the value
/// itself, which may hold a secret.
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Parses Stream draft from an inbound (missing streamSettings → default tcp).
pub fn parse_inbound_stream(inbound: &Value) -> InboundStreamDraft {
    let Some(stream) = inbound.get("streamSettings").and_then(Value::as_object) else {
        return InboundStreamDraft::default();
    };

    let (wire, method_key) = if let Some(n) = stream.get("network").and_then(Value::as_str) {
        (n.to_owned(), StreamMethodKey::Network)
    } else if let Some(m) = stream.get("method").and_then(Value::as_str) {
        (m.to_owned(), StreamMethodKey::Method)
    } else {
        ("tcp".to_owned(), StreamMethodKey::Network)
    };

    let method = StreamMethod::from_wire(&wire);
    let other_method = if method.is_none() {
        Some(wire)
    } else {
        None
    };

    let mut extras = Map::new();
    let reserved = [
        "network",
        "method",
        "security",
        "realitySettings",
        "tlsSettings",
        "tcpSettings",
        "rawSettings",
        "xhttpSettings",
        "grpcSettings",
        "wsSettings",
        "kcpSettings",
        "httpupgradeSettings",
        "hysteriaSettings",
        "finalmask",
        "sockopt",
    ];
    for (key, value) in stream {
        if !reserved.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }

    let mut draft = InboundStreamDraft {
        method,
        other_method,
        method_key,
        tcp: TcpStreamSettings::default(),
        xhttp: XhttpStreamSettings::default(),
        grpc: GrpcStreamSettings::default(),
        ws: WsStreamSettings::default(),
        kcp: KcpStreamSettings::default(),
        hysteria: HysteriaStreamSettings::default(),
        quic_params: QuicParamsDraft::default(),
        write_quic_params: false,
        finalmask_tcp: Vec::new(),
        write_finalmask_tcp: false,
        finalmask_udp: Vec::new(),
        write_finalmask_udp: false,
        finalmask_foreign: stream.get("finalmask").is_some_and(is_foreign_finalmask),
        sockopt: SockoptDraft::default(),
        write_sockopt: false,
        extras,
    };

    if let Some(tcp) = stream.get("tcpSettings").and_then(Value::as_object) {
        draft.tcp = parse_tcp(tcp, TcpNestedKey::TcpSettings);
    } else if let Some(raw) = stream.get("rawSettings").and_then(Value::as_object) {
        draft.tcp = parse_tcp(raw, TcpNestedKey::RawSettings);
    }
    if let Some(xhttp) = stream.get("xhttpSettings").and_then(Value::as_object) {
        draft.xhttp = parse_xhttp(xhttp);
    }
    if let Some(grpc) = stream.get("grpcSettings").and_then(Value::as_object) {
        draft.grpc = parse_grpc(grpc);
    }
    if let Some(ws) = stream.get("wsSettings").and_then(Value::as_object) {
        draft.ws = parse_ws(ws);
    }
    if let Some(kcp) = stream.get("kcpSettings").and_then(Value::as_object) {
        draft.kcp = parse_kcp(kcp);
    }
    if let Some(hy) = stream.get("hysteriaSettings").and_then(Value::as_object) {
        draft.hysteria = parse_hysteria(hy);
    }
    if let Some(qp) = stream
        .get("finalmask")
        .and_then(|f| f.get("quicParams"))
        .and_then(Value::as_object)
    {
        draft.quic_params = parse_quic_params(qp);
        draft.write_quic_params = true;
    }
    if let Some(tcp) = stream
        .get("finalmask")
        .and_then(|f| f.get("tcp"))
        .and_then(Value::as_array)
    {
        if let Some(layers) = parse_finalmask_layers(tcp) {
            draft.finalmask_tcp = layers;
            draft.write_finalmask_tcp = true;
        }
    }
    if let Some(udp) = stream
        .get("finalmask")
        .and_then(|f| f.get("udp"))
        .and_then(Value::as_array)
    {
        if let Some(layers) = parse_finalmask_layers(udp) {
            draft.finalmask_udp = layers;
            draft.write_finalmask_udp = true;
        }
    }
    if let Some(sockopt) = stream.get("sockopt").and_then(Value::as_object) {
        draft.sockopt = parse_sockopt(sockopt);
        draft.write_sockopt = true;
    }

    draft
}

fn parse_tcp(object: &Map<String, Value>, nested_key: TcpNestedKey) -> TcpStreamSettings {
    let mut extras = Map::new();
    for (key, value) in object {
        if key != "acceptProxyProtocol" {
            extras.insert(key.clone(), value.clone());
        }
    }
    TcpStreamSettings {
        accept_proxy_protocol: object
            .get("acceptProxyProtocol")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        extras,
        nested_key,
    }
}

fn parse_grpc(object: &Map<String, Value>) -> GrpcStreamSettings {
    let mut extras = Map::new();
    for (key, value) in object {
        if key != "serviceName" && key != "multiMode" {
            extras.insert(key.clone(), value.clone());
        }
    }
    GrpcStreamSettings {
        service_name: object
            .get("serviceName")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        multi_mode: object
            .get("multiMode")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        extras,
    }
}

fn parse_ws(object: &Map<String, Value>) -> WsStreamSettings {
    let known = ["path", "host", "acceptProxyProtocol"];
    let mut extras = Map::new();
    for (key, value) in object {
        if !known.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    let raw_path = object
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let (path, ed) = split_ws_path_and_ed(&raw_path);
    WsStreamSettings {
        path,
        host: object
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        accept_proxy_protocol: object
            .get("acceptProxyProtocol")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ed,
        extras,
    }
}

fn parse_kcp(object: &Map<String, Value>) -> KcpStreamSettings {
    // `cwndMultiplier`/`maxSendingWindow` are typed only when they hold an unsigned integer;
    // any other shape stays in extras untouched instead of being dropped.
    let cwnd_multiplier = object.get("cwndMultiplier").and_then(Value::as_u64);
    let max_sending_window = object.get("maxSendingWindow").and_then(Value::as_u64);
    let mut extras = Map::new();
    for (key, value) in object {
        let typed = match key.as_str() {
            "mtu" | "tti" | "uplinkCapacity" | "downlinkCapacity" => true,
            "cwndMultiplier" => cwnd_multiplier.is_some(),
            "maxSendingWindow" => max_sending_window.is_some(),
            _ => false,
        };
        if !typed {
            extras.insert(key.clone(), value.clone());
        }
    }
    let defaults = KcpStreamSettings::default();
    KcpStreamSettings {
        mtu: object
            .get("mtu")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.mtu),
        tti: object
            .get("tti")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.tti),
        uplink_capacity: object
            .get("uplinkCapacity")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.uplink_capacity),
        downlink_capacity: object
            .get("downlinkCapacity")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.downlink_capacity),
        cwnd_multiplier,
        max_sending_window,
        extras,
    }
}

/// Hard-validates mKCP values exactly like Xray-core's `KCPConfig.Build()` (Roadmap §2.6 stage
/// 0.6): every field fits `uint32`, `mtu ≥ 21`, `tti` 10–1000, `cwndMultiplier ≥ 1`, and the
/// sending buffer `maxSendingWindow / mtu` is non-zero — checked with the core defaults for absent
/// keys, as the core applies them before validating.
pub fn validate_kcp_settings(kcp: &KcpStreamSettings) -> ConfigModifyResult<()> {
    let invalid = |message: String| {
        Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            message,
        ))
    };
    for (key, value) in [
        ("mtu", Some(kcp.mtu)),
        ("tti", Some(kcp.tti)),
        ("uplinkCapacity", Some(kcp.uplink_capacity)),
        ("downlinkCapacity", Some(kcp.downlink_capacity)),
        ("cwndMultiplier", kcp.cwnd_multiplier),
        ("maxSendingWindow", kcp.max_sending_window),
    ] {
        if let Some(value) = value
            && u32::try_from(value).is_err()
        {
            return invalid(format!(
                "kcpSettings.{key} must fit a 32-bit unsigned integer (got {value})"
            ));
        }
    }
    if kcp.mtu < KCP_MTU_MIN {
        return invalid(format!(
            "kcpSettings.mtu must be at least {KCP_MTU_MIN} (got {})",
            kcp.mtu
        ));
    }
    if !(KCP_TTI_MIN..=KCP_TTI_MAX).contains(&kcp.tti) {
        return invalid(format!(
            "kcpSettings.tti must be between {KCP_TTI_MIN} and {KCP_TTI_MAX} ms (got {})",
            kcp.tti
        ));
    }
    let cwnd = kcp.cwnd_multiplier.unwrap_or(KCP_DEFAULT_CWND_MULTIPLIER);
    if cwnd < KCP_CWND_MULTIPLIER_MIN {
        return invalid(format!(
            "kcpSettings.cwndMultiplier must be at least {KCP_CWND_MULTIPLIER_MIN} (got {cwnd})"
        ));
    }
    let window = kcp.max_sending_window.unwrap_or(KCP_DEFAULT_MAX_SENDING_WINDOW);
    if window / kcp.mtu == 0 {
        return invalid(format!(
            "kcpSettings.maxSendingWindow ({window}{}) must be at least mtu ({})",
            if kcp.max_sending_window.is_none() { ", the default" } else { "" },
            kcp.mtu
        ));
    }
    Ok(())
}

/// Splits `path?ed=N` into path (other query preserved) and Early Data size.
pub fn split_ws_path_and_ed(raw_path: &str) -> (String, Option<u64>) {
    let Some((base, query)) = raw_path.split_once('?') else {
        return (raw_path.to_owned(), None);
    };
    let mut ed = None;
    let mut other: Vec<&str> = Vec::new();
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        if let Some(value) = part.strip_prefix("ed=") {
            ed = value.parse::<u64>().ok();
        } else {
            other.push(part);
        }
    }
    let path = if other.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", other.join("&"))
    };
    (path, ed)
}

/// Joins path + optional `ed` into the wire `wsSettings.path` value.
pub fn join_ws_path_and_ed(path: &str, ed: Option<u64>) -> String {
    let trimmed = path.trim();
    let base = if trimmed.is_empty() { "/" } else { trimmed };
    match ed {
        Some(n) => {
            if base.contains('?') {
                format!("{base}&ed={n}")
            } else {
                format!("{base}?ed={n}")
            }
        }
        None => {
            if trimmed.is_empty() {
                String::new()
            } else {
                trimmed.to_owned()
            }
        }
    }
}

fn parse_hysteria(object: &Map<String, Value>) -> HysteriaStreamSettings {
    let known = ["version", "auth", "udpIdleTimeout"];
    let mut extras = Map::new();
    for (key, value) in object {
        if !known.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    HysteriaStreamSettings {
        version: object.get("version").and_then(Value::as_u64),
        auth: object
            .get("auth")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        udp_idle_timeout: object.get("udpIdleTimeout").and_then(Value::as_u64),
        extras,
    }
}

/// Applies Stream draft into inbound (step 4). Preserves security/reality/tls.
pub fn apply_inbound_stream(
    inbound: &mut Value,
    draft: &InboundStreamDraft,
) -> ConfigModifyResult<()> {
    if draft.other_method.is_some() && draft.method.is_none() {
        // Read-only exotic method: do not rewrite streamSettings method/network.
        return Ok(());
    }

    let Some(method) = draft.method else {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "stream method is required".to_owned(),
        ));
    };

    let root = inbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        )
    })?;

    if !root.contains_key("streamSettings") || root.get("streamSettings").is_some_and(Value::is_null)
    {
        root.insert("streamSettings".to_owned(), Value::Object(Map::new()));
    }

    let stream = root
        .get_mut("streamSettings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "streamSettings must be a JSON object".to_owned(),
            )
        })?;

    // A non-object `finalmask` on disk is not Feldjäger's (Roadmap §2.6 stage 0.5): never wrap or
    // overwrite it. Checked before anything is mutated, so a rejected draft leaves the inbound as
    // it was.
    if draft.writes_finalmask()
        && let Some(existing) = stream.get("finalmask").filter(|v| is_foreign_finalmask(v))
    {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!(
                "streamSettings.finalmask is {}, not a JSON object; Feldjäger leaves it as is — \
                 fix or remove it on the Raw JSON tab before editing FinalMask or quicParams",
                json_kind(existing)
            ),
        ));
    }

    // Preserve security-related keys.
    let security = stream.get("security").cloned();
    let reality = stream.get("realitySettings").cloned();
    let tls = stream.get("tlsSettings").cloned();
    let sockopt = stream.get("sockopt").cloned();

    // Drop previous method settings keys we manage.
    for key in [
        "tcpSettings",
        "rawSettings",
        "xhttpSettings",
        "grpcSettings",
        "wsSettings",
        "kcpSettings",
        "hysteriaSettings",
        "network",
        "method",
    ] {
        stream.remove(key);
    }

    match draft.method_key {
        StreamMethodKey::Network => {
            stream.insert(
                "network".to_owned(),
                Value::String(method.as_wire().to_owned()),
            );
        }
        StreamMethodKey::Method => {
            // Prefer raw alias when writing method key for tcp (docs often use raw).
            let wire = match method {
                StreamMethod::Tcp => "raw",
                other => other.as_wire(),
            };
            stream.insert("method".to_owned(), Value::String(wire.to_owned()));
        }
    }

    match method {
        StreamMethod::Tcp => {
            let key = draft.tcp.nested_key.as_str();
            let mut object = Map::new();
            if draft.tcp.accept_proxy_protocol {
                object.insert("acceptProxyProtocol".to_owned(), Value::Bool(true));
            }
            for (k, v) in &draft.tcp.extras {
                object.insert(k.clone(), v.clone());
            }
            if !object.is_empty() || draft.tcp.accept_proxy_protocol {
                stream.insert(key.to_owned(), Value::Object(object));
            }
        }
        StreamMethod::Xhttp => {
            validate_xhttp_settings(&draft.xhttp)?;
            stream.insert(
                "xhttpSettings".to_owned(),
                Value::Object(xhttp_to_object(&draft.xhttp)),
            );
        }
        StreamMethod::Grpc => {
            let mut object = Map::new();
            if !draft.grpc.service_name.trim().is_empty() {
                object.insert(
                    "serviceName".to_owned(),
                    Value::String(draft.grpc.service_name.trim().to_owned()),
                );
            }
            if draft.grpc.multi_mode {
                object.insert("multiMode".to_owned(), Value::Bool(true));
            }
            for (k, v) in &draft.grpc.extras {
                object.insert(k.clone(), v.clone());
            }
            stream.insert("grpcSettings".to_owned(), Value::Object(object));
        }
        StreamMethod::Ws => {
            let mut object = Map::new();
            let wire_path = join_ws_path_and_ed(&draft.ws.path, draft.ws.ed);
            if !wire_path.is_empty() {
                object.insert("path".to_owned(), Value::String(wire_path));
            }
            if !draft.ws.host.trim().is_empty() {
                object.insert(
                    "host".to_owned(),
                    Value::String(draft.ws.host.trim().to_owned()),
                );
            }
            if draft.ws.accept_proxy_protocol {
                object.insert("acceptProxyProtocol".to_owned(), Value::Bool(true));
            }
            for (k, v) in &draft.ws.extras {
                object.insert(k.clone(), v.clone());
            }
            stream.insert("wsSettings".to_owned(), Value::Object(object));
        }
        StreamMethod::Mkcp => {
            validate_kcp_settings(&draft.kcp)?;
            let mut object = Map::new();
            object.insert("mtu".to_owned(), Value::Number(draft.kcp.mtu.into()));
            object.insert("tti".to_owned(), Value::Number(draft.kcp.tti.into()));
            object.insert(
                "uplinkCapacity".to_owned(),
                Value::Number(draft.kcp.uplink_capacity.into()),
            );
            object.insert(
                "downlinkCapacity".to_owned(),
                Value::Number(draft.kcp.downlink_capacity.into()),
            );
            if let Some(cwnd) = draft.kcp.cwnd_multiplier {
                object.insert("cwndMultiplier".to_owned(), Value::Number(cwnd.into()));
            }
            if let Some(window) = draft.kcp.max_sending_window {
                object.insert("maxSendingWindow".to_owned(), Value::Number(window.into()));
            }
            for (k, v) in &draft.kcp.extras {
                if !object.contains_key(k) {
                    object.insert(k.clone(), v.clone());
                }
            }
            stream.insert("kcpSettings".to_owned(), Value::Object(object));
        }
        StreamMethod::Hysteria => {
            let mut object = Map::new();
            if let Some(version) = draft.hysteria.version {
                object.insert("version".to_owned(), Value::Number(version.into()));
            }
            if !draft.hysteria.auth.trim().is_empty() {
                object.insert(
                    "auth".to_owned(),
                    Value::String(draft.hysteria.auth.trim().to_owned()),
                );
            }
            if let Some(timeout) = draft.hysteria.udp_idle_timeout {
                object.insert("udpIdleTimeout".to_owned(), Value::Number(timeout.into()));
            }
            for (k, v) in &draft.hysteria.extras {
                object.insert(k.clone(), v.clone());
            }
            stream.insert("hysteriaSettings".to_owned(), Value::Object(object));
        }
    }

    if let Some(value) = security {
        stream.insert("security".to_owned(), value);
    }
    if let Some(value) = reality {
        stream.insert("realitySettings".to_owned(), value);
    }
    if let Some(value) = tls {
        stream.insert("tlsSettings".to_owned(), value);
    }

    if draft.write_finalmask_tcp {
        validate_finalmask_layers(&draft.finalmask_tcp, FinalMaskChain::Tcp, StreamDirection::Inbound)?;
    }
    if draft.write_finalmask_udp {
        validate_finalmask_layers(&draft.finalmask_udp, FinalMaskChain::Udp, StreamDirection::Inbound)?;
    }
    if draft.write_quic_params {
        validate_quic_params(&draft.quic_params).map_err(|message| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("streamSettings.finalmask.{message}"),
            )
        })?;
    }

    // `finalmask` is never removed above, so when nothing is written it simply stays as it was
    // (object, `null` or a foreign value alike). When writing, the value is an object or
    // absent/`null` (foreign values were rejected before any mutation).
    if draft.writes_finalmask() {
        let mut finalmask = match stream.remove("finalmask") {
            Some(Value::Object(existing)) => existing,
            _ => Map::new(),
        };
        if draft.write_quic_params {
            finalmask.insert("quicParams".to_owned(), quic_params_to_value(&draft.quic_params));
        }
        if draft.write_finalmask_tcp {
            finalmask.insert(
                "tcp".to_owned(),
                finalmask_layers_to_value(&draft.finalmask_tcp),
            );
        }
        if draft.write_finalmask_udp {
            finalmask.insert(
                "udp".to_owned(),
                finalmask_layers_to_value(&draft.finalmask_udp),
            );
        }
        stream.insert("finalmask".to_owned(), Value::Object(finalmask));
    }

    if draft.write_sockopt {
        validate_sockopt(&draft.sockopt)?;
        stream.insert("sockopt".to_owned(), sockopt_to_value(&draft.sockopt));
    } else if let Some(value) = sockopt {
        stream.insert("sockopt".to_owned(), value);
    }
    for (key, value) in &draft.extras {
        if !stream.contains_key(key) {
            stream.insert(key.clone(), value.clone());
        }
    }

    Ok(())
}

/// Applies only `streamSettings.sockopt` (Tunnel Shell Save, Roadmap §2.3:88). Unlike
/// [`apply_inbound_stream`], leaves every other `streamSettings` key (network, security,
/// tlsSettings, …) byte-for-byte untouched — Tunnel Shell Save must not mutate transport/security.
pub fn apply_tunnel_sockopt(
    inbound: &mut Value,
    draft: &InboundStreamDraft,
) -> ConfigModifyResult<()> {
    if !draft.write_sockopt {
        return Ok(());
    }
    validate_sockopt(&draft.sockopt)?;

    let root = inbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        )
    })?;
    if !root.contains_key("streamSettings") || root.get("streamSettings").is_some_and(Value::is_null)
    {
        root.insert("streamSettings".to_owned(), Value::Object(Map::new()));
    }
    let stream = root
        .get_mut("streamSettings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "streamSettings must be a JSON object".to_owned(),
            )
        })?;

    let value = sockopt_to_value(&draft.sockopt);
    if value.as_object().is_some_and(Map::is_empty) {
        stream.remove("sockopt");
    } else {
        stream.insert("sockopt".to_owned(), value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_defaults_when_missing() {
        let draft = parse_inbound_stream(&json!({"protocol":"vless"}));
        assert_eq!(draft.method, Some(StreamMethod::Tcp));
        assert!(draft.is_editable());
    }

    #[test]
    fn apply_switches_method_and_drops_old_settings() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {"path":"/old","keep":1},
                "customTop": true
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        draft.method = Some(StreamMethod::Grpc);
        draft.grpc.service_name = "svc".to_owned();
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let stream = &inbound["streamSettings"];
        assert_eq!(stream["network"], "grpc");
        assert!(stream.get("xhttpSettings").is_none());
        assert_eq!(stream["grpcSettings"]["serviceName"], "svc");
        assert_eq!(stream["security"], "none");
        assert_eq!(stream["customTop"], true);
    }

    #[test]
    fn exotic_method_is_no_write() {
        let mut inbound = json!({
            "streamSettings": {"network":"httpupgrade","httpupgradeSettings":{"path":"/"}}
        });
        let draft = parse_inbound_stream(&inbound);
        assert!(!draft.is_editable());
        let before = inbound.clone();
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        assert_eq!(inbound, before);
    }

    #[test]
    fn ws_alias_parses_and_writes_websocket() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": "/ray?ed=2560",
                    "host": "example.com",
                    "acceptProxyProtocol": true,
                    "headers": {"User-Agent": "x"}
                }
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        assert_eq!(draft.method, Some(StreamMethod::Ws));
        assert_eq!(draft.ws.path, "/ray");
        assert_eq!(draft.ws.ed, Some(2560));
        assert_eq!(draft.ws.host, "example.com");
        assert!(draft.ws.accept_proxy_protocol);
        assert_eq!(draft.ws.extras.get("headers").and_then(|v| v.get("User-Agent")), Some(&json!("x")));

        draft.ws.path = "/v".to_owned();
        draft.ws.ed = Some(2048);
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let stream = &inbound["streamSettings"];
        assert_eq!(stream["network"], "websocket");
        assert_eq!(stream["wsSettings"]["path"], "/v?ed=2048");
        assert_eq!(stream["wsSettings"]["host"], "example.com");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["wsSettings"]["headers"]["User-Agent"], "x");
    }

    #[test]
    fn apply_ws_drops_old_transport_settings() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {"path": "/old"}
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        draft.method = Some(StreamMethod::Ws);
        draft.ws.path = "/ws".to_owned();
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let stream = &inbound["streamSettings"];
        assert_eq!(stream["network"], "websocket");
        assert!(stream.get("xhttpSettings").is_none());
        assert_eq!(stream["wsSettings"]["path"], "/ws");
    }

    #[test]
    fn mkcp_alias_parses_and_writes_full_defaults() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "kcp",
                "security": "tls",
                "kcpSettings": {
                    "mtu": 1400,
                    "tti": 30,
                    "uplinkCapacity": 10,
                    "downlinkCapacity": 100,
                    "congestion": true,
                    "readBufferSize": 4,
                    "writeBufferSize": 4,
                    "header": {"type": "none"},
                    "seed": "legacy"
                }
            }
        });
        let draft = parse_inbound_stream(&inbound);
        assert_eq!(draft.method, Some(StreamMethod::Mkcp));
        assert_eq!(draft.kcp.mtu, 1400);
        assert_eq!(draft.kcp.tti, 30);
        // Keys the core ignores are no longer typed; they round-trip via extras.
        assert_eq!(draft.kcp.extras.get("congestion"), Some(&json!(true)));
        assert!(draft.kcp.has_ignored_fields());
        assert_eq!(
            draft.kcp.extras.get("header").and_then(|v| v.get("type")),
            Some(&json!("none"))
        );
        assert_eq!(draft.kcp.extras.get("seed"), Some(&json!("legacy")));

        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let stream = &inbound["streamSettings"];
        assert_eq!(stream["network"], "mkcp");
        assert_eq!(stream["kcpSettings"]["mtu"], 1400);
        assert_eq!(stream["kcpSettings"]["tti"], 30);
        assert_eq!(stream["kcpSettings"]["uplinkCapacity"], 10);
        assert_eq!(stream["kcpSettings"]["downlinkCapacity"], 100);
        assert_eq!(stream["kcpSettings"]["congestion"], true);
        assert_eq!(stream["kcpSettings"]["readBufferSize"], 4);
        assert_eq!(stream["kcpSettings"]["writeBufferSize"], 4);
        assert_eq!(stream["kcpSettings"]["header"]["type"], "none");
        assert_eq!(stream["kcpSettings"]["seed"], "legacy");
        assert_eq!(stream["security"], "tls");
    }

    #[test]
    fn apply_mkcp_writes_documented_defaults_and_drops_old_settings() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {"path": "/old"}
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        draft.method = Some(StreamMethod::Mkcp);
        draft.kcp = KcpStreamSettings::default();
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let stream = &inbound["streamSettings"];
        assert_eq!(stream["network"], "mkcp");
        assert!(stream.get("xhttpSettings").is_none());
        assert_eq!(stream["kcpSettings"]["mtu"], KCP_DEFAULT_MTU);
        assert_eq!(stream["kcpSettings"]["tti"], KCP_DEFAULT_TTI);
        assert_eq!(stream["kcpSettings"]["uplinkCapacity"], KCP_DEFAULT_UPLINK);
        assert_eq!(stream["kcpSettings"]["downlinkCapacity"], KCP_DEFAULT_DOWNLINK);
        // Keys Xray-core ignores are never written for a fresh mKCP transport, and the optional
        // core fields stay absent (the core applies its own defaults).
        let kcp = stream["kcpSettings"].as_object().expect("kcpSettings object");
        for key in KCP_IGNORED_FIELDS.iter().chain(&["cwndMultiplier", "maxSendingWindow"]) {
            assert!(!kcp.contains_key(*key), "{key} must not be written by default");
        }
    }

    #[test]
    fn xhttp_defaults_written_on_apply() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        draft.method = Some(StreamMethod::Xhttp);
        draft.xhttp = XhttpStreamSettings::default();
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let xhttp = &inbound["streamSettings"]["xhttpSettings"];
        assert_eq!(xhttp["path"], "/");
        assert_eq!(xhttp["mode"], "auto");
        assert_eq!(xhttp["xPaddingBytes"], "100-1000");
        assert_eq!(xhttp["scMaxBufferedPosts"], 30);
        assert_eq!(xhttp["noSSEHeader"], false);
        assert!(
            xhttp.get("xmux").is_none(),
            "xmux is optional and must be omitted unless explicitly enabled"
        );
    }

    #[test]
    fn validate_kcp_rejects_out_of_range_mtu_tti() {
        let mut kcp = KcpStreamSettings::default();
        kcp.mtu = 20;
        assert!(validate_kcp_settings(&kcp).is_err());
        kcp.mtu = KCP_DEFAULT_MTU;
        kcp.tti = 5;
        assert!(validate_kcp_settings(&kcp).is_err());
        kcp.tti = KCP_TTI_MAX + 1;
        assert!(validate_kcp_settings(&kcp).is_err());
        kcp.tti = KCP_DEFAULT_TTI;
        assert!(validate_kcp_settings(&kcp).is_ok());
    }

    #[test]
    fn validate_kcp_mirrors_core_build_bounds() {
        let ok = |kcp: &KcpStreamSettings| validate_kcp_settings(kcp).is_ok();
        let mut kcp = KcpStreamSettings::default();
        // Values the docs call out of range but the core accepts must pass (no stricter gate).
        for (mtu, tti) in [(KCP_MTU_MIN, KCP_TTI_MIN), (500, 1000), (2000, 999)] {
            (kcp.mtu, kcp.tti) = (mtu, tti);
            assert!(ok(&kcp), "mtu {mtu} tti {tti}");
        }
        kcp = KcpStreamSettings::default();

        kcp.cwnd_multiplier = Some(0);
        assert!(!ok(&kcp), "cwndMultiplier 0");
        kcp.cwnd_multiplier = Some(4);
        assert!(ok(&kcp));

        // maxSendingWindow / mtu must be non-zero: at least one packet in the sending buffer.
        kcp.max_sending_window = Some(KCP_DEFAULT_MTU - 1);
        assert!(!ok(&kcp), "window below mtu");
        kcp.max_sending_window = Some(KCP_DEFAULT_MTU);
        assert!(ok(&kcp));
        // The core default window (2 MiB) is checked too when the key is absent.
        kcp.max_sending_window = None;
        kcp.mtu = KCP_DEFAULT_MAX_SENDING_WINDOW + 1;
        let err = validate_kcp_settings(&kcp).unwrap_err();
        assert!(err.to_string().contains("the default"), "{err}");

        // Every field is a uint32 in the core.
        kcp = KcpStreamSettings::default();
        kcp.uplink_capacity = u64::from(u32::MAX) + 1;
        assert!(!ok(&kcp), "uplinkCapacity above u32");
    }

    #[test]
    fn mkcp_new_core_fields_round_trip_and_bad_shapes_stay_in_extras() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "mkcp",
                "kcpSettings": {"mtu": 1350, "cwndMultiplier": 2, "maxSendingWindow": "big"}
            }
        });
        let draft = parse_inbound_stream(&inbound);
        assert_eq!(draft.kcp.cwnd_multiplier, Some(2));
        assert_eq!(draft.kcp.max_sending_window, None);
        assert_eq!(draft.kcp.extras.get("maxSendingWindow"), Some(&json!("big")));
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let kcp = &inbound["streamSettings"]["kcpSettings"];
        assert_eq!(kcp["cwndMultiplier"], 2);
        assert_eq!(kcp["maxSendingWindow"], "big", "an unrepresentable value is not dropped");
    }

    #[test]
    fn mkcp_remove_ignored_fields_keeps_legacy_obfuscation_for_migration() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "mkcp",
                "kcpSettings": {
                    "congestion": false,
                    "readBufferSize": 2,
                    "writeBufferSize": 2,
                    "seed": "s",
                    "futureKey": 1
                }
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        assert!(draft.kcp.remove_ignored_fields());
        assert!(!draft.kcp.has_ignored_fields());
        assert!(!draft.kcp.remove_ignored_fields(), "second call removes nothing");
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let kcp = inbound["streamSettings"]["kcpSettings"].as_object().expect("object");
        for key in KCP_IGNORED_FIELDS {
            assert!(!kcp.contains_key(*key), "{key}");
        }
        assert_eq!(kcp["seed"], "s");
        assert_eq!(kcp["futureKey"], 1);
    }

    #[test]
    fn apply_mkcp_rejects_invalid_ranges() {
        let mut inbound = json!({"streamSettings": {"network": "tcp"}});
        let mut draft = parse_inbound_stream(&inbound);
        draft.method = Some(StreamMethod::Mkcp);
        draft.kcp.mtu = KCP_MTU_MIN - 1;
        let err = apply_inbound_stream(&mut inbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(err.to_string().contains("mtu"));
    }

    #[test]
    fn parse_reads_finalmask_tcp_and_udp_layers() {
        let inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "finalmask": {
                    "tcp": [{"type": "fragment", "settings": {"packets": "tlshello"}}],
                    "udp": [{"type": "salamander", "settings": {"password": "x"}}]
                }
            }
        });
        let draft = parse_inbound_stream(&inbound);
        assert!(draft.write_finalmask_tcp);
        assert_eq!(draft.finalmask_tcp.len(), 1);
        assert_eq!(draft.finalmask_tcp[0].layer_type, "fragment");
        assert!(draft.write_finalmask_udp);
        assert_eq!(draft.finalmask_udp.len(), 1);
        assert_eq!(draft.finalmask_udp[0].layer_type, "salamander");
    }

    #[test]
    fn apply_writes_finalmask_tcp_udp_and_preserves_quic_params() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "finalmask": {
                    "quicParams": {"congestion": "bbr"},
                    "other": "keep-me"
                }
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        draft.finalmask_tcp = vec![FinalMaskLayerDraft {
            layer_type: "sudoku".to_owned(),
            settings: json!({"password": "abc"}),
        }];
        draft.write_finalmask_tcp = true;
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let finalmask = &inbound["streamSettings"]["finalmask"];
        assert_eq!(finalmask["tcp"][0]["type"], "sudoku");
        assert_eq!(finalmask["tcp"][0]["settings"]["password"], "abc");
        // Untouched sibling keys under finalmask survive.
        assert_eq!(finalmask["quicParams"]["congestion"], "bbr");
        assert_eq!(finalmask["other"], "keep-me");
    }

    #[test]
    fn apply_round_trips_full_quic_params_and_rejects_what_the_core_rejects() {
        // Roadmap §2.6 stage 3.1: all 17 fields survive a Save untouched…
        let quic_params = json!({
            "congestion": "force-brutal", "debug": false, "bbrProfile": "aggressive",
            "brutalUp": "100 mbps", "brutalDown": "200 mbps", "brutalDisableLossCompensation": true,
            "initStreamReceiveWindow": 16384, "maxStreamReceiveWindow": 8388608,
            "initConnectionReceiveWindow": 0, "maxConnectionReceiveWindow": 20971520,
            "maxIdleTimeout": 30, "keepAlivePeriod": 10, "disablePathMTUDiscovery": false,
            "disableChromeParrot": true, "disableGSO": false, "maxIncomingStreams": 8,
            "disableStatelessReset": true
        });
        let mut inbound = json!({
            "streamSettings": {"network": "hysteria", "finalmask": {"quicParams": quic_params.clone()}}
        });
        let draft = parse_inbound_stream(&inbound);
        assert!(draft.write_quic_params);
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        assert_eq!(inbound["streamSettings"]["finalmask"]["quicParams"], quic_params);

        // …and an edit the core's Build() refuses is refused before anything is written.
        let mut broken = draft.clone();
        broken.quic_params.brutal_up.clear();
        let error = apply_inbound_stream(&mut inbound.clone(), &broken).unwrap_err();
        assert!(
            error.to_string().contains("streamSettings.finalmask.quicParams.congestion force-brutal requires brutalUp"),
            "{error}"
        );
        // A number where the core wants a Bandwidth string is kept, not converted — and refused.
        let mut numeric = json!({
            "streamSettings": {"network": "hysteria", "finalmask": {"quicParams": {"brutalUp": 1000000}}}
        });
        let draft = parse_inbound_stream(&numeric);
        let error = apply_inbound_stream(&mut numeric, &draft).unwrap_err();
        assert!(error.to_string().contains("quicParams.brutalUp must be a string"), "{error}");
    }

    #[test]
    fn apply_without_finalmask_edits_preserves_existing_object_untouched() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "finalmask": {"tcp": [{"type": "fragment", "settings": {"length": "100-200"}}]}
            }
        });
        let before = inbound["streamSettings"]["finalmask"].clone();
        let draft = parse_inbound_stream(&inbound);
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        assert_eq!(inbound["streamSettings"]["finalmask"], before);
    }

    #[test]
    fn apply_rejects_finalmask_layer_with_empty_type() {
        let mut inbound = json!({"streamSettings": {"network": "tcp"}});
        let mut draft = parse_inbound_stream(&inbound);
        draft.finalmask_udp = vec![FinalMaskLayerDraft::default()];
        draft.write_finalmask_udp = true;
        let err = apply_inbound_stream(&mut inbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(err.to_string().contains("type"));
    }

    /// Roadmap §2.6 stage 1.1: `udphop` is client-only — writing it into an inbound is refused
    /// before any mutation. An on-disk chain is always re-written by a Shell Save, so the layer
    /// has to be removed first; without it the Save goes through.
    #[test]
    fn apply_rejects_client_only_udphop_layer_on_inbound() {
        let original = json!({"streamSettings": {"network": "tcp", "finalmask": {"udp": [
            {"type": "udphop", "settings": {"mode": "intervalRemote"}}
        ]}}});
        let mut inbound = original.clone();
        let mut draft = parse_inbound_stream(&inbound);
        assert_eq!(draft.finalmask_udp.len(), 1);
        assert!(draft.write_finalmask_udp, "an on-disk chain is re-written");
        let err = apply_inbound_stream(&mut inbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(err.to_string().contains("client only"));
        assert_eq!(inbound, original);

        draft.finalmask_udp.clear();
        apply_inbound_stream(&mut inbound, &draft).expect("layer removed");
        assert_eq!(inbound["streamSettings"]["finalmask"]["udp"], json!([]));
    }

    #[test]
    fn parse_flags_only_non_object_non_null_finalmask_as_foreign() {
        for (finalmask, foreign) in [
            (json!("udphop"), true),
            (json!([{"type": "fragment"}]), true),
            (json!(42), true),
            (json!(false), true),
            (json!(null), false),
            (json!({"tcp": []}), false),
        ] {
            let inbound = json!({"streamSettings": {"network": "tcp", "finalmask": finalmask}});
            let draft = parse_inbound_stream(&inbound);
            assert_eq!(draft.finalmask_foreign, foreign, "{finalmask}");
            if foreign {
                assert!(!draft.writes_finalmask(), "{finalmask}: parse must not claim it");
            }
        }
        assert!(!parse_inbound_stream(&json!({"streamSettings": {}})).finalmask_foreign);
    }

    #[test]
    fn apply_keeps_foreign_finalmask_byte_for_byte_without_wrapping() {
        let mut inbound = json!({
            "streamSettings": {"network": "tcp", "finalmask": ["opaque", 1]}
        });
        let mut draft = parse_inbound_stream(&inbound);
        draft.method = Some(StreamMethod::Ws); // an unrelated Stream edit
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        assert_eq!(inbound["streamSettings"]["finalmask"], json!(["opaque", 1]));
        assert_eq!(inbound["streamSettings"]["network"], "websocket");
    }

    #[test]
    fn apply_rejects_finalmask_edit_over_foreign_value_and_leaves_inbound_unchanged() {
        let original = json!({
            "streamSettings": {"network": "tcp", "finalmask": "not-an-object"}
        });
        for edit in ["quic", "tcp", "udp"] {
            let mut inbound = original.clone();
            let mut draft = parse_inbound_stream(&inbound);
            let layer = vec![FinalMaskLayerDraft {
                layer_type: "salamander".to_owned(),
                settings: json!({"password": "p"}),
            }];
            match edit {
                "quic" => draft.write_quic_params = true,
                "tcp" => (draft.finalmask_tcp, draft.write_finalmask_tcp) = (layer, true),
                _ => (draft.finalmask_udp, draft.write_finalmask_udp) = (layer, true),
            }
            let err = apply_inbound_stream(&mut inbound, &draft).unwrap_err();
            assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed, "{edit}");
            let message = err.to_string();
            assert!(message.contains("a string") && !message.contains("not-an-object"), "{message}");
            assert!(!message.contains("_preserved"));
            assert_eq!(inbound, original, "{edit}: nothing may change on rejection");
        }
    }

    #[test]
    fn apply_replaces_null_finalmask_with_an_object_when_edited() {
        let mut inbound = json!({"streamSettings": {"network": "tcp", "finalmask": null}});
        let mut draft = parse_inbound_stream(&inbound);
        draft.finalmask_udp = vec![FinalMaskLayerDraft {
            layer_type: "salamander".to_owned(),
            settings: json!({"password": "pass"}),
        }];
        draft.write_finalmask_udp = true;
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        assert_eq!(
            inbound["streamSettings"]["finalmask"],
            json!({"udp": [{"type": "salamander", "settings": {"password": "pass"}}]})
        );
    }

    #[test]
    fn apply_without_edits_keeps_null_finalmask() {
        let mut inbound = json!({"streamSettings": {"network": "tcp", "finalmask": null}});
        let draft = parse_inbound_stream(&inbound);
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        assert_eq!(inbound["streamSettings"]["finalmask"], Value::Null);
    }

    #[test]
    fn parse_reads_sockopt_object_and_sets_write_flag() {
        let inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"tproxy": "redirect", "acceptProxyProtocol": true}
            }
        });
        let draft = parse_inbound_stream(&inbound);
        assert!(draft.write_sockopt);
        assert_eq!(draft.sockopt.tproxy, "redirect");
        assert!(draft.sockopt.accept_proxy_protocol);
    }

    #[test]
    fn apply_writes_sockopt_from_draft_when_edited() {
        let mut inbound = json!({"streamSettings": {"network": "tcp"}});
        let mut draft = parse_inbound_stream(&inbound);
        assert!(!draft.write_sockopt);
        draft.sockopt.accept_proxy_protocol = true;
        draft.sockopt.tproxy = "tproxy".to_owned();
        draft.write_sockopt = true;
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let sockopt = &inbound["streamSettings"]["sockopt"];
        assert_eq!(sockopt["acceptProxyProtocol"], true);
        assert_eq!(sockopt["tproxy"], "tproxy");
    }

    #[test]
    fn apply_without_sockopt_edits_preserves_malformed_shape_untouched() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "sockopt": "not-an-object"
            }
        });
        let before = inbound["streamSettings"]["sockopt"].clone();
        let draft = parse_inbound_stream(&inbound);
        assert!(!draft.write_sockopt);
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        assert_eq!(inbound["streamSettings"]["sockopt"], before);
    }

    #[test]
    fn apply_sockopt_unknown_future_field_roundtrips_via_extras() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"tproxy": "off", "futureField": "keep-me"}
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        assert!(draft.write_sockopt);
        draft.sockopt.tproxy = "redirect".to_owned();
        apply_inbound_stream(&mut inbound, &draft).unwrap();
        let sockopt = &inbound["streamSettings"]["sockopt"];
        assert_eq!(sockopt["tproxy"], "redirect");
        assert_eq!(sockopt["futureField"], "keep-me");
    }

    #[test]
    fn apply_tunnel_sockopt_noop_when_not_edited() {
        let mut inbound = json!({
            "protocol": "tunnel",
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "sockopt": {"tproxy": "redirect"},
                "futureField": "keep"
            }
        });
        let before = inbound["streamSettings"].clone();
        let draft = parse_inbound_stream(&inbound);
        assert!(draft.write_sockopt);
        // Simulate a Shell Save where the Tunnel GUI never touched sockopt.
        let mut untouched = InboundStreamDraft::default();
        untouched.sockopt = draft.sockopt.clone();
        apply_tunnel_sockopt(&mut inbound, &untouched).unwrap();
        assert_eq!(inbound["streamSettings"], before);
    }

    #[test]
    fn apply_tunnel_sockopt_writes_only_sockopt_key() {
        let mut inbound = json!({
            "protocol": "tunnel",
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "sockopt": {"tproxy": "redirect", "acceptProxyProtocol": true},
                "futureField": "keep"
            }
        });
        let mut draft = parse_inbound_stream(&inbound);
        assert!(draft.write_sockopt);
        draft.sockopt.tproxy = "tproxy".to_owned();
        apply_tunnel_sockopt(&mut inbound, &draft).unwrap();
        let stream = &inbound["streamSettings"];
        assert_eq!(stream["sockopt"]["tproxy"], "tproxy");
        assert_eq!(stream["sockopt"]["acceptProxyProtocol"], true);
        assert_eq!(stream["network"], "tcp");
        assert_eq!(stream["security"], "none");
        assert_eq!(stream["futureField"], "keep");
    }

    #[test]
    fn apply_tunnel_sockopt_creates_stream_settings_when_absent() {
        let mut inbound = json!({"protocol": "tunnel"});
        let mut draft = InboundStreamDraft::default();
        draft.sockopt.tproxy = "off".to_owned();
        draft.write_sockopt = true;
        apply_tunnel_sockopt(&mut inbound, &draft).unwrap();
        assert_eq!(inbound["streamSettings"]["sockopt"]["tproxy"], "off");
    }
}
