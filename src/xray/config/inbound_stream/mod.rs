//! Inbound Stream tab (IB-L3): method/network + nested *Settings.
//!
//! **Spike lock (network vs method):**
//! - Read: `network` first, else `method`, else default `tcp`.
//! - Write: prefer the key that already exists on disk; new streamSettings write `network`.
//! - `tcp` ≡ `raw` for gates/UI; when creating new tcp transport, write `network: "tcp"`.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

mod finalmask;
mod sockopt;
mod xhttp;

pub use finalmask::{
    FinalMaskLayerDraft, TCP_FINALMASK_TYPES, UDP_FINALMASK_TYPES, finalmask_layers_to_value,
    hysteria_salamander_obfs_password, parse_finalmask_layers, validate_finalmask_layers,
};
pub use sockopt::{
    ADDRESS_PORT_STRATEGIES, DOMAIN_STRATEGIES, HappyEyeballsDraft, SockoptDraft,
    TCP_CONGESTION_PRESETS, TPROXY_MODES, TcpFastOpenDraft, parse_sockopt, sockopt_to_value,
    validate_sockopt,
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

/// Documented default `mtu` for [`KcpStreamSettings`].
pub const KCP_DEFAULT_MTU: u64 = 1350;
/// Documented default `tti` (ms).
pub const KCP_DEFAULT_TTI: u64 = 50;
/// Documented default `uplinkCapacity` (MB/s).
pub const KCP_DEFAULT_UPLINK: u64 = 5;
/// Documented default `downlinkCapacity` (MB/s).
pub const KCP_DEFAULT_DOWNLINK: u64 = 20;
/// Documented default `readBufferSize` (MB).
pub const KCP_DEFAULT_READ_BUFFER: u64 = 2;
/// Documented default `writeBufferSize` (MB).
pub const KCP_DEFAULT_WRITE_BUFFER: u64 = 2;
/// Inclusive `mtu` range from Xray docs.
pub const KCP_MTU_MIN: u64 = 576;
/// Inclusive `mtu` max from Xray docs.
pub const KCP_MTU_MAX: u64 = 1460;
/// Inclusive `tti` min (ms).
pub const KCP_TTI_MIN: u64 = 10;
/// Inclusive `tti` max (ms).
pub const KCP_TTI_MAX: u64 = 100;

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

/// Nested fields for mKCP `kcpSettings` (Wave C1 allowlist + extras).
///
/// Always holds documented defaults when constructed via [`Default`]; Save
/// writes the full seven-field object. Legacy `header` / `seed` live in
/// [`Self::extras`] only (FinalMask tip in GUI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcpStreamSettings {
    /// Maximum transmission unit (576–1460).
    pub mtu: u64,
    /// Transmission time interval in ms (10–100).
    pub tti: u64,
    /// Uplink capacity MB/s.
    pub uplink_capacity: u64,
    /// Downlink capacity MB/s.
    pub downlink_capacity: u64,
    /// Congestion control.
    pub congestion: bool,
    /// Per-connection read buffer size MB.
    pub read_buffer_size: u64,
    /// Per-connection write buffer size MB.
    pub write_buffer_size: u64,
    /// Unknown keys under kcpSettings (including removed `header` / `seed`).
    pub extras: Map<String, Value>,
}

impl Default for KcpStreamSettings {
    fn default() -> Self {
        Self {
            mtu: KCP_DEFAULT_MTU,
            tti: KCP_DEFAULT_TTI,
            uplink_capacity: KCP_DEFAULT_UPLINK,
            downlink_capacity: KCP_DEFAULT_DOWNLINK,
            congestion: false,
            read_buffer_size: KCP_DEFAULT_READ_BUFFER,
            write_buffer_size: KCP_DEFAULT_WRITE_BUFFER,
            extras: Map::new(),
        }
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

/// Typed `finalmask.quicParams` fields for Hysteria congestion (Wave A CQ5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuicParamsDraft {
    /// `congestion`: reno | bbr | brutal | force-brutal.
    pub congestion: String,
    /// `brutalUp` rate string (e.g. `100 mbps`).
    pub brutal_up: String,
    /// `brutalDown` rate string.
    pub brutal_down: String,
    /// Unknown keys under quicParams.
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
    /// Typed `finalmask.tcp` masking layers (VLESS/Trojan; not Hysteria).
    pub finalmask_tcp: Vec<FinalMaskLayerDraft>,
    /// Whether to write `finalmask.tcp` from [`Self::finalmask_tcp`].
    pub write_finalmask_tcp: bool,
    /// Typed `finalmask.udp` masking layers (VLESS/Trojan; not Hysteria).
    pub finalmask_udp: Vec<FinalMaskLayerDraft>,
    /// Whether to write `finalmask.udp` from [`Self::finalmask_udp`].
    pub write_finalmask_udp: bool,
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
    let known = [
        "mtu",
        "tti",
        "uplinkCapacity",
        "downlinkCapacity",
        "congestion",
        "readBufferSize",
        "writeBufferSize",
    ];
    let mut extras = Map::new();
    for (key, value) in object {
        if !known.contains(&key.as_str()) {
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
        congestion: object
            .get("congestion")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        read_buffer_size: object
            .get("readBufferSize")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.read_buffer_size),
        write_buffer_size: object
            .get("writeBufferSize")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.write_buffer_size),
        extras,
    }
}

/// Hard-validates mKCP numeric ranges from Xray docs before write.
pub fn validate_kcp_settings(kcp: &KcpStreamSettings) -> ConfigModifyResult<()> {
    if !(KCP_MTU_MIN..=KCP_MTU_MAX).contains(&kcp.mtu) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!(
                "kcpSettings.mtu must be between {KCP_MTU_MIN} and {KCP_MTU_MAX} (got {})",
                kcp.mtu
            ),
        ));
    }
    if !(KCP_TTI_MIN..=KCP_TTI_MAX).contains(&kcp.tti) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!(
                "kcpSettings.tti must be between {KCP_TTI_MIN} and {KCP_TTI_MAX} ms (got {})",
                kcp.tti
            ),
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

fn parse_quic_params(object: &Map<String, Value>) -> QuicParamsDraft {
    let known = ["congestion", "brutalUp", "brutalDown"];
    let mut extras = Map::new();
    for (key, value) in object {
        if !known.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    QuicParamsDraft {
        congestion: object
            .get("congestion")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        brutal_up: object
            .get("brutalUp")
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .unwrap_or_default(),
        brutal_down: object
            .get("brutalDown")
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .unwrap_or_default(),
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

    // Preserve security-related keys.
    let security = stream.get("security").cloned();
    let reality = stream.get("realitySettings").cloned();
    let tls = stream.get("tlsSettings").cloned();
    let finalmask = stream.get("finalmask").cloned();
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
            object.insert("congestion".to_owned(), Value::Bool(draft.kcp.congestion));
            object.insert(
                "readBufferSize".to_owned(),
                Value::Number(draft.kcp.read_buffer_size.into()),
            );
            object.insert(
                "writeBufferSize".to_owned(),
                Value::Number(draft.kcp.write_buffer_size.into()),
            );
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
        validate_finalmask_layers(&draft.finalmask_tcp)?;
    }
    if draft.write_finalmask_udp {
        validate_finalmask_layers(&draft.finalmask_udp)?;
    }

    if draft.write_quic_params || draft.write_finalmask_tcp || draft.write_finalmask_udp {
        let mut finalmask = match stream.remove("finalmask") {
            Some(Value::Object(existing)) => existing,
            Some(other) => {
                // Preserve non-object finalmask as extras-like: wrap
                let mut m = Map::new();
                m.insert("_preserved".to_owned(), other);
                m
            }
            None => match finalmask {
                Some(Value::Object(existing)) => existing,
                _ => Map::new(),
            },
        };
        if draft.write_quic_params {
            let mut qp = Map::new();
            if !draft.quic_params.congestion.trim().is_empty() {
                qp.insert(
                    "congestion".to_owned(),
                    Value::String(draft.quic_params.congestion.trim().to_owned()),
                );
            }
            if !draft.quic_params.brutal_up.trim().is_empty() {
                qp.insert(
                    "brutalUp".to_owned(),
                    Value::String(draft.quic_params.brutal_up.trim().to_owned()),
                );
            }
            if !draft.quic_params.brutal_down.trim().is_empty() {
                qp.insert(
                    "brutalDown".to_owned(),
                    Value::String(draft.quic_params.brutal_down.trim().to_owned()),
                );
            }
            for (k, v) in &draft.quic_params.extras {
                if !qp.contains_key(k) {
                    qp.insert(k.clone(), v.clone());
                }
            }
            finalmask.insert("quicParams".to_owned(), Value::Object(qp));
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
    } else if let Some(value) = finalmask {
        stream.insert("finalmask".to_owned(), value);
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
        assert!(draft.kcp.congestion);
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
        assert_eq!(stream["kcpSettings"]["congestion"], false);
        assert_eq!(stream["kcpSettings"]["readBufferSize"], KCP_DEFAULT_READ_BUFFER);
        assert_eq!(stream["kcpSettings"]["writeBufferSize"], KCP_DEFAULT_WRITE_BUFFER);
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
        assert!(xhttp.get("xmux").is_some());
    }

    #[test]
    fn validate_kcp_rejects_out_of_range_mtu_tti() {
        let mut kcp = KcpStreamSettings::default();
        kcp.mtu = 500;
        assert!(validate_kcp_settings(&kcp).is_err());
        kcp.mtu = KCP_DEFAULT_MTU;
        kcp.tti = 5;
        assert!(validate_kcp_settings(&kcp).is_err());
        kcp.tti = KCP_DEFAULT_TTI;
        assert!(validate_kcp_settings(&kcp).is_ok());
    }

    #[test]
    fn apply_mkcp_rejects_invalid_ranges() {
        let mut inbound = json!({"streamSettings": {"network": "tcp"}});
        let mut draft = parse_inbound_stream(&inbound);
        draft.method = Some(StreamMethod::Mkcp);
        draft.kcp.mtu = 2000;
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
    fn apply_without_finalmask_edits_preserves_existing_object_untouched() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "finalmask": {"tcp": [{"type": "fragment", "settings": {}}]}
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
