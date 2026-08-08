//! XHTTP / SplitHTTP `xhttpSettings` (Wave C3): typed allowlist + extras.
//!
//! Documented defaults follow Xray `splithttp` normalize helpers and discussion #4113.
//! Save writes the typed surface (mKCP-style); unknown keys live in [`XhttpStreamSettings::extras`].

use serde_json::{Map, Number, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Allowed `mode` values.
pub const XHTTP_MODES: &[&str] = &["auto", "packet-up", "stream-one", "stream-up"];
/// Default `mode`.
pub const XHTTP_MODE_DEFAULT: &str = "auto";
/// Default `path`.
pub const XHTTP_PATH_DEFAULT: &str = "/";

/// Documented `xPaddingBytes` from.
pub const XHTTP_DEFAULT_PADDING_FROM: i64 = 100;
/// Documented `xPaddingBytes` to.
pub const XHTTP_DEFAULT_PADDING_TO: i64 = 1000;
/// Documented `scMaxEachPostBytes`.
pub const XHTTP_DEFAULT_SC_MAX_EACH_POST: i64 = 1_000_000;
/// Documented `scMinPostsIntervalMs`.
pub const XHTTP_DEFAULT_SC_MIN_POSTS_INTERVAL_MS: i64 = 30;
/// Documented `scMaxBufferedPosts`.
pub const XHTTP_DEFAULT_SC_MAX_BUFFERED_POSTS: i64 = 30;
/// Documented `scStreamUpServerSecs` from.
pub const XHTTP_DEFAULT_SC_STREAM_UP_FROM: i64 = 20;
/// Documented `scStreamUpServerSecs` to.
pub const XHTTP_DEFAULT_SC_STREAM_UP_TO: i64 = 80;
/// Documented `serverMaxHeaderBytes`.
pub const XHTTP_DEFAULT_SERVER_MAX_HEADER_BYTES: i64 = 8192;

/// Placement values for session / seq / padding / uplink data.
pub const XHTTP_PLACEMENTS: &[&str] = &[
    "path",
    "query",
    "header",
    "cookie",
    "body",
    "auto",
    "queryInHeader",
];
/// Padding methods when `xPaddingObfsMode` is on.
pub const XHTTP_PADDING_METHODS: &[&str] = &["repeat-x", "tokenish"];
/// Common uplink HTTP methods.
pub const XHTTP_UPLINK_METHODS: &[&str] = &["POST", "GET", "PUT"];
/// Predefined `sessionIDTable` names from Xray.
pub const XHTTP_SESSION_ID_TABLES: &[&str] = &[
    "ALPHABET",
    "Alphabet",
    "BASE36",
    "Base62",
    "HEX",
    "alphabet",
    "base36",
    "hex",
    "number",
];
/// Download `security` choices.
pub const XHTTP_DOWNLOAD_SECURITIES: &[&str] = &["none", "tls", "reality"];

/// Inclusive range used by many XHTTP knobs (`"a-b"` or number on wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhttpRange {
    /// Inclusive lower bound.
    pub from: i64,
    /// Inclusive upper bound.
    pub to: i64,
}

impl XhttpRange {
    /// Fixed single value.
    pub const fn fixed(value: i64) -> Self {
        Self {
            from: value,
            to: value,
        }
    }

    /// Inclusive span.
    pub const fn span(from: i64, to: i64) -> Self {
        Self { from, to }
    }
}

/// Nested `xmux` object (client-oriented; written on inbound for share/`extra`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmuxDraft {
    /// `maxConcurrency` range (0 = unset / core default when all zero).
    pub max_concurrency: XhttpRange,
    /// `maxConnections` range (conflicts with maxConcurrency when both non-zero).
    pub max_connections: XhttpRange,
    /// `cMaxReuseTimes`.
    pub c_max_reuse_times: XhttpRange,
    /// `hMaxRequestTimes`.
    pub h_max_request_times: XhttpRange,
    /// `hMaxReusableSecs`.
    pub h_max_reusable_secs: XhttpRange,
    /// `hKeepAlivePeriod` (not a range; 0 = browser/quic default).
    pub h_keep_alive_period: i64,
    /// Unknown keys under xmux.
    pub extras: Map<String, Value>,
}

impl Default for XmuxDraft {
    fn default() -> Self {
        Self {
            max_concurrency: XhttpRange::fixed(0),
            max_connections: XhttpRange::fixed(0),
            c_max_reuse_times: XhttpRange::fixed(0),
            h_max_request_times: XhttpRange::fixed(0),
            h_max_reusable_secs: XhttpRange::fixed(0),
            h_keep_alive_period: 0,
            extras: Map::new(),
        }
    }
}

/// One-level `downloadSettings` (no nested download inside nested xhttp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpDownloadDraft {
    /// Outbound-style dial address.
    pub address: String,
    /// Dial port (default 443).
    pub port: u64,
    /// Wire `network` (always `xhttp` when written).
    pub network: String,
    /// `none` | `tls` | `reality`.
    pub security: String,
    /// SNI / first Reality serverName when security is tls/reality.
    pub server_name: String,
    /// Nested xhttp settings without further download.
    pub xhttp: XhttpCoreSettings,
    /// Other download streamSettings keys (sockopt, full tls/reality blobs, …).
    pub extras: Map<String, Value>,
}

impl Default for XhttpDownloadDraft {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: 443,
            network: "xhttp".to_owned(),
            security: "tls".to_owned(),
            server_name: String::new(),
            xhttp: XhttpCoreSettings::default(),
            extras: Map::new(),
        }
    }
}

/// Typed XHTTP fields excluding `downloadSettings` / top-level extras.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpCoreSettings {
    /// Host header check (server) / send (client). Empty = do not check / omit.
    pub host: String,
    /// Request path.
    pub path: String,
    /// Framing mode.
    pub mode: String,
    /// Extra request headers.
    pub headers: Vec<(String, String)>,
    /// Header padding byte range.
    pub x_padding_bytes: XhttpRange,
    /// Disable gRPC Content-Type on stream-up/one (client).
    pub no_grpc_header: bool,
    /// Disable SSE Content-Type on download (server).
    pub no_sse_header: bool,
    /// Max POST body size (packet-up).
    pub sc_max_each_post_bytes: XhttpRange,
    /// Min interval between POSTs (packet-up, client).
    pub sc_min_posts_interval_ms: XhttpRange,
    /// Server upload queue depth (packet-up, server).
    pub sc_max_buffered_posts: i64,
    /// Server keepalive padding interval (stream-up, server); `-1` disables.
    pub sc_stream_up_server_secs: XhttpRange,
    /// Connection pool / mux knobs.
    pub xmux: XmuxDraft,
    /// Advanced padding obfuscation.
    pub x_padding_obfs_mode: bool,
    /// Padding key name when obfs mode is on.
    pub x_padding_key: String,
    /// Padding header name when placement uses a header.
    pub x_padding_header: String,
    /// Padding placement.
    pub x_padding_placement: String,
    /// Padding generation method.
    pub x_padding_method: String,
    /// Uplink HTTP method (default POST when empty).
    pub uplink_http_method: String,
    /// Session id placement.
    pub session_id_placement: String,
    /// Session id key name.
    pub session_id_key: String,
    /// Sequence placement.
    pub seq_placement: String,
    /// Sequence key name.
    pub seq_key: String,
    /// Uplink data placement.
    pub uplink_data_placement: String,
    /// Uplink data key name.
    pub uplink_data_key: String,
    /// Uplink chunk size when data is in header/cookie.
    pub uplink_chunk_size: XhttpRange,
    /// Max request header bytes (server).
    pub server_max_header_bytes: i64,
    /// Session id character table (predefined name or custom charset).
    pub session_id_table: String,
    /// Session id length range (0 = UUID).
    pub session_id_length: XhttpRange,
}

impl Default for XhttpCoreSettings {
    fn default() -> Self {
        Self {
            host: String::new(),
            path: XHTTP_PATH_DEFAULT.to_owned(),
            mode: XHTTP_MODE_DEFAULT.to_owned(),
            headers: Vec::new(),
            x_padding_bytes: XhttpRange::span(
                XHTTP_DEFAULT_PADDING_FROM,
                XHTTP_DEFAULT_PADDING_TO,
            ),
            no_grpc_header: false,
            no_sse_header: false,
            sc_max_each_post_bytes: XhttpRange::fixed(XHTTP_DEFAULT_SC_MAX_EACH_POST),
            sc_min_posts_interval_ms: XhttpRange::fixed(XHTTP_DEFAULT_SC_MIN_POSTS_INTERVAL_MS),
            sc_max_buffered_posts: XHTTP_DEFAULT_SC_MAX_BUFFERED_POSTS,
            sc_stream_up_server_secs: XhttpRange::span(
                XHTTP_DEFAULT_SC_STREAM_UP_FROM,
                XHTTP_DEFAULT_SC_STREAM_UP_TO,
            ),
            xmux: XmuxDraft::default(),
            x_padding_obfs_mode: false,
            x_padding_key: String::new(),
            x_padding_header: String::new(),
            x_padding_placement: String::new(),
            x_padding_method: String::new(),
            uplink_http_method: String::new(),
            session_id_placement: String::new(),
            session_id_key: String::new(),
            seq_placement: String::new(),
            seq_key: String::new(),
            uplink_data_placement: String::new(),
            uplink_data_key: String::new(),
            uplink_chunk_size: XhttpRange::fixed(0),
            server_max_header_bytes: XHTTP_DEFAULT_SERVER_MAX_HEADER_BYTES,
            session_id_table: String::new(),
            session_id_length: XhttpRange::fixed(0),
        }
    }
}

/// Nested fields for xhttp (Wave C3 allowlist + extras).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XhttpStreamSettings {
    /// Typed core fields.
    pub core: XhttpCoreSettings,
    /// Optional one-level `downloadSettings`.
    pub download: Option<XhttpDownloadDraft>,
    /// Unknown keys under xhttpSettings.
    pub extras: Map<String, Value>,
}

impl Default for XhttpStreamSettings {
    fn default() -> Self {
        Self {
            core: XhttpCoreSettings::default(),
            download: None,
            extras: Map::new(),
        }
    }
}

impl XhttpStreamSettings {
    /// Convenience: path.
    pub fn path(&self) -> &str {
        &self.core.path
    }

    /// Convenience: mode.
    pub fn mode(&self) -> &str {
        &self.core.mode
    }

    /// Convenience: host.
    pub fn host(&self) -> &str {
        &self.core.host
    }
}

const CORE_KEYS: &[&str] = &[
    "host",
    "path",
    "mode",
    "headers",
    "xPaddingBytes",
    "noGRPCHeader",
    "noSSEHeader",
    "scMaxEachPostBytes",
    "scMinPostsIntervalMs",
    "scMaxBufferedPosts",
    "scStreamUpServerSecs",
    "xmux",
    "downloadSettings",
    "xPaddingObfsMode",
    "xPaddingKey",
    "xPaddingHeader",
    "xPaddingPlacement",
    "xPaddingMethod",
    "uplinkHTTPMethod",
    "sessionIDPlacement",
    "sessionIDKey",
    "seqPlacement",
    "seqKey",
    "uplinkDataPlacement",
    "uplinkDataKey",
    "uplinkChunkSize",
    "serverMaxHeaderBytes",
    "sessionIDTable",
    "sessionIDLength",
];

const XMUX_KEYS: &[&str] = &[
    "maxConcurrency",
    "maxConnections",
    "cMaxReuseTimes",
    "hMaxRequestTimes",
    "hMaxReusableSecs",
    "hKeepAlivePeriod",
];

const DOWNLOAD_TYPED_KEYS: &[&str] = &[
    "address",
    "port",
    "network",
    "security",
    "tlsSettings",
    "realitySettings",
    "xhttpSettings",
];

/// Parse `xhttpSettings` object.
pub fn parse_xhttp(object: &Map<String, Value>) -> XhttpStreamSettings {
    let mut extras = Map::new();
    for (key, value) in object {
        if !CORE_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    let core = parse_core(object);
    let download = object
        .get("downloadSettings")
        .and_then(Value::as_object)
        .map(parse_download);
    XhttpStreamSettings {
        core,
        download,
        extras,
    }
}

fn parse_core(object: &Map<String, Value>) -> XhttpCoreSettings {
    let mut core = XhttpCoreSettings::default();
    if let Some(host) = object.get("host").and_then(Value::as_str) {
        core.host = host.to_owned();
    }
    if let Some(path) = object.get("path").and_then(Value::as_str) {
        core.path = if path.is_empty() {
            XHTTP_PATH_DEFAULT.to_owned()
        } else {
            path.to_owned()
        };
    }
    if let Some(mode) = object.get("mode").and_then(Value::as_str) {
        core.mode = if mode.is_empty() {
            XHTTP_MODE_DEFAULT.to_owned()
        } else {
            mode.to_owned()
        };
    }
    if let Some(headers) = object.get("headers").and_then(Value::as_object) {
        core.headers = headers
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
            .collect();
        core.headers.sort_by(|a, b| a.0.cmp(&b.0));
    }
    if let Some(range) = object.get("xPaddingBytes").and_then(parse_range_value) {
        core.x_padding_bytes = range;
    }
    core.no_grpc_header = object
        .get("noGRPCHeader")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    core.no_sse_header = object
        .get("noSSEHeader")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(range) = object.get("scMaxEachPostBytes").and_then(parse_range_value) {
        core.sc_max_each_post_bytes = range;
    }
    if let Some(range) = object
        .get("scMinPostsIntervalMs")
        .and_then(parse_range_value)
    {
        core.sc_min_posts_interval_ms = range;
    }
    if let Some(n) = object.get("scMaxBufferedPosts").and_then(value_as_i64) {
        core.sc_max_buffered_posts = n;
    }
    if let Some(range) = object
        .get("scStreamUpServerSecs")
        .and_then(parse_range_value)
    {
        core.sc_stream_up_server_secs = range;
    }
    if let Some(xmux) = object.get("xmux").and_then(Value::as_object) {
        core.xmux = parse_xmux(xmux);
    }
    core.x_padding_obfs_mode = object
        .get("xPaddingObfsMode")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    core.x_padding_key = string_field(object, "xPaddingKey");
    core.x_padding_header = string_field(object, "xPaddingHeader");
    core.x_padding_placement = string_field(object, "xPaddingPlacement");
    core.x_padding_method = string_field(object, "xPaddingMethod");
    core.uplink_http_method = string_field(object, "uplinkHTTPMethod");
    core.session_id_placement = string_field(object, "sessionIDPlacement");
    core.session_id_key = string_field(object, "sessionIDKey");
    core.seq_placement = string_field(object, "seqPlacement");
    core.seq_key = string_field(object, "seqKey");
    core.uplink_data_placement = string_field(object, "uplinkDataPlacement");
    core.uplink_data_key = string_field(object, "uplinkDataKey");
    if let Some(range) = object.get("uplinkChunkSize").and_then(parse_range_value) {
        core.uplink_chunk_size = range;
    }
    if let Some(n) = object.get("serverMaxHeaderBytes").and_then(value_as_i64) {
        core.server_max_header_bytes = n;
    }
    core.session_id_table = string_field(object, "sessionIDTable");
    if let Some(range) = object.get("sessionIDLength").and_then(parse_range_value) {
        core.session_id_length = range;
    }
    core
}

fn parse_xmux(object: &Map<String, Value>) -> XmuxDraft {
    let mut extras = Map::new();
    for (key, value) in object {
        if !XMUX_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    let defaults = XmuxDraft::default();
    XmuxDraft {
        max_concurrency: object
            .get("maxConcurrency")
            .and_then(parse_range_value)
            .unwrap_or(defaults.max_concurrency),
        max_connections: object
            .get("maxConnections")
            .and_then(parse_range_value)
            .unwrap_or(defaults.max_connections),
        c_max_reuse_times: object
            .get("cMaxReuseTimes")
            .and_then(parse_range_value)
            .unwrap_or(defaults.c_max_reuse_times),
        h_max_request_times: object
            .get("hMaxRequestTimes")
            .and_then(parse_range_value)
            .unwrap_or(defaults.h_max_request_times),
        h_max_reusable_secs: object
            .get("hMaxReusableSecs")
            .and_then(parse_range_value)
            .unwrap_or(defaults.h_max_reusable_secs),
        h_keep_alive_period: object
            .get("hKeepAlivePeriod")
            .and_then(value_as_i64)
            .unwrap_or(0),
        extras,
    }
}

fn parse_download(object: &Map<String, Value>) -> XhttpDownloadDraft {
    let mut extras = Map::new();
    for (key, value) in object {
        if !DOWNLOAD_TYPED_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    let security = object
        .get("security")
        .and_then(Value::as_str)
        .unwrap_or("tls")
        .to_owned();
    let mut server_name = String::new();
    if let Some(tls) = object.get("tlsSettings").and_then(Value::as_object) {
        if let Some(sni) = tls.get("serverName").and_then(Value::as_str) {
            server_name = sni.to_owned();
        }
        let mut tls_extras = tls.clone();
        tls_extras.remove("serverName");
        if !tls_extras.is_empty() {
            extras.insert("tlsSettings".to_owned(), Value::Object(tls_extras));
        }
    }
    if let Some(reality) = object.get("realitySettings").and_then(Value::as_object) {
        if server_name.is_empty() {
            if let Some(names) = reality.get("serverNames").and_then(Value::as_array) {
                if let Some(first) = names.first().and_then(Value::as_str) {
                    server_name = first.to_owned();
                }
            }
        }
        extras.insert("realitySettings".to_owned(), Value::Object(reality.clone()));
    }

    let xhttp = if let Some(xo) = object.get("xhttpSettings").and_then(Value::as_object) {
        let mut nested = xo.clone();
        if let Some(deep) = nested.remove("downloadSettings") {
            extras.insert("_nestedDownloadSettings".to_owned(), deep);
        }
        for (k, v) in xo {
            if !CORE_KEYS.contains(&k.as_str()) {
                extras.insert(format!("xhttpSettings.{k}"), v.clone());
            }
        }
        parse_core(&nested)
    } else {
        XhttpCoreSettings::default()
    };

    XhttpDownloadDraft {
        address: object
            .get("address")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        port: object
            .get("port")
            .and_then(Value::as_u64)
            .unwrap_or(443),
        network: object
            .get("network")
            .and_then(Value::as_str)
            .unwrap_or("xhttp")
            .to_owned(),
        security,
        server_name,
        xhttp,
        extras,
    }
}

/// Serialize typed XHTTP settings to a JSON object (always writes documented defaults).
pub fn xhttp_to_object(settings: &XhttpStreamSettings) -> Map<String, Value> {
    let mut object = core_to_object(&settings.core);
    if let Some(download) = &settings.download {
        object.insert(
            "downloadSettings".to_owned(),
            Value::Object(download_to_object(download)),
        );
    }
    for (k, v) in &settings.extras {
        if !object.contains_key(k) {
            object.insert(k.clone(), v.clone());
        }
    }
    object
}

/// Build share-link `extra` JSON (everything except host/path/mode).
pub fn xhttp_extra_object(settings: &XhttpStreamSettings) -> Map<String, Value> {
    let mut object = xhttp_to_object(settings);
    object.remove("host");
    object.remove("path");
    object.remove("mode");
    object
}

/// Compact JSON string for `extra=` query (empty object → None).
pub fn xhttp_extra_json(settings: &XhttpStreamSettings) -> Option<String> {
    let object = xhttp_extra_object(settings);
    if object.is_empty() {
        None
    } else {
        Some(Value::Object(object).to_string())
    }
}

fn core_to_object(core: &XhttpCoreSettings) -> Map<String, Value> {
    let mut object = Map::new();
    if !core.host.trim().is_empty() {
        object.insert(
            "host".to_owned(),
            Value::String(core.host.trim().to_owned()),
        );
    }
    let path = core.path.trim();
    object.insert(
        "path".to_owned(),
        Value::String(if path.is_empty() {
            XHTTP_PATH_DEFAULT.to_owned()
        } else {
            path.to_owned()
        }),
    );
    let mode = core.mode.trim();
    object.insert(
        "mode".to_owned(),
        Value::String(if mode.is_empty() {
            XHTTP_MODE_DEFAULT.to_owned()
        } else {
            mode.to_owned()
        }),
    );
    if !core.headers.is_empty() {
        let mut headers = Map::new();
        for (k, v) in &core.headers {
            let key = k.trim();
            if key.is_empty() {
                continue;
            }
            headers.insert(key.to_owned(), Value::String(v.clone()));
        }
        if !headers.is_empty() {
            object.insert("headers".to_owned(), Value::Object(headers));
        }
    }
    object.insert(
        "xPaddingBytes".to_owned(),
        range_to_value(core.x_padding_bytes),
    );
    object.insert("noGRPCHeader".to_owned(), Value::Bool(core.no_grpc_header));
    object.insert("noSSEHeader".to_owned(), Value::Bool(core.no_sse_header));
    object.insert(
        "scMaxEachPostBytes".to_owned(),
        range_to_value(core.sc_max_each_post_bytes),
    );
    object.insert(
        "scMinPostsIntervalMs".to_owned(),
        range_to_value(core.sc_min_posts_interval_ms),
    );
    object.insert(
        "scMaxBufferedPosts".to_owned(),
        i64_to_value(core.sc_max_buffered_posts),
    );
    object.insert(
        "scStreamUpServerSecs".to_owned(),
        range_to_value(core.sc_stream_up_server_secs),
    );
    object.insert("xmux".to_owned(), Value::Object(xmux_to_object(&core.xmux)));
    object.insert(
        "xPaddingObfsMode".to_owned(),
        Value::Bool(core.x_padding_obfs_mode),
    );
    insert_nonempty_string(&mut object, "xPaddingKey", &core.x_padding_key);
    insert_nonempty_string(&mut object, "xPaddingHeader", &core.x_padding_header);
    insert_nonempty_string(&mut object, "xPaddingPlacement", &core.x_padding_placement);
    insert_nonempty_string(&mut object, "xPaddingMethod", &core.x_padding_method);
    insert_nonempty_string(&mut object, "uplinkHTTPMethod", &core.uplink_http_method);
    insert_nonempty_string(&mut object, "sessionIDPlacement", &core.session_id_placement);
    insert_nonempty_string(&mut object, "sessionIDKey", &core.session_id_key);
    insert_nonempty_string(&mut object, "seqPlacement", &core.seq_placement);
    insert_nonempty_string(&mut object, "seqKey", &core.seq_key);
    insert_nonempty_string(&mut object, "uplinkDataPlacement", &core.uplink_data_placement);
    insert_nonempty_string(&mut object, "uplinkDataKey", &core.uplink_data_key);
    if core.uplink_chunk_size.from != 0 || core.uplink_chunk_size.to != 0 {
        object.insert(
            "uplinkChunkSize".to_owned(),
            range_to_value(core.uplink_chunk_size),
        );
    }
    object.insert(
        "serverMaxHeaderBytes".to_owned(),
        i64_to_value(core.server_max_header_bytes),
    );
    insert_nonempty_string(&mut object, "sessionIDTable", &core.session_id_table);
    if core.session_id_length.from != 0 || core.session_id_length.to != 0 {
        object.insert(
            "sessionIDLength".to_owned(),
            range_to_value(core.session_id_length),
        );
    }
    object
}

fn xmux_to_object(xmux: &XmuxDraft) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert(
        "maxConcurrency".to_owned(),
        range_to_value(xmux.max_concurrency),
    );
    object.insert(
        "maxConnections".to_owned(),
        range_to_value(xmux.max_connections),
    );
    object.insert(
        "cMaxReuseTimes".to_owned(),
        range_to_value(xmux.c_max_reuse_times),
    );
    object.insert(
        "hMaxRequestTimes".to_owned(),
        range_to_value(xmux.h_max_request_times),
    );
    object.insert(
        "hMaxReusableSecs".to_owned(),
        range_to_value(xmux.h_max_reusable_secs),
    );
    object.insert(
        "hKeepAlivePeriod".to_owned(),
        i64_to_value(xmux.h_keep_alive_period),
    );
    for (k, v) in &xmux.extras {
        if !object.contains_key(k) {
            object.insert(k.clone(), v.clone());
        }
    }
    object
}

fn download_to_object(download: &XhttpDownloadDraft) -> Map<String, Value> {
    let mut object = Map::new();
    if !download.address.trim().is_empty() {
        object.insert(
            "address".to_owned(),
            Value::String(download.address.trim().to_owned()),
        );
    }
    object.insert(
        "port".to_owned(),
        Value::Number(Number::from(download.port)),
    );
    object.insert(
        "network".to_owned(),
        Value::String({
            let n = download.network.trim();
            if n.is_empty() {
                "xhttp".to_owned()
            } else {
                n.to_owned()
            }
        }),
    );
    let security = download.security.trim();
    let security = if security.is_empty() { "tls" } else { security };
    object.insert("security".to_owned(), Value::String(security.to_owned()));

    let sni = download.server_name.trim();
    match security {
        "tls" => {
            let mut tls = match download.extras.get("tlsSettings") {
                Some(Value::Object(existing)) => existing.clone(),
                _ => Map::new(),
            };
            if !sni.is_empty() {
                tls.insert("serverName".to_owned(), Value::String(sni.to_owned()));
            }
            if !tls.is_empty() {
                object.insert("tlsSettings".to_owned(), Value::Object(tls));
            }
        }
        "reality" => {
            let mut reality = match download.extras.get("realitySettings") {
                Some(Value::Object(existing)) => existing.clone(),
                _ => Map::new(),
            };
            if !sni.is_empty() {
                reality.insert(
                    "serverNames".to_owned(),
                    Value::Array(vec![Value::String(sni.to_owned())]),
                );
            }
            if !reality.is_empty() {
                object.insert("realitySettings".to_owned(), Value::Object(reality));
            }
        }
        _ => {}
    }

    let mut nested = core_to_object(&download.xhttp);
    // Restore nested unknown keys stashed as xhttpSettings.*
    for (k, v) in &download.extras {
        if let Some(rest) = k.strip_prefix("xhttpSettings.") {
            if !nested.contains_key(rest) {
                nested.insert(rest.to_owned(), v.clone());
            }
        }
    }
    if let Some(deep) = download.extras.get("_nestedDownloadSettings") {
        nested.insert("downloadSettings".to_owned(), deep.clone());
    }
    object.insert("xhttpSettings".to_owned(), Value::Object(nested));

    for (k, v) in &download.extras {
        if k == "tlsSettings"
            || k == "realitySettings"
            || k == "_nestedDownloadSettings"
            || k.starts_with("xhttpSettings.")
        {
            continue;
        }
        if !object.contains_key(k) {
            object.insert(k.clone(), v.clone());
        }
    }
    object
}

/// Hard-validate XHTTP draft before write.
pub fn validate_xhttp_settings(settings: &XhttpStreamSettings) -> ConfigModifyResult<()> {
    validate_core(&settings.core, "xhttpSettings")?;
    if let Some(download) = &settings.download {
        if download.address.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "downloadSettings.address is required when downloadSettings is enabled"
                    .to_owned(),
            ));
        }
        if download.port == 0 {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "downloadSettings.port must be > 0".to_owned(),
            ));
        }
        let network = download.network.trim();
        if !network.is_empty() && network != "xhttp" && network != "splithttp" {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("downloadSettings.network must be xhttp (got {network})"),
            ));
        }
        let security = download.security.trim();
        if !security.is_empty() && !XHTTP_DOWNLOAD_SECURITIES.contains(&security) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("downloadSettings.security must be none|tls|reality (got {security})"),
            ));
        }
        validate_core(&download.xhttp, "downloadSettings.xhttpSettings")?;
    }
    Ok(())
}

fn validate_core(core: &XhttpCoreSettings, prefix: &str) -> ConfigModifyResult<()> {
    let mode = core.mode.trim();
    if !mode.is_empty() && !XHTTP_MODES.contains(&mode) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{prefix}.mode must be one of {XHTTP_MODES:?} (got {mode})"),
        ));
    }
    validate_range(core.x_padding_bytes, &format!("{prefix}.xPaddingBytes"), 0, 1_000_000)?;
    validate_range(
        core.sc_max_each_post_bytes,
        &format!("{prefix}.scMaxEachPostBytes"),
        1,
        100_000_000,
    )?;
    validate_range(
        core.sc_min_posts_interval_ms,
        &format!("{prefix}.scMinPostsIntervalMs"),
        0,
        60_000,
    )?;
    if core.sc_max_buffered_posts < 0 {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{prefix}.scMaxBufferedPosts must be >= 0"),
        ));
    }
    // Allow -1 (disable) as fixed, or positive keepalive range.
    let su = core.sc_stream_up_server_secs;
    if su.from == -1 && su.to == -1 {
        // ok
    } else {
        validate_range(su, &format!("{prefix}.scStreamUpServerSecs"), 1, 3600)?;
    }
    if core.server_max_header_bytes < 0 {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{prefix}.serverMaxHeaderBytes must be >= 0"),
        ));
    }
    validate_optional_placement(core.x_padding_placement.trim(), &format!("{prefix}.xPaddingPlacement"))?;
    validate_optional_placement(
        core.session_id_placement.trim(),
        &format!("{prefix}.sessionIDPlacement"),
    )?;
    validate_optional_placement(core.seq_placement.trim(), &format!("{prefix}.seqPlacement"))?;
    validate_optional_placement(
        core.uplink_data_placement.trim(),
        &format!("{prefix}.uplinkDataPlacement"),
    )?;
    let method = core.x_padding_method.trim();
    if !method.is_empty() && !XHTTP_PADDING_METHODS.contains(&method) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!(
                "{prefix}.xPaddingMethod must be one of {:?} (got {method})",
                XHTTP_PADDING_METHODS
            ),
        ));
    }
    let xmux = &core.xmux;
    let conc_on = xmux.max_concurrency.from != 0 || xmux.max_concurrency.to != 0;
    let conn_on = xmux.max_connections.from != 0 || xmux.max_connections.to != 0;
    if conc_on && conn_on {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!(
                "{prefix}.xmux: maxConcurrency and maxConnections conflict — set only one"
            ),
        ));
    }
    validate_range(
        xmux.max_concurrency,
        &format!("{prefix}.xmux.maxConcurrency"),
        0,
        10_000,
    )?;
    validate_range(
        xmux.max_connections,
        &format!("{prefix}.xmux.maxConnections"),
        0,
        10_000,
    )?;
    Ok(())
}

fn validate_optional_placement(value: &str, field: &str) -> ConfigModifyResult<()> {
    if value.is_empty() {
        return Ok(());
    }
    if !XHTTP_PLACEMENTS.contains(&value) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field} must be one of {:?} (got {value})", XHTTP_PLACEMENTS),
        ));
    }
    Ok(())
}

fn validate_range(
    range: XhttpRange,
    field: &str,
    min: i64,
    max: i64,
) -> ConfigModifyResult<()> {
    if range.from > range.to {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field}: from ({}) must be <= to ({})", range.from, range.to),
        ));
    }
    if range.from < min || range.to > max {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field}: values must be in {min}..={max} (got {}-{})", range.from, range.to),
        ));
    }
    Ok(())
}

fn parse_range_value(value: &Value) -> Option<XhttpRange> {
    match value {
        Value::Number(n) => n.as_i64().map(XhttpRange::fixed),
        Value::String(s) => parse_range_string(s),
        Value::Object(obj) => {
            let from = obj.get("from").and_then(value_as_i64)?;
            let to = obj.get("to").and_then(value_as_i64).unwrap_or(from);
            Some(XhttpRange { from, to })
        }
        _ => None,
    }
}

fn parse_range_string(raw: &str) -> Option<XhttpRange> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((a, b)) = trimmed.split_once('-') {
        // Allow negative disable: "-1" is a single number, not a range.
        if a.is_empty() {
            return trimmed.parse::<i64>().ok().map(XhttpRange::fixed);
        }
        let from = a.trim().parse::<i64>().ok()?;
        let to = b.trim().parse::<i64>().ok()?;
        Some(XhttpRange { from, to })
    } else {
        trimmed.parse::<i64>().ok().map(XhttpRange::fixed)
    }
}

fn range_to_value(range: XhttpRange) -> Value {
    if range.from == range.to {
        i64_to_value(range.from)
    } else {
        Value::String(format!("{}-{}", range.from, range.to))
    }
}

fn i64_to_value(n: i64) -> Value {
    Value::Number(Number::from(n))
}

fn value_as_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64().or_else(|| n.as_u64().map(|u| u as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn string_field(object: &Map<String, Value>, key: &str) -> String {
    object
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn insert_nonempty_string(object: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        object.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_round_trip_writes_padding_and_mode() {
        let settings = XhttpStreamSettings::default();
        let object = xhttp_to_object(&settings);
        assert_eq!(object.get("path"), Some(&json!("/")));
        assert_eq!(object.get("mode"), Some(&json!("auto")));
        assert_eq!(object.get("xPaddingBytes"), Some(&json!("100-1000")));
        assert_eq!(object.get("scMaxBufferedPosts"), Some(&json!(30)));
        assert_eq!(object.get("scStreamUpServerSecs"), Some(&json!("20-80")));
        assert_eq!(object.get("noSSEHeader"), Some(&json!(false)));
        let parsed = parse_xhttp(&object);
        assert_eq!(parsed.core.path, "/");
        assert_eq!(parsed.core.mode, "auto");
        assert_eq!(parsed.core.x_padding_bytes, XhttpRange::span(100, 1000));
    }

    #[test]
    fn parse_range_forms_and_headers() {
        let object = json!({
            "path": "/x",
            "mode": "packet-up",
            "xPaddingBytes": 500,
            "scMaxEachPostBytes": {"from": 1000, "to": 2000},
            "headers": {"User-Agent": "ua", "Accept": "*/*"},
            "keep": true
        })
        .as_object()
        .unwrap()
        .clone();
        let parsed = parse_xhttp(&object);
        assert_eq!(parsed.core.x_padding_bytes, XhttpRange::fixed(500));
        assert_eq!(parsed.core.sc_max_each_post_bytes, XhttpRange::span(1000, 2000));
        assert_eq!(parsed.core.headers.len(), 2);
        assert!(parsed.extras.contains_key("keep"));
    }

    #[test]
    fn validate_rejects_mode_and_xmux_conflict() {
        let mut settings = XhttpStreamSettings::default();
        settings.core.mode = "nope".to_owned();
        assert!(validate_xhttp_settings(&settings).is_err());
        settings.core.mode = "auto".to_owned();
        settings.core.xmux.max_concurrency = XhttpRange::fixed(8);
        settings.core.xmux.max_connections = XhttpRange::fixed(1);
        assert!(validate_xhttp_settings(&settings).is_err());
        settings.core.xmux.max_connections = XhttpRange::fixed(0);
        assert!(validate_xhttp_settings(&settings).is_ok());
    }

    #[test]
    fn download_one_level_and_extra_json() {
        let mut settings = XhttpStreamSettings::default();
        settings.download = Some(XhttpDownloadDraft {
            address: "dl.example".to_owned(),
            port: 443,
            network: "xhttp".to_owned(),
            security: "tls".to_owned(),
            server_name: "dl.example".to_owned(),
            xhttp: XhttpCoreSettings {
                path: "/same".to_owned(),
                ..XhttpCoreSettings::default()
            },
            extras: Map::new(),
        });
        assert!(validate_xhttp_settings(&settings).is_ok());
        let object = xhttp_to_object(&settings);
        assert_eq!(
            object["downloadSettings"]["address"],
            json!("dl.example")
        );
        assert_eq!(object["downloadSettings"]["network"], json!("xhttp"));
        let extra = xhttp_extra_json(&settings).expect("extra");
        let parsed: Value = serde_json::from_str(&extra).unwrap();
        let obj = parsed.as_object().unwrap();
        assert!(!obj.contains_key("path"));
        assert!(!obj.contains_key("mode"));
        assert!(!obj.contains_key("host"));
        assert!(obj.contains_key("downloadSettings"));
        assert!(obj.contains_key("xPaddingBytes"));
    }

    #[test]
    fn sc_stream_up_disable_minus_one() {
        let mut settings = XhttpStreamSettings::default();
        settings.core.sc_stream_up_server_secs = XhttpRange::fixed(-1);
        assert!(validate_xhttp_settings(&settings).is_ok());
        let object = xhttp_to_object(&settings);
        assert_eq!(object.get("scStreamUpServerSecs"), Some(&json!(-1)));
    }
}
