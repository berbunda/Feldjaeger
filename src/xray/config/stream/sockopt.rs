//! `streamSettings.sockopt` low-level socket options (Roadmap §2.3:87).
//!
//! `sockopt` is a `streamSettings` sibling of `security`/`realitySettings`/`tlsSettings`/
//! `finalmask` — not transport-specific, applies regardless of the chosen transport method.
//! Documented fields split into inbound-only, outbound-only, and shared
//! ([`INBOUND_ONLY_SOCKOPT_FIELDS`], [`OUTBOUND_ONLY_SOCKOPT_FIELDS`], [`sockopt_field_applies`]);
//! Feldjäger models every documented field as typed data regardless of direction, so a draft never
//! drops a field that doesn't apply; each editor shows the fields of its side (the inbound Stream
//! tab, the Outbound Shell "Socket options" section — Roadmap §4.2).
//! See <https://xtls.github.io/en/config/transports/sockopt.html>.
//!
//! Verified against `XTLS/Xray-core@main` (`infra/conf/transport_sockopt.go`): `SocketConfig` is
//! decoded by Go's `encoding/json` (key match is case-insensitive, integers are `int32` /
//! `uint32`) and `Build()` refuses an unknown `domainStrategy` / `addressPortStrategy`;
//! [`validate_sockopt`] mirrors that.

use serde_json::{Map, Value};

use super::StreamDirection;
use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// `sockopt` keys that only configure a listening socket (meaningless on an outbound).
pub const INBOUND_ONLY_SOCKOPT_FIELDS: &[&str] =
    &["acceptProxyProtocol", "trustedXForwardedFor", "V6Only"];

/// `sockopt` keys that only configure a dialing socket (meaningless on an inbound).
pub const OUTBOUND_ONLY_SOCKOPT_FIELDS: &[&str] = &[
    "mark",
    "domainStrategy",
    "dialerProxy",
    TCP_CONGESTION_KEY,
    "interface",
    "tcpMptcp",
    "addressPortStrategy",
    "happyEyeballs",
];

/// Canonical spelling of the congestion-control key (`json:"tcpCongestion"` in the core). The
/// documentation long spelled it `tcpcongestion`; Go matches keys case-insensitively, so every
/// spelling is read, an existing one is kept, and a new key is written canonically.
pub const TCP_CONGESTION_KEY: &str = "tcpCongestion";

/// Whether the `sockopt` key `field` has an effect on a socket of the given direction.
/// Keys in neither list (e.g. `tcpFastOpen`, `tproxy`, keep-alive/timeout fields,
/// `customSockopt`, unknown future keys) are treated as shared.
pub fn sockopt_field_applies(field: &str, direction: StreamDirection) -> bool {
    match direction {
        StreamDirection::Inbound => !OUTBOUND_ONLY_SOCKOPT_FIELDS.contains(&field),
        StreamDirection::Outbound => !INBOUND_ONLY_SOCKOPT_FIELDS.contains(&field),
    }
}

/// Documented `tproxy` values (free text is still accepted/preserved for forward-compat).
pub const TPROXY_MODES: &[&str] = &["redirect", "tproxy", "off"];

/// Documented `domainStrategy` values (outbound-only).
pub const DOMAIN_STRATEGIES: &[&str] = &[
    "AsIs",
    "UseIP",
    "UseIPv6v4",
    "UseIPv6",
    "UseIPv4v6",
    "UseIPv4",
    "ForceIP",
    "ForceIPv6v4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv4",
];

/// Documented `addressPortStrategy` values (outbound-only).
pub const ADDRESS_PORT_STRATEGIES: &[&str] = &[
    "none",
    "SrvPortOnly",
    "SrvAddressOnly",
    "SrvPortAndAddress",
    "TxtPortOnly",
    "TxtAddressOnly",
    "TxtPortAndAddress",
];

/// Common `tcpCongestion` presets (outbound-only, Linux); free text also accepted since kernel
/// congestion-control modules vary by system.
pub const TCP_CONGESTION_PRESETS: &[&str] = &["bbr", "cubic", "reno"];

/// `sockopt.tcpFastOpen`: `bool` enables/disables; a positive integer sets the inbound TFO
/// backlog. `Unset` means the key is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpFastOpenDraft {
    /// Key absent.
    #[default]
    Unset,
    /// Plain `true`/`false`.
    Bool(bool),
    /// Positive backlog integer (inbound TFO queue length).
    Backlog(u64),
}

/// `sockopt.happyEyeballs` (outbound-only; RFC 8305 dual-stack connection racing).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HappyEyeballsDraft {
    /// `tryDelayMs`.
    pub try_delay_ms: Option<u64>,
    /// `prioritizeIPv6`.
    pub prioritize_ipv6: Option<bool>,
    /// `interleave`.
    pub interleave: Option<u64>,
    /// `maxConcurrentTry`.
    pub max_concurrent_try: Option<u64>,
    /// Unknown keys under `happyEyeballs`.
    pub extras: Map<String, Value>,
}

/// Typed `streamSettings.sockopt` fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockoptDraft {
    /// `mark` (`SO_MARK`; outbound-only, Linux, requires `CAP_NET_ADMIN`).
    pub mark: Option<i64>,
    /// `tcpMaxSeg`.
    pub tcp_max_seg: Option<u64>,
    /// `tcpFastOpen`.
    pub tcp_fast_open: TcpFastOpenDraft,
    /// `tproxy` (`"redirect"` / `"tproxy"` / `"off"` / free text); empty = key absent.
    pub tproxy: String,
    /// `domainStrategy` (outbound-only); empty = key absent.
    pub domain_strategy: String,
    /// `dialerProxy` (outbound-only, chains through another outbound tag); empty = key absent.
    pub dialer_proxy: String,
    /// `acceptProxyProtocol` (inbound-only). Distinct from the existing per-transport
    /// `tcpSettings.acceptProxyProtocol` / `wsSettings.acceptProxyProtocol` fields already
    /// modeled on [`crate::xray::config::inbound_stream::TcpStreamSettings`] /
    /// [`crate::xray::config::inbound_stream::WsStreamSettings`] — the two are
    /// separate wire locations and must not be conflated.
    pub accept_proxy_protocol: bool,
    /// `trustedXForwardedFor` (HTTP-based transports only).
    pub trusted_x_forwarded_for: Vec<String>,
    /// `tcpKeepAliveIdle` in seconds.
    pub tcp_keep_alive_idle: Option<i64>,
    /// `tcpKeepAliveInterval` in seconds.
    pub tcp_keep_alive_interval: Option<i64>,
    /// `tcpUserTimeout` in milliseconds.
    pub tcp_user_timeout: Option<u64>,
    /// `tcpCongestion` (outbound-only, Linux); empty = key absent.
    pub tcp_congestion: String,
    /// Spelling of the congestion key found on disk (e.g. the documented `tcpcongestion`);
    /// `None` = write [`TCP_CONGESTION_KEY`].
    pub tcp_congestion_key: Option<String>,
    /// `interface` (outbound-only, bind to network interface); empty = key absent.
    pub interface: String,
    /// `V6Only` (inbound-only, Linux).
    pub v6_only: bool,
    /// `tcpWindowClamp`.
    pub tcp_window_clamp: Option<u64>,
    /// `tcpMptcp` (outbound-only, Linux 5.6+).
    pub tcp_mptcp: bool,
    /// `addressPortStrategy` (outbound-only); empty = key absent.
    pub address_port_strategy: String,
    /// `customSockopt` array, preserved as raw JSON — advanced/rare per-OS escape hatch, same
    /// trust boundary as [`crate::xray::config::inbound_security::TlsSettingsDraft::ech_sockopt`].
    pub custom_sockopt: Option<Value>,
    /// `happyEyeballs` (outbound-only).
    pub happy_eyeballs: Option<HappyEyeballsDraft>,
    /// Unknown/future keys under `sockopt`.
    pub extras: Map<String, Value>,
}

impl Default for SockoptDraft {
    fn default() -> Self {
        Self {
            mark: None,
            tcp_max_seg: None,
            tcp_fast_open: TcpFastOpenDraft::default(),
            tproxy: String::new(),
            domain_strategy: String::new(),
            dialer_proxy: String::new(),
            accept_proxy_protocol: false,
            trusted_x_forwarded_for: Vec::new(),
            tcp_keep_alive_idle: None,
            tcp_keep_alive_interval: None,
            tcp_user_timeout: None,
            tcp_congestion: String::new(),
            tcp_congestion_key: None,
            interface: String::new(),
            v6_only: false,
            tcp_window_clamp: None,
            tcp_mptcp: false,
            address_port_strategy: String::new(),
            custom_sockopt: None,
            happy_eyeballs: None,
            extras: Map::new(),
        }
    }
}

const KNOWN_SOCKOPT_KEYS: &[&str] = &[
    "mark",
    "tcpMaxSeg",
    "tcpFastOpen",
    "tproxy",
    "domainStrategy",
    "dialerProxy",
    "acceptProxyProtocol",
    "trustedXForwardedFor",
    "tcpKeepAliveIdle",
    "tcpKeepAliveInterval",
    "tcpUserTimeout",
    TCP_CONGESTION_KEY,
    "interface",
    "V6Only",
    "tcpWindowClamp",
    "tcpMptcp",
    "addressPortStrategy",
    "customSockopt",
    "happyEyeballs",
];

const KNOWN_HAPPY_EYEBALLS_KEYS: &[&str] =
    &["tryDelayMs", "prioritizeIPv6", "interleave", "maxConcurrentTry"];

fn is_tcp_congestion_key(key: &str) -> bool {
    key.eq_ignore_ascii_case(TCP_CONGESTION_KEY)
}

fn string_field(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned()
}

fn insert_non_empty_string(object: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        object.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

fn parse_happy_eyeballs(object: &Map<String, Value>) -> HappyEyeballsDraft {
    let mut extras = Map::new();
    for (key, value) in object {
        if !KNOWN_HAPPY_EYEBALLS_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    HappyEyeballsDraft {
        try_delay_ms: object.get("tryDelayMs").and_then(Value::as_u64),
        prioritize_ipv6: object.get("prioritizeIPv6").and_then(Value::as_bool),
        interleave: object.get("interleave").and_then(Value::as_u64),
        max_concurrent_try: object.get("maxConcurrentTry").and_then(Value::as_u64),
        extras,
    }
}

fn happy_eyeballs_to_value(draft: &HappyEyeballsDraft) -> Value {
    let mut object = Map::new();
    if let Some(delay) = draft.try_delay_ms {
        object.insert("tryDelayMs".to_owned(), Value::Number(delay.into()));
    }
    if let Some(prioritize) = draft.prioritize_ipv6 {
        object.insert("prioritizeIPv6".to_owned(), Value::Bool(prioritize));
    }
    if let Some(interleave) = draft.interleave {
        object.insert("interleave".to_owned(), Value::Number(interleave.into()));
    }
    if let Some(max_try) = draft.max_concurrent_try {
        object.insert("maxConcurrentTry".to_owned(), Value::Number(max_try.into()));
    }
    for (k, v) in &draft.extras {
        if !object.contains_key(k) {
            object.insert(k.clone(), v.clone());
        }
    }
    Value::Object(object)
}

/// Parses a `streamSettings.sockopt` object into a typed draft. Every known key is read
/// independently and permissively; a known key with an unrecognized shape (e.g. `tcpFastOpen`
/// as a string, non-array `customSockopt`) is preserved in [`SockoptDraft::extras`] instead of
/// being silently dropped.
pub fn parse_sockopt(object: &Map<String, Value>) -> SockoptDraft {
    let mut extras = Map::new();
    for (key, value) in object {
        if !KNOWN_SOCKOPT_KEYS.contains(&key.as_str()) && !is_tcp_congestion_key(key) {
            extras.insert(key.clone(), value.clone());
        }
    }
    // The canonical spelling wins when several are present; the others are not read.
    let tcp_congestion_key = object
        .keys()
        .filter(|key| is_tcp_congestion_key(key))
        .min_by_key(|key| key.as_str() != TCP_CONGESTION_KEY)
        .cloned();
    for key in object.keys().filter(|key| is_tcp_congestion_key(key)) {
        if Some(key) != tcp_congestion_key.as_ref() {
            extras.insert(key.clone(), object[key.as_str()].clone());
        }
    }

    let tcp_fast_open = match object.get("tcpFastOpen") {
        None => TcpFastOpenDraft::Unset,
        Some(Value::Bool(b)) => TcpFastOpenDraft::Bool(*b),
        Some(Value::Number(n)) if n.as_u64().is_some() => {
            TcpFastOpenDraft::Backlog(n.as_u64().expect("checked is_some above"))
        }
        Some(other) => {
            extras.insert("tcpFastOpen".to_owned(), other.clone());
            TcpFastOpenDraft::Unset
        }
    };

    let custom_sockopt = match object.get("customSockopt") {
        Some(value) if value.is_array() => Some(value.clone()),
        Some(other) => {
            extras.insert("customSockopt".to_owned(), other.clone());
            None
        }
        None => None,
    };

    let happy_eyeballs = match object.get("happyEyeballs") {
        Some(Value::Object(obj)) => Some(parse_happy_eyeballs(obj)),
        Some(other) => {
            extras.insert("happyEyeballs".to_owned(), other.clone());
            None
        }
        None => None,
    };

    SockoptDraft {
        mark: object.get("mark").and_then(Value::as_i64),
        tcp_max_seg: object.get("tcpMaxSeg").and_then(Value::as_u64),
        tcp_fast_open,
        tproxy: string_field(object.get("tproxy")),
        domain_strategy: string_field(object.get("domainStrategy")),
        dialer_proxy: string_field(object.get("dialerProxy")),
        accept_proxy_protocol: object
            .get("acceptProxyProtocol")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        trusted_x_forwarded_for: object
            .get("trustedXForwardedFor")
            .and_then(Value::as_array)
            .map(|array| {
                array
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        tcp_keep_alive_idle: object.get("tcpKeepAliveIdle").and_then(Value::as_i64),
        tcp_keep_alive_interval: object.get("tcpKeepAliveInterval").and_then(Value::as_i64),
        tcp_user_timeout: object.get("tcpUserTimeout").and_then(Value::as_u64),
        tcp_congestion: string_field(tcp_congestion_key.as_deref().and_then(|key| object.get(key))),
        tcp_congestion_key: tcp_congestion_key.filter(|key| key != TCP_CONGESTION_KEY),
        interface: string_field(object.get("interface")),
        v6_only: object.get("V6Only").and_then(Value::as_bool).unwrap_or(false),
        tcp_window_clamp: object.get("tcpWindowClamp").and_then(Value::as_u64),
        tcp_mptcp: object.get("tcpMptcp").and_then(Value::as_bool).unwrap_or(false),
        address_port_strategy: string_field(object.get("addressPortStrategy")),
        custom_sockopt,
        happy_eyeballs,
        extras,
    }
}

/// Builds the `sockopt` object `Value` from a typed draft. Each field is written only when set /
/// non-default; unknown/future keys from [`SockoptDraft::extras`] are always preserved.
pub fn sockopt_to_value(draft: &SockoptDraft) -> Value {
    let mut object = Map::new();

    if let Some(mark) = draft.mark {
        object.insert("mark".to_owned(), Value::Number(mark.into()));
    }
    if let Some(seg) = draft.tcp_max_seg {
        object.insert("tcpMaxSeg".to_owned(), Value::Number(seg.into()));
    }
    match draft.tcp_fast_open {
        TcpFastOpenDraft::Unset => {}
        TcpFastOpenDraft::Bool(b) => {
            object.insert("tcpFastOpen".to_owned(), Value::Bool(b));
        }
        TcpFastOpenDraft::Backlog(n) => {
            object.insert("tcpFastOpen".to_owned(), Value::Number(n.into()));
        }
    }
    insert_non_empty_string(&mut object, "tproxy", &draft.tproxy);
    insert_non_empty_string(&mut object, "domainStrategy", &draft.domain_strategy);
    insert_non_empty_string(&mut object, "dialerProxy", &draft.dialer_proxy);
    if draft.accept_proxy_protocol {
        object.insert("acceptProxyProtocol".to_owned(), Value::Bool(true));
    }
    if !draft.trusted_x_forwarded_for.is_empty() {
        object.insert(
            "trustedXForwardedFor".to_owned(),
            Value::Array(
                draft
                    .trusted_x_forwarded_for
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(idle) = draft.tcp_keep_alive_idle {
        object.insert("tcpKeepAliveIdle".to_owned(), Value::Number(idle.into()));
    }
    if let Some(interval) = draft.tcp_keep_alive_interval {
        object.insert(
            "tcpKeepAliveInterval".to_owned(),
            Value::Number(interval.into()),
        );
    }
    if let Some(timeout) = draft.tcp_user_timeout {
        object.insert("tcpUserTimeout".to_owned(), Value::Number(timeout.into()));
    }
    insert_non_empty_string(
        &mut object,
        draft.tcp_congestion_key.as_deref().unwrap_or(TCP_CONGESTION_KEY),
        &draft.tcp_congestion,
    );
    insert_non_empty_string(&mut object, "interface", &draft.interface);
    if draft.v6_only {
        object.insert("V6Only".to_owned(), Value::Bool(true));
    }
    if let Some(clamp) = draft.tcp_window_clamp {
        object.insert("tcpWindowClamp".to_owned(), Value::Number(clamp.into()));
    }
    if draft.tcp_mptcp {
        object.insert("tcpMptcp".to_owned(), Value::Bool(true));
    }
    insert_non_empty_string(
        &mut object,
        "addressPortStrategy",
        &draft.address_port_strategy,
    );
    if let Some(custom) = &draft.custom_sockopt {
        object.insert("customSockopt".to_owned(), custom.clone());
    }
    if let Some(happy_eyeballs) = &draft.happy_eyeballs {
        object.insert(
            "happyEyeballs".to_owned(),
            happy_eyeballs_to_value(happy_eyeballs),
        );
    }
    for (k, v) in &draft.extras {
        if !object.contains_key(k) {
            object.insert(k.clone(), v.clone());
        }
    }

    Value::Object(object)
}

/// Validates a sockopt draft before writing, refusing exactly what Xray-core refuses when it loads
/// `SocketConfig`: integers outside `int32` (`mark`, keep-alive, `tcpMaxSeg`, `tcpUserTimeout`,
/// `tcpWindowClamp`) or `uint32` (`happyEyeballs.interleave` / `maxConcurrentTry`) fail the JSON
/// decode, and `Build()` refuses a `domainStrategy` / `addressPortStrategy` it does not know
/// (matched case-insensitively; empty = default). Unknown `tproxy` values are not an error (the
/// core turns them into `off`), and OS-specific limits (Linux-only fields, `CAP_NET_ADMIN`, kernel
/// congestion modules) are left to the post-write `xray run -test`.
pub fn validate_sockopt(draft: &SockoptDraft) -> ConfigModifyResult<()> {
    let signed: [(&str, Option<i64>); 3] = [
        ("mark", draft.mark),
        ("tcpKeepAliveIdle", draft.tcp_keep_alive_idle),
        ("tcpKeepAliveInterval", draft.tcp_keep_alive_interval),
    ];
    for (key, value) in signed {
        if let Some(value) = value
            && i32::try_from(value).is_err()
        {
            return invalid(format!("streamSettings.sockopt.{key} must fit a 32-bit integer (got {value})"));
        }
    }
    let unsigned: [(&str, Option<u64>); 3] = [
        ("tcpMaxSeg", draft.tcp_max_seg),
        ("tcpUserTimeout", draft.tcp_user_timeout),
        ("tcpWindowClamp", draft.tcp_window_clamp),
    ];
    for (key, value) in unsigned {
        if let Some(value) = value
            && i32::try_from(value).is_err()
        {
            return invalid(format!("streamSettings.sockopt.{key} must fit a 32-bit integer (got {value})"));
        }
    }
    if let Some(happy_eyeballs) = &draft.happy_eyeballs {
        for (key, value) in [
            ("interleave", happy_eyeballs.interleave),
            ("maxConcurrentTry", happy_eyeballs.max_concurrent_try),
        ] {
            if let Some(value) = value
                && u32::try_from(value).is_err()
            {
                return invalid(format!(
                    "streamSettings.sockopt.happyEyeballs.{key} must fit a 32-bit unsigned integer (got {value})"
                ));
            }
        }
    }
    for (key, value, known) in [
        ("domainStrategy", &draft.domain_strategy, DOMAIN_STRATEGIES),
        ("addressPortStrategy", &draft.address_port_strategy, ADDRESS_PORT_STRATEGIES),
    ] {
        if !value.is_empty() && !known.iter().any(|preset| preset.eq_ignore_ascii_case(value)) {
            return invalid(format!(
                "streamSettings.sockopt.{key} \"{value}\" is not supported by Xray-core (expected one of {})",
                known.join(", ")
            ));
        }
    }
    Ok(())
}

fn invalid(message: String) -> ConfigModifyResult<()> {
    Err(ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_object() -> Map<String, Value> {
        json!({
            "tproxy": "redirect",
            "acceptProxyProtocol": true,
            "tcpFastOpen": 256,
            "V6Only": true,
            "tcpMaxSeg": 1440,
            "tcpKeepAliveIdle": 30,
            "tcpKeepAliveInterval": 10,
            "tcpUserTimeout": 5000,
            "tcpWindowClamp": 65535,
            "trustedXForwardedFor": ["10.0.0.1", "10.0.0.2"],
            "customSockopt": [{"opt": "1", "value": "1", "type": "int"}],
            "mark": 255,
            "domainStrategy": "UseIPv4",
            "dialerProxy": "out-1",
            "tcpcongestion": "bbr",
            "interface": "eth0",
            "tcpMptcp": true,
            "addressPortStrategy": "SrvPortOnly",
            "happyEyeballs": {
                "tryDelayMs": 250,
                "prioritizeIPv6": true,
                "interleave": 1,
                "maxConcurrentTry": 4
            },
            "futureField": "keep-me"
        })
        .as_object()
        .expect("object literal")
        .clone()
    }

    #[test]
    fn parses_known_fields_and_extras() {
        let draft = parse_sockopt(&sample_object());
        assert_eq!(draft.tproxy, "redirect");
        assert!(draft.accept_proxy_protocol);
        assert_eq!(draft.tcp_fast_open, TcpFastOpenDraft::Backlog(256));
        assert!(draft.v6_only);
        assert_eq!(draft.tcp_max_seg, Some(1440));
        assert_eq!(draft.tcp_keep_alive_idle, Some(30));
        assert_eq!(draft.tcp_keep_alive_interval, Some(10));
        assert_eq!(draft.tcp_user_timeout, Some(5000));
        assert_eq!(draft.tcp_window_clamp, Some(65535));
        assert_eq!(
            draft.trusted_x_forwarded_for,
            vec!["10.0.0.1".to_owned(), "10.0.0.2".to_owned()]
        );
        assert_eq!(draft.mark, Some(255));
        assert_eq!(draft.domain_strategy, "UseIPv4");
        assert_eq!(draft.dialer_proxy, "out-1");
        assert_eq!(draft.tcp_congestion, "bbr");
        assert_eq!(draft.tcp_congestion_key.as_deref(), Some("tcpcongestion"));
        assert_eq!(draft.interface, "eth0");
        assert!(draft.tcp_mptcp);
        assert_eq!(draft.address_port_strategy, "SrvPortOnly");
        assert_eq!(
            draft.custom_sockopt,
            Some(json!([{"opt": "1", "value": "1", "type": "int"}]))
        );
        let happy_eyeballs = draft.happy_eyeballs.expect("happyEyeballs");
        assert_eq!(happy_eyeballs.try_delay_ms, Some(250));
        assert_eq!(happy_eyeballs.prioritize_ipv6, Some(true));
        assert_eq!(happy_eyeballs.interleave, Some(1));
        assert_eq!(happy_eyeballs.max_concurrent_try, Some(4));
        assert_eq!(draft.extras.get("futureField"), Some(&json!("keep-me")));
    }

    #[test]
    fn tcp_fast_open_variants() {
        assert_eq!(
            parse_sockopt(json!({"tcpFastOpen": true}).as_object().unwrap()).tcp_fast_open,
            TcpFastOpenDraft::Bool(true)
        );
        assert_eq!(
            parse_sockopt(json!({"tcpFastOpen": false}).as_object().unwrap()).tcp_fast_open,
            TcpFastOpenDraft::Bool(false)
        );
        assert_eq!(
            parse_sockopt(json!({}).as_object().unwrap()).tcp_fast_open,
            TcpFastOpenDraft::Unset
        );
    }

    #[test]
    fn unrecognized_tcp_fast_open_shape_preserved_in_extras() {
        let draft = parse_sockopt(json!({"tcpFastOpen": "weird"}).as_object().unwrap());
        assert_eq!(draft.tcp_fast_open, TcpFastOpenDraft::Unset);
        assert_eq!(draft.extras.get("tcpFastOpen"), Some(&json!("weird")));
    }

    #[test]
    fn non_array_custom_sockopt_preserved_in_extras() {
        let draft = parse_sockopt(json!({"customSockopt": {"not": "array"}}).as_object().unwrap());
        assert_eq!(draft.custom_sockopt, None);
        assert_eq!(
            draft.extras.get("customSockopt"),
            Some(&json!({"not": "array"}))
        );
    }

    #[test]
    fn non_object_happy_eyeballs_preserved_in_extras() {
        let draft = parse_sockopt(json!({"happyEyeballs": "nope"}).as_object().unwrap());
        assert_eq!(draft.happy_eyeballs, None);
        assert_eq!(draft.extras.get("happyEyeballs"), Some(&json!("nope")));
    }

    #[test]
    fn roundtrips_full_object_through_value() {
        let draft = parse_sockopt(&sample_object());
        let value = sockopt_to_value(&draft);
        let object = value.as_object().expect("object");
        let reparsed = parse_sockopt(object);
        assert_eq!(reparsed, draft);
    }

    #[test]
    fn to_value_omits_default_fields() {
        let draft = SockoptDraft::default();
        assert_eq!(sockopt_to_value(&draft), json!({}));
    }

    #[test]
    fn validate_mirrors_socket_config_build() {
        assert!(validate_sockopt(&SockoptDraft::default()).is_ok());
        assert!(validate_sockopt(&parse_sockopt(&sample_object())).is_ok());
        let check = |edit: fn(&mut SockoptDraft)| {
            let mut draft = SockoptDraft::default();
            edit(&mut draft);
            validate_sockopt(&draft)
        };
        // The core turns an unknown tproxy into "off" and matches strategies case-insensitively.
        assert!(check(|d| d.tproxy = "not-a-real-mode".to_owned()).is_ok());
        assert!(check(|d| d.domain_strategy = "forceipv6v4".to_owned()).is_ok());
        assert!(check(|d| d.address_port_strategy = "NONE".to_owned()).is_ok());
        assert!(check(|d| d.domain_strategy = "UseIPv5".to_owned()).is_err());
        assert!(check(|d| d.address_port_strategy = "SrvOnly".to_owned()).is_err());
        // int32 / uint32 fields.
        assert!(check(|d| d.mark = Some(i64::from(i32::MIN))).is_ok());
        assert!(check(|d| d.mark = Some(i64::from(i32::MAX) + 1)).is_err());
        assert!(check(|d| d.tcp_user_timeout = Some(1 << 31)).is_err());
        assert!(check(|d| d.tcp_keep_alive_idle = Some(-1)).is_ok());
        let error = check(|d| {
            d.happy_eyeballs = Some(HappyEyeballsDraft { interleave: Some(1 << 32), ..Default::default() })
        })
        .unwrap_err();
        assert!(error.message().contains("happyEyeballs.interleave"), "{error}");
    }

    #[test]
    fn tcp_congestion_reads_every_spelling_and_writes_canonically() {
        let legacy = parse_sockopt(json!({"tcpcongestion": "bbr"}).as_object().unwrap());
        assert_eq!(legacy.tcp_congestion, "bbr");
        assert!(legacy.extras.is_empty());
        assert_eq!(sockopt_to_value(&legacy), json!({"tcpcongestion": "bbr"}), "spelling kept");

        let mut fresh = SockoptDraft::default();
        fresh.tcp_congestion = "cubic".to_owned();
        assert_eq!(sockopt_to_value(&fresh), json!({"tcpCongestion": "cubic"}));

        // Both spellings: the canonical one is read; the other is preserved untouched.
        let both = parse_sockopt(json!({"tcpcongestion": "reno", "tcpCongestion": "bbr"}).as_object().unwrap());
        assert_eq!(both.tcp_congestion, "bbr");
        assert_eq!(both.tcp_congestion_key, None);
        assert_eq!(both.extras.get("tcpcongestion"), Some(&json!("reno")));
    }

    #[test]
    fn direction_lists_cover_only_known_keys_and_never_overlap() {
        for field in INBOUND_ONLY_SOCKOPT_FIELDS.iter().chain(OUTBOUND_ONLY_SOCKOPT_FIELDS) {
            assert!(KNOWN_SOCKOPT_KEYS.contains(field), "{field} is not a modeled sockopt key");
        }
        for field in INBOUND_ONLY_SOCKOPT_FIELDS {
            assert!(!OUTBOUND_ONLY_SOCKOPT_FIELDS.contains(field), "{field} in both lists");
        }
    }

    #[test]
    fn field_applicability_follows_direction() {
        use StreamDirection::{Inbound, Outbound};
        assert!(sockopt_field_applies("acceptProxyProtocol", Inbound));
        assert!(!sockopt_field_applies("acceptProxyProtocol", Outbound));
        assert!(sockopt_field_applies("dialerProxy", Outbound));
        assert!(!sockopt_field_applies("dialerProxy", Inbound));
        // Shared and unknown/future keys apply to both sides.
        for field in ["tcpFastOpen", "tproxy", "customSockopt", "someFutureKey"] {
            assert!(sockopt_field_applies(field, Inbound), "{field}");
            assert!(sockopt_field_applies(field, Outbound), "{field}");
        }
    }
}
