//! `streamSettings.sockopt` low-level socket options (Roadmap §2.3:87).
//!
//! `sockopt` is a `streamSettings` sibling of `security`/`realitySettings`/`tlsSettings`/
//! `finalmask` — not transport-specific, applies regardless of the chosen transport method.
//! Documented fields split roughly into inbound-only, outbound-only, and shared; Feldjäger
//! models every documented field as typed data (so the draft is outbound-ready), but only the
//! inbound Stream tab exposes editable widgets today — outbound-only fields still round-trip
//! losslessly, just without a dedicated widget yet. See
//! <https://xtls.github.io/en/config/transports/sockopt.html>.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::ConfigModifyResult;

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

/// Common `tcpcongestion` presets (outbound-only, Linux); free text also accepted since kernel
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
    /// modeled on [`super::TcpStreamSettings`] / [`super::WsStreamSettings`] — the two are
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
    /// `tcpcongestion` (outbound-only, Linux); empty = key absent.
    pub tcpcongestion: String,
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
    /// trust boundary as [`super::super::inbound_security::TlsSettingsDraft::ech_sockopt`].
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
            tcpcongestion: String::new(),
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
    "tcpcongestion",
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
        if !KNOWN_SOCKOPT_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
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
        tcpcongestion: string_field(object.get("tcpcongestion")),
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
    insert_non_empty_string(&mut object, "tcpcongestion", &draft.tcpcongestion);
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

/// Validates a sockopt draft before writing.
///
/// Intentionally a no-op today: none of the documented fields interact with the existing
/// compatibility gates (Reality/Vision/Hysteria/TLS-certs/Shadowsocks), and OS/runtime-specific
/// constraints (Linux-only fields, `CAP_NET_ADMIN`, kernel congestion modules) are already caught
/// by the post-write `xray run -test` step. Kept as a named function so a future real constraint
/// has an obvious home, matching the `validate_kcp_settings` / `validate_finalmask_layers`
/// call-site convention in `apply_inbound_stream`.
pub fn validate_sockopt(_draft: &SockoptDraft) -> ConfigModifyResult<()> {
    Ok(())
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
        assert_eq!(draft.tcpcongestion, "bbr");
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
    fn validate_accepts_anything() {
        assert!(validate_sockopt(&SockoptDraft::default()).is_ok());
        let mut draft = SockoptDraft::default();
        draft.tproxy = "not-a-real-mode".to_owned();
        assert!(validate_sockopt(&draft).is_ok());
    }
}
