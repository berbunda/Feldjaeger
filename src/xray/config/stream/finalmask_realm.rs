//! `finalmask.udp[].settings` for `type = "realm"` (Roadmap §2.6 stage 1.2), matching the core's
//! `Realm` (`infra/conf/transport_finalmask.go`) and `transport/internet/finalmask/realm`.
//!
//! A realm layer punches UDP through NAT with the help of a Hysteria-style realm server: both
//! peers register under the same realm id at `url` (HTTPS for `realm://`, plain HTTP for
//! `realm+http://`, `token` as the bearer credential), discover their public addresses with the
//! STUN servers and optionally map a port on the local gateway (UPnP / NAT-PMP). The mask works on
//! both sides (`NewConnServer` / `NewConnClient`).
//!
//! `url` is kept as text (lossless); [`RealmUrl`] is a field view of it that parses the way Go's
//! `url.Parse` + `Realm.Build()` do and composes back a URL the core reads into the same fields.
//! `tlsConfig` (client TLS towards the realm server, a full `TLSConfig`) stays a raw JSON object —
//! Feldjäger has no client-shaped TLS editor yet (Outbound `streamSettings`, Roadmap §4.2).

use serde_json::{Map, Value};

use super::finalmask_layers::{
    apply_extras, apply_optional_string, apply_string_array, bool_option_field, extras_of,
    object_field, string_array_field, string_field,
};

/// `realm.settings.ipMode` values the core recognizes (after lower-casing); anything else —
/// including empty — silently means `dual`.
pub const REALM_IP_MODES: &[&str] = &["dual", "v4", "v6"];

/// Core default of `portMapping.timeout` (seconds; `0` / absent).
pub const REALM_DEFAULT_PORT_MAP_TIMEOUT_SECS: i64 = 10;
/// Core default of `portMapping.lifetime` (seconds; `0` / absent).
pub const REALM_DEFAULT_PORT_MAP_LIFETIME_SECS: i64 = 600;

/// `realm.settings.portMapping` — the core's `realm.PortMapping` message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealmPortMapping {
    /// `enabled`; `None` = key absent (= disabled).
    pub enabled: Option<bool>,
    /// `timeout` in seconds (gateway discovery and each mapping request); `None` = key absent.
    pub timeout: Option<i64>,
    /// `lifetime` in seconds (mapping lease); `None` = key absent.
    pub lifetime: Option<i64>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

impl RealmPortMapping {
    /// `true` when the mapping is switched on.
    pub fn is_enabled(&self) -> bool {
        self.enabled == Some(true)
    }

    /// `true` when nothing but `enabled` would be written.
    pub fn is_bare(&self) -> bool {
        self.timeout.is_none() && self.lifetime.is_none() && self.extras.is_empty()
    }
}

const KNOWN_PORT_MAPPING_KEYS: &[&str] = &["enabled", "timeout", "lifetime"];

/// Absent/`null` → `Some(None)`; `None` when present but not an integer (Go decodes the field
/// into `int64`, so a float or a string fails in the core too).
fn i64_field(value: Option<&Value>) -> Option<Option<i64>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(value) => value.as_i64().map(Some),
    }
}

fn parse_port_mapping(value: &Value) -> Option<RealmPortMapping> {
    let object = value.as_object()?;
    Some(RealmPortMapping {
        enabled: bool_option_field(object.get("enabled"))?,
        timeout: i64_field(object.get("timeout"))?,
        lifetime: i64_field(object.get("lifetime"))?,
        extras: extras_of(object, KNOWN_PORT_MAPPING_KEYS),
    })
}

fn port_mapping_to_value(draft: &RealmPortMapping) -> Value {
    let mut object = Map::new();
    if let Some(enabled) = draft.enabled {
        object.insert("enabled".to_owned(), Value::Bool(enabled));
    }
    if let Some(timeout) = draft.timeout {
        object.insert("timeout".to_owned(), Value::from(timeout));
    }
    if let Some(lifetime) = draft.lifetime {
        object.insert("lifetime".to_owned(), Value::from(lifetime));
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

/// `finalmask.udp[].settings` for `type = "realm"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealmSettings {
    /// `url` — `realm://TOKEN@HOST[:PORT]/ID` or `realm+http://…` (see [`RealmUrl`]); empty =
    /// key absent.
    pub url: String,
    /// `stunServers[]` — `host:port` entries; empty = key absent.
    pub stun_servers: Vec<String>,
    /// `tlsConfig` — client TLS towards the realm server, preserved raw; `None` = key absent.
    pub tls_config: Option<Value>,
    /// `ipMode` — one of [`REALM_IP_MODES`]; empty = key absent (= `dual`).
    pub ip_mode: String,
    /// `portMapping`; `None` = key absent.
    pub port_mapping: Option<RealmPortMapping>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_REALM_KEYS: &[&str] = &["url", "stunServers", "tlsConfig", "ipMode", "portMapping"];

/// Parses `settings` as `realm`. `None` when `settings` isn't an object or a known key can't be
/// represented losslessly.
pub fn parse_realm_settings(settings: &Value) -> Option<RealmSettings> {
    let object = settings.as_object()?;
    let port_mapping = match object.get("portMapping") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_port_mapping(value)?),
    };
    Some(RealmSettings {
        url: string_field(object.get("url"))?,
        stun_servers: string_array_field(object.get("stunServers"))?,
        tls_config: object_field(object.get("tlsConfig"))?,
        ip_mode: string_field(object.get("ipMode"))?,
        port_mapping,
        extras: extras_of(object, KNOWN_REALM_KEYS),
    })
}

/// Builds the `settings` `Value` for a `realm` layer.
pub fn realm_settings_to_value(draft: &RealmSettings) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "url", &draft.url);
    apply_string_array(&mut object, "stunServers", &draft.stun_servers);
    if let Some(tls_config) = &draft.tls_config {
        object.insert("tlsConfig".to_owned(), tls_config.clone());
    }
    apply_optional_string(&mut object, "ipMode", &draft.ip_mode);
    if let Some(port_mapping) = &draft.port_mapping {
        object.insert("portMapping".to_owned(), port_mapping_to_value(port_mapping));
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

/// `true` when the core recognizes `ip_mode` (case-insensitive) or it is empty (= `dual`).
pub fn realm_ip_mode_is_known(ip_mode: &str) -> bool {
    ip_mode.is_empty() || REALM_IP_MODES.iter().any(|mode| ip_mode.eq_ignore_ascii_case(mode))
}

/// Validates a `realm` layer like `Realm.Build()` (`url`, non-empty `stunServers` that split as
/// `host:port`) plus what the runtime silently drops: a STUN entry whose port is not a number
/// (`resolveSTUNServers` skips it), a realm-server port outside 1–65535, a negative port-mapping
/// timeout/lifetime (`PortMapConfig.withDefaults` fails). `tlsConfig` is left to the core's
/// `TLSConfig.Build()` (`xray run -test` reports it).
pub fn validate_realm_settings(draft: &RealmSettings) -> Result<(), String> {
    if draft.url.is_empty() {
        return Err("url is required (realm://TOKEN@HOST[:PORT]/ID)".to_owned());
    }
    parse_realm_url(&draft.url)
        .and_then(|url| url.validate())
        .map_err(|error| format!("url: {error}"))?;
    if draft.stun_servers.is_empty() {
        return Err("stunServers: at least one host:port is required".to_owned());
    }
    for server in &draft.stun_servers {
        let (_, port) = split_host_port(server).map_err(|error| format!("stunServers: \"{server}\": {error}"))?;
        if parse_port(port).is_none() {
            return Err(format!(
                "stunServers: \"{server}\": port must be a number 1–65535 (Xray-core skips the server otherwise)"
            ));
        }
    }
    if let Some(mapping) = &draft.port_mapping {
        for (name, value) in [("timeout", mapping.timeout), ("lifetime", mapping.lifetime)] {
            if value.is_some_and(|value| value < 0) {
                return Err(format!("portMapping.{name} must not be negative"));
            }
        }
    }
    Ok(())
}

// ─── url ────────────────────────────────────────────────────────────────────

/// The scheme of a realm `url`: how the realm server is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RealmScheme {
    /// `realm://` — HTTPS, default port 443.
    #[default]
    Https,
    /// `realm+http://` — plain HTTP, default port 80.
    Http,
}

impl RealmScheme {
    /// The URL scheme text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Https => "realm",
            Self::Http => "realm+http",
        }
    }

    /// The port the core uses when `url` has none.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
        }
    }
}

/// Field view of a realm `url`, as `Realm.Build()` reads it: `token` = decoded userinfo (a `:`
/// in it is part of the token), `host` without brackets, `port` (empty = scheme default), `id` =
/// decoded path without the leading `/`. `suffix` keeps a `?query` / `#fragment` verbatim (the core
/// ignores them) so editing a field never drops it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealmUrl {
    /// `realm` / `realm+http`.
    pub scheme: RealmScheme,
    /// Bearer token for the realm server (decoded).
    pub token: String,
    /// Realm server host name or IP (IPv6 without brackets).
    pub host: String,
    /// Realm server port; empty = [`RealmScheme::default_port`].
    pub port: String,
    /// Realm id both peers register under (decoded).
    pub id: String,
    /// `?query` / `#fragment`, verbatim.
    pub suffix: String,
}

impl RealmUrl {
    /// Composes the `url` text. Token and id are percent-encoded so the core decodes them back
    /// unchanged (`/` stays literal in the id, like a path).
    pub fn to_url_text(&self) -> String {
        let mut text = format!("{}://", self.scheme.as_str());
        if !self.token.is_empty() {
            text.push_str(&percent_encode(&self.token, false));
            text.push('@');
        }
        if self.host.contains(':') {
            text.push('[');
            text.push_str(&self.host);
            text.push(']');
        } else {
            text.push_str(&self.host);
        }
        if !self.port.is_empty() {
            text.push(':');
            text.push_str(&self.port);
        }
        text.push('/');
        text.push_str(&percent_encode(&self.id, true));
        text.push_str(&self.suffix);
        text
    }

    /// The checks `Realm.Build()` makes after parsing (non-empty host, token, id), plus a port in
    /// 1–65535 (the core accepts any digits and then cannot connect).
    pub fn validate(&self) -> Result<(), String> {
        if self.host.is_empty() {
            return Err("host is required".to_owned());
        }
        if self.token.is_empty() {
            return Err("token is required (realm://TOKEN@HOST/ID)".to_owned());
        }
        if self.id.is_empty() {
            return Err("realm id is required (the path: realm://TOKEN@HOST/ID)".to_owned());
        }
        if !self.port.is_empty() && parse_port(&self.port).is_none() {
            return Err(format!("port \"{}\" is outside 1–65535", self.port));
        }
        Ok(())
    }
}

/// Parses a realm `url` the way Go's `url.Parse` splits it and `Realm.Build()` reads it. Only
/// structural problems are errors here (unknown scheme, bad escape, bad port syntax); empty
/// token / id / host are reported by [`RealmUrl::validate`], so the GUI can show the fields of a
/// URL that is still being filled in.
pub fn parse_realm_url(text: &str) -> Result<RealmUrl, String> {
    if text.chars().any(|c| c.is_control() || c == ' ') {
        return Err("must not contain spaces or control characters".to_owned());
    }
    let (scheme, rest) = text
        .split_once("://")
        .ok_or_else(|| "expected realm://TOKEN@HOST[:PORT]/ID".to_owned())?;
    // `url.Parse` lower-cases the scheme.
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "realm" => RealmScheme::Https,
        "realm+http" => RealmScheme::Http,
        _ => return Err(format!("invalid scheme \"{scheme}\" (expected realm or realm+http)")),
    };
    // Fragment first, then query — the order `url.Parse` uses.
    let suffix_at = rest.find(['?', '#']).unwrap_or(rest.len());
    let (rest, suffix) = rest.split_at(suffix_at);
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(index) => (&authority[..index], &authority[index + 1..]),
        None => ("", authority),
    };
    // `validUserinfo`: anything else must be percent-encoded.
    if let Some(bad) = userinfo
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || "-._:~!$&'()*+,;=%@".contains(*c)))
    {
        return Err(format!("token: '{bad}' must be percent-encoded"));
    }
    let (host, port) = split_url_host_port(host_port)?;
    Ok(RealmUrl {
        scheme,
        token: percent_decode(userinfo).map_err(|error| format!("token: {error}"))?,
        host: host.to_owned(),
        port: port.to_owned(),
        id: percent_decode(path.strip_prefix('/').unwrap_or(path)).map_err(|error| format!("id: {error}"))?,
        suffix: suffix.to_owned(),
    })
}

/// `host[:port]` / `[v6][:port]` of a URL authority (`url.Parse`'s `parseHost`: the port, when
/// present, is digits only and may be empty).
fn split_url_host_port(host_port: &str) -> Result<(&str, &str), String> {
    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let (host, after) = bracketed
            .split_once(']')
            .ok_or_else(|| "missing ']' in host".to_owned())?;
        match after {
            "" => (host, ""),
            _ => (
                host,
                after
                    .strip_prefix(':')
                    .ok_or_else(|| format!("invalid port \"{after}\" after host"))?,
            ),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) => (host, port),
            None => (host_port, ""),
        }
    };
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid port \":{port}\""));
    }
    if host.contains(['[', ']']) || (!host_port.starts_with('[') && host.contains(':')) {
        return Err(format!("invalid host \"{host}\""));
    }
    Ok((host, port))
}

/// Go's `net.SplitHostPort`: `host:port` or `[host]:port`; the port may be any text.
fn split_host_port(text: &str) -> Result<(&str, &str), String> {
    if let Some(bracketed) = text.strip_prefix('[') {
        let (host, after) = bracketed
            .split_once(']')
            .ok_or_else(|| "missing ']' in address".to_owned())?;
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| "missing port in address".to_owned())?;
        if host.contains('[') || port.contains([']', '[']) {
            return Err("unexpected '[' or ']' in address".to_owned());
        }
        return Ok((host, port));
    }
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| "missing port in address".to_owned())?;
    if host.contains(':') {
        return Err("too many colons in address (put an IPv6 address in brackets)".to_owned());
    }
    if text.contains(['[', ']']) {
        return Err("unexpected '[' or ']' in address".to_owned());
    }
    Ok((host, port))
}

/// A decimal port 1–65535.
fn parse_port(text: &str) -> Option<u16> {
    text.parse::<u16>().ok().filter(|port| *port != 0)
}

/// Percent-decodes like Go's `PathUnescape` (`+` stays `+`); the result must be UTF-8.
fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = text
                .get(index + 1..index + 3)
                .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or_else(|| format!("invalid escape \"{}\"", &text[index..text.len().min(index + 3)]))?;
            decoded.push(u8::from_str_radix(hex, 16).map_err(|error| error.to_string())?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "decodes to invalid UTF-8".to_owned())
}

/// Percent-encodes everything but RFC 3986 unreserved characters (and `/` when `keep_slash`).
fn percent_encode(text: &str, keep_slash: bool) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) || (keep_slash && byte == b'/') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn realm_settings_round_trip_with_typed_port_mapping() {
        let settings = json!({
            "url": "realm://tok@realm.example.com:8443/room",
            "stunServers": ["stun.l.google.com:19302", "[2001:db8::1]:3478"],
            "tlsConfig": {"serverName": "realm.example.com", "fingerprint": "chrome"},
            "ipMode": "V4",
            "portMapping": {"enabled": false, "timeout": 5, "lifetime": 0, "future": 1},
            "futureKey": "keep"
        });
        let draft = parse_realm_settings(&settings).expect("parsed");
        let mapping = draft.port_mapping.as_ref().expect("mapping");
        assert_eq!(mapping.enabled, Some(false));
        assert_eq!(mapping.timeout, Some(5));
        assert_eq!(mapping.lifetime, Some(0));
        assert_eq!(realm_settings_to_value(&draft), settings);
        assert_eq!(validate_realm_settings(&draft), Ok(()));
    }

    #[test]
    fn unrepresentable_port_mapping_falls_back_to_raw_json() {
        for mapping in [json!("on"), json!({"enabled": "yes"}), json!({"timeout": 1.5}), json!({"lifetime": "10"})] {
            assert!(parse_realm_settings(&json!({"portMapping": mapping})).is_none(), "{mapping}");
        }
    }

    #[test]
    fn url_parses_like_build() {
        let url = parse_realm_url("REALM+HTTP://a%3Ab+c@[2001:db8::1]:8080/team%2Fone/x?q=1#f").expect("parsed");
        assert_eq!(
            url,
            RealmUrl {
                scheme: RealmScheme::Http,
                token: "a:b+c".to_owned(),
                host: "2001:db8::1".to_owned(),
                port: "8080".to_owned(),
                id: "team/one/x".to_owned(),
                suffix: "?q=1#f".to_owned(),
            }
        );
        // A `:` in the userinfo is part of the token (Build() reads `u.User.String()`).
        assert_eq!(parse_realm_url("realm://user:pass@h/id").unwrap().token, "user:pass");
        // `@` in the token: the last `@` ends the userinfo, like `url.Parse`.
        assert_eq!(parse_realm_url("realm://a@b@h/id").unwrap().token, "a@b");
        // Empty port = scheme default.
        let url = parse_realm_url("realm://t@h:/id").unwrap();
        assert_eq!((url.port.as_str(), url.scheme.default_port()), ("", 443));

        for (bad, needle) in [
            ("https://t@h/id", "scheme"),
            ("realm:t@h/id", "expected"),
            ("realm://t@h:44a/id", "port"),
            ("realm://t@[::1/id", "]"),
            ("realm://t@::1/id", "host"),
            ("realm://t%zz@h/id", "token"),
            ("realm://tö@h/id", "percent-encoded"),
            ("realm://t\"@h/id", "percent-encoded"),
            ("realm://t@h/i d", "spaces"),
        ] {
            let error = parse_realm_url(bad).expect_err(bad);
            assert!(error.contains(needle), "{bad}: {error}");
        }
    }

    #[test]
    fn url_validation_mirrors_build() {
        let check = |text: &str| parse_realm_url(text).and_then(|url| url.validate());
        assert_eq!(check("realm://t@h/id"), Ok(()));
        assert!(check("realm://h/id").unwrap_err().contains("token"));
        assert!(check("realm://t@/id").unwrap_err().contains("host"));
        assert!(check("realm://t@h/").unwrap_err().contains("id"));
        assert!(check("realm://t@h").unwrap_err().contains("id"));
        assert!(check("realm://t@h:0/id").unwrap_err().contains("1–65535"));
        assert!(check("realm://t@h:70000/id").unwrap_err().contains("1–65535"));
    }

    #[test]
    fn composed_url_parses_back_to_the_same_fields() {
        let cases = [
            RealmUrl {
                scheme: RealmScheme::Https,
                token: "p@ss:w/rd?#%+ ü".to_owned(),
                host: "realm.example.com".to_owned(),
                port: String::new(),
                id: "team/one two".to_owned(),
                suffix: String::new(),
            },
            RealmUrl {
                scheme: RealmScheme::Http,
                token: "t".to_owned(),
                host: "2001:db8::1".to_owned(),
                port: "8080".to_owned(),
                id: "id".to_owned(),
                suffix: "?keep=1".to_owned(),
            },
        ];
        for url in cases {
            let text = url.to_url_text();
            assert_eq!(parse_realm_url(&text), Ok(url), "{text}");
        }
        assert_eq!(
            RealmUrl { host: "h".to_owned(), token: "t".to_owned(), id: "r".to_owned(), ..RealmUrl::default() }
                .to_url_text(),
            "realm://t@h/r"
        );
    }

    #[test]
    fn settings_validation_mirrors_build_and_runtime() {
        let valid = |settings: Value| validate_realm_settings(&parse_realm_settings(&settings).expect("parsed"));
        let base = |extra: Value| {
            let mut settings = json!({"url": "realm://t@h/id", "stunServers": ["stun.example.com:3478"]});
            settings.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            settings
        };
        assert_eq!(valid(base(json!({}))), Ok(()));
        assert_eq!(valid(base(json!({"stunServers": ["[::1]:3478", "1.2.3.4:19302"]}))), Ok(()));
        // An unknown ipMode is not an error in the core (it means dual).
        assert_eq!(valid(base(json!({"ipMode": "both"}))), Ok(()));
        for (bad, needle) in [
            (json!({"stunServers": ["stun.example.com:3478"]}), "url is required"),
            (base(json!({"url": "realm://h/id"})), "url: token"),
            (base(json!({"stunServers": []})), "at least one"),
            (base(json!({"stunServers": ["stun.example.com"]})), "missing port"),
            (base(json!({"stunServers": ["::1:3478"]})), "too many colons"),
            (base(json!({"stunServers": ["stun.example.com:stun"]})), "port must be a number"),
            (base(json!({"portMapping": {"enabled": true, "timeout": -1}})), "portMapping.timeout"),
            (base(json!({"portMapping": {"lifetime": -5}})), "portMapping.lifetime"),
        ] {
            let error = valid(bad.clone()).expect_err(&bad.to_string());
            assert!(error.contains(needle), "{bad}: {error}");
        }
    }

    #[test]
    fn ip_mode_presets_match_the_core() {
        for mode in ["", "dual", "V4", "v6"] {
            assert!(realm_ip_mode_is_known(mode), "{mode}");
        }
        assert!(!realm_ip_mode_is_known("4"));
        assert!(!realm_ip_mode_is_known("ipv4"));
    }
}
