//! `finalmask.udp[].settings` for `type = "xdns"` (Roadmap §2.6 stage 1.3) — DNS tunnelling of
//! UDP payloads, schema of XTLS/Xray-core#6718 (v26.9.30): `infra/conf/transport_finalmask.go`
//! (`XDNS`, `XDNSDomain`, `XDNSResolver`) and `transport/internet/finalmask/xdns`.
//!
//! ```jsonc
//! { "domains":   [{ "name": "t.example.com", "lenLimit": 255, "labelLimit": 63, "types": [16], "edns0": 1232 }],
//!   "resolvers": [{ "type": "udp", "settings": { "addr": "1.1.1.1:53" } }],   // client only
//!   "extraPoll": 0 }
//! ```
//!
//! Both sides need `domains`; only the client (outbound) uses `resolvers` — the server ignores
//! them. Both checks sit in the mask constructors (`NewServer` / `NewClient`), so `xray run -test`
//! (which builds but never listens or dials) does not catch them.
//!
//! The previous schema (v26.9.9 – v26.9.29) used strings: `domains: ["t.example.com:txt"]`
//! (server) and `resolvers: ["t.example.com:txt+udp://1.1.1.1:53"]` (client); before that a single
//! `domain`. Such settings are not representable by [`XdnsSettings`] (the GUI keeps them on the
//! raw-JSON editor) and [`migrate_legacy_xdns_settings`] converts them on request.

use serde_json::{Map, Value, json};

use super::StreamDirection;
use super::finalmask_layers::{apply_extras, extras_of, string_field};

/// DNS record types `NewDomain` accepts, with their names: A, CNAME, TXT, AAAA.
pub const XDNS_RECORD_TYPES: &[(i64, &str)] = &[(1, "A"), (5, "CNAME"), (16, "TXT"), (28, "AAAA")];
/// Core default of `domains[].lenLimit` (`0` / absent).
pub const XDNS_DEFAULT_LEN_LIMIT: i64 = 255;
/// Core default of `domains[].labelLimit` (`0` / absent).
pub const XDNS_DEFAULT_LABEL_LIMIT: i64 = 63;
/// `resolvers[].type` values (`xdnsLoader`, case-insensitive).
pub const XDNS_RESOLVER_KINDS: &[&str] = &["udp", "tcp"];

/// One `domains[]` entry — the core's `XDNSDomain`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XdnsDomain {
    /// `name` — the tunnel domain (the server must be authoritative for it).
    pub name: String,
    /// `lenLimit` — maximum query-name length; `None` = key absent (= 255).
    pub len_limit: Option<i64>,
    /// `labelLimit` — maximum label length; `None` = key absent (= 63).
    pub label_limit: Option<i64>,
    /// `types` — DNS record types to use ([`XDNS_RECORD_TYPES`]); empty = key absent.
    pub types: Vec<i64>,
    /// `edns0` — EDNS0 UDP payload size, `0` = off; `None` = key absent.
    pub edns0: Option<i64>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// One `resolvers[]` entry — the core's `XDNSResolver` (`type` + `settings.addr`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XdnsResolver {
    /// `type` — `udp` or `tcp`.
    pub kind: String,
    /// `settings.addr` — resolver `host:port`.
    pub addr: String,
    /// `true` when `settings` is present (it is required by the core).
    pub has_settings: bool,
    /// Unknown keys inside `settings`, preserved verbatim.
    pub settings_extras: Map<String, Value>,
    /// Unknown keys of the entry, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// `finalmask.udp[].settings` for `type = "xdns"` (v26.9.30 schema).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XdnsSettings {
    /// `domains[]`; empty = key absent.
    pub domains: Vec<XdnsDomain>,
    /// `resolvers[]` (client side); empty = key absent.
    pub resolvers: Vec<XdnsResolver>,
    /// `extraPoll` (0–3); `None` = key absent.
    pub extra_poll: Option<i64>,
    /// Unknown keys (including the legacy `domain`), preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_XDNS_KEYS: &[&str] = &["domains", "resolvers", "extraPoll"];
const KNOWN_DOMAIN_KEYS: &[&str] = &["name", "lenLimit", "labelLimit", "types", "edns0"];
const KNOWN_RESOLVER_KEYS: &[&str] = &["type", "settings"];
const KNOWN_RESOLVER_SETTINGS_KEYS: &[&str] = &["addr"];

/// Absent/`null` → `Some(None)`; `None` when present but not an integer.
fn integer_field(value: Option<&Value>) -> Option<Option<i64>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(value) => value.as_i64().map(Some),
    }
}

fn objects(value: Option<&Value>) -> Option<Vec<&Map<String, Value>>> {
    match value {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(Value::as_object).collect(),
        Some(_) => None,
    }
}

fn parse_domain(object: &Map<String, Value>) -> Option<XdnsDomain> {
    let types = match object.get("types") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(Value::as_i64).collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    Some(XdnsDomain {
        name: string_field(object.get("name"))?,
        len_limit: integer_field(object.get("lenLimit"))?,
        label_limit: integer_field(object.get("labelLimit"))?,
        types,
        edns0: integer_field(object.get("edns0"))?,
        extras: extras_of(object, KNOWN_DOMAIN_KEYS),
    })
}

fn parse_resolver(object: &Map<String, Value>) -> Option<XdnsResolver> {
    let (has_settings, addr, settings_extras) = match object.get("settings") {
        None | Some(Value::Null) => (false, String::new(), Map::new()),
        Some(Value::Object(settings)) => (
            true,
            string_field(settings.get("addr"))?,
            extras_of(settings, KNOWN_RESOLVER_SETTINGS_KEYS),
        ),
        Some(_) => return None,
    };
    Some(XdnsResolver {
        kind: string_field(object.get("type"))?,
        addr,
        has_settings,
        settings_extras,
        extras: extras_of(object, KNOWN_RESOLVER_KEYS),
    })
}

/// Parses `settings` as `xdns` (v26.9.30 schema). `None` when `settings` isn't an object, a known
/// key can't be represented losslessly — notably the legacy string `domains` / `resolvers`
/// ([`xdns_has_legacy_fields`]).
pub fn parse_xdns_settings(settings: &Value) -> Option<XdnsSettings> {
    let object = settings.as_object()?;
    Some(XdnsSettings {
        domains: objects(object.get("domains"))?.into_iter().map(parse_domain).collect::<Option<_>>()?,
        resolvers: objects(object.get("resolvers"))?.into_iter().map(parse_resolver).collect::<Option<_>>()?,
        extra_poll: integer_field(object.get("extraPoll"))?,
        extras: extras_of(object, KNOWN_XDNS_KEYS),
    })
}

fn domain_to_value(domain: &XdnsDomain) -> Value {
    let mut object = Map::new();
    object.insert("name".to_owned(), Value::String(domain.name.trim().to_owned()));
    for (key, value) in [("lenLimit", domain.len_limit), ("labelLimit", domain.label_limit)] {
        if let Some(value) = value {
            object.insert(key.to_owned(), Value::from(value));
        }
    }
    if !domain.types.is_empty() {
        object.insert("types".to_owned(), Value::Array(domain.types.iter().copied().map(Value::from).collect()));
    }
    if let Some(edns0) = domain.edns0 {
        object.insert("edns0".to_owned(), Value::from(edns0));
    }
    apply_extras(&mut object, &domain.extras);
    Value::Object(object)
}

fn resolver_to_value(resolver: &XdnsResolver) -> Value {
    let mut object = Map::new();
    object.insert("type".to_owned(), Value::String(resolver.kind.trim().to_owned()));
    let addr = resolver.addr.trim();
    if resolver.has_settings || !addr.is_empty() || !resolver.settings_extras.is_empty() {
        let mut settings = Map::new();
        if !addr.is_empty() {
            settings.insert("addr".to_owned(), Value::String(addr.to_owned()));
        }
        apply_extras(&mut settings, &resolver.settings_extras);
        object.insert("settings".to_owned(), Value::Object(settings));
    }
    apply_extras(&mut object, &resolver.extras);
    Value::Object(object)
}

/// Builds the `settings` `Value` for an `xdns` layer.
pub fn xdns_settings_to_value(draft: &XdnsSettings) -> Value {
    let mut object = Map::new();
    if !draft.domains.is_empty() {
        object.insert("domains".to_owned(), Value::Array(draft.domains.iter().map(domain_to_value).collect()));
    }
    if !draft.resolvers.is_empty() {
        object.insert("resolvers".to_owned(), Value::Array(draft.resolvers.iter().map(resolver_to_value).collect()));
    }
    if let Some(extra_poll) = draft.extra_poll {
        object.insert("extraPoll".to_owned(), Value::from(extra_poll));
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── validation ─────────────────────────────────────────────────────────────

/// Go decodes these fields into `int32`.
fn check_i32(name: &str, value: i64) -> Result<(), String> {
    i32::try_from(value)
        .map(|_| ())
        .map_err(|_| format!("{name} {value} is outside the 32-bit integer range"))
}

/// One domain as `XDNS.Build()` + `NewDomain()` check it: no `..`; `lenLimit` 0–255 and
/// `labelLimit` 0–63 (0 = default); at least one type, each A/CNAME/TXT/AAAA (Go casts the
/// `int32` to `uint16`); `edns0` 0 or 512–4096; the name fits in `lenLimit` with room for at
/// least 17 bytes of payload. Feldjäger also requires a non-empty `name` (the core would tunnel
/// under the DNS root). IDNA conversion is left to the core.
pub fn validate_xdns_domain(domain: &XdnsDomain) -> Result<(), String> {
    let name = domain.name.trim();
    if name.is_empty() {
        return Err("name is required (the tunnel domain, e.g. t.example.com)".to_owned());
    }
    if name.contains("..") {
        return Err(format!("invalid domain \"{name}\" (empty label)"));
    }
    for value in [domain.len_limit, domain.label_limit, domain.edns0].into_iter().flatten().chain(domain.types.iter().copied()) {
        check_i32("value", value)?;
    }
    let len_limit = domain.len_limit.filter(|limit| *limit != 0).unwrap_or(XDNS_DEFAULT_LEN_LIMIT);
    let label_limit = domain.label_limit.filter(|limit| *limit != 0).unwrap_or(XDNS_DEFAULT_LABEL_LIMIT);
    if !(0..=255).contains(&len_limit) {
        return Err(format!("lenLimit must lie within 0–255 (got {len_limit})"));
    }
    if !(0..=63).contains(&label_limit) {
        return Err(format!("labelLimit must lie within 0–63 (got {label_limit})"));
    }
    if domain.types.is_empty() {
        return Err("types: at least one DNS record type is required (A, CNAME, TXT, AAAA)".to_owned());
    }
    if let Some(bad) = domain.types.iter().find(|kind| xdns_record_type_name(**kind).is_none()) {
        return Err(format!("types: unsupported DNS record type {bad} (expected 1 A, 5 CNAME, 16 TXT, 28 AAAA)"));
    }
    let edns0 = i64::from(domain.edns0.unwrap_or(0) as i32 as u16);
    if edns0 != 0 && !(512..=4096).contains(&edns0) {
        return Err(format!("edns0 must be 0 (off) or within 512–4096 (got {edns0})"));
    }
    // `dnsmessage.NewName(domain + ".")`: at most 255 bytes.
    let name_len = name.len() as i64 + 1;
    if name_len > 255 {
        return Err("name is longer than 254 bytes".to_owned());
    }
    if len_limit < name_len + 1 {
        return Err(format!("lenLimit {len_limit} is too small for \"{name}\" (needs at least {})", name_len + 1));
    }
    let capacity = xdns_payload_capacity(name_len, len_limit, label_limit);
    if capacity < 17 {
        return Err(format!(
            "\"{name}\" leaves only {capacity} payload bytes per query with lenLimit {len_limit} / labelLimit \
             {label_limit} (at least 17 needed) — use a shorter name or larger limits"
        ));
    }
    Ok(())
}

/// `NewDomain`'s payload capacity: the labels that fit before the tunnel name, base32-decoded.
fn xdns_payload_capacity(name_len: i64, len_limit: i64, label_limit: i64) -> i64 {
    let room = len_limit - name_len - 1;
    let labels = room / (label_limit + 1);
    let left = room % (label_limit + 1);
    let mut chars = labels * label_limit;
    if left > 1 {
        chars += left - 1;
    }
    // `base32.NoPadding.DecodedLen`.
    chars / 8 * 5 + chars % 8 * 5 / 8
}

/// The name of an accepted record type (after the core's `uint16` cast).
pub fn xdns_record_type_name(kind: i64) -> Option<&'static str> {
    let cast = i64::from(kind as i32 as u16);
    XDNS_RECORD_TYPES.iter().find(|(code, _)| *code == cast).map(|(_, name)| *name)
}

/// Validates an `xdns` layer: every domain ([`validate_xdns_domain`]), every resolver (`type`
/// `udp`/`tcp`, `settings` present, `addr` = `host:port` as `net.ParseDestination` needs it at
/// dial time), `extraPoll` 0–3 (`Build()`), and what the constructors require — `domains` on both
/// sides, `resolvers` on the client side.
pub fn validate_xdns_settings(draft: &XdnsSettings, direction: StreamDirection) -> Result<(), String> {
    if draft.domains.is_empty() {
        return Err("domains: at least one tunnel domain is required".to_owned());
    }
    for (index, domain) in draft.domains.iter().enumerate() {
        validate_xdns_domain(domain).map_err(|error| format!("domains[{index}]: {error}"))?;
    }
    for (index, resolver) in draft.resolvers.iter().enumerate() {
        validate_xdns_resolver(resolver).map_err(|error| format!("resolvers[{index}]: {error}"))?;
    }
    if direction == StreamDirection::Outbound && draft.resolvers.is_empty() {
        return Err("resolvers: the client side needs at least one resolver".to_owned());
    }
    if let Some(extra_poll) = draft.extra_poll
        && !(0..=3).contains(&extra_poll)
    {
        return Err(format!("extraPoll must lie within 0–3 (got {extra_poll})"));
    }
    Ok(())
}

fn validate_xdns_resolver(resolver: &XdnsResolver) -> Result<(), String> {
    let kind = resolver.kind.trim();
    if !XDNS_RESOLVER_KINDS.iter().any(|known| kind.eq_ignore_ascii_case(known)) {
        return Err(format!("type \"{kind}\" must be udp or tcp"));
    }
    let addr = resolver.addr.trim();
    if !resolver.has_settings && addr.is_empty() {
        return Err("settings.addr is required (resolver host:port)".to_owned());
    }
    let port = addr
        .rsplit_once(':')
        .filter(|(host, _)| !host.is_empty() && (!host.contains(':') || (host.starts_with('[') && host.ends_with(']'))))
        .map(|(_, port)| port);
    match port.and_then(|port| port.parse::<u16>().ok()).filter(|port| *port != 0) {
        Some(_) => Ok(()),
        None => Err(format!("settings.addr \"{addr}\" must be host:port (IPv6 in brackets), port 1–65535")),
    }
}

// ─── legacy schema ──────────────────────────────────────────────────────────

/// `true` when `settings` uses the pre-v26.9.30 schema: a `domain` key, or string entries in
/// `domains` / `resolvers`.
pub fn xdns_has_legacy_fields(settings: &Value) -> bool {
    let has_strings = |key: &str| {
        settings
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(Value::is_string))
    };
    settings.get("domain").is_some() || has_strings("domains") || has_strings("resolvers")
}

/// Old `name[:method]` spec (`parseDomainSpec`): the method is after the last `:`; empty / `txt`
/// = TXT, `a` = A, `aaaa` = AAAA.
fn legacy_domain_spec(spec: &str) -> Result<(String, i64), String> {
    let (name, method) = match spec.rsplit_once(':') {
        Some((name, method)) => (name, method),
        None => (spec, ""),
    };
    if name.is_empty() {
        return Err(format!("\"{spec}\": empty domain"));
    }
    let kind = match method.to_lowercase().as_str() {
        "" | "txt" => 16,
        "a" => 1,
        "aaaa" => 28,
        _ => return Err(format!("\"{spec}\": unsupported method \"{method}\" (txt, a, aaaa)")),
    };
    Ok((name.to_owned(), kind))
}

/// Converts pre-v26.9.30 `xdns` settings to the v26.9.30 schema (an explicit user action):
///
/// - `domains: ["name[:method]"]` → `{name, types: [type]}` (no method = TXT, the old default);
/// - `resolvers: ["name[:method]+udp://addr"]` → `{type: "udp", settings: {addr}}`, and the name
///   joins `domains` (the client now needs it there) — merged by name, types united;
/// - a string `domain` (the pre-v26.9.9 single domain) becomes a `domains` entry and is removed.
///
/// Entries already in the new shape and unknown keys are kept. Fails on anything it can't convert
/// without guessing (a non-string `domain`, an unsupported method, a resolver without
/// `+udp://`), leaving the settings untouched.
pub fn migrate_legacy_xdns_settings(settings: &Value) -> Result<Value, String> {
    let mut object = settings.as_object().cloned().ok_or("settings must be a JSON object")?;
    let mut domains: Vec<Value> = Vec::new();
    let add_domain = |domains: &mut Vec<Value>, name: String, kind: i64| {
        let existing = domains.iter_mut().find(|domain| {
            domain.get("name").and_then(Value::as_str).is_some_and(|known| known.eq_ignore_ascii_case(&name))
        });
        match existing {
            Some(domain) => {
                if let Some(types) = domain.get_mut("types").and_then(Value::as_array_mut)
                    && !types.iter().any(|known| known.as_i64() == Some(kind))
                {
                    types.push(Value::from(kind));
                }
            }
            None => domains.push(json!({"name": name, "types": [kind]})),
        }
    };

    if let Some(domain) = object.remove("domain") {
        let Value::String(spec) = domain else {
            return Err("domain is not a string — remove it on the Raw JSON editor".to_owned());
        };
        let (name, kind) = legacy_domain_spec(&spec)?;
        add_domain(&mut domains, name, kind);
    }
    for entry in object.get("domains").and_then(Value::as_array).cloned().unwrap_or_default() {
        match entry {
            Value::String(spec) => {
                let (name, kind) = legacy_domain_spec(&spec).map_err(|error| format!("domains: {error}"))?;
                add_domain(&mut domains, name, kind);
            }
            other => domains.push(other),
        }
    }
    let mut resolvers = Vec::new();
    for entry in object.get("resolvers").and_then(Value::as_array).cloned().unwrap_or_default() {
        match entry {
            Value::String(spec) => {
                let (head, addr) = spec
                    .split_once("+udp://")
                    .filter(|(_, addr)| !addr.is_empty())
                    .ok_or_else(|| format!("resolvers: \"{spec}\" is not NAME[:METHOD]+udp://ADDR"))?;
                let (name, kind) = legacy_domain_spec(head).map_err(|error| format!("resolvers: {error}"))?;
                add_domain(&mut domains, name, kind);
                resolvers.push(json!({"type": "udp", "settings": {"addr": addr}}));
            }
            other => resolvers.push(other),
        }
    }
    for (key, values) in [("domains", domains), ("resolvers", resolvers)] {
        if values.is_empty() {
            object.remove(key);
        } else {
            object.insert(key.to_owned(), Value::Array(values));
        }
    }
    Ok(Value::Object(object))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> XdnsDomain {
        XdnsDomain { name: name.to_owned(), types: vec![16], ..XdnsDomain::default() }
    }

    #[test]
    fn new_schema_round_trips() {
        let settings = json!({
            "domains": [
                {"name": "t.example.com", "lenLimit": 255, "labelLimit": 63, "types": [16, 1], "edns0": 1232, "x": 1},
                {"name": "u.example.com", "types": [28]}
            ],
            "resolvers": [
                {"type": "udp", "settings": {"addr": "1.1.1.1:53", "future": true}},
                {"type": "TCP", "settings": {"addr": "[2606:4700::1111]:53"}, "y": 2}
            ],
            "extraPoll": 2,
            "futureKey": "keep"
        });
        let draft = parse_xdns_settings(&settings).expect("parsed");
        assert_eq!(draft.domains[0].types, vec![16, 1]);
        assert_eq!(draft.resolvers[1].addr, "[2606:4700::1111]:53");
        assert_eq!(xdns_settings_to_value(&draft), settings);
        assert_eq!(validate_xdns_settings(&draft, StreamDirection::Outbound), Ok(()));
    }

    #[test]
    fn legacy_strings_are_not_owned_by_the_typed_form() {
        for legacy in [
            json!({"domains": ["t.example.com:txt"]}),
            json!({"resolvers": ["t.example.com+udp://1.1.1.1:53"]}),
            json!({"domains": [{"name": "t.example.com", "types": "16"}]}),
        ] {
            assert!(parse_xdns_settings(&legacy).is_none(), "{legacy}");
        }
        // A legacy `domain` alone parses (kept in extras) but is still flagged.
        let settings = json!({"domain": "t.example.com", "domains": [{"name": "t.example.com", "types": [16]}]});
        let draft = parse_xdns_settings(&settings).expect("parsed");
        assert_eq!(xdns_settings_to_value(&draft), settings);
        assert!(xdns_has_legacy_fields(&settings));
        assert!(!xdns_has_legacy_fields(&json!({"domains": [{"name": "a"}], "resolvers": []})));
    }

    #[test]
    fn domain_validation_mirrors_new_domain() {
        assert_eq!(validate_xdns_domain(&domain("t.example.com")), Ok(()));
        let with = |edit: fn(&mut XdnsDomain)| {
            let mut entry = domain("t.example.com");
            edit(&mut entry);
            validate_xdns_domain(&entry)
        };
        assert_eq!(with(|d| d.types = vec![1, 5, 16, 28]), Ok(()));
        assert_eq!(with(|d| d.edns0 = Some(512)), Ok(()));
        assert_eq!(with(|d| d.len_limit = Some(0)), Ok(()));
        // The core casts `int32` to `uint16`: 65552 is TXT.
        assert_eq!(with(|d| d.types = vec![65552]), Ok(()));
        for (edit, needle) in [
            (with(|d| d.name = String::new()), "name is required"),
            (with(|d| d.name = "a..b".to_owned()), "invalid domain"),
            (with(|d| d.types = Vec::new()), "at least one"),
            (with(|d| d.types = vec![15]), "unsupported DNS record type 15"),
            (with(|d| d.edns0 = Some(100)), "edns0"),
            (with(|d| d.edns0 = Some(5000)), "edns0"),
            (with(|d| d.len_limit = Some(256)), "lenLimit must lie"),
            (with(|d| d.label_limit = Some(64)), "labelLimit"),
            (with(|d| d.len_limit = Some(10)), "too small"),
            // "t.example.com." at lenLimit 40: 25 bytes of room → 24 base32 chars → 15 bytes < 17.
            (with(|d| d.len_limit = Some(40)), "payload bytes"),
            (with(|d| d.types = vec![i64::from(i32::MAX) + 1]), "32-bit"),
        ] {
            let error = edit.expect_err(needle);
            assert!(error.contains(needle), "{needle}: {error}");
        }
    }

    #[test]
    fn capacity_matches_the_core_formula() {
        // name "t.example.com." = 14 bytes: room 240 → 3 labels of 63 (+3 dots) and 48 left → 47
        // chars; 236 chars of base32 → 147 bytes.
        assert_eq!(xdns_payload_capacity(14, 255, 63), 147);
        assert_eq!(xdns_payload_capacity(14, 40, 63), 15);
    }

    #[test]
    fn settings_validation_by_direction() {
        let base = XdnsSettings {
            domains: vec![domain("t.example.com")],
            ..XdnsSettings::default()
        };
        // The server needs no resolvers; the client does.
        assert_eq!(validate_xdns_settings(&base, StreamDirection::Inbound), Ok(()));
        assert!(validate_xdns_settings(&base, StreamDirection::Outbound).unwrap_err().contains("resolvers"));
        assert!(validate_xdns_settings(&XdnsSettings::default(), StreamDirection::Inbound).unwrap_err().contains("domains"));
        let resolver = |kind: &str, addr: &str| XdnsResolver {
            kind: kind.to_owned(),
            addr: addr.to_owned(),
            has_settings: true,
            ..XdnsResolver::default()
        };
        for (entry, error) in [
            (resolver("udp", "1.1.1.1:53"), None),
            (resolver("TCP", "dns.example.com:853"), None),
            (resolver("udp", "[::1]:53"), None),
            (resolver("doh", "1.1.1.1:53"), Some("udp or tcp")),
            (resolver("udp", "1.1.1.1"), Some("host:port")),
            (resolver("udp", "::1:53"), Some("host:port")),
            (resolver("udp", "1.1.1.1:0"), Some("host:port")),
            (XdnsResolver { kind: "udp".to_owned(), ..XdnsResolver::default() }, Some("settings.addr is required")),
        ] {
            let draft = XdnsSettings { resolvers: vec![entry.clone()], ..base.clone() };
            match (error, validate_xdns_settings(&draft, StreamDirection::Outbound)) {
                (None, Ok(())) => {}
                (Some(needle), Err(message)) => assert!(message.contains(needle), "{entry:?}: {message}"),
                (expected, got) => panic!("{entry:?}: expected {expected:?}, got {got:?}"),
            }
        }
        let draft = XdnsSettings { extra_poll: Some(4), ..base };
        assert!(validate_xdns_settings(&draft, StreamDirection::Inbound).unwrap_err().contains("extraPoll"));
    }

    #[test]
    fn legacy_settings_migrate_to_the_new_schema() {
        let legacy = json!({
            "domain": "old.example.com",
            "domains": ["t.example.com:txt", "u.example.com:AAAA", {"name": "v.example.com", "types": [1]}],
            "resolvers": ["t.example.com:a+udp://1.1.1.1:53", "w.example.com+udp://8.8.8.8:53"],
            "futureKey": 1
        });
        let migrated = migrate_legacy_xdns_settings(&legacy).expect("migrates");
        assert_eq!(
            migrated,
            json!({
                "domains": [
                    {"name": "old.example.com", "types": [16]},
                    {"name": "t.example.com", "types": [16, 1]},
                    {"name": "u.example.com", "types": [28]},
                    {"name": "v.example.com", "types": [1]},
                    {"name": "w.example.com", "types": [16]}
                ],
                "resolvers": [
                    {"type": "udp", "settings": {"addr": "1.1.1.1:53"}},
                    {"type": "udp", "settings": {"addr": "8.8.8.8:53"}}
                ],
                "futureKey": 1
            })
        );
        assert!(!xdns_has_legacy_fields(&migrated));
        assert!(parse_xdns_settings(&migrated).is_some());
        // Idempotent on the new schema.
        assert_eq!(migrate_legacy_xdns_settings(&migrated), Ok(migrated));

        for (bad, needle) in [
            (json!({"domain": {"x": 1}}), "not a string"),
            (json!({"domains": ["t.example.com:mx"]}), "unsupported method"),
            (json!({"resolvers": ["t.example.com 1.1.1.1"]}), "+udp://"),
            (json!({"domains": [":txt"]}), "empty domain"),
        ] {
            let error = migrate_legacy_xdns_settings(&bad).expect_err(&bad.to_string());
            assert!(error.contains(needle), "{bad}: {error}");
        }
    }
}
