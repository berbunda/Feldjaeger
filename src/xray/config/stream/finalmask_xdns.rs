//! `finalmask.udp[].settings` for `type = "xdns"` (Roadmap §2.6 stages 1.3 and 1.6) — DNS
//! tunnelling of UDP payloads, schema of XTLS/Xray-core#7090 (v26.10.10):
//! `infra/conf/transport_finalmask.go` (`XDNS`, `XDNSDomain`, `XDNSResolver`) and
//! `transport/internet/finalmask/xdns`.
//!
//! ```jsonc
//! { "domains":   [{ "names": ["t.example.com"], "lenLimit": 255, "labelLimit": 63, "types": [16], "edns0": 1232 }],
//!   "resolvers": [{ "addrs": ["udp://1.1.1.1:53", "tcp://8.8.8.8"] }],   // client only
//!   "extraPoll": 0 }
//! ```
//!
//! Both sides need `domains`; only the client (outbound) uses `resolvers` — the server ignores
//! them. `Build()` expands every `names[]` entry into its own domain (limits, types and `edns0`
//! shared) and checks it with all four record types; the `types` actually set, and "at least one
//! domain / resolver", are checked only by the mask constructors (`NewServer` / `NewClient`), so
//! `xray run -test` (which builds but never listens or dials) does not catch them. Empty `types`
//! means TXT on the client and all four types on the server.
//!
//! A resolver address is `[udp|tcp://]host[:port]`: no scheme means `udp`, no port means 53.
//! `Build()` runs it through `url.Parse`, so a bare IPv6 address is split at its last colon
//! (`2606:4700::1111` → host `2606:4700:`, port `1111`) and still "builds" — Feldjäger requires
//! brackets.
//!
//! Two older schemas exist and are not representable by [`XdnsSettings`] (the GUI keeps them on
//! the raw-JSON editor, [`migrate_legacy_xdns_settings`] converts them on request):
//!
//! - v26.9.9 – v26.9.29: strings — `domains: ["t.example.com:txt"]` (server) and
//!   `resolvers: ["t.example.com:txt+udp://1.1.1.1:53"]` (client); before that a single `domain`;
//! - v26.9.30 (XTLS/Xray-core#6718): objects with one `name` per domain and
//!   `{type, settings: {addr}}` per resolver. v26.10.10 ignores both keys, so such a config still
//!   passes `xray run -test` but the server stops with "empty domains" (checked with
//!   `xray.exe` 26.10.10).

use serde_json::{Map, Value, json};

use super::StreamDirection;
use super::finalmask_layers::{apply_extras, extras_of, string_array_field};

/// DNS record types `NewDomain` accepts, with their names: A, CNAME, TXT, AAAA.
pub const XDNS_RECORD_TYPES: &[(i64, &str)] = &[(1, "A"), (5, "CNAME"), (16, "TXT"), (28, "AAAA")];
/// Core default of `domains[].lenLimit` (`0` / absent).
pub const XDNS_DEFAULT_LEN_LIMIT: i64 = 255;
/// Core default of `domains[].labelLimit` (`0` / absent).
pub const XDNS_DEFAULT_LABEL_LIMIT: i64 = 63;
/// Schemes of a `resolvers[].addrs[]` entry (`url.Parse` lowercases them); none = `udp`.
pub const XDNS_RESOLVER_KINDS: &[&str] = &["udp", "tcp"];
/// Port of a `resolvers[].addrs[]` entry without one.
pub const XDNS_DEFAULT_RESOLVER_PORT: u16 = 53;

/// What empty `types` means on each side: TXT for the client (`NewClient`), all four for the
/// server (`NewServer`).
pub fn xdns_default_types(direction: StreamDirection) -> &'static [i64] {
    match direction {
        StreamDirection::Outbound => &[16],
        StreamDirection::Inbound => &[1, 5, 16, 28],
    }
}

/// One `domains[]` entry — the core's `XDNSDomain`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XdnsDomain {
    /// `names` — tunnel domains sharing the settings below (the server must be authoritative for
    /// each).
    pub names: Vec<String>,
    /// `lenLimit` — maximum query-name length; `None` = key absent (= 255).
    pub len_limit: Option<i64>,
    /// `labelLimit` — maximum label length; `None` = key absent (= 63).
    pub label_limit: Option<i64>,
    /// `types` — DNS record types to use ([`XDNS_RECORD_TYPES`]); empty = key absent
    /// ([`xdns_default_types`]).
    pub types: Vec<i64>,
    /// `edns0` — EDNS0 UDP payload size, `0` = off; `None` = key absent.
    pub edns0: Option<i64>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// One `resolvers[]` entry — the core's `XDNSResolver`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XdnsResolver {
    /// `addrs` — `[udp|tcp://]host[:port]` resolver addresses.
    pub addrs: Vec<String>,
    /// Unknown keys of the entry, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// `finalmask.udp[].settings` for `type = "xdns"` (v26.10.10 schema).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XdnsSettings {
    /// `domains[]`; empty = key absent.
    pub domains: Vec<XdnsDomain>,
    /// `resolvers[]` (client side); empty = key absent.
    pub resolvers: Vec<XdnsResolver>,
    /// `extraPoll` (0–3); `None` = key absent.
    pub extra_poll: Option<i64>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_XDNS_KEYS: &[&str] = &["domains", "resolvers", "extraPoll"];
const KNOWN_DOMAIN_KEYS: &[&str] = &["names", "lenLimit", "labelLimit", "types", "edns0"];
const KNOWN_RESOLVER_KEYS: &[&str] = &["addrs"];
/// Keys of the v26.9.30 schema that v26.10.10 no longer reads.
const V26_9_30_DOMAIN_KEYS: &[&str] = &["name"];
const V26_9_30_RESOLVER_KEYS: &[&str] = &["type", "settings"];

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

fn has_any_key(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter().any(|key| object.contains_key(*key))
}

fn parse_domain(object: &Map<String, Value>) -> Option<XdnsDomain> {
    if has_any_key(object, V26_9_30_DOMAIN_KEYS) {
        return None;
    }
    let types = match object.get("types") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(Value::as_i64).collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    Some(XdnsDomain {
        names: string_array_field(object.get("names"))?,
        len_limit: integer_field(object.get("lenLimit"))?,
        label_limit: integer_field(object.get("labelLimit"))?,
        types,
        edns0: integer_field(object.get("edns0"))?,
        extras: extras_of(object, KNOWN_DOMAIN_KEYS),
    })
}

fn parse_resolver(object: &Map<String, Value>) -> Option<XdnsResolver> {
    if has_any_key(object, V26_9_30_RESOLVER_KEYS) {
        return None;
    }
    Some(XdnsResolver {
        addrs: string_array_field(object.get("addrs"))?,
        extras: extras_of(object, KNOWN_RESOLVER_KEYS),
    })
}

/// Parses `settings` as `xdns` (v26.10.10 schema). `None` when `settings` isn't an object or a
/// known key can't be represented losslessly — notably the older schemas
/// ([`xdns_has_legacy_fields`]).
pub fn parse_xdns_settings(settings: &Value) -> Option<XdnsSettings> {
    let object = settings.as_object()?;
    if object.contains_key("domain") {
        return None;
    }
    Some(XdnsSettings {
        domains: objects(object.get("domains"))?.into_iter().map(parse_domain).collect::<Option<_>>()?,
        resolvers: objects(object.get("resolvers"))?.into_iter().map(parse_resolver).collect::<Option<_>>()?,
        extra_poll: integer_field(object.get("extraPoll"))?,
        extras: extras_of(object, KNOWN_XDNS_KEYS),
    })
}

fn strings_to_value(items: &[String]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .map(|item| Value::String(item.to_owned()))
            .collect(),
    )
}

fn domain_to_value(domain: &XdnsDomain) -> Value {
    let mut object = Map::new();
    object.insert("names".to_owned(), strings_to_value(&domain.names));
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
    object.insert("addrs".to_owned(), strings_to_value(&resolver.addrs));
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

/// One domain as `XDNS.Build()` + `NewDomain()` check it: at least one name, each checked by
/// [`validate_xdns_name`]; `lenLimit` 0–255 and `labelLimit` 0–63 (0 = default); each type
/// A/CNAME/TXT/AAAA (Go casts the `int32` to `uint16`; empty = [`xdns_default_types`]); `edns0`
/// 0 or 512–4096. IDNA conversion is left to the core.
pub fn validate_xdns_domain(domain: &XdnsDomain) -> Result<(), String> {
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
    if let Some(bad) = domain.types.iter().find(|kind| xdns_record_type_name(**kind).is_none()) {
        return Err(format!("types: unsupported DNS record type {bad} (expected 1 A, 5 CNAME, 16 TXT, 28 AAAA)"));
    }
    let edns0 = i64::from(domain.edns0.unwrap_or(0) as i32 as u16);
    if edns0 != 0 && !(512..=4096).contains(&edns0) {
        return Err(format!("edns0 must be 0 (off) or within 512–4096 (got {edns0})"));
    }
    let names: Vec<&str> = domain.names.iter().map(|name| name.trim()).filter(|name| !name.is_empty()).collect();
    if names.is_empty() {
        return Err("names: at least one tunnel domain is required (e.g. t.example.com)".to_owned());
    }
    for (index, name) in names.into_iter().enumerate() {
        validate_xdns_name(name, len_limit, label_limit).map_err(|error| format!("names[{index}]: {error}"))?;
    }
    Ok(())
}

/// One tunnel name with the effective limits, as `NewDomain()` checks it: no `..`; the name fits
/// in `lenLimit` with room for at least 17 bytes of payload. Feldjäger also requires a non-empty
/// name (the core would tunnel under the DNS root).
fn validate_xdns_name(name: &str, len_limit: i64, label_limit: i64) -> Result<(), String> {
    if name.is_empty() {
        return Err("the tunnel domain is empty".to_owned());
    }
    if name.contains("..") {
        return Err(format!("invalid domain \"{name}\" (empty label)"));
    }
    // `dnsmessage.NewName(domain + ".")`: at most 255 bytes.
    let name_len = name.len() as i64 + 1;
    if name_len > 255 {
        return Err(format!("\"{name}\" is longer than 254 bytes"));
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

/// Validates an `xdns` layer: every domain ([`validate_xdns_domain`]), every resolver address
/// ([`validate_xdns_resolver_addr`]), `extraPoll` 0–3 (`Build()`), and what the constructors
/// require — at least one domain name on both sides, at least one resolver address on the client
/// side.
pub fn validate_xdns_settings(draft: &XdnsSettings, direction: StreamDirection) -> Result<(), String> {
    if draft.domains.is_empty() {
        return Err("domains: at least one tunnel domain is required".to_owned());
    }
    for (index, domain) in draft.domains.iter().enumerate() {
        validate_xdns_domain(domain).map_err(|error| format!("domains[{index}]: {error}"))?;
    }
    let mut addr_count = 0;
    for (index, resolver) in draft.resolvers.iter().enumerate() {
        for (addr_index, addr) in resolver.addrs.iter().map(|addr| addr.trim()).filter(|addr| !addr.is_empty()).enumerate() {
            validate_xdns_resolver_addr(addr).map_err(|error| format!("resolvers[{index}].addrs[{addr_index}]: {error}"))?;
            addr_count += 1;
        }
    }
    if direction == StreamDirection::Outbound && addr_count == 0 {
        return Err("resolvers: the client side needs at least one resolver address".to_owned());
    }
    if let Some(extra_poll) = draft.extra_poll
        && !(0..=3).contains(&extra_poll)
    {
        return Err(format!("extraPoll must lie within 0–3 (got {extra_poll})"));
    }
    Ok(())
}

/// One `addrs[]` entry, `[udp|tcp://]host[:port]`, as `XDNS.Build()` reads it (`url.Parse`,
/// default scheme `udp`, default port 53) plus what makes the dial work: a host, a port 1–65535,
/// IPv6 in brackets. A path, query or user part — which the core would silently drop — is refused.
pub fn validate_xdns_resolver_addr(addr: &str) -> Result<(), String> {
    let format = "expected [udp|tcp://]host[:port], IPv6 in brackets";
    let rest = match addr.split_once("://") {
        Some((scheme, rest)) => {
            if !XDNS_RESOLVER_KINDS.iter().any(|known| scheme.eq_ignore_ascii_case(known)) {
                return Err(format!("\"{addr}\": scheme \"{scheme}\" must be udp or tcp"));
            }
            rest
        }
        None => addr,
    };
    if rest.contains(['/', '?', '#', '@']) || rest.chars().any(char::is_whitespace) {
        return Err(format!("\"{addr}\": {format}"));
    }
    let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or_else(|| format!("\"{addr}\": unclosed '['"))?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(format!("\"{addr}\": \"{host}\" in brackets is not an IPv6 address"));
        }
        match after {
            "" => (host, None),
            _ => match after.strip_prefix(':') {
                Some(port) => (host, Some(port)),
                None => return Err(format!("\"{addr}\": {format}")),
            },
        }
    } else {
        match rest.rsplit_once(':') {
            Some((host, _)) if host.contains(':') => {
                return Err(format!("\"{addr}\": an IPv6 address needs brackets, e.g. [2606:4700::1111]:53"));
            }
            Some((host, port)) => (host, Some(port)),
            None => (rest, None),
        }
    };
    if host.is_empty() {
        return Err(format!("\"{addr}\": the host is empty"));
    }
    match port.filter(|port| !port.is_empty()) {
        None => Ok(()),
        Some(port) => match port.parse::<u16>() {
            Ok(port) if port != 0 => Ok(()),
            _ => Err(format!("\"{addr}\": port \"{port}\" must be 1–65535 (empty = {XDNS_DEFAULT_RESOLVER_PORT})")),
        },
    }
}

// ─── older schemas ──────────────────────────────────────────────────────────

fn array_items<'a>(settings: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    settings.get(key).and_then(Value::as_array).into_iter().flatten()
}

/// `true` when `settings` uses the pre-v26.9.30 string schema: a `domain` key, or string entries
/// in `domains` / `resolvers`.
pub fn xdns_has_string_schema(settings: &Value) -> bool {
    settings.get("domain").is_some()
        || array_items(settings, "domains").any(Value::is_string)
        || array_items(settings, "resolvers").any(Value::is_string)
}

/// `true` when `settings` has v26.9.30 objects: a domain with `name`, or a resolver with `type` /
/// `settings` — keys Xray-core v26.10.10 no longer reads.
pub fn xdns_has_v26_9_30_objects(settings: &Value) -> bool {
    let with = |key: &str, keys: &[&str]| {
        array_items(settings, key).filter_map(Value::as_object).any(|object| has_any_key(object, keys))
    };
    with("domains", V26_9_30_DOMAIN_KEYS) || with("resolvers", V26_9_30_RESOLVER_KEYS)
}

/// `true` when `settings` uses the v26.10.10 keys (`domains[].names`, `resolvers[].addrs`).
pub fn xdns_uses_names_addrs(settings: &Value) -> bool {
    let with = |key: &str, field: &str| {
        array_items(settings, key).filter_map(Value::as_object).any(|object| object.contains_key(field))
    };
    with("domains", "names") || with("resolvers", "addrs")
}

/// `true` when `settings` is (partly) in one of the older schemas — string or v26.9.30.
pub fn xdns_has_legacy_fields(settings: &Value) -> bool {
    xdns_has_string_schema(settings) || xdns_has_v26_9_30_objects(settings)
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

/// Step 1 of the migration: the string schema → v26.9.30 objects.
///
/// - `domains: ["name[:method]"]` → `{name, types: [type]}` (no method = TXT, the old default);
/// - `resolvers: ["name[:method]+udp://addr"]` → `{type: "udp", settings: {addr}}`, and the name
///   joins `domains` (the client now needs it there) — merged by name, types united;
/// - a string `domain` (the pre-v26.9.9 single domain) becomes a `domains` entry and is removed.
fn migrate_string_schema(object: &mut Map<String, Value>) -> Result<(), String> {
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
    Ok(())
}

/// Step 2 of the migration: v26.9.30 objects → v26.10.10. A domain's `name` joins its `names`
/// (one domain object per name — the limits may differ, so nothing is merged); a resolver
/// `{type, settings: {addr}}` becomes `{addrs: ["type://addr"]}`, keeping its other keys.
fn migrate_v26_9_30_objects(object: &mut Map<String, Value>) -> Result<(), String> {
    if let Some(domains) = object.get_mut("domains").and_then(Value::as_array_mut) {
        for (index, domain) in domains.iter_mut().enumerate() {
            let Some(domain) = domain.as_object_mut() else { continue };
            let Some(name) = domain.remove("name") else { continue };
            let name = match name {
                Value::String(name) => name.trim().to_owned(),
                Value::Null => String::new(),
                _ => return Err(format!("domains[{index}].name is not a string")),
            };
            let mut names = match domain.remove("names") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(names)) => names,
                Some(_) => return Err(format!("domains[{index}].names is not a list")),
            };
            if !name.is_empty() && !names.iter().any(|known| known.as_str() == Some(name.as_str())) {
                names.insert(0, Value::String(name));
            }
            domain.insert("names".to_owned(), Value::Array(names));
        }
    }
    if let Some(resolvers) = object.get_mut("resolvers").and_then(Value::as_array_mut) {
        for (index, resolver) in resolvers.iter_mut().enumerate() {
            let Some(resolver) = resolver.as_object_mut() else { continue };
            if !has_any_key(resolver, V26_9_30_RESOLVER_KEYS) {
                continue;
            }
            let kind = match resolver.remove("type") {
                Some(Value::String(kind)) if XDNS_RESOLVER_KINDS.iter().any(|known| kind.trim().eq_ignore_ascii_case(known)) => {
                    kind.trim().to_ascii_lowercase()
                }
                Some(Value::String(kind)) => return Err(format!("resolvers[{index}].type \"{kind}\" is not udp or tcp")),
                _ => return Err(format!("resolvers[{index}].type is missing")),
            };
            let addr = match resolver.remove("settings") {
                Some(Value::Object(settings)) => {
                    if let Some(key) = settings.keys().find(|key| key.as_str() != "addr") {
                        return Err(format!("resolvers[{index}].settings.{key} has no place in the new schema"));
                    }
                    match settings.get("addr") {
                        Some(Value::String(addr)) if !addr.trim().is_empty() => addr.trim().to_owned(),
                        _ => return Err(format!("resolvers[{index}].settings.addr is missing")),
                    }
                }
                _ => return Err(format!("resolvers[{index}].settings is missing")),
            };
            let mut addrs = match resolver.remove("addrs") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(addrs)) => addrs,
                Some(_) => return Err(format!("resolvers[{index}].addrs is not a list")),
            };
            addrs.insert(0, Value::String(format!("{kind}://{addr}")));
            resolver.insert("addrs".to_owned(), Value::Array(addrs));
        }
    }
    Ok(())
}

/// Converts `xdns` settings in either older schema to the v26.10.10 schema (an explicit user
/// action): string schema → v26.9.30 objects → v26.10.10 (`names[]` / `addrs[]`). Entries already
/// in the new shape and unknown keys are kept; the result is a fixed point. Fails on anything it
/// can't convert without guessing (a non-string `domain`, an unsupported method, a resolver
/// without `+udp://` or `type`, extra keys in a resolver's `settings`), leaving the settings
/// untouched.
pub fn migrate_legacy_xdns_settings(settings: &Value) -> Result<Value, String> {
    let mut object = settings.as_object().cloned().ok_or("settings must be a JSON object")?;
    migrate_string_schema(&mut object)?;
    migrate_v26_9_30_objects(&mut object)?;
    Ok(Value::Object(object))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> XdnsDomain {
        XdnsDomain { names: vec![name.to_owned()], types: vec![16], ..XdnsDomain::default() }
    }

    fn resolver(addr: &str) -> XdnsResolver {
        XdnsResolver { addrs: vec![addr.to_owned()], ..XdnsResolver::default() }
    }

    #[test]
    fn new_schema_round_trips() {
        let settings = json!({
            "domains": [
                {"names": ["t.example.com", "u.example.com"], "lenLimit": 255, "labelLimit": 63, "types": [16, 1], "edns0": 1232, "x": 1},
                {"names": ["v.example.com"]}
            ],
            "resolvers": [
                {"addrs": ["udp://1.1.1.1:53", "8.8.8.8"], "future": true},
                {"addrs": ["TCP://[2606:4700::1111]"]}
            ],
            "extraPoll": 2,
            "futureKey": "keep"
        });
        let draft = parse_xdns_settings(&settings).expect("parsed");
        assert_eq!(draft.domains[0].names, vec!["t.example.com", "u.example.com"]);
        assert!(draft.domains[1].types.is_empty());
        assert_eq!(draft.resolvers[1].addrs, vec!["TCP://[2606:4700::1111]"]);
        assert_eq!(xdns_settings_to_value(&draft), settings);
        assert_eq!(validate_xdns_settings(&draft, StreamDirection::Outbound), Ok(()));
    }

    #[test]
    fn older_schemas_are_not_owned_by_the_typed_form() {
        for legacy in [
            json!({"domains": ["t.example.com:txt"]}),
            json!({"resolvers": ["t.example.com+udp://1.1.1.1:53"]}),
            json!({"domain": "t.example.com", "domains": [{"names": ["t.example.com"]}]}),
            json!({"domains": [{"name": "t.example.com", "types": [16]}]}),
            json!({"domains": [{"names": ["t.example.com"]}], "resolvers": [{"type": "udp", "settings": {"addr": "1.1.1.1:53"}}]}),
            json!({"domains": [{"names": ["t.example.com"], "types": "16"}]}),
            json!({"domains": [{"names": "t.example.com"}]}),
        ] {
            assert!(parse_xdns_settings(&legacy).is_none(), "{legacy}");
        }
        assert!(xdns_has_string_schema(&json!({"domain": "t.example.com"})));
        assert!(xdns_has_v26_9_30_objects(&json!({"resolvers": [{"settings": {"addr": "1.1.1.1"}}]})));
        assert!(!xdns_has_legacy_fields(&json!({"domains": [{"names": ["a"]}], "resolvers": []})));
        assert!(xdns_uses_names_addrs(&json!({"resolvers": [{"addrs": []}]})));
        assert!(!xdns_uses_names_addrs(&json!({"domains": [{"name": "a"}]})));
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
        // v26.10.10: empty types = the side's default.
        assert_eq!(with(|d| d.types = Vec::new()), Ok(()));
        assert_eq!(with(|d| d.edns0 = Some(512)), Ok(()));
        assert_eq!(with(|d| d.len_limit = Some(0)), Ok(()));
        assert_eq!(with(|d| d.names.push("u.example.com".to_owned())), Ok(()));
        // The core casts `int32` to `uint16`: 65552 is TXT.
        assert_eq!(with(|d| d.types = vec![65552]), Ok(()));
        for (edit, needle) in [
            (with(|d| d.names = Vec::new()), "names: at least one"),
            (with(|d| d.names = vec!["  ".to_owned()]), "names: at least one"),
            (with(|d| d.names.push("a..b".to_owned())), "names[1]: invalid domain"),
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
        // chars; 236 chars of base32 → 147 bytes (`xray run -test` logs "t.example.com. 147").
        assert_eq!(xdns_payload_capacity(14, 255, 63), 147);
        assert_eq!(xdns_payload_capacity(14, 40, 63), 15);
    }

    #[test]
    fn resolver_addresses_follow_build() {
        for good in ["1.1.1.1", "1.1.1.1:53", "udp://1.1.1.1", "TCP://dns.example.com:853", "[::1]", "udp://[2606:4700::1111]:53", "8.8.8.8:"] {
            assert_eq!(validate_xdns_resolver_addr(good), Ok(()), "{good}");
        }
        for (bad, needle) in [
            ("doh://1.1.1.1", "must be udp or tcp"),
            ("2606:4700::1111", "needs brackets"),
            ("udp://::1:53", "needs brackets"),
            ("[1.1.1.1]:53", "not an IPv6 address"),
            ("[::1", "unclosed"),
            ("[::1]53", "expected"),
            ("1.1.1.1:0", "port \"0\""),
            ("1.1.1.1:70000", "port \"70000\""),
            ("udp://:53", "host is empty"),
            ("udp://1.1.1.1/dns-query", "expected"),
            ("1.1.1.1 53", "expected"),
        ] {
            let error = validate_xdns_resolver_addr(bad).expect_err(bad);
            assert!(error.contains(needle), "{bad}: {error}");
        }
    }

    #[test]
    fn settings_validation_by_direction() {
        let base = XdnsSettings { domains: vec![domain("t.example.com")], ..XdnsSettings::default() };
        // The server needs no resolvers; the client does.
        assert_eq!(validate_xdns_settings(&base, StreamDirection::Inbound), Ok(()));
        assert!(validate_xdns_settings(&base, StreamDirection::Outbound).unwrap_err().contains("resolvers"));
        // A resolver object without addresses does not count.
        let empty = XdnsSettings { resolvers: vec![XdnsResolver::default()], ..base.clone() };
        assert!(validate_xdns_settings(&empty, StreamDirection::Outbound).unwrap_err().contains("resolvers"));
        assert!(validate_xdns_settings(&XdnsSettings::default(), StreamDirection::Inbound).unwrap_err().contains("domains"));
        let bad = XdnsSettings { resolvers: vec![resolver("1.1.1.1"), resolver("doh://x")], ..base.clone() };
        let error = validate_xdns_settings(&bad, StreamDirection::Outbound).unwrap_err();
        assert!(error.starts_with("resolvers[1].addrs[0]:"), "{error}");
        let draft = XdnsSettings { extra_poll: Some(4), ..base };
        assert!(validate_xdns_settings(&draft, StreamDirection::Inbound).unwrap_err().contains("extraPoll"));
    }

    #[test]
    fn default_types_depend_on_the_side() {
        assert_eq!(xdns_default_types(StreamDirection::Outbound), &[16]);
        assert_eq!(xdns_default_types(StreamDirection::Inbound), &[1, 5, 16, 28]);
    }

    #[test]
    fn string_schema_migrates_to_the_new_schema() {
        let legacy = json!({
            "domain": "old.example.com",
            "domains": ["t.example.com:txt", "u.example.com:AAAA", {"names": ["v.example.com"], "types": [1]}],
            "resolvers": ["t.example.com:a+udp://1.1.1.1:53", "w.example.com+udp://8.8.8.8:53"],
            "futureKey": 1
        });
        let migrated = migrate_legacy_xdns_settings(&legacy).expect("migrates");
        assert_eq!(
            migrated,
            json!({
                "domains": [
                    {"names": ["old.example.com"], "types": [16]},
                    {"names": ["t.example.com"], "types": [16, 1]},
                    {"names": ["u.example.com"], "types": [28]},
                    {"names": ["v.example.com"], "types": [1]},
                    {"names": ["w.example.com"], "types": [16]}
                ],
                "resolvers": [
                    {"addrs": ["udp://1.1.1.1:53"]},
                    {"addrs": ["udp://8.8.8.8:53"]}
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

    #[test]
    fn v26_9_30_objects_migrate_to_the_new_schema() {
        let legacy = json!({
            "domains": [
                {"name": "t.example.com", "lenLimit": 200, "types": [16, 28], "x": 1},
                {"name": "u.example.com", "types": [1]}
            ],
            "resolvers": [
                {"type": "udp", "settings": {"addr": "1.1.1.1:53"}},
                {"type": "TCP", "settings": {"addr": "[2606:4700::1111]:53"}, "y": 2}
            ],
            "extraPoll": 1
        });
        let migrated = migrate_legacy_xdns_settings(&legacy).expect("migrates");
        assert_eq!(
            migrated,
            json!({
                "domains": [
                    {"names": ["t.example.com"], "lenLimit": 200, "types": [16, 28], "x": 1},
                    {"names": ["u.example.com"], "types": [1]}
                ],
                "resolvers": [
                    {"addrs": ["udp://1.1.1.1:53"]},
                    {"addrs": ["tcp://[2606:4700::1111]:53"], "y": 2}
                ],
                "extraPoll": 1
            })
        );
        let draft = parse_xdns_settings(&migrated).expect("parsed");
        assert_eq!(validate_xdns_settings(&draft, StreamDirection::Outbound), Ok(()));
        assert_eq!(migrate_legacy_xdns_settings(&migrated), Ok(migrated));

        for (bad, needle) in [
            (json!({"resolvers": [{"type": "doh", "settings": {"addr": "1.1.1.1"}}]}), "not udp or tcp"),
            (json!({"resolvers": [{"settings": {"addr": "1.1.1.1"}}]}), "type is missing"),
            (json!({"resolvers": [{"type": "udp"}]}), "settings is missing"),
            (json!({"resolvers": [{"type": "udp", "settings": {"addr": "1.1.1.1", "z": 1}}]}), "settings.z"),
            (json!({"domains": [{"name": 5}]}), "name is not a string"),
        ] {
            let error = migrate_legacy_xdns_settings(&bad).expect_err(&bad.to_string());
            assert!(error.contains(needle), "{bad}: {error}");
        }
    }
}
