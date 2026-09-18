//! Typed editors for select `finalmask.tcp[]` / `finalmask.udp[]` layer `settings` shapes
//! (Roadmap follow-up to `finalmask.rs`, Xray-core v26.9.9 `infra/conf/transport_finalmask.go`).
//!
//! [`super::finalmask`] models the layer *chain* (ordered `{type, settings}` entries) with
//! `settings` left as opaque JSON by design — the right default for FinalMask's genuine
//! packet-scripting DSL layer types (`header-custom`, `mkcp-legacy`), per `docs/rules.md`'s
//! "rare/advanced fields may be displayed through generic JSON" allowance.
//!
//! This module promotes the layer types with a small, stable, documented schema to typed
//! structs + parse/`*_to_value` pairs, so the GUI can offer a form instead of a raw-JSON
//! textbox for them specifically. `fragment`/`sudoku` stay TCP-only, the rest are UDP-only, per
//! [`super::finalmask::TCP_FINALMASK_TYPES`] / [`super::finalmask::UDP_FINALMASK_TYPES`].
//! `header-custom`, `mkcp-legacy`, and `xmc` are intentionally **not** covered here — they stay
//! on the raw-JSON path.
//!
//! Every struct keeps an `extras: Map<String, Value>` catch-all so unknown/future keys inside a
//! layer's `settings` object always round-trip losslessly, matching every other typed editor in
//! this crate.

use serde_json::{Map, Value};

use super::sockopt::{SockoptDraft, parse_sockopt, sockopt_to_value};

fn string_field(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").trim().to_owned()
}

fn string_array_field(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn u32_field(value: Option<&Value>) -> Option<u32> {
    value.and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok())
}

fn apply_optional_string(object: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        object.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

fn apply_string_array(object: &mut Map<String, Value>, key: &str, values: &[String]) {
    if !values.is_empty() {
        object.insert(
            key.to_owned(),
            Value::Array(values.iter().cloned().map(Value::String).collect()),
        );
    }
}

fn apply_u32(object: &mut Map<String, Value>, key: &str, value: Option<u32>) {
    if let Some(value) = value {
        object.insert(key.to_owned(), Value::from(value));
    }
}

fn extras_of(object: &Map<String, Value>, known: &[&str]) -> Map<String, Value> {
    object
        .iter()
        .filter(|(key, _)| !known.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn apply_extras(object: &mut Map<String, Value>, extras: &Map<String, Value>) {
    for (key, value) in extras {
        object.entry(key.clone()).or_insert_with(|| value.clone());
    }
}

// ─── fragment (TCP) ─────────────────────────────────────────────────────────

/// `finalmask.tcp[].settings` for `type = "fragment"` (TCP-layer packet fragmentation).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FragmentMaskSettings {
    /// `packets` (e.g. `"1-3"` or `"tlshello"`); empty = key absent.
    pub packets: String,
    /// `length` `Int32Range` (e.g. `"100-200"`); empty = key absent.
    pub length: String,
    /// `delay` `Int32Range` in ms; empty = key absent.
    pub delay: String,
    /// `lengths[]`, each an `Int32Range`; empty = key absent.
    pub lengths: Vec<String>,
    /// `delays[]`, each an `Int32Range`; empty = key absent.
    pub delays: Vec<String>,
    /// `maxSplit` `Int32Range`; empty = key absent.
    pub max_split: String,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_FRAGMENT_MASK_KEYS: &[&str] =
    &["packets", "length", "delay", "lengths", "delays", "maxSplit"];

/// Parses `finalmask.tcp[].settings` as `fragment`. `None` when `settings` isn't an object.
pub fn parse_fragment_mask_settings(settings: &Value) -> Option<FragmentMaskSettings> {
    let object = settings.as_object()?;
    Some(FragmentMaskSettings {
        packets: string_field(object.get("packets")),
        length: string_field(object.get("length")),
        delay: string_field(object.get("delay")),
        lengths: string_array_field(object.get("lengths")),
        delays: string_array_field(object.get("delays")),
        max_split: string_field(object.get("maxSplit")),
        extras: extras_of(object, KNOWN_FRAGMENT_MASK_KEYS),
    })
}

/// Builds the `settings` `Value` for a `fragment` layer.
pub fn fragment_mask_settings_to_value(draft: &FragmentMaskSettings) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "packets", &draft.packets);
    apply_optional_string(&mut object, "length", &draft.length);
    apply_optional_string(&mut object, "delay", &draft.delay);
    apply_string_array(&mut object, "lengths", &draft.lengths);
    apply_string_array(&mut object, "delays", &draft.delays);
    apply_optional_string(&mut object, "maxSplit", &draft.max_split);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── salamander (UDP) ───────────────────────────────────────────────────────

/// `finalmask.udp[].settings` for `type = "salamander"` (Hysteria2-compatible obfuscation).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SalamanderSettings {
    /// `password`; empty = key absent.
    pub password: String,
    /// `packetSize` `Int32Range`; empty = key absent.
    pub packet_size: String,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_SALAMANDER_KEYS: &[&str] = &["password", "packetSize"];

/// Parses `finalmask.udp[].settings` as `salamander`. `None` when `settings` isn't an object.
pub fn parse_salamander_settings(settings: &Value) -> Option<SalamanderSettings> {
    let object = settings.as_object()?;
    Some(SalamanderSettings {
        password: string_field(object.get("password")),
        packet_size: string_field(object.get("packetSize")),
        extras: extras_of(object, KNOWN_SALAMANDER_KEYS),
    })
}

/// Builds the `settings` `Value` for a `salamander` layer.
pub fn salamander_settings_to_value(draft: &SalamanderSettings) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "password", &draft.password);
    apply_optional_string(&mut object, "packetSize", &draft.packet_size);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── sudoku (UDP, TCP) ──────────────────────────────────────────────────────

/// `finalmask.tcp[]` / `finalmask.udp[].settings` for `type = "sudoku"`.
///
/// Xray-core accepts legacy snake_case aliases (`custom_table`/`custom_tables`/`padding_min`/
/// `padding_max`) for the camelCase fields below; Feldjäger reads either but always **writes**
/// the canonical camelCase key, same idiom as `routing_settings.rs`'s `sourceIP`/`source`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SudokuSettings {
    /// `password`; empty = key absent.
    pub password: String,
    /// `ascii`; empty = key absent.
    pub ascii: String,
    /// `customTable` (alias `custom_table`); empty = key absent.
    pub custom_table: String,
    /// `customTables[]` (alias `custom_tables`); empty = key absent.
    pub custom_tables: Vec<String>,
    /// `paddingMin` (alias `padding_min`); `None` = key absent.
    pub padding_min: Option<u32>,
    /// `paddingMax` (alias `padding_max`); `None` = key absent.
    pub padding_max: Option<u32>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_SUDOKU_KEYS: &[&str] = &[
    "password",
    "ascii",
    "customTable",
    "custom_table",
    "customTables",
    "custom_tables",
    "paddingMin",
    "padding_min",
    "paddingMax",
    "padding_max",
];

/// Parses `settings` as `sudoku`. `None` when `settings` isn't an object.
pub fn parse_sudoku_settings(settings: &Value) -> Option<SudokuSettings> {
    let object = settings.as_object()?;
    let custom_table = {
        let canonical = string_field(object.get("customTable"));
        if canonical.is_empty() {
            string_field(object.get("custom_table"))
        } else {
            canonical
        }
    };
    let custom_tables = {
        let canonical = string_array_field(object.get("customTables"));
        if canonical.is_empty() {
            string_array_field(object.get("custom_tables"))
        } else {
            canonical
        }
    };
    let padding_min = u32_field(object.get("paddingMin")).or_else(|| u32_field(object.get("padding_min")));
    let padding_max = u32_field(object.get("paddingMax")).or_else(|| u32_field(object.get("padding_max")));
    Some(SudokuSettings {
        password: string_field(object.get("password")),
        ascii: string_field(object.get("ascii")),
        custom_table,
        custom_tables,
        padding_min,
        padding_max,
        extras: extras_of(object, KNOWN_SUDOKU_KEYS),
    })
}

/// Builds the `settings` `Value` for a `sudoku` layer (always writes canonical camelCase keys).
pub fn sudoku_settings_to_value(draft: &SudokuSettings) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "password", &draft.password);
    apply_optional_string(&mut object, "ascii", &draft.ascii);
    apply_optional_string(&mut object, "customTable", &draft.custom_table);
    apply_string_array(&mut object, "customTables", &draft.custom_tables);
    apply_u32(&mut object, "paddingMin", draft.padding_min);
    apply_u32(&mut object, "paddingMax", draft.padding_max);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── realm (UDP) ────────────────────────────────────────────────────────────

/// `finalmask.udp[].settings` for `type = "realm"`.
///
/// `tlsConfig` and `portMapping` are nested objects with their own sub-schemas; kept as raw
/// `Value` (same trust boundary as `SockoptDraft::custom_sockopt`) rather than duplicating a
/// second typed TLS/port-mapping editor here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealmSettings {
    /// `url`; empty = key absent.
    pub url: String,
    /// `stunServers[]`; empty = key absent.
    pub stun_servers: Vec<String>,
    /// `tlsConfig` object, preserved raw; `None` = key absent.
    pub tls_config: Option<Value>,
    /// `ipMode`; empty = key absent.
    pub ip_mode: String,
    /// `portMapping` object, preserved raw; `None` = key absent.
    pub port_mapping: Option<Value>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_REALM_KEYS: &[&str] = &["url", "stunServers", "tlsConfig", "ipMode", "portMapping"];

/// Parses `settings` as `realm`. `None` when `settings` isn't an object.
pub fn parse_realm_settings(settings: &Value) -> Option<RealmSettings> {
    let object = settings.as_object()?;
    Some(RealmSettings {
        url: string_field(object.get("url")),
        stun_servers: string_array_field(object.get("stunServers")),
        tls_config: object.get("tlsConfig").filter(|v| v.is_object()).cloned(),
        ip_mode: string_field(object.get("ipMode")),
        port_mapping: object.get("portMapping").filter(|v| v.is_object()).cloned(),
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
        object.insert("portMapping".to_owned(), port_mapping.clone());
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── udphop (UDP) ───────────────────────────────────────────────────────────

/// `finalmask.udp[].settings` for `type = "udphop"` — the UDP port-hopping mask
/// (XTLS/Xray-core#6327).
///
/// `sockopt` reuses the existing [`SockoptDraft`]/[`parse_sockopt`]/[`sockopt_to_value`] typed
/// editor rather than a second copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHopSettings {
    /// `sockopt`; `None` = key absent.
    pub sockopt: Option<SockoptDraft>,
    /// `mode`; empty = key absent.
    pub mode: String,
    /// `interval` `Int32Range`; empty = key absent.
    pub interval: String,
    /// `remotePorts` — `PortList` free text (single port, range, or comma list); empty = key
    /// absent.
    pub remote_ports: String,
    /// `remoteIPs[]`; empty = key absent.
    pub remote_ips: Vec<String>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

impl Default for UdpHopSettings {
    fn default() -> Self {
        Self {
            sockopt: None,
            mode: String::new(),
            interval: String::new(),
            remote_ports: String::new(),
            remote_ips: Vec::new(),
            extras: Map::new(),
        }
    }
}

const KNOWN_UDPHOP_KEYS: &[&str] = &["sockopt", "mode", "interval", "remotePorts", "remoteIPs"];

/// Parses `settings` as `udphop`. `None` when `settings` isn't an object.
pub fn parse_udphop_settings(settings: &Value) -> Option<UdpHopSettings> {
    let object = settings.as_object()?;
    let sockopt = object.get("sockopt").and_then(Value::as_object).map(parse_sockopt);
    Some(UdpHopSettings {
        sockopt,
        mode: string_field(object.get("mode")),
        interval: string_field(object.get("interval")),
        remote_ports: string_field(object.get("remotePorts")),
        remote_ips: string_array_field(object.get("remoteIPs")),
        extras: extras_of(object, KNOWN_UDPHOP_KEYS),
    })
}

/// Builds the `settings` `Value` for a `udphop` layer.
pub fn udphop_settings_to_value(draft: &UdpHopSettings) -> Value {
    let mut object = Map::new();
    if let Some(sockopt) = &draft.sockopt {
        object.insert("sockopt".to_owned(), sockopt_to_value(sockopt));
    }
    apply_optional_string(&mut object, "mode", &draft.mode);
    apply_optional_string(&mut object, "interval", &draft.interval);
    apply_optional_string(&mut object, "remotePorts", &draft.remote_ports);
    apply_string_array(&mut object, "remoteIPs", &draft.remote_ips);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── noise (UDP) ────────────────────────────────────────────────────────────

/// One `finalmask.udp[].settings.noise[]` entry (UDP noise mask).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoiseMaskItem {
    /// `rand` `Int32Range`; empty = key absent.
    pub rand: String,
    /// `randRange` `Int32Range`; empty = key absent.
    pub rand_range: String,
    /// `type` (payload-spec kind; free text, e.g. `rand`/`str`/`hex`/`base64`).
    pub kind: String,
    /// `packet` payload spec (string-shaped forms only; shape depends on `kind`).
    pub packet: String,
    /// `delay` `Int32Range`; empty = key absent.
    pub delay: String,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_NOISE_ITEM_KEYS: &[&str] = &["rand", "randRange", "type", "packet", "delay"];

fn parse_noise_item(value: &Value) -> Option<NoiseMaskItem> {
    let object = value.as_object()?;
    Some(NoiseMaskItem {
        rand: string_field(object.get("rand")),
        rand_range: string_field(object.get("randRange")),
        kind: string_field(object.get("type")),
        packet: string_field(object.get("packet")),
        delay: string_field(object.get("delay")),
        extras: extras_of(object, KNOWN_NOISE_ITEM_KEYS),
    })
}

fn noise_item_to_value(draft: &NoiseMaskItem) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "rand", &draft.rand);
    apply_optional_string(&mut object, "randRange", &draft.rand_range);
    apply_optional_string(&mut object, "type", &draft.kind);
    apply_optional_string(&mut object, "packet", &draft.packet);
    apply_optional_string(&mut object, "delay", &draft.delay);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

/// `finalmask.udp[].settings` for `type = "noise"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoiseMaskSettings {
    /// `reset` `Int32Range`; empty = key absent.
    pub reset: String,
    /// `noise[]`; empty = key absent.
    pub noise: Vec<NoiseMaskItem>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_NOISE_MASK_KEYS: &[&str] = &["reset", "noise"];

/// Parses `settings` as `noise`. `None` when `settings` isn't an object, or any `noise[]` entry
/// isn't itself an object — callers should then leave the layer's settings on the raw-JSON path.
pub fn parse_noise_mask_settings(settings: &Value) -> Option<NoiseMaskSettings> {
    let object = settings.as_object()?;
    let noise = match object.get("noise") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(parse_noise_item)
            .collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    Some(NoiseMaskSettings {
        reset: string_field(object.get("reset")),
        noise,
        extras: extras_of(object, KNOWN_NOISE_MASK_KEYS),
    })
}

/// Builds the `settings` `Value` for a `noise` layer.
pub fn noise_mask_settings_to_value(draft: &NoiseMaskSettings) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "reset", &draft.reset);
    if !draft.noise.is_empty() {
        object.insert(
            "noise".to_owned(),
            Value::Array(draft.noise.iter().map(noise_item_to_value).collect()),
        );
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── xdns (UDP) ─────────────────────────────────────────────────────────────

/// `finalmask.udp[].settings` for `type = "xdns"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XdnsSettings {
    /// `domain`, preserved raw (single string or matcher object, per Xray-core); `None` = key
    /// absent.
    pub domain: Option<Value>,
    /// `domains[]`; empty = key absent.
    pub domains: Vec<String>,
    /// `resolvers[]`; empty = key absent.
    pub resolvers: Vec<String>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_XDNS_KEYS: &[&str] = &["domain", "domains", "resolvers"];

/// Parses `settings` as `xdns`. `None` when `settings` isn't an object.
pub fn parse_xdns_settings(settings: &Value) -> Option<XdnsSettings> {
    let object = settings.as_object()?;
    Some(XdnsSettings {
        domain: object.get("domain").cloned(),
        domains: string_array_field(object.get("domains")),
        resolvers: string_array_field(object.get("resolvers")),
        extras: extras_of(object, KNOWN_XDNS_KEYS),
    })
}

/// Builds the `settings` `Value` for an `xdns` layer.
pub fn xdns_settings_to_value(draft: &XdnsSettings) -> Value {
    let mut object = Map::new();
    if let Some(domain) = &draft.domain {
        object.insert("domain".to_owned(), domain.clone());
    }
    apply_string_array(&mut object, "domains", &draft.domains);
    apply_string_array(&mut object, "resolvers", &draft.resolvers);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── xicmp (UDP) ────────────────────────────────────────────────────────────

/// `finalmask.udp[].settings` for `type = "xicmp"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XicmpSettings {
    /// `dgram`.
    pub dgram: bool,
    /// `ips[]`; empty = key absent.
    pub ips: Vec<String>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_XICMP_KEYS: &[&str] = &["dgram", "ips"];

/// Parses `settings` as `xicmp`. `None` when `settings` isn't an object.
pub fn parse_xicmp_settings(settings: &Value) -> Option<XicmpSettings> {
    let object = settings.as_object()?;
    Some(XicmpSettings {
        dgram: object.get("dgram").and_then(Value::as_bool).unwrap_or(false),
        ips: string_array_field(object.get("ips")),
        extras: extras_of(object, KNOWN_XICMP_KEYS),
    })
}

/// Builds the `settings` `Value` for an `xicmp` layer.
pub fn xicmp_settings_to_value(draft: &XicmpSettings) -> Value {
    let mut object = Map::new();
    if draft.dgram {
        object.insert("dgram".to_owned(), Value::Bool(true));
    }
    apply_string_array(&mut object, "ips", &draft.ips);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fragment_mask_roundtrip() {
        let settings = json!({
            "packets": "tlshello",
            "length": "100-200",
            "lengths": ["1-2", "3-4"],
            "maxSplit": "1-3",
            "futureField": "keep"
        });
        let draft = parse_fragment_mask_settings(&settings).expect("parsed");
        assert_eq!(draft.packets, "tlshello");
        assert_eq!(draft.lengths, vec!["1-2".to_owned(), "3-4".to_owned()]);
        assert_eq!(draft.delay, "");
        let value = fragment_mask_settings_to_value(&draft);
        assert_eq!(value["packets"], "tlshello");
        assert_eq!(value["futureField"], "keep");
        assert!(value.get("delay").is_none());
    }

    #[test]
    fn salamander_roundtrip() {
        let settings = json!({"password": "secret", "packetSize": "1200-1500"});
        let draft = parse_salamander_settings(&settings).expect("parsed");
        assert_eq!(draft.password, "secret");
        assert_eq!(draft.packet_size, "1200-1500");
        let value = salamander_settings_to_value(&draft);
        assert_eq!(value, settings);
    }

    #[test]
    fn sudoku_reads_legacy_aliases_writes_canonical() {
        let settings = json!({
            "password": "p",
            "custom_table": "legacy-table",
            "custom_tables": ["a", "b"],
            "padding_min": 10,
            "padding_max": 20
        });
        let draft = parse_sudoku_settings(&settings).expect("parsed");
        assert_eq!(draft.custom_table, "legacy-table");
        assert_eq!(draft.custom_tables, vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(draft.padding_min, Some(10));
        assert_eq!(draft.padding_max, Some(20));
        let value = sudoku_settings_to_value(&draft);
        assert_eq!(value["customTable"], "legacy-table");
        assert_eq!(value["customTables"], json!(["a", "b"]));
        assert_eq!(value["paddingMin"], 10);
        assert!(value.get("custom_table").is_none());
    }

    #[test]
    fn sudoku_prefers_canonical_over_legacy() {
        let settings = json!({"customTable": "new", "custom_table": "old"});
        let draft = parse_sudoku_settings(&settings).expect("parsed");
        assert_eq!(draft.custom_table, "new");
    }

    #[test]
    fn realm_roundtrip_preserves_raw_subobjects() {
        let settings = json!({
            "url": "https://example.com",
            "stunServers": ["stun.example.com:3478"],
            "tlsConfig": {"serverName": "example.com"},
            "ipMode": "4",
            "portMapping": {"foo": "bar"}
        });
        let draft = parse_realm_settings(&settings).expect("parsed");
        assert_eq!(draft.url, "https://example.com");
        assert_eq!(draft.tls_config, Some(json!({"serverName": "example.com"})));
        let value = realm_settings_to_value(&draft);
        assert_eq!(value, settings);
    }

    #[test]
    fn udphop_roundtrip_reuses_sockopt_editor() {
        let settings = json!({
            "sockopt": {"mark": 255},
            "mode": "native",
            "interval": "5-10",
            "remotePorts": "20000-30000",
            "remoteIPs": ["10.0.0.1"]
        });
        let draft = parse_udphop_settings(&settings).expect("parsed");
        assert!(draft.sockopt.is_some());
        assert_eq!(draft.mode, "native");
        assert_eq!(draft.remote_ports, "20000-30000");
        let value = udphop_settings_to_value(&draft);
        assert_eq!(value["mode"], "native");
        assert_eq!(value["remotePorts"], "20000-30000");
        assert_eq!(value["remoteIPs"], json!(["10.0.0.1"]));
        assert_eq!(value["sockopt"]["mark"], 255);
    }

    #[test]
    fn udphop_settings_without_sockopt_omit_key() {
        let draft = UdpHopSettings {
            mode: "native".to_owned(),
            ..UdpHopSettings::default()
        };
        let value = udphop_settings_to_value(&draft);
        assert!(value.get("sockopt").is_none());
    }

    #[test]
    fn noise_mask_roundtrip() {
        let settings = json!({
            "reset": "5-10",
            "noise": [
                {"rand": "1-2", "type": "str", "packet": "hello", "delay": "1-2"}
            ]
        });
        let draft = parse_noise_mask_settings(&settings).expect("parsed");
        assert_eq!(draft.noise.len(), 1);
        assert_eq!(draft.noise[0].kind, "str");
        let value = noise_mask_settings_to_value(&draft);
        assert_eq!(value, settings);
    }

    #[test]
    fn noise_mask_rejects_malformed_entries() {
        let settings = json!({"noise": ["not-an-object"]});
        assert!(parse_noise_mask_settings(&settings).is_none());
    }

    #[test]
    fn xdns_roundtrip_preserves_raw_domain() {
        let settings = json!({
            "domain": "example.com",
            "domains": ["a.com", "b.com"],
            "resolvers": ["1.1.1.1"]
        });
        let draft = parse_xdns_settings(&settings).expect("parsed");
        assert_eq!(draft.domain, Some(json!("example.com")));
        let value = xdns_settings_to_value(&draft);
        assert_eq!(value, settings);
    }

    #[test]
    fn xicmp_roundtrip() {
        let settings = json!({"dgram": true, "ips": ["1.2.3.4"]});
        let draft = parse_xicmp_settings(&settings).expect("parsed");
        assert!(draft.dgram);
        let value = xicmp_settings_to_value(&draft);
        assert_eq!(value, settings);
    }

    #[test]
    fn xicmp_omits_false_dgram() {
        let draft = XicmpSettings {
            dgram: false,
            ips: vec!["1.2.3.4".to_owned()],
            extras: Map::new(),
        };
        let value = xicmp_settings_to_value(&draft);
        assert!(value.get("dgram").is_none());
    }
}
