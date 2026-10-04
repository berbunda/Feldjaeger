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
//! `header-custom` UDP and `xmc` are intentionally **not** covered here — they stay on the
//! raw-JSON path; `mkcp-legacy` got a typed form in stage 2.1 ([`super::finalmask_mkcp`]),
//! `header-custom` TCP in stage 2.2 ([`super::finalmask_header_custom`]).
//!
//! Every struct keeps an `extras: Map<String, Value>` catch-all so unknown/future keys inside a
//! layer's `settings` object always round-trip losslessly, matching every other typed editor in
//! this crate.
//!
//! **Lossless-or-raw rule** (Roadmap §2.6 stage 0.1): every `parse_*` either represents each
//! known key without losing it, or returns `None` so the GUI keeps the layer on the raw-JSON
//! editor. Multi-shape fields (`Int32Range`, `PortList`, `packet`) use the shape-preserving types
//! from [`super::values`]; a known key holding a JSON shape the typed struct can't hold (a number
//! where a string is expected, …) is never silently dropped.

use serde_json::{Map, Value};

use super::values::{PacketValue, PortListValue, RangeValue, parse_range_string, parse_range_values};

/// Absent/`null` → `""`; `None` when present but not a string.
pub(super) fn string_field(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => Some(String::new()),
        Some(Value::String(text)) => Some(text.trim().to_owned()),
        Some(_) => None,
    }
}

/// Absent/`null` → empty; `None` when present but not an array of strings. Blank entries are
/// dropped (they carry no meaning for any FinalMask list field).
pub(super) fn string_array_field(value: Option<&Value>) -> Option<Vec<String>> {
    match value {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::trim))
            .collect::<Option<Vec<_>>>()
            .map(|items| {
                items
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            }),
        Some(_) => None,
    }
}

/// Absent/`null` → `Some(None)`; `None` when present but not a `u32` number.
fn u32_field(value: Option<&Value>) -> Option<Option<u32>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(value) => value.as_u64().and_then(|n| u32::try_from(n).ok()).map(Some),
    }
}

/// Absent/`null` → `false`; `None` when present but not a bool.
fn bool_field(value: Option<&Value>) -> Option<bool> {
    match value {
        None | Some(Value::Null) => Some(false),
        Some(value) => value.as_bool(),
    }
}

/// Absent/`null` → `Some(None)`; `None` when present but not a bool (keeps an explicit `false`).
pub(super) fn bool_option_field(value: Option<&Value>) -> Option<Option<bool>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(value) => value.as_bool().map(Some),
    }
}

/// Absent/`null` → `Some(None)`; `None` when present but not an object.
pub(super) fn object_field(value: Option<&Value>) -> Option<Option<Value>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(value) if value.is_object() => Some(Some(value.clone())),
        Some(_) => None,
    }
}

fn apply_range(object: &mut Map<String, Value>, key: &str, value: &RangeValue) {
    if let Some(value) = value.to_value() {
        object.insert(key.to_owned(), value);
    }
}

fn apply_range_array(object: &mut Map<String, Value>, key: &str, values: &[RangeValue]) {
    let items: Vec<Value> = values.iter().filter_map(RangeValue::to_value).collect();
    if !items.is_empty() {
        object.insert(key.to_owned(), Value::Array(items));
    }
}

pub(super) fn apply_optional_string(object: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        object.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

pub(super) fn apply_string_array(object: &mut Map<String, Value>, key: &str, values: &[String]) {
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

pub(super) fn extras_of(object: &Map<String, Value>, known: &[&str]) -> Map<String, Value> {
    object
        .iter()
        .filter(|(key, _)| !known.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub(super) fn apply_extras(object: &mut Map<String, Value>, extras: &Map<String, Value>) {
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
    /// `length` `Int32Range` (e.g. `"100-200"`, legacy single form of `lengths`); empty = key absent.
    pub length: RangeValue,
    /// `delay` `Int32Range` in ms (legacy single form of `delays`); empty = key absent.
    pub delay: RangeValue,
    /// `lengths[]`, each an `Int32Range`; empty = key absent.
    pub lengths: Vec<RangeValue>,
    /// `delays[]`, each an `Int32Range`; empty = key absent.
    pub delays: Vec<RangeValue>,
    /// `maxSplit` `Int32Range`; empty = key absent.
    pub max_split: RangeValue,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_FRAGMENT_MASK_KEYS: &[&str] =
    &["packets", "length", "delay", "lengths", "delays", "maxSplit"];

/// The `fragment.packets` keyword for the first TLS handshake record (any case).
pub const FRAGMENT_PACKETS_TLSHELLO: &str = "tlshello";

/// Which writes a `fragment` layer splits, as `FragmentMask.Build()` reads `packets`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentPackets {
    /// Empty `packets` — every write of the connection.
    All,
    /// `tlshello` — only the first write, and only when it is a whole TLS handshake record
    /// (`fragment/conn.go`); it is re-cut into several TLS records.
    TlsHello,
    /// `FROM-TO` — the writes numbered `FROM..=TO` (1-based), split into TCP writes. The core
    /// keeps the order as written, so `from > to` matches no write at all.
    Range { from: i64, to: i64 },
}

/// What a `fragment.packets` value selects; `None` when it is neither `tlshello` nor a range (the
/// `Build()` error is reported by [`validate_fragment_mask_settings`]).
pub fn fragment_packets_mode(packets: &str) -> Option<FragmentPackets> {
    if packets.is_empty() {
        return Some(FragmentPackets::All);
    }
    if packets.eq_ignore_ascii_case(FRAGMENT_PACKETS_TLSHELLO) {
        return Some(FragmentPackets::TlsHello);
    }
    parse_range_string(packets).map(|(from, to)| FragmentPackets::Range { from, to })
}

impl FragmentMaskSettings {
    /// What `packets` selects (see [`fragment_packets_mode`]).
    pub fn packets_mode(&self) -> Option<FragmentPackets> {
        fragment_packets_mode(&self.packets)
    }

    /// Whether `tlshello` sends its re-cut TLS records together in one write instead of one write
    /// per record. The core does so when the delay list it builds — `delays`, or `[delay]` when
    /// `delays` is empty — is exactly one entry with an upper bound of 0 (`mergeTlsHelloSegments`);
    /// so an absent `delay` merges too.
    pub fn merges_tls_records(&self) -> bool {
        let upper = |value: &RangeValue| value.bounds().ok().flatten().map_or(0, |(_, to)| to);
        match self.delays.as_slice() {
            [] => upper(&self.delay) == 0,
            [only] => upper(only) == 0,
            _ => false,
        }
    }
}

/// Parses `finalmask.tcp[].settings` as `fragment`. `None` when `settings` isn't an object or a
/// known key can't be represented losslessly.
pub fn parse_fragment_mask_settings(settings: &Value) -> Option<FragmentMaskSettings> {
    let object = settings.as_object()?;
    Some(FragmentMaskSettings {
        packets: string_field(object.get("packets"))?,
        length: RangeValue::parse(object.get("length"))?,
        delay: RangeValue::parse(object.get("delay"))?,
        lengths: parse_range_values(object.get("lengths"))?,
        delays: parse_range_values(object.get("delays"))?,
        max_split: RangeValue::parse(object.get("maxSplit"))?,
        extras: extras_of(object, KNOWN_FRAGMENT_MASK_KEYS),
    })
}

/// Validates a `fragment` layer like `FragmentMask.Build()`: `packets` is `tlshello`, empty or a
/// range whose **first** number (as written — the core does not reorder it here) is not 0; the
/// last `lengths` entry (or `length` when `lengths` is empty — absent counts as 0) must not start
/// at 0, so a length is required; every range parses.
pub fn validate_fragment_mask_settings(draft: &FragmentMaskSettings) -> Result<(), String> {
    for (name, value) in [("length", &draft.length), ("delay", &draft.delay), ("maxSplit", &draft.max_split)] {
        value.validate().map_err(|error| format!("{name}: {error}"))?;
    }
    for (name, values) in [("lengths", &draft.lengths), ("delays", &draft.delays)] {
        for (index, value) in values.iter().enumerate() {
            value.validate().map_err(|error| format!("{name}[{index}]: {error}"))?;
        }
    }
    let packets = draft.packets.as_str();
    if !packets.is_empty() && !packets.eq_ignore_ascii_case("tlshello") {
        let (from, _) = parse_range_string(packets)
            .ok_or_else(|| format!("packets: \"{packets}\" is neither tlshello nor a range \"FROM-TO\""))?;
        if from == 0 {
            return Err("packets: a range must not start at 0 (use tlshello for the TLS ClientHello)".to_owned());
        }
    }
    let last_min = |value: &RangeValue| value.bounds().ok().flatten().map_or(0, |(from, _)| from);
    match draft.lengths.last() {
        Some(last) if last_min(last) == 0 => {
            Err("lengths: the last entry must not start at 0".to_owned())
        }
        None if last_min(&draft.length) == 0 => {
            Err("length is required (a fragment size \"MIN-MAX\" with MIN ≥ 1, or lengths)".to_owned())
        }
        _ => Ok(()),
    }
}

/// Builds the `settings` `Value` for a `fragment` layer.
pub fn fragment_mask_settings_to_value(draft: &FragmentMaskSettings) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "packets", &draft.packets);
    apply_range(&mut object, "length", &draft.length);
    apply_range(&mut object, "delay", &draft.delay);
    apply_range_array(&mut object, "lengths", &draft.lengths);
    apply_range_array(&mut object, "delays", &draft.delays);
    apply_range(&mut object, "maxSplit", &draft.max_split);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── salamander (UDP) ───────────────────────────────────────────────────────

/// `finalmask.udp[].settings` for `type = "salamander"` (Hysteria2-compatible obfuscation).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SalamanderSettings {
    /// `password`; empty = key absent.
    pub password: String,
    /// `packetSize` `Int32Range` (non-empty enables Gecko); empty = key absent.
    pub packet_size: RangeValue,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_SALAMANDER_KEYS: &[&str] = &["password", "packetSize"];

/// Parses `finalmask.udp[].settings` as `salamander`. `None` when `settings` isn't an object or
/// a known key can't be represented losslessly.
pub fn parse_salamander_settings(settings: &Value) -> Option<SalamanderSettings> {
    let object = settings.as_object()?;
    Some(SalamanderSettings {
        password: string_field(object.get("password"))?,
        packet_size: RangeValue::parse(object.get("packetSize"))?,
        extras: extras_of(object, KNOWN_SALAMANDER_KEYS),
    })
}

/// Validates a `salamander` layer like `Salamander.Build()`: a `packetSize` with a positive upper
/// bound switches to Gecko and must lie within 1–2048. Then the runtime check of the obfuscator:
/// `password` has at least [`SALAMANDER_MIN_PASSWORD_BYTES`] bytes.
pub fn validate_salamander_settings(draft: &SalamanderSettings) -> Result<(), String> {
    if let Some((from, to)) = draft.packet_size.bounds().map_err(|error| format!("packetSize: {error}"))?
        && to > 0
        && (from <= 0 || to > 2048)
    {
        return Err("packetSize must lie within 1–2048 (Gecko packet sizes)".to_owned());
    }
    // `NewSalamanderObfuscator` refuses a short key when the listener / dialer is created, which
    // `Build()` (and so `xray run -test`) never reaches.
    let len = draft.password.len();
    if len < SALAMANDER_MIN_PASSWORD_BYTES {
        let unit = if len == 1 { "byte" } else { "bytes" };
        return Err(format!(
            "password is {len} {unit}, Xray-core needs at least {SALAMANDER_MIN_PASSWORD_BYTES} — the \
             layer fails to start (xray run -test does not catch it)"
        ));
    }
    Ok(())
}

/// Shortest `salamander` password Xray-core accepts (`smPSKMinLen`), in bytes.
pub const SALAMANDER_MIN_PASSWORD_BYTES: usize = 4;

/// Builds the `settings` `Value` for a `salamander` layer.
pub fn salamander_settings_to_value(draft: &SalamanderSettings) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "password", &draft.password);
    apply_range(&mut object, "packetSize", &draft.packet_size);
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

/// Parses `settings` as `sudoku`. `None` when `settings` isn't an object or a known key (either
/// spelling) can't be represented losslessly.
pub fn parse_sudoku_settings(settings: &Value) -> Option<SudokuSettings> {
    let object = settings.as_object()?;
    let custom_table = {
        let canonical = string_field(object.get("customTable"))?;
        let legacy = string_field(object.get("custom_table"))?;
        if canonical.is_empty() { legacy } else { canonical }
    };
    let custom_tables = {
        let canonical = string_array_field(object.get("customTables"))?;
        let legacy = string_array_field(object.get("custom_tables"))?;
        if canonical.is_empty() { legacy } else { canonical }
    };
    let padding_min = u32_field(object.get("paddingMin"))?.or(u32_field(object.get("padding_min"))?);
    let padding_max = u32_field(object.get("paddingMax"))?.or(u32_field(object.get("padding_max"))?);
    Some(SudokuSettings {
        password: string_field(object.get("password"))?,
        ascii: string_field(object.get("ascii"))?,
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

/// `sudoku.ascii` presets: `entropy` (= empty, the default) and `ascii`. Xray-core also accepts
/// `prefer_entropy` / `prefer_ascii`, trimmed and in any case (`normalizeASCII`).
pub const SUDOKU_ASCII_MODES: &[&str] = &["entropy", "ascii"];

/// Largest padding percentage the core uses; larger `paddingMin` / `paddingMax` are capped.
pub const SUDOKU_MAX_PADDING: u32 = 100;

impl SudokuSettings {
    /// Whether `ascii` selects the printable-ASCII layout; `None` for a value the core rejects.
    pub fn prefers_ascii(&self) -> Option<bool> {
        match self.ascii.trim().to_ascii_lowercase().as_str() {
            "" | "entropy" | "prefer_entropy" => Some(false),
            "ascii" | "prefer_ascii" => Some(true),
            _ => None,
        }
    }

    /// The custom table patterns the core uses: `customTables`, or `customTable` when the list is
    /// empty (`normalizedCustomPatterns`). The ASCII layout uses none of them.
    pub fn custom_patterns(&self) -> Vec<&str> {
        if self.custom_tables.is_empty() {
            vec![self.custom_table.as_str()]
        } else {
            self.custom_tables.iter().map(String::as_str).collect()
        }
    }

    /// `(paddingMin, paddingMax)` as the core uses them (`normalizedPadding`): each capped at
    /// [`SUDOKU_MAX_PADDING`], and the maximum raised to the minimum.
    pub fn effective_padding(&self) -> (u32, u32) {
        let min = self.padding_min.unwrap_or(0).min(SUDOKU_MAX_PADDING);
        let max = self.padding_max.unwrap_or(0).min(SUDOKU_MAX_PADDING).max(min);
        (min, max)
    }
}

/// Checks a custom table pattern like the core's `normalizeCustomTable`: spaces dropped, case
/// ignored, exactly 8 characters — two `x`, two `p` and four `v`. A blank pattern means the
/// default layout and is fine.
pub fn validate_sudoku_custom_table(pattern: &str) -> Result<(), String> {
    let cleaned: String = pattern.trim().to_lowercase().chars().filter(|c| *c != ' ').collect();
    if cleaned.is_empty() {
        return Ok(());
    }
    let count = |wanted: char| cleaned.chars().filter(|c| *c == wanted).count();
    if cleaned.len() != 8 {
        return Err(format!("must be 8 characters, got {}", cleaned.chars().count()));
    }
    if let Some(other) = cleaned.chars().find(|c| !matches!(c, 'x' | 'p' | 'v')) {
        return Err(format!("has invalid character '{other}' (only x, p and v)"));
    }
    if count('x') != 2 || count('p') != 2 || count('v') != 4 {
        return Err("must contain exactly 2 x, 2 p and 4 v".to_owned());
    }
    Ok(())
}

/// Validates a `sudoku` layer. `Sudoku.Build()` checks nothing; the core reads `ascii` and the
/// custom tables only when it builds the byte tables (`getTables`) — per connection on `tcp[]`,
/// when the listener / dialer is created on `udp[]` — so a bad value passes `xray run -test` and
/// then breaks every connection. Custom tables are not read in the ASCII layout.
pub fn validate_sudoku_settings(draft: &SudokuSettings) -> Result<(), String> {
    const NOT_CAUGHT: &str = "Xray-core fails the connection (xray run -test does not catch it)";
    let Some(ascii) = draft.prefers_ascii() else {
        return Err(format!(
            "ascii: unknown mode \"{}\" (entropy or ascii) — {NOT_CAUGHT}",
            draft.ascii
        ));
    };
    if ascii {
        return Ok(());
    }
    let name = if draft.custom_tables.is_empty() { "customTable" } else { "customTables" };
    for (index, pattern) in draft.custom_patterns().into_iter().enumerate() {
        validate_sudoku_custom_table(pattern).map_err(|error| {
            let at = if draft.custom_tables.is_empty() { String::new() } else { format!("[{index}]") };
            format!("{name}{at}: \"{pattern}\" {error} — {NOT_CAUGHT}")
        })?;
    }
    Ok(())
}

// ─── realm (UDP) ────────────────────────────────────────────────────────────
// Lives in `super::finalmask_realm` (Roadmap §2.6 stage 1.2: URL field view + validation).

pub use super::finalmask_realm::{
    REALM_DEFAULT_PORT_MAP_LIFETIME_SECS, REALM_DEFAULT_PORT_MAP_TIMEOUT_SECS, REALM_IP_MODES,
    RealmPortMapping, RealmScheme, RealmSettings, RealmUrl, parse_realm_settings, parse_realm_url,
    realm_ip_mode_is_known, realm_settings_to_value, validate_realm_settings,
};

// ─── udphop (UDP) ───────────────────────────────────────────────────────────

/// `finalmask.udp[].settings` for `type = "udphop"` — the UDP port-hopping mask
/// (XTLS/Xray-core#6327), matching the core's `UDPHop` (`infra/conf/transport_finalmask.go`).
///
/// The mask is **client-only**: its server wrapper returns `"udphop: client only"`, so it only
/// makes sense in an outbound (see [`super::finalmask::CLIENT_ONLY_UDP_FINALMASK_TYPES`]).
///
/// `sockopt` is not a field of the mask since XTLS/Xray-core#6754 (v26.9.30); an on-disk value
/// stays in [`Self::extras`] untouched until the user removes it
/// ([`Self::remove_legacy_sockopt`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UdpHopSettings {
    /// `mode` — comma-separated hop modes (see [`UdpHopModes`]); empty = key absent.
    pub mode: String,
    /// `interval` `Int32Range` in seconds (core default 30, minimum 5); empty = key absent.
    pub interval: RangeValue,
    /// `remotePorts` — `PortList` (single port, range, or comma list); empty = key absent.
    pub remote_ports: PortListValue,
    /// `remoteIPs[]` — IP addresses or CIDR prefixes; empty = key absent.
    pub remote_ips: Vec<String>,
    /// Unknown keys (including the legacy `sockopt`), preserved verbatim.
    pub extras: Map<String, Value>,
}

/// The `udphop.settings` key dropped by XTLS/Xray-core#6754.
pub const UDPHOP_LEGACY_SOCKOPT_KEY: &str = "sockopt";

impl UdpHopSettings {
    /// `true` when the on-disk layer still carries the removed `sockopt`.
    pub fn has_legacy_sockopt(&self) -> bool {
        self.extras.contains_key(UDPHOP_LEGACY_SOCKOPT_KEY)
    }

    /// Drops the removed `sockopt` (an explicit user action in the editor).
    pub fn remove_legacy_sockopt(&mut self) {
        self.extras.remove(UDPHOP_LEGACY_SOCKOPT_KEY);
    }
}

const KNOWN_UDPHOP_KEYS: &[&str] = &["mode", "interval", "remotePorts", "remoteIPs"];

/// The hop modes selected in `udphop.mode`, as `UDPHop.Build()` reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UdpHopModes {
    /// `intervalLocal` — every interval, dial a fresh local socket (new local port).
    pub interval_local: bool,
    /// `intervalRemote` — every interval, pick a new remote IP/port from `remoteIPs`/`remotePorts`.
    pub interval_remote: bool,
    /// `perConnRemote` — pick a random remote IP/port from `remoteIPs`/`remotePorts` once, when
    /// the connection is opened.
    pub per_conn_remote: bool,
}

impl UdpHopModes {
    /// Canonical `mode` text (`intervalLocal,intervalRemote,perConnRemote` order); empty when no
    /// mode is selected.
    pub fn to_mode_text(self) -> String {
        [
            (self.interval_local, "intervalLocal"),
            (self.interval_remote, "intervalRemote"),
            (self.per_conn_remote, "perConnRemote"),
        ]
        .into_iter()
        .filter_map(|(selected, name)| selected.then_some(name))
        .collect::<Vec<_>>()
        .join(",")
    }

    /// `true` when a mode that picks remote targets is selected.
    pub fn picks_remote(self) -> bool {
        self.interval_remote || self.per_conn_remote
    }
}

/// Parses `udphop.mode` exactly like `UDPHop.Build()`: split on `,` (no trimming — `"a, b"` is
/// invalid in the core), each token case-insensitive. An empty `mode` is an error in the core
/// too (it splits into one empty token).
pub fn parse_udphop_mode(text: &str) -> Result<UdpHopModes, String> {
    if text.is_empty() {
        return Err(
            "mode is required: select at least one of intervalLocal, intervalRemote, perConnRemote"
                .to_owned(),
        );
    }
    let mut modes = UdpHopModes::default();
    for token in text.split(',') {
        match token.to_lowercase().as_str() {
            "intervallocal" => modes.interval_local = true,
            "intervalremote" => modes.interval_remote = true,
            "perconnremote" => modes.per_conn_remote = true,
            _ => {
                return Err(format!(
                    "invalid mode \"{token}\" (expected intervalLocal, intervalRemote or \
                     perConnRemote, comma-separated without spaces)"
                ));
            }
        }
    }
    Ok(modes)
}

/// Core default for an absent / zero `udphop.interval`, in seconds.
pub const UDPHOP_DEFAULT_INTERVAL_SECS: i64 = 30;
/// Smallest `udphop.interval` lower bound the core accepts, in seconds.
pub const UDPHOP_MIN_INTERVAL_SECS: i64 = 5;

/// Validates a `udphop` layer the way `UDPHop.Build()` does (`mode`, `interval`, `remoteIPs`)
/// plus `PortList` decoding of `remotePorts`.
pub fn validate_udphop_settings(draft: &UdpHopSettings) -> Result<(), String> {
    parse_udphop_mode(&draft.mode)?;
    match draft.interval.bounds().map_err(|error| format!("interval: {error}"))? {
        // Absent and `0` / `"0"` both mean the 30 s default in the core.
        None | Some((0, 0)) => {}
        Some((from, _)) if from < UDPHOP_MIN_INTERVAL_SECS => {
            return Err(format!(
                "interval must be at least {UDPHOP_MIN_INTERVAL_SECS} seconds (got \"{}\")",
                draft.interval.text.trim()
            ));
        }
        Some(_) => {}
    }
    draft
        .remote_ports
        .validate()
        .map_err(|error| format!("remotePorts: {error}"))?;
    if let Some(ip) = draft.remote_ips.iter().find(|ip| !is_ip_or_prefix(ip)) {
        return Err(format!("remoteIPs: invalid IP address or CIDR prefix \"{ip}\""));
    }
    Ok(())
}

/// `true` for what `netip.ParseAddr` accepts: an IPv4 / IPv6 address, an IPv6 one with a zone
/// (`fe80::1%eth0`).
fn is_ip_addr(text: &str) -> bool {
    use std::net::{IpAddr, Ipv6Addr};

    match text.split_once('%') {
        Some((address, zone)) => !zone.is_empty() && address.parse::<Ipv6Addr>().is_ok(),
        None => text.parse::<IpAddr>().is_ok(),
    }
}

/// `true` for what `netip.ParsePrefix` or `netip.ParseAddr` accepts: `1.2.3.4`, `10.0.0.0/8`,
/// `2001:db8::/32`, or an IPv6 address with a zone (`fe80::1%eth0`, address form only).
fn is_ip_or_prefix(text: &str) -> bool {
    use std::net::IpAddr;

    if let Some((address, bits)) = text.split_once('/') {
        let Ok(address) = address.parse::<IpAddr>() else {
            return false;
        };
        // Decimal bits without sign or leading zeros, at most the address length.
        let max_bits = if address.is_ipv4() { 32 } else { 128 };
        return !bits.is_empty()
            && bits.bytes().all(|b| b.is_ascii_digit())
            && (bits == "0" || !bits.starts_with('0'))
            && bits.parse::<u32>().is_ok_and(|bits| bits <= max_bits);
    }
    is_ip_addr(text)
}

/// Parses `settings` as `udphop`. `None` when `settings` isn't an object or a known key can't be
/// represented losslessly.
pub fn parse_udphop_settings(settings: &Value) -> Option<UdpHopSettings> {
    let object = settings.as_object()?;
    Some(UdpHopSettings {
        mode: string_field(object.get("mode"))?,
        interval: RangeValue::parse(object.get("interval"))?,
        remote_ports: PortListValue::parse(object.get("remotePorts"))?,
        remote_ips: string_array_field(object.get("remoteIPs"))?,
        extras: extras_of(object, KNOWN_UDPHOP_KEYS),
    })
}

/// Builds the `settings` `Value` for a `udphop` layer.
pub fn udphop_settings_to_value(draft: &UdpHopSettings) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "mode", &draft.mode);
    apply_range(&mut object, "interval", &draft.interval);
    if let Some(remote_ports) = draft.remote_ports.to_value() {
        object.insert("remotePorts".to_owned(), remote_ports);
    }
    apply_string_array(&mut object, "remoteIPs", &draft.remote_ips);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

// ─── noise (UDP) ────────────────────────────────────────────────────────────

/// One `finalmask.udp[].settings.noise[]` entry (UDP noise mask).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoiseMaskItem {
    /// `rand` `Int32Range` — random-byte count (conflicts with `packet`); empty = key absent.
    pub rand: RangeValue,
    /// `randRange` `Int32Range` — random-byte value range (default `0-255`); empty = key absent.
    pub rand_range: RangeValue,
    /// `type` — `packet` encoding: `array` (default) | `str` | `hex` | `base64`.
    pub kind: String,
    /// `packet` fixed payload, interpreted per `kind`; empty = key absent.
    pub packet: PacketValue,
    /// `delay` `Int32Range` in ms; empty = key absent.
    pub delay: RangeValue,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_NOISE_ITEM_KEYS: &[&str] = &["rand", "randRange", "type", "packet", "delay"];

/// What a `noise[]` item sends, as `noise/conn.go` `buildPacket` decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseItemPayload {
    /// `type: "exp"` — bytes built from the expression in `packet`; `rand` / `randRange` unused.
    Exp,
    /// `rand` with a positive upper bound — that many random bytes, values within `randRange`.
    Rand,
    /// `packet` — fixed bytes.
    Packet,
    /// Neither — an empty datagram.
    Empty,
}

impl NoiseMaskItem {
    /// What the item sends; `None` when it sets both `packet` and `rand` (a `Build()` error).
    pub fn payload(&self) -> Option<NoiseItemPayload> {
        let has_packet = !self.packet.text.trim().is_empty();
        let has_rand = self.rand.bounds().ok().flatten().is_some_and(|(_, to)| to > 0);
        match (has_packet, has_rand) {
            (true, true) => None,
            _ if self.kind.eq_ignore_ascii_case(NOISE_EXP_KIND) => Some(NoiseItemPayload::Exp),
            (false, true) => Some(NoiseItemPayload::Rand),
            (true, false) => Some(NoiseItemPayload::Packet),
            (false, false) => Some(NoiseItemPayload::Empty),
        }
    }
}

fn parse_noise_item(value: &Value) -> Option<NoiseMaskItem> {
    let object = value.as_object()?;
    Some(NoiseMaskItem {
        rand: RangeValue::parse(object.get("rand"))?,
        rand_range: RangeValue::parse(object.get("randRange"))?,
        kind: string_field(object.get("type"))?,
        packet: PacketValue::parse(object.get("packet"))?,
        delay: RangeValue::parse(object.get("delay"))?,
        extras: extras_of(object, KNOWN_NOISE_ITEM_KEYS),
    })
}

fn noise_item_to_value(draft: &NoiseMaskItem) -> Value {
    let mut object = Map::new();
    apply_range(&mut object, "rand", &draft.rand);
    apply_range(&mut object, "randRange", &draft.rand_range);
    apply_optional_string(&mut object, "type", &draft.kind);
    if let Some(packet) = draft.packet.to_value(&draft.kind) {
        object.insert("packet".to_owned(), packet);
    }
    apply_range(&mut object, "delay", &draft.delay);
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

/// `finalmask.udp[].settings` for `type = "noise"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoiseMaskSettings {
    /// `reset` `Int32Range` in seconds (`0` = send once); empty = key absent.
    pub reset: RangeValue,
    /// `noise[]`; empty = key absent.
    pub noise: Vec<NoiseMaskItem>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_NOISE_MASK_KEYS: &[&str] = &["reset", "noise"];

/// Parses `settings` as `noise`. `None` when `settings` isn't an object, any `noise[]` entry
/// isn't itself an object, or a known key can't be represented losslessly — callers should then
/// leave the layer's settings on the raw-JSON path.
pub fn parse_noise_mask_settings(settings: &Value) -> Option<NoiseMaskSettings> {
    let object = settings.as_object()?;
    let noise = match object.get("noise") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(parse_noise_item)
            .collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    Some(NoiseMaskSettings {
        reset: RangeValue::parse(object.get("reset"))?,
        noise,
        extras: extras_of(object, KNOWN_NOISE_MASK_KEYS),
    })
}

/// `packet` encodings `PraseByteSlice` knows (lower-case; empty = `array`).
pub(super) const PACKET_KINDS: &[&str] = &["", "array", "str", "hex", "base64"];

/// The `noise[].type` that turns `packet` into an expression (XTLS/Xray-core#6862, v26.9.30).
pub const NOISE_EXP_KIND: &str = "exp";

/// Validates a `noise` layer like `NoiseMask.Build()`. Per item: `packet` and a positive `rand`
/// exclude each other; `type: "exp"` needs a string expression ([`validate_noise_exp`]);
/// otherwise `randRange` lies within 0–255 and `packet` decodes per `type` — `str`/`hex`/`base64`
/// need a `packet` (decoding an absent value fails in the core), an unknown `type` is an error.
pub fn validate_noise_mask_settings(draft: &NoiseMaskSettings) -> Result<(), String> {
    draft.reset.validate().map_err(|error| format!("reset: {error}"))?;
    for (index, item) in draft.noise.iter().enumerate() {
        validate_noise_item(item).map_err(|error| format!("noise[{index}]: {error}"))?;
    }
    Ok(())
}

fn validate_noise_item(item: &NoiseMaskItem) -> Result<(), String> {
    for (name, value) in [("rand", &item.rand), ("randRange", &item.rand_range), ("delay", &item.delay)] {
        value.validate().map_err(|error| format!("{name}: {error}"))?;
    }
    let has_packet = !item.packet.text.trim().is_empty();
    let rand_to = item.rand.bounds().ok().flatten().map_or(0, |(_, to)| to);
    if has_packet && rand_to > 0 {
        return Err("set either packet or rand, not both".to_owned());
    }
    let kind = item.kind.to_lowercase();
    if kind == NOISE_EXP_KIND {
        return match item.packet.to_value(&item.kind) {
            Some(Value::String(exp)) => validate_noise_exp(&exp),
            _ => Err("packet of type \"exp\" must be an expression string, e.g. \"<b 0x01> <r 8-16>\"".to_owned()),
        };
    }
    if let Some((from, to)) = item.rand_range.bounds().ok().flatten()
        && (from < 0 || to > 255)
    {
        return Err("randRange must lie within 0–255".to_owned());
    }
    if !PACKET_KINDS.contains(&kind.as_str()) {
        return Err(format!(
            "unknown type \"{}\" (expected array, str, hex, base64 or exp)",
            item.kind
        ));
    }
    if !has_packet && !kind.is_empty() && kind != "array" {
        return Err(format!("packet is required for type \"{}\"", item.kind));
    }
    item.packet.validate(&item.kind)
}

/// Validates a `noise` `exp` expression like `parseNoiseExp` / `buildNoiseSegment`: one or more
/// `<key arg>` segments separated only by whitespace — `<b HEX>` bytes (`0x` prefix and inner
/// spaces allowed), `<r N>` / `<rc N>` / `<rd N>` random / ASCII / digit runs of a size or
/// `MIN-MAX` (0–65535, not reversed), `<t>` timestamp, `<c>` counter, `<n>` nonce.
///
/// Hand-written equivalent of the core's `<\s*([a-z]+)(?:\s+([^>]*?))?\s*>` scan (RE2 `\s` =
/// space, `\t`, `\n`, `\f`, `\r`).
pub fn validate_noise_exp(exp: &str) -> Result<(), String> {
    let is_space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\x0c' | '\r');
    let mut rest = exp;
    let mut segments = 0;
    loop {
        rest = rest.trim_start_matches(is_space);
        if rest.is_empty() {
            break;
        }
        let invalid = || format!("invalid noise exp near \"{rest}\"");
        let inner = rest.strip_prefix('<').ok_or_else(invalid)?;
        let close = inner.find('>').ok_or_else(invalid)?;
        let body = inner[..close].trim_start_matches(is_space);
        let key_len = body.find(|c: char| !c.is_ascii_lowercase()).unwrap_or(body.len());
        let (key, after_key) = body.split_at(key_len);
        // After the key: nothing (but spaces), or at least one space and then the argument.
        let arg = if after_key.trim_matches(is_space).is_empty() {
            ""
        } else if after_key.starts_with(is_space) {
            after_key.trim_matches(is_space)
        } else {
            return Err(invalid());
        };
        if key.is_empty() {
            return Err(invalid());
        }
        validate_noise_segment(key, arg)?;
        segments += 1;
        rest = &inner[close + 1..];
    }
    if segments == 0 {
        return Err(format!("empty noise exp: \"{exp}\""));
    }
    Ok(())
}

fn validate_noise_segment(key: &str, arg: &str) -> Result<(), String> {
    match key {
        "b" => {
            let joined: String = arg.split_whitespace().collect();
            let hex = joined.strip_prefix("0x").unwrap_or(&joined);
            let hex = hex.strip_prefix("0X").unwrap_or(hex);
            if hex.is_empty() {
                return Err("empty bytes in noise exp <b>".to_owned());
            }
            if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("invalid hex in noise exp: <b {arg}>"));
            }
            Ok(())
        }
        "r" | "rc" | "rd" => {
            if arg.is_empty() {
                return Err(format!("<{key}> in noise exp needs a size"));
            }
            match parse_range_string(arg) {
                Some((low, high)) if low >= 0 && high >= low && high <= 65535 => Ok(()),
                _ => Err(format!("invalid size in noise exp: <{key} {arg}> (N or MIN-MAX within 0–65535)")),
            }
        }
        "t" | "c" | "n" if arg.is_empty() => Ok(()),
        "t" | "c" | "n" => Err(format!("<{key}> in noise exp takes no argument")),
        _ => Err(format!("unknown <{key}> in noise exp (expected b, r, rc, rd, t, c, n)")),
    }
}

/// Builds the `settings` `Value` for a `noise` layer.
pub fn noise_mask_settings_to_value(draft: &NoiseMaskSettings) -> Value {
    let mut object = Map::new();
    apply_range(&mut object, "reset", &draft.reset);
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
// Lives in `super::finalmask_xdns` (Roadmap §2.6 stage 1.3: v26.9.30 schema + migration).

pub use super::finalmask_xdns::{
    XDNS_DEFAULT_LABEL_LIMIT, XDNS_DEFAULT_LEN_LIMIT, XDNS_RECORD_TYPES, XDNS_RESOLVER_KINDS,
    XdnsDomain, XdnsResolver, XdnsSettings, migrate_legacy_xdns_settings, parse_xdns_settings,
    validate_xdns_settings, xdns_has_legacy_fields, xdns_record_type_name, xdns_settings_to_value,
};

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

/// Parses `settings` as `xicmp`. `None` when `settings` isn't an object or a known key can't be
/// represented losslessly.
pub fn parse_xicmp_settings(settings: &Value) -> Option<XicmpSettings> {
    let object = settings.as_object()?;
    Some(XicmpSettings {
        dgram: bool_field(object.get("dgram"))?,
        ips: string_array_field(object.get("ips"))?,
        extras: extras_of(object, KNOWN_XICMP_KEYS),
    })
}

/// Validates an `xicmp` layer like `Xicmp.Build()`: every `ips[]` entry is an IP address.
pub fn validate_xicmp_settings(draft: &XicmpSettings) -> Result<(), String> {
    match draft.ips.iter().find(|ip| !is_ip_addr(ip)) {
        Some(ip) => Err(format!("ips: invalid IP address \"{ip}\"")),
        None => Ok(()),
    }
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
    use super::super::values::range_values_to_lines;
    use super::*;
    use serde_json::json;

    /// Roadmap §2.6 stage 0.1 regression: numeric `Int32Range`/`PortList` values and byte-array
    /// packets used to be dropped by the string-only reader on the next write.
    /// `parse_* → *_to_value` for one layer type.
    type RoundTrip = fn(&Value) -> Option<Value>;

    #[test]
    fn numeric_and_byte_array_values_round_trip_unchanged() {
        let cases: [(&str, Value, RoundTrip); 4] = [
            (
                "fragment",
                json!({"packets": "tlshello", "length": 100, "delay": 0,
                       "lengths": [100, "200-300"], "delays": [10], "maxSplit": 3}),
                |s| parse_fragment_mask_settings(s).map(|d| fragment_mask_settings_to_value(&d)),
            ),
            (
                "noise",
                json!({"reset": 0, "noise": [
                    {"rand": 16, "randRange": "0-255", "delay": 10},
                    {"type": "array", "packet": [1, 2, 255]},
                    {"packet": [7, 8]}
                ]}),
                |s| parse_noise_mask_settings(s).map(|d| noise_mask_settings_to_value(&d)),
            ),
            (
                "salamander",
                json!({"password": "p", "packetSize": 1200}),
                |s| parse_salamander_settings(s).map(|d| salamander_settings_to_value(&d)),
            ),
            (
                "udphop",
                json!({"mode": "intervalRemote", "interval": 30, "remotePorts": 443}),
                |s| parse_udphop_settings(s).map(|d| udphop_settings_to_value(&d)),
            ),
        ];
        for (name, settings, round_trip) in cases {
            assert_eq!(round_trip(&settings), Some(settings), "{name} must round-trip unchanged");
        }
    }

    /// Roadmap §2.6 stage 0.2: `parse → to_value` may normalize once (legacy aliases, trimming,
    /// dropped defaults), but its output must be a fixed point — otherwise every user edit would
    /// keep rewriting the layer.
    #[test]
    fn parse_to_value_is_idempotent_after_one_normalization() {
        let cases: [(&str, Value, RoundTrip); 8] = [
            ("fragment", json!({"packets": " tlshello ", "length": 100, "lengths": ["1-2", 3], "x": 1}),
             |s| parse_fragment_mask_settings(s).map(|d| fragment_mask_settings_to_value(&d))),
            ("salamander", json!({"password": " p ", "packetSize": 1200}),
             |s| parse_salamander_settings(s).map(|d| salamander_settings_to_value(&d))),
            ("sudoku", json!({"custom_table": "t", "padding_min": 1, "custom_tables": ["a", ""]}),
             |s| parse_sudoku_settings(s).map(|d| sudoku_settings_to_value(&d))),
            ("realm", json!({"url": "realm://t@h/id", "stunServers": ["s:3478"], "portMapping": {"enabled": true}}),
             |s| parse_realm_settings(s).map(|d| realm_settings_to_value(&d))),
            ("udphop", json!({"mode": "intervalRemote", "interval": "5-10", "remotePorts": 443, "sockopt": {"mark": 1}}),
             |s| parse_udphop_settings(s).map(|d| udphop_settings_to_value(&d))),
            ("noise", json!({"reset": null, "noise": [{"type": "", "packet": [1], "rand": "1-2"}]}),
             |s| parse_noise_mask_settings(s).map(|d| noise_mask_settings_to_value(&d))),
            ("xdns", json!({"domain": "legacy", "domains": [{"name": " t.example.com ", "types": [16]}], "resolvers": []}),
             |s| parse_xdns_settings(s).map(|d| xdns_settings_to_value(&d))),
            ("xicmp", json!({"dgram": false, "ips": []}),
             |s| parse_xicmp_settings(s).map(|d| xicmp_settings_to_value(&d))),
        ];
        for (name, settings, round_trip) in cases {
            let once = round_trip(&settings).unwrap_or_else(|| panic!("{name} parses"));
            let twice = round_trip(&once).unwrap_or_else(|| panic!("{name} re-parses"));
            assert_eq!(once, twice, "{name} is not a fixed point after normalization");
        }
    }

    /// A known key holding a shape the typed struct can't represent sends the layer to the
    /// raw-JSON editor instead of silently dropping the key.
    #[test]
    fn unrepresentable_known_keys_fall_back_to_raw_json() {
        assert!(parse_fragment_mask_settings(&json!({"lengths": [1.5]})).is_none());
        assert!(parse_fragment_mask_settings(&json!({"packets": 1})).is_none());
        assert!(parse_salamander_settings(&json!({"password": 123})).is_none());
        assert!(parse_sudoku_settings(&json!({"paddingMin": "10"})).is_none());
        assert!(parse_realm_settings(&json!({"tlsConfig": "x"})).is_none());
        assert!(parse_udphop_settings(&json!({"remoteIPs": "10.0.0.1"})).is_none());
        assert!(parse_noise_mask_settings(&json!({"noise": [{"packet": [300]}]})).is_none());
        assert!(parse_xdns_settings(&json!({"domains": ["t.example.com"]})).is_none());
        assert!(parse_xicmp_settings(&json!({"dgram": "yes"})).is_none());
    }

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
        assert_eq!(
            range_values_to_lines(&draft.lengths),
            vec!["1-2".to_owned(), "3-4".to_owned()]
        );
        assert_eq!(draft.delay.text, "");
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
        assert_eq!(draft.packet_size.text, "1200-1500");
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
    fn realm_roundtrip_preserves_raw_tls_config() {
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

    /// Roadmap §2.6 stage 1.1: `sockopt` is not a mask field any more (#6754) — kept verbatim
    /// until explicitly removed, never rewritten through a typed editor.
    #[test]
    fn udphop_keeps_legacy_sockopt_verbatim_until_removed() {
        let settings = json!({
            "sockopt": {"mark": 255, "futureSockopt": true},
            "mode": "intervalRemote",
            "interval": "5-10",
            "remotePorts": "20000-30000",
            "remoteIPs": ["10.0.0.1"]
        });
        let mut draft = parse_udphop_settings(&settings).expect("parsed");
        assert!(draft.has_legacy_sockopt());
        assert_eq!(draft.remote_ports.text, "20000-30000");
        assert_eq!(udphop_settings_to_value(&draft), settings);

        draft.remove_legacy_sockopt();
        assert!(!draft.has_legacy_sockopt());
        let value = udphop_settings_to_value(&draft);
        assert!(value.get("sockopt").is_none());
        assert_eq!(value["mode"], "intervalRemote");
    }

    #[test]
    fn udphop_mode_parses_like_the_core() {
        let modes = parse_udphop_mode("intervalLocal,PERCONNREMOTE").expect("valid");
        assert_eq!(
            modes,
            UdpHopModes { interval_local: true, interval_remote: false, per_conn_remote: true }
        );
        assert_eq!(modes.to_mode_text(), "intervalLocal,perConnRemote");
        assert!(modes.picks_remote());
        // Duplicates are harmless in the core.
        assert!(parse_udphop_mode("intervalRemote,intervalRemote").is_ok());
        // `strings.Split` without trimming: a space makes the token invalid.
        assert!(parse_udphop_mode("intervalLocal, intervalRemote").unwrap_err().contains("\" intervalRemote\""));
        // Empty mode = one empty token = error in the core.
        assert!(parse_udphop_mode("").unwrap_err().contains("required"));
        assert!(parse_udphop_mode("intervalLocal,").is_err());
        assert!(parse_udphop_mode("native").is_err());
        assert_eq!(UdpHopModes::default().to_mode_text(), "");
    }

    #[test]
    fn udphop_validation_mirrors_build() {
        let valid = |settings: Value| {
            validate_udphop_settings(&parse_udphop_settings(&settings).expect("parsed"))
        };
        for ok in [
            json!({"mode": "intervalLocal"}),
            json!({"mode": "intervalRemote", "interval": 0}),
            json!({"mode": "intervalRemote", "interval": "0"}),
            json!({"mode": "intervalRemote", "interval": 5}),
            json!({"mode": "intervalRemote", "interval": "10-5"}),
            json!({"mode": "perConnRemote", "remotePorts": "443,20000-30000", "remoteIPs": [
                "10.0.0.1", "10.0.0.0/8", "2001:db8::/32", "::ffff:1.2.3.4", "fe80::1%eth0", "0.0.0.0/0"
            ]}),
        ] {
            assert_eq!(valid(ok.clone()), Ok(()), "{ok}");
        }
        for (bad, needle) in [
            (json!({}), "required"),
            (json!({"mode": "intervalRemote", "interval": 4}), "at least 5"),
            (json!({"mode": "intervalRemote", "interval": "3-10"}), "at least 5"),
            (json!({"mode": "intervalRemote", "interval": "-5"}), "at least 5"),
            (json!({"mode": "intervalRemote", "interval": "a-b"}), "interval"),
            (json!({"mode": "intervalRemote", "remotePorts": "70000"}), "remotePorts"),
            (json!({"mode": "intervalRemote", "remoteIPs": ["example.com"]}), "remoteIPs"),
            (json!({"mode": "intervalRemote", "remoteIPs": ["10.0.0.0/33"]}), "remoteIPs"),
            (json!({"mode": "intervalRemote", "remoteIPs": ["10.0.0.0/08"]}), "remoteIPs"),
            (json!({"mode": "intervalRemote", "remoteIPs": ["10.0.0.1%eth0"]}), "remoteIPs"),
            (json!({"mode": "intervalRemote", "remoteIPs": ["fe80::%eth0/64"]}), "remoteIPs"),
        ] {
            let error = valid(bad.clone()).expect_err(&bad.to_string());
            assert!(error.contains(needle), "{bad}: {error}");
        }
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

    /// `(settings, Some(error substring))` cases for one layer's `parse → validate`.
    fn check_cases<D>(
        parse: fn(&Value) -> Option<D>,
        validate: fn(&D) -> Result<(), String>,
        cases: &[(Value, Option<&str>)],
    ) {
        for (settings, expected) in cases {
            let result = validate(&parse(settings).unwrap_or_else(|| panic!("{settings} parses")));
            match (expected, result) {
                (None, Ok(())) => {}
                (Some(needle), Err(error)) => assert!(error.contains(needle), "{settings}: {error}"),
                (expected, result) => panic!("{settings}: expected {expected:?}, got {result:?}"),
            }
        }
    }

    /// Roadmap §2.6 stage 1.4: `FragmentMask.Build()`.
    #[test]
    fn fragment_validation_mirrors_build() {
        check_cases(parse_fragment_mask_settings, validate_fragment_mask_settings, &[
            (json!({"packets": "tlshello", "length": "100-200"}), None),
            (json!({"packets": "TLSHello", "length": 1}), None),
            (json!({"packets": "1-3", "lengths": ["0-5", "1-5"], "delays": [0]}), None),
            // Only the first number counts, as written: "3-0" passes, "0-3" does not.
            (json!({"packets": "3-0", "length": 5}), None),
            (json!({"packets": "0-3", "length": 5}), Some("must not start at 0")),
            (json!({"packets": "0", "length": 5}), Some("must not start at 0")),
            (json!({"packets": "tls", "length": 5}), Some("neither tlshello")),
            (json!({"packets": "tlshello"}), Some("length is required")),
            (json!({"length": "0-10"}), Some("length is required")),
            // `lengths` wins over `length`; only its last entry matters.
            (json!({"length": 5, "lengths": ["1-2", "0-3"]}), Some("last entry")),
            (json!({"lengths": ["a"]}), Some("lengths[0]")),
            (json!({"length": 5, "maxSplit": "x-y"}), Some("maxSplit")),
        ]);
    }

    /// Roadmap §2.6 stage 1.4: `Salamander.Build()` (Gecko packet sizes); stage 2.5: the key
    /// length `NewSalamanderObfuscator` checks when the layer starts.
    #[test]
    fn salamander_validation_mirrors_build() {
        check_cases(parse_salamander_settings, validate_salamander_settings, &[
            (json!({"password": "pass"}), None),
            (json!({"password": "pass", "packetSize": "1-2048"}), None),
            (json!({"password": "pass", "packetSize": 1200}), None),
            // A non-positive upper bound means plain salamander.
            (json!({"password": "pass", "packetSize": "-5-0"}), None),
            (json!({"packetSize": "0-1200"}), Some("1–2048")),
            (json!({"packetSize": 4096}), Some("1–2048")),
            (json!({"packetSize": "big"}), Some("packetSize")),
            // Bytes, not characters: "äö" is 4 bytes.
            (json!({"password": "äö"}), None),
            (json!({"password": "abc"}), Some("password is 3 bytes")),
            (json!({}), Some("password is 0 bytes")),
        ]);
    }

    /// Roadmap §2.6 stage 2.5: which writes `packets` selects, and when `tlshello` sends its
    /// records in one write (`fragment/conn.go`).
    #[test]
    fn fragment_packets_mode_and_record_merging_follow_the_core() {
        assert_eq!(fragment_packets_mode(""), Some(FragmentPackets::All));
        assert_eq!(fragment_packets_mode("TLSHello"), Some(FragmentPackets::TlsHello));
        assert_eq!(fragment_packets_mode("2"), Some(FragmentPackets::Range { from: 2, to: 2 }));
        // Kept as written: the core does not reorder `packets`.
        assert_eq!(fragment_packets_mode("3-1"), Some(FragmentPackets::Range { from: 3, to: 1 }));
        assert_eq!(fragment_packets_mode("tls"), None);

        let merges = |settings: Value| parse_fragment_mask_settings(&settings).expect("parsed").merges_tls_records();
        assert!(merges(json!({"packets": "tlshello", "length": 5})));
        assert!(merges(json!({"delay": 0})));
        assert!(merges(json!({"delays": ["0"]})));
        // `delays` wins over `delay`.
        assert!(merges(json!({"delay": 10, "delays": [0]})));
        assert!(!merges(json!({"delay": "5-10"})));
        assert!(!merges(json!({"delays": [0, 0]})));
    }

    /// Roadmap §2.6 stage 2.5: what a `noise` item sends (`buildPacket`).
    #[test]
    fn noise_item_payload_follows_build_packet() {
        let payload = |item: Value| {
            let settings = json!({"noise": [item]});
            parse_noise_mask_settings(&settings).expect("parsed").noise[0].payload()
        };
        assert_eq!(payload(json!({})), Some(NoiseItemPayload::Empty));
        assert_eq!(payload(json!({"rand": "0"})), Some(NoiseItemPayload::Empty));
        assert_eq!(payload(json!({"rand": "8-16"})), Some(NoiseItemPayload::Rand));
        assert_eq!(payload(json!({"packet": [1, 2]})), Some(NoiseItemPayload::Packet));
        assert_eq!(payload(json!({"type": "EXP", "packet": "<r 8>"})), Some(NoiseItemPayload::Exp));
        assert_eq!(payload(json!({"packet": "x", "type": "str", "rand": 4})), None);
    }

    /// Roadmap §2.6 stage 2.5: `ascii` and the custom tables are checked as `getTables` reads them.
    #[test]
    fn sudoku_validation_mirrors_get_tables() {
        check_cases(parse_sudoku_settings, validate_sudoku_settings, &[
            (json!({}), None),
            (json!({"ascii": " Prefer_ASCII "}), None),
            (json!({"ascii": "entropy", "customTable": "xpxvvpvv"}), None),
            // Spaces and case are ignored; a blank entry is the built-in layout.
            (json!({"customTables": ["XP XV VP VV", " "]}), None),
            // The legacy key is read when the canonical one is absent.
            (json!({"custom_table": "xxxpvvvv"}), Some("customTable: \"xxxpvvvv\" must contain exactly 2 x")),
            (json!({"customTable": "xpxvvpva"}), Some("invalid character 'a'")),
            (json!({"customTables": ["xpxvvpvv", "xpxvvpv"]}), Some("customTables[1]")),
            // `customTables` hides `customTable`; the ASCII layout reads neither.
            (json!({"customTable": "bad", "customTables": ["xpxvvpvv"]}), None),
            (json!({"ascii": "ascii", "customTables": ["bad"]}), None),
            (json!({"ascii": "binary"}), Some("ascii: unknown mode \"binary\"")),
        ]);
        let padding = |settings: Value| parse_sudoku_settings(&settings).expect("parsed").effective_padding();
        assert_eq!(padding(json!({})), (0, 0));
        assert_eq!(padding(json!({"paddingMin": 20, "paddingMax": 5})), (20, 20));
        assert_eq!(padding(json!({"padding_min": 150, "paddingMax": 300})), (100, 100));
    }

    /// Roadmap §2.6 stage 1.4: `NoiseMask.Build()`, including `type: "exp"` (#6862).
    #[test]
    fn noise_validation_mirrors_build() {
        let item = |item: Value| json!({"reset": "5-10", "noise": [{"rand": 1}, item]});
        check_cases(parse_noise_mask_settings, validate_noise_mask_settings, &[
            (item(json!({"rand": "10-20", "randRange": "65-90", "delay": 5})), None),
            (item(json!({"packet": [1, 2, 3]})), None),
            (item(json!({"type": "str", "packet": "hello"})), None),
            (item(json!({"type": "HEX", "packet": "0a0b"})), None),
            (item(json!({"type": "exp", "packet": " <b 0x16 03 01> <r 8-16>\n<rc 4><rd 2> <t><c> < n > "})), None),
            // `rand` with a non-positive upper bound does not clash with `packet`.
            (item(json!({"packet": [1], "rand": 0})), None),
            (item(json!({"packet": [1], "rand": "1-4"})), Some("noise[1]: set either packet or rand")),
            (item(json!({"rand": 4, "randRange": "0-300"})), Some("randRange")),
            (item(json!({"type": "str"})), Some("packet is required")),
            (item(json!({"type": "bin", "packet": "x"})), Some("unknown type")),
            (item(json!({"type": "hex", "packet": "abc"})), Some("hex")),
            (item(json!({"type": "exp"})), Some("expression string")),
            (item(json!({"type": "exp", "packet": [1]})), Some("expression string")),
            (item(json!({"type": "exp", "packet": "<r 8> x"})), Some("near")),
            (item(json!({"type": "exp", "packet": "<B 01>"})), Some("near")),
            (item(json!({"type": "exp", "packet": "<b>"})), Some("empty bytes")),
            (item(json!({"type": "exp", "packet": "<b 0x123>"})), Some("invalid hex")),
            (item(json!({"type": "exp", "packet": "<r>"})), Some("needs a size")),
            (item(json!({"type": "exp", "packet": "<r 16-8>"})), Some("invalid size")),
            (item(json!({"type": "exp", "packet": "<rd 70000>"})), Some("invalid size")),
            (item(json!({"type": "exp", "packet": "<t 1>"})), Some("takes no argument")),
            (item(json!({"type": "exp", "packet": "<x>"})), Some("unknown <x>")),
            (item(json!({"type": "exp", "packet": "<r8>"})), Some("near")),
            (item(json!({"type": "exp", "packet": "  "})), Some("expression string")),
            (json!({"reset": "a"}), Some("reset")),
        ]);
        assert!(validate_noise_exp("   ").unwrap_err().contains("empty noise exp"));
    }

    /// Roadmap §2.6 stage 1.4: `Xicmp.Build()` (`netip.ParseAddr`).
    #[test]
    fn xicmp_validation_mirrors_build() {
        check_cases(parse_xicmp_settings, validate_xicmp_settings, &[
            (json!({"ips": ["1.2.3.4", "2001:db8::1", "fe80::1%eth0"]}), None),
            (json!({"ips": ["10.0.0.0/8"]}), Some("10.0.0.0/8")),
            (json!({"ips": ["example.com"]}), Some("invalid IP")),
        ]);
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
