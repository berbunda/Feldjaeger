//! FinalMask layer `type = "header-custom"` — scripted header bytes (Roadmap §2.6 stages 2.2
//! TCP, 2.3 UDP). The two chains have different schemas.
//!
//! Checked against `XTLS/Xray-core@main` (`infra/conf/transport_finalmask.go` `HeaderCustomTCP` /
//! `TCPItem`, `HeaderCustomUDP` / `UDPItem`; `transport/internet/finalmask/header/custom/
//! {tcp,udp}.go`).
//!
//! **TCP** (`finalmask.tcp[]`): `settings` is `{clients, servers, errors}`, each a list of
//! *sequences*, each sequence a list of items — a handshake exchanged before the real stream.
//!
//! - The client writes `clients[i]`, then reads `servers[i]`; the server reads `clients[i]` and
//!   answers with `servers[i]`. Leftover `servers` sequences follow after the last client one.
//! - When a received sequence does not match, the server writes `errors[i]` (if present) and
//!   refuses the connection; the client never uses `errors`.
//! - `delay` (ms) only applies when writing: buffered items are flushed, then the writer sleeps.
//!
//! **UDP** (`finalmask.udp[]`): `settings` is `{mode, client, server}`, two item lists (no
//! `delay`). `mode` (case-sensitive) is `prefix` (default, empty) — `client` / `server` are a
//! header in front of every packet the respective side sends, a received packet whose header
//! does not match is dropped — or `standalone` — `client` is a separate handshake packet the
//! client sends once per destination and waits for, `server` is the reply; data packets travel
//! unchanged.
//!
//! An item is exactly one *kind* — fixed bytes (`packet` decoded per `type`), `rand` random bytes
//! (values within `randRange`, default 0–255; any content is accepted when reading), the bytes
//! captured earlier under a `reuse` name, or a computed `transform` — or none. `capture` saves
//! the item's bytes under a name for later `reuse` / `transform`.
//!
//! The typed draft keeps every value in the JSON shape it was read in (strings verbatim, `rand`
//! as a Go `int32` number, ranges and packets via [`super::values`]); `transform` stays a raw JSON
//! object (its expression grammar is open-ended — `op` names are evaluated at runtime). Shapes
//! the draft cannot hold losslessly keep the layer on the raw-JSON editor: a known key of the
//! wrong JSON type, and `packet: null` / `transform: null` (a `json.RawMessage` `null` counts as a
//! set `packet` in the core, so dropping it would change validation).

use serde_json::{Map, Value};

use super::finalmask_layers::{apply_extras, extras_of};
use super::finalmask_mkcp::verbatim_string;
use super::values::{PacketValue, RangeValue};

/// The three sequence lists of a `header-custom` TCP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderCustomTcpGroup {
    /// `clients` — written by the client, checked by the server.
    Clients,
    /// `servers` — written by the server, checked by the client.
    Servers,
    /// `errors` — written by the server when `clients[i]` does not match.
    Errors,
}

impl HeaderCustomTcpGroup {
    /// All groups in `settings` order.
    pub const ALL: [Self; 3] = [Self::Clients, Self::Servers, Self::Errors];

    /// The JSON key (`"clients"` / `"servers"` / `"errors"`).
    pub fn key(self) -> &'static str {
        match self {
            Self::Clients => "clients",
            Self::Servers => "servers",
            Self::Errors => "errors",
        }
    }
}

/// What a `header-custom` item contributes to the byte stream (`validateCustomItemSpec`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCustomItemKind {
    /// No kind: nothing is written or read (a `delay` point).
    Empty,
    /// `packet`: fixed bytes.
    Packet,
    /// `rand > 0`: random bytes.
    Rand,
    /// `reuse`: the bytes captured under that name.
    Reuse,
    /// `transform`: computed bytes.
    Transform,
}

/// One `header-custom` item: `TCPItem`, or `UDPItem` (no `delay` — the key is kept in `extras`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderCustomItem {
    /// `delay` `Int32Range` in ms before writing this item (TCP only); empty = key absent.
    pub delay: RangeValue,
    /// `rand` (Go `int32`) as text; empty = key absent. Written as a JSON number when it parses,
    /// otherwise as typed (Save then reports the core's decode error).
    pub rand: String,
    /// `randRange` `Int32Range` — byte values for `rand` (absent = 0–255); empty = key absent.
    pub rand_range: RangeValue,
    /// `type`, verbatim — `packet` encoding: `array` (default) | `str` | `hex` | `base64`.
    pub kind: String,
    /// `packet`, interpreted per `kind`; empty = key absent.
    pub packet: PacketValue,
    /// `capture`, verbatim — variable name the item's bytes are saved under.
    pub capture: String,
    /// `reuse`, verbatim — variable name whose bytes this item is.
    pub reuse: String,
    /// `transform` expression object, kept as raw JSON; `None` = key absent.
    pub transform: Option<Value>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

impl HeaderCustomItem {
    /// The item's kind as the core counts it; `None` when more than one is set (Save refuses
    /// that). `capture` without a kind is also refused, but its kind is still [`Empty`].
    ///
    /// [`Empty`]: HeaderCustomItemKind::Empty
    pub fn kind(&self) -> Option<HeaderCustomItemKind> {
        let rand_set = self.rand.trim().parse::<i64>().is_ok_and(|n| n > 0);
        let set = [
            (self.packet.to_value(&self.kind).is_some(), HeaderCustomItemKind::Packet),
            (rand_set, HeaderCustomItemKind::Rand),
            (!self.reuse.is_empty(), HeaderCustomItemKind::Reuse),
            (self.transform.is_some(), HeaderCustomItemKind::Transform),
        ];
        let mut kinds = set.into_iter().filter(|(on, _)| *on).map(|(_, kind)| kind);
        match (kinds.next(), kinds.next()) {
            (None, _) => Some(HeaderCustomItemKind::Empty),
            (Some(kind), None) => Some(kind),
            (Some(_), Some(_)) => None,
        }
    }
}

/// One group's sequences.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderCustomSequences {
    /// The sequences, each an ordered list of items.
    pub sequences: Vec<Vec<HeaderCustomItem>>,
    /// The key was on disk as an array — written back even when empty (`"errors": []`).
    pub present: bool,
}

/// `finalmask.tcp[].settings` for `type = "header-custom"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderCustomTcpSettings {
    /// `clients`.
    pub clients: HeaderCustomSequences,
    /// `servers`.
    pub servers: HeaderCustomSequences,
    /// `errors`.
    pub errors: HeaderCustomSequences,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

impl HeaderCustomTcpSettings {
    /// The sequences of `group`.
    pub fn group(&self, group: HeaderCustomTcpGroup) -> &HeaderCustomSequences {
        match group {
            HeaderCustomTcpGroup::Clients => &self.clients,
            HeaderCustomTcpGroup::Servers => &self.servers,
            HeaderCustomTcpGroup::Errors => &self.errors,
        }
    }

    /// The sequences of `group`, mutable.
    pub fn group_mut(&mut self, group: HeaderCustomTcpGroup) -> &mut HeaderCustomSequences {
        match group {
            HeaderCustomTcpGroup::Clients => &mut self.clients,
            HeaderCustomTcpGroup::Servers => &mut self.servers,
            HeaderCustomTcpGroup::Errors => &mut self.errors,
        }
    }
}

/// The `header-custom` UDP `mode` the core picks for an empty value.
pub const HEADER_CUSTOM_UDP_DEFAULT_MODE: &str = "prefix";

/// The two item lists of a `header-custom` UDP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderCustomUdpGroup {
    /// `client` — sent by the client.
    Client,
    /// `server` — sent by the server.
    Server,
}

impl HeaderCustomUdpGroup {
    /// Both groups in `settings` order.
    pub const ALL: [Self; 2] = [Self::Client, Self::Server];

    /// The JSON key (`"client"` / `"server"`).
    pub fn key(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// One UDP group's items.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderCustomItems {
    /// The items, in order.
    pub items: Vec<HeaderCustomItem>,
    /// The key was on disk as an array — written back even when empty (`"server": []`).
    pub present: bool,
}

/// `finalmask.udp[].settings` for `type = "header-custom"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderCustomUdpSettings {
    /// `mode`, verbatim; empty = key absent (= `prefix`).
    pub mode: String,
    /// `client`.
    pub client: HeaderCustomItems,
    /// `server`.
    pub server: HeaderCustomItems,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

impl HeaderCustomUdpSettings {
    /// The items of `group`, mutable.
    pub fn group_mut(&mut self, group: HeaderCustomUdpGroup) -> &mut HeaderCustomItems {
        match group {
            HeaderCustomUdpGroup::Client => &mut self.client,
            HeaderCustomUdpGroup::Server => &mut self.server,
        }
    }

    /// `true` for `mode = "standalone"` (exact, like the core); `false` for `prefix`, empty or
    /// an unknown mode (Save refuses that).
    pub fn is_standalone(&self) -> bool {
        self.mode == "standalone"
    }
}

const KNOWN_TCP_ITEM_KEYS: &[&str] =
    &["delay", "rand", "randRange", "type", "packet", "capture", "reuse", "transform"];

/// `UDPItem` has no `delay`: an on-disk `delay` is an unknown key there.
const KNOWN_UDP_ITEM_KEYS: &[&str] = &["rand", "randRange", "type", "packet", "capture", "reuse", "transform"];

const KNOWN_HEADER_CUSTOM_TCP_KEYS: &[&str] = &["clients", "servers", "errors"];

const KNOWN_HEADER_CUSTOM_UDP_KEYS: &[&str] = &["mode", "client", "server"];

/// A Go `int32` read as text: absent / `null` = `""`; `None` for any other non-`int32` value.
fn int32_text(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => Some(String::new()),
        Some(value) => value.as_i64().filter(|n| i32::try_from(*n).is_ok()).map(|n| n.to_string()),
    }
}

fn parse_tcp_item(value: &Value) -> Option<HeaderCustomItem> {
    parse_item(value, KNOWN_TCP_ITEM_KEYS)
}

fn parse_udp_item(value: &Value) -> Option<HeaderCustomItem> {
    parse_item(value, KNOWN_UDP_ITEM_KEYS)
}

/// One item; `delay` is read only when `known` lists it (TCP), otherwise it stays in `extras`.
fn parse_item(value: &Value, known: &[&str]) -> Option<HeaderCustomItem> {
    let object = value.as_object()?;
    let delay = if known.contains(&"delay") { RangeValue::parse(object.get("delay"))? } else { RangeValue::default() };
    let packet = match object.get("packet") {
        Some(Value::Null) => return None,
        packet => PacketValue::parse(packet)?,
    };
    let transform = match object.get("transform") {
        None => None,
        Some(value) if value.is_object() => Some(value.clone()),
        Some(_) => return None,
    };
    Some(HeaderCustomItem {
        delay,
        rand: int32_text(object.get("rand"))?,
        rand_range: RangeValue::parse(object.get("randRange"))?,
        kind: verbatim_string(object.get("type"))?,
        packet,
        capture: verbatim_string(object.get("capture"))?,
        reuse: verbatim_string(object.get("reuse"))?,
        transform,
        extras: extras_of(object, known),
    })
}

/// Writes an item of either chain: a UDP item's `delay` is always empty (its on-disk `delay`
/// lives in `extras`), so the same writer serves both.
fn item_to_value(item: &HeaderCustomItem) -> Value {
    let mut object = Map::new();
    let mut insert = |key: &str, value: Option<Value>| {
        if let Some(value) = value {
            object.insert(key.to_owned(), value);
        }
    };
    insert("delay", item.delay.to_value());
    let rand = item.rand.trim();
    insert(
        "rand",
        (!rand.is_empty()).then(|| rand.parse::<i64>().map_or_else(|_| Value::String(item.rand.clone()), Value::from)),
    );
    insert("randRange", item.rand_range.to_value());
    for (key, text) in [("type", &item.kind), ("capture", &item.capture), ("reuse", &item.reuse)] {
        insert(key, (!text.is_empty()).then(|| Value::String(text.clone())));
    }
    insert("packet", item.packet.to_value(&item.kind));
    insert("transform", item.transform.clone());
    apply_extras(&mut object, &item.extras);
    Value::Object(object)
}

fn parse_sequences(value: Option<&Value>) -> Option<HeaderCustomSequences> {
    match value {
        None | Some(Value::Null) => Some(HeaderCustomSequences::default()),
        Some(Value::Array(sequences)) => Some(HeaderCustomSequences {
            sequences: sequences
                .iter()
                .map(|sequence| sequence.as_array()?.iter().map(parse_tcp_item).collect())
                .collect::<Option<_>>()?,
            present: true,
        }),
        Some(_) => None,
    }
}

/// Parses `settings` as `header-custom` TCP. `None` when `settings` isn't an object or any known
/// key can't be represented losslessly (see the module docs) — the layer then stays on the
/// raw-JSON editor.
pub fn parse_header_custom_tcp_settings(settings: &Value) -> Option<HeaderCustomTcpSettings> {
    let object = settings.as_object()?;
    Some(HeaderCustomTcpSettings {
        clients: parse_sequences(object.get("clients"))?,
        servers: parse_sequences(object.get("servers"))?,
        errors: parse_sequences(object.get("errors"))?,
        extras: extras_of(object, KNOWN_HEADER_CUSTOM_TCP_KEYS),
    })
}

/// Builds the `settings` `Value` for a `header-custom` TCP layer. A group is written when it has
/// sequences or was present on disk; an empty sequence stays (`[]` — the server still answers
/// the matching client sequence with nothing).
pub fn header_custom_tcp_settings_to_value(draft: &HeaderCustomTcpSettings) -> Value {
    let mut object = Map::new();
    for group in HeaderCustomTcpGroup::ALL {
        let sequences = draft.group(group);
        if sequences.present || !sequences.sequences.is_empty() {
            let value = sequences
                .sequences
                .iter()
                .map(|sequence| Value::Array(sequence.iter().map(item_to_value).collect()))
                .collect();
            object.insert(group.key().to_owned(), Value::Array(value));
        }
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

fn parse_udp_items(value: Option<&Value>) -> Option<HeaderCustomItems> {
    match value {
        None | Some(Value::Null) => Some(HeaderCustomItems::default()),
        Some(Value::Array(items)) => Some(HeaderCustomItems {
            items: items.iter().map(parse_udp_item).collect::<Option<_>>()?,
            present: true,
        }),
        Some(_) => None,
    }
}

/// Parses `settings` as `header-custom` UDP. `None` when `settings` isn't an object, `mode`
/// isn't a string, or an item can't be represented losslessly (see the module docs).
pub fn parse_header_custom_udp_settings(settings: &Value) -> Option<HeaderCustomUdpSettings> {
    let object = settings.as_object()?;
    Some(HeaderCustomUdpSettings {
        mode: verbatim_string(object.get("mode"))?,
        client: parse_udp_items(object.get("client"))?,
        server: parse_udp_items(object.get("server"))?,
        extras: extras_of(object, KNOWN_HEADER_CUSTOM_UDP_KEYS),
    })
}

/// Builds the `settings` `Value` for a `header-custom` UDP layer: `mode` when set, a group when
/// it has items or was present on disk.
pub fn header_custom_udp_settings_to_value(draft: &HeaderCustomUdpSettings) -> Value {
    let mut object = Map::new();
    if !draft.mode.is_empty() {
        object.insert("mode".to_owned(), Value::String(draft.mode.clone()));
    }
    for (group, items) in [(HeaderCustomUdpGroup::Client, &draft.client), (HeaderCustomUdpGroup::Server, &draft.server)] {
        if items.present || !items.items.is_empty() {
            let value = items.items.iter().map(item_to_value).collect();
            object.insert(group.key().to_owned(), Value::Array(value));
        }
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::config::stream::finalmask_raw::validate_header_custom_tcp;
    use serde_json::json;

    fn round_trip(settings: &Value) -> Option<Value> {
        parse_header_custom_tcp_settings(settings).map(|draft| header_custom_tcp_settings_to_value(&draft))
    }

    #[test]
    fn documented_shapes_round_trip_unchanged() {
        let settings = json!({
            "clients": [[
                {"delay": "10-20", "rand": 8, "randRange": "65-90"},
                {"type": "str", "packet": "GET / HTTP/1.1\r\nHost: a\r\n\r\n"},
                {"packet": [1, 2, 3], "capture": "head"},
                {"reuse": "head", "delay": 5},
                {"transform": {"op": "xor", "args": [{"reuse": "head"}, {"type": "hex", "bytes": "ff"}]}},
                {}
            ], []],
            "servers": [[{"type": "base64", "packet": "AQID", "future": 1}]],
            "errors": [],
            "x": true
        });
        assert_eq!(round_trip(&settings), Some(settings));
        assert_eq!(round_trip(&json!({})), Some(json!({})));
    }

    #[test]
    fn unrepresentable_shapes_stay_raw() {
        for settings in [
            json!([]),
            json!({"clients": {}}),
            json!({"clients": [{}]}),
            json!({"clients": [[1]]}),
            json!({"clients": [[{"rand": "4"}]]}),
            json!({"clients": [[{"rand": 4_000_000_000_i64}]]}),
            json!({"clients": [[{"rand": 1.5}]]}),
            json!({"clients": [[{"packet": null, "reuse": "x"}]]}),
            json!({"clients": [[{"packet": 7}]]}),
            json!({"clients": [[{"transform": null}]]}),
            json!({"clients": [[{"transform": "xor"}]]}),
            json!({"clients": [[{"capture": 1}]]}),
            json!({"servers": [[{"delay": true}]]}),
        ] {
            assert!(parse_header_custom_tcp_settings(&settings).is_none(), "{settings}");
        }
        // `null` groups and scalar `null`s are the core's zero values.
        let parsed = parse_header_custom_tcp_settings(&json!({"errors": null, "clients": [[{"rand": null}]]}))
            .expect("typed");
        assert!(!parsed.errors.present);
        assert_eq!(parsed.clients.sequences[0][0], HeaderCustomItem::default());
    }

    #[test]
    fn edits_write_core_shapes() {
        let mut draft = HeaderCustomTcpSettings::default();
        draft.servers.sequences.push(vec![
            HeaderCustomItem { rand: " 16 ".to_owned(), rand_range: RangeValue::new("0-255"), ..Default::default() },
            HeaderCustomItem { kind: "array".to_owned(), packet: PacketValue::new("22, 3, 1"), ..Default::default() },
            HeaderCustomItem { rand: "x".to_owned(), ..Default::default() },
        ]);
        let value = header_custom_tcp_settings_to_value(&draft);
        assert_eq!(
            value,
            json!({"servers": [[{"rand": 16, "randRange": "0-255"}, {"type": "array", "packet": [22, 3, 1]}, {"rand": "x"}]]})
        );
        // Text the core can't decode is written as typed, and Save names it.
        assert!(validate_header_custom_tcp(&value).unwrap_err().contains("servers[0][2]: rand"));

        // Removing every sequence of a group that was on disk keeps `[]`; a new group disappears.
        let mut draft = parse_header_custom_tcp_settings(&json!({"errors": [[{"rand": 1}]]})).expect("typed");
        draft.errors.sequences.clear();
        draft.clients.sequences.push(Vec::new());
        draft.clients.sequences.clear();
        assert_eq!(header_custom_tcp_settings_to_value(&draft), json!({"errors": []}));
    }

    #[test]
    fn kind_mirrors_validate_custom_item_spec() {
        let item = |value: Value| parse_tcp_item(&value).expect("typed");
        assert_eq!(item(json!({"delay": 5})).kind(), Some(HeaderCustomItemKind::Empty));
        assert_eq!(item(json!({"capture": "x"})).kind(), Some(HeaderCustomItemKind::Empty));
        assert_eq!(item(json!({"packet": [1]})).kind(), Some(HeaderCustomItemKind::Packet));
        assert_eq!(item(json!({"rand": 4})).kind(), Some(HeaderCustomItemKind::Rand));
        // `rand <= 0` is not a kind.
        assert_eq!(item(json!({"rand": 0, "reuse": "v"})).kind(), Some(HeaderCustomItemKind::Reuse));
        assert_eq!(item(json!({"transform": {"op": "concat"}})).kind(), Some(HeaderCustomItemKind::Transform));
        assert_eq!(item(json!({"packet": [1], "rand": 2})).kind(), None);
    }

    fn udp_round_trip(settings: &Value) -> Option<Value> {
        parse_header_custom_udp_settings(settings).map(|draft| header_custom_udp_settings_to_value(&draft))
    }

    /// Roadmap §2.6 stage 2.3.
    #[test]
    fn udp_shapes_round_trip_and_delay_is_an_unknown_key() {
        let settings = json!({
            "mode": "standalone",
            "client": [{"rand": 4, "capture": "n"}, {"type": "str", "packet": "A\r\n"}, {"rand": 1, "delay": "x"}],
            "server": [],
            "x": 1
        });
        assert_eq!(udp_round_trip(&settings), Some(settings.clone()));
        let draft = parse_header_custom_udp_settings(&settings).expect("typed");
        assert!(draft.is_standalone() && draft.server.present);
        // `UDPItem` has no `delay`: it is not a typed field there, but it is kept.
        assert_eq!(draft.client.items[2].delay, RangeValue::default());
        assert_eq!(draft.client.items[2].extras.get("delay"), Some(&json!("x")));
        // The mode is case-sensitive in the core and kept verbatim.
        let prefix = parse_header_custom_udp_settings(&json!({"mode": "Prefix"})).expect("typed");
        assert!(!prefix.is_standalone());
        assert_eq!(header_custom_udp_settings_to_value(&prefix), json!({"mode": "Prefix"}));
        assert_eq!(udp_round_trip(&json!({"mode": null, "client": null})), Some(json!({})));

        for raw in [
            json!({"mode": 1}),
            json!({"client": {}}),
            json!({"client": [[{"rand": 1}]]}),
            json!({"server": [{"packet": null}]}),
            json!({"server": [{"rand": "1"}]}),
        ] {
            assert!(parse_header_custom_udp_settings(&raw).is_none(), "{raw}");
        }
    }

    #[test]
    fn udp_edits_write_core_shapes() {
        let mut draft = parse_header_custom_udp_settings(&json!({"server": [{"rand": 2}]})).expect("typed");
        draft.mode = "standalone".to_owned();
        draft.group_mut(HeaderCustomUdpGroup::Client).items.push(HeaderCustomItem {
            kind: "hex".to_owned(),
            packet: PacketValue::new("0a0b"),
            ..Default::default()
        });
        draft.server.items.clear();
        assert_eq!(
            header_custom_udp_settings_to_value(&draft),
            json!({"mode": "standalone", "client": [{"type": "hex", "packet": "0a0b"}], "server": []})
        );
    }

    /// The valid `header-custom` fixtures are owned by the typed form without changes.
    #[test]
    fn valid_fixtures_round_trip() {
        for json in [
            include_str!("fixtures/finalmask/valid/header_custom_tcp.json"),
            include_str!("fixtures/finalmask/valid/header_custom_tcp_http.json"),
        ] {
            let fixture: Value = serde_json::from_str(json).expect("fixture");
            let settings = &fixture["tcp"][0]["settings"];
            assert_eq!(round_trip(settings).as_ref(), Some(settings));
        }
        for json in [
            include_str!("fixtures/finalmask/valid/header_custom_udp.json"),
            include_str!("fixtures/finalmask/valid/header_custom_udp_prefix.json"),
        ] {
            let fixture: Value = serde_json::from_str(json).expect("fixture");
            let settings = &fixture["udp"][0]["settings"];
            assert_eq!(udp_round_trip(settings).as_ref(), Some(settings));
        }
    }
}
