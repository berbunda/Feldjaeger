//! `Build()`-mirroring validation of FinalMask layer types on their JSON (Roadmap §2.6 stage 1.4):
//! `header-custom` (TCP and UDP shapes). `mkcp-legacy` has a typed form since stage 2.1
//! ([`super::finalmask_mkcp`]), `xmc` since stage 2.4 ([`super::finalmask_xmc`]) — both validated
//! in their own modules; `header-custom` TCP since stage 2.2
//! ([`super::finalmask_header_custom`]) — it is still validated here, on the JSON, because the
//! core counts a `packet: null` as set and decodes `transform` recursively, which the draft keeps
//! raw.
//!
//! These checks read the `settings` JSON directly, with the decoding rules of the core's Go
//! structs (`infra/conf/transport_finalmask.go`): an absent or `null` field is the zero value, a
//! field of the wrong JSON type is a decode error, and a `json.RawMessage` field (`packet`,
//! `bytes`) counts as "set" whenever the key is present — even as `null`.

use std::collections::HashMap;

use serde_json::{Map, Value};

use super::StreamDirection;
use super::finalmask_layers::PACKET_KINDS;
use super::values::{PacketValue, RangeValue, decoded_packet_len};

type Object = Map<String, Value>;

fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Object, String> {
    value.as_object().ok_or_else(|| format!("{what} must be a JSON object"))
}

/// A Go `string` field: absent / `null` = `""`.
fn string_of<'a>(object: &'a Object, key: &str) -> Result<&'a str, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

/// A Go `int32` field: absent / `null` = 0.
fn i32_of(object: &Object, key: &str) -> Result<i64, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => value
            .as_i64()
            .filter(|n| i32::try_from(*n).is_ok())
            .ok_or_else(|| format!("{key} must be a 32-bit integer")),
    }
}

/// A Go slice field: absent / `null` = empty.
fn array_of<'a>(object: &'a Object, key: &str) -> Result<&'a [Value], String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(format!("{key} must be an array")),
    }
}

/// An `Int32Range` field: `(from, to)` after `ensureOrder`; absent / `null` = `None`.
fn range_of(object: &Object, key: &str) -> Result<Option<(i64, i64)>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => RangeValue::parse(Some(value))
            .ok_or_else(|| format!("{key} must be a number or a \"FROM-TO\" string"))?
            .bounds()
            .map_err(|error| format!("{key}: {error}")),
    }
}

/// `PraseByteSlice(packet, type)` for a raw `json.RawMessage` field.
fn validate_raw_packet(packet: Option<&Value>, kind: &str, field: &str) -> Result<(), String> {
    let lower = kind.to_lowercase();
    if !PACKET_KINDS.contains(&lower.as_str()) {
        return Err(format!("unknown type \"{kind}\" (expected array, str, hex or base64)"));
    }
    match packet {
        // Decoding an empty `RawMessage` fails for every type but `array`.
        None if lower.is_empty() || lower == "array" => Ok(()),
        None => Err(format!("{field} is required for type \"{kind}\"")),
        // `null` decodes into the zero value without an error.
        Some(Value::Null) => Ok(()),
        Some(value) => PacketValue::parse(Some(value))
            .ok_or_else(|| format!("{field} must be a string or a list of bytes 0–255"))?
            .validate(kind)
            .map_err(|error| format!("{field}: {error}")),
    }
}

/// `customVarNamePattern`: `^[A-Za-z_][A-Za-z0-9_]*$` (empty = unset).
fn validate_var_name(key: &str, name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = match chars.next() {
        None => true,
        Some(first) => {
            (first.is_ascii_alphabetic() || first == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    };
    if valid {
        Ok(())
    } else {
        Err(format!("{key}: invalid variable name \"{name}\" (letters, digits, _; not starting with a digit)"))
    }
}

// ─── header-custom ──────────────────────────────────────────────────────────

/// One `header-custom` item (`TCPItem` with `delay`, or `UDPItem`): `validateCustomItemSpec`, then
/// `randRange` within 0–255, `packet` per `type`, and the `transform` expression.
fn validate_custom_item(item: &Value, tcp: bool) -> Result<(), String> {
    let object = as_object(item, "an item")?;
    let capture = string_of(object, "capture")?;
    let reuse = string_of(object, "reuse")?;
    let rand = i32_of(object, "rand")?;
    let kind = string_of(object, "type")?;
    let packet = object.get("packet");
    let transform = object.get("transform").filter(|value| !value.is_null());
    validate_var_name("capture", capture)?;
    validate_var_name("reuse", reuse)?;

    let kinds = [packet.is_some(), rand > 0, !reuse.is_empty(), transform.is_some()]
        .into_iter()
        .filter(|set| *set)
        .count();
    if kinds > 1 || (kinds == 0 && !capture.is_empty()) {
        return Err("exactly one of packet, rand, reuse, transform must be set".to_owned());
    }
    if tcp {
        range_of(object, "delay")?;
    }
    if let Some((from, to)) = range_of(object, "randRange")?
        && (from < 0 || to > 255)
    {
        return Err("randRange must lie within 0–255".to_owned());
    }
    validate_raw_packet(packet, kind, "packet")?;
    if let Some(transform) = transform {
        validate_transform(transform).map_err(|error| format!("transform: {error}"))?;
    }
    Ok(())
}

/// `buildCustomTransform`: `op` and at least one argument, each setting exactly one of `bytes`,
/// `u64`, `reuse`, `metadata`, `transform` (nested expressions recurse).
fn validate_transform(transform: &Value) -> Result<(), String> {
    let object = as_object(transform, "transform")?;
    if string_of(object, "op")?.is_empty() {
        return Err("op is required".to_owned());
    }
    let args = array_of(object, "args")?;
    if args.is_empty() {
        return Err("args are required".to_owned());
    }
    for (index, arg) in args.iter().enumerate() {
        validate_transform_arg(arg).map_err(|error| format!("args[{index}]: {error}"))?;
    }
    Ok(())
}

fn validate_transform_arg(arg: &Value) -> Result<(), String> {
    let object = as_object(arg, "an argument")?;
    let bytes = object.get("bytes");
    let u64_set = match object.get("u64") {
        None | Some(Value::Null) => false,
        Some(value) if value.as_u64().is_some() => true,
        Some(_) => return Err("u64 must be a non-negative integer".to_owned()),
    };
    let reuse = string_of(object, "reuse")?;
    let metadata = string_of(object, "metadata")?;
    let transform = object.get("transform").filter(|value| !value.is_null());
    let kinds = [bytes.is_some(), u64_set, !reuse.is_empty(), !metadata.is_empty(), transform.is_some()]
        .into_iter()
        .filter(|set| *set)
        .count();
    if kinds != 1 {
        return Err("exactly one of bytes, u64, reuse, metadata, transform must be set".to_owned());
    }
    if bytes.is_some() {
        return validate_raw_packet(bytes, string_of(object, "type")?, "bytes");
    }
    validate_var_name("reuse", reuse)?;
    match transform {
        Some(transform) => validate_transform(transform).map_err(|error| format!("transform: {error}")),
        None => Ok(()),
    }
}

/// `HeaderCustomTCP.Build()`: `clients` / `servers` / `errors` are lists of item sequences.
pub fn validate_header_custom_tcp(settings: &Value) -> Result<(), String> {
    let object = as_object(settings, "settings")?;
    for group in ["clients", "servers", "errors"] {
        for (sequence_index, sequence) in array_of(object, group)?.iter().enumerate() {
            let items = sequence
                .as_array()
                .ok_or_else(|| format!("{group}[{sequence_index}] must be an array of items"))?;
            for (item_index, item) in items.iter().enumerate() {
                validate_custom_item(item, true)
                    .map_err(|error| format!("{group}[{sequence_index}][{item_index}]: {error}"))?;
            }
        }
    }
    Ok(())
}

// ─── header-custom UDP header sizes (listener / dialer creation) ─────────────

/// The size `measureItem` gives a validated item; records `capture` in `sizes` like the core.
/// Kinds are tried in the core's order (`rand`, `packet`, `reuse`, `transform`).
fn measure_item(item: &Value, sizes: &mut HashMap<String, usize>) -> Result<usize, String> {
    let object = as_object(item, "an item")?;
    let rand = i32_of(object, "rand")?;
    let packet_len = match object.get("packet") {
        Some(packet) => decoded_packet_len(packet, string_of(object, "type")?).unwrap_or(0),
        None => 0,
    };
    let reuse = string_of(object, "reuse")?;
    let size = if rand > 0 {
        usize::try_from(rand).unwrap_or(0)
    } else if packet_len > 0 {
        packet_len
    } else if !reuse.is_empty() {
        variable_size(reuse, sizes)?
    } else if let Some(transform) = object.get("transform").filter(|value| !value.is_null()) {
        measure_expr(transform, sizes).map_err(|error| format!("transform: {error}"))?
    } else {
        0
    };
    let capture = string_of(object, "capture")?;
    if !capture.is_empty() {
        sizes.insert(capture.to_owned(), size);
    }
    Ok(size)
}

fn variable_size(name: &str, sizes: &HashMap<String, usize>) -> Result<usize, String> {
    sizes
        .get(name)
        .copied()
        .ok_or_else(|| format!("unknown variable \"{name}\" — no earlier item captures it"))
}

/// `measureExpr`: only byte-producing ops with a fixed width can be sized.
fn measure_expr(expr: &Value, sizes: &HashMap<String, usize>) -> Result<usize, String> {
    let object = as_object(expr, "transform")?;
    let op = string_of(object, "op")?;
    let args = array_of(object, "args")?;
    // `slice` / `pad` / `truncate`: the length argument must be a `u64`.
    let fixed_length = |count: usize, index: usize| -> Result<usize, String> {
        if args.len() != count {
            return Err(format!("{op} expects {count} args"));
        }
        args[index]
            .get("u64")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| format!("{op} length must be u64"))
    };
    match op {
        "concat" => args.iter().try_fold(0usize, |total, arg| Ok(total + measure_expr_arg(arg, sizes)?)),
        "slice" => fixed_length(3, 2),
        "pad" => fixed_length(3, 1),
        "truncate" => fixed_length(2, 1),
        "be16" | "le16" => Ok(2),
        "be32" | "le32" => Ok(4),
        "le64" => Ok(8),
        other => Err(format!("op \"{other}\" has no fixed byte size")),
    }
}

/// `measureExprArg`, after `buildCustomTransformArg` (exactly one value is set).
fn measure_expr_arg(arg: &Value, sizes: &HashMap<String, usize>) -> Result<usize, String> {
    let object = as_object(arg, "an argument")?;
    if let Some(bytes) = object.get("bytes") {
        return Ok(decoded_packet_len(bytes, string_of(object, "type")?).unwrap_or(0));
    }
    if object.get("u64").is_some_and(|value| !value.is_null()) {
        return Err("a u64 argument has no byte width".to_owned());
    }
    let reuse = string_of(object, "reuse")?;
    if !reuse.is_empty() {
        return variable_size(reuse, sizes);
    }
    let metadata = string_of(object, "metadata")?;
    if !metadata.is_empty() {
        return Err(format!("metadata \"{metadata}\" cannot be sized"));
    }
    match object.get("transform") {
        Some(transform) => measure_expr(transform, sizes),
        None => Err("empty argument".to_owned()),
    }
}

/// Sizes `items` in order (`measureUDPItemsWithFallback`), starting from `sizes`.
fn measure_items(group: &str, items: &[Value], mut sizes: HashMap<String, usize>) -> Result<(), String> {
    for (index, item) in items.iter().enumerate() {
        measure_item(item, &mut sizes).map_err(|error| format!("{group}[{index}]: {error}"))?;
    }
    Ok(())
}

/// `collectSavedUDPSizes`: the sizes `client` captures, skipping items that can't be sized.
fn collect_saved_sizes(items: &[Value]) -> HashMap<String, usize> {
    let mut sizes = HashMap::new();
    for item in items {
        let _ = measure_item(item, &mut sizes);
    }
    sizes
}

/// The header sizes Xray-core measures when a `header-custom` UDP listener / dialer is created
/// (`NewConn{Server,Client}UDP[Standalone]`), so the failure only shows at start —
/// `xray run -test` does not create it. Run after [`validate_header_custom_udp`].
///
/// `prefix` (both sides) measures `client`, and `server` with the sizes `client` captures;
/// `standalone` measures only what this side receives: `client` on the server (inbound), `server`
/// on the client (outbound) — what it sends is evaluated per packet, where `metadata` works.
pub fn validate_header_custom_udp_sizes(settings: &Value, direction: StreamDirection) -> Result<(), String> {
    let object = as_object(settings, "settings")?;
    let standalone = string_of(object, "mode")? == "standalone";
    let client = array_of(object, "client")?;
    let server = array_of(object, "server")?;
    let side = match direction {
        StreamDirection::Inbound => "listener",
        StreamDirection::Outbound => "dialer",
    };
    let runtime = |error: String| {
        format!("{error} (Xray-core sizes the header when the {side} is created; `xray run -test` does not check it)")
    };
    if !standalone || direction == StreamDirection::Inbound {
        measure_items("client", client, HashMap::new()).map_err(runtime)?;
    }
    if !standalone || direction == StreamDirection::Outbound {
        measure_items("server", server, collect_saved_sizes(client)).map_err(runtime)?;
    }
    Ok(())
}

/// `header-custom` UDP `mode` values (case-sensitive in the core; empty = `prefix`).
pub const HEADER_CUSTOM_UDP_MODES: &[&str] = &["prefix", "standalone"];

/// `HeaderCustomUDP.Build()`: `mode`, then `client` / `server` item lists.
pub fn validate_header_custom_udp(settings: &Value) -> Result<(), String> {
    let object = as_object(settings, "settings")?;
    let mode = string_of(object, "mode")?;
    if !mode.is_empty() && !HEADER_CUSTOM_UDP_MODES.contains(&mode) {
        return Err(format!("unknown mode \"{mode}\" (expected prefix or standalone, lower-case)"));
    }
    for group in ["client", "server"] {
        for (index, item) in array_of(object, group)?.iter().enumerate() {
            validate_custom_item(item, false).map_err(|error| format!("{group}[{index}]: {error}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tcp(settings: Value) -> Result<(), String> {
        validate_header_custom_tcp(&settings)
    }

    fn udp(settings: Value) -> Result<(), String> {
        validate_header_custom_udp(&settings)
    }

    #[test]
    fn header_custom_tcp_accepts_documented_shapes() {
        let settings = json!({
            "clients": [[
                {"delay": "10-20", "rand": 8, "randRange": "65-90"},
                {"type": "str", "packet": "GET / HTTP/1.1\r\n"},
                {"packet": [1, 2, 3], "capture": "head"},
                {"reuse": "head"},
                {"transform": {"op": "xor", "args": [{"reuse": "head"}, {"type": "hex", "bytes": "ff"}]}},
                {"delay": 5}
            ]],
            "servers": [[{"type": "base64", "packet": "AQID"}]],
            "errors": []
        });
        assert_eq!(tcp(settings), Ok(()));
    }

    #[test]
    fn header_custom_items_mirror_validate_custom_item_spec() {
        for (item, needle) in [
            (json!({"packet": [1], "rand": 4}), "exactly one"),
            (json!({"packet": null, "reuse": "x"}), "exactly one"),
            (json!({"capture": "x"}), "exactly one"),
            (json!({"capture": "1x", "rand": 1}), "capture: invalid variable name"),
            (json!({"reuse": "a-b"}), "reuse: invalid variable name"),
            (json!({"rand": 4, "randRange": "0-256"}), "randRange"),
            (json!({"rand": 4, "randRange": -1}), "randRange"),
            (json!({"rand": "4"}), "rand must be a 32-bit integer"),
            (json!({"type": "hex", "packet": "f"}), "hex"),
            (json!({"type": "str"}), "packet is required"),
            (json!({"type": "bin", "rand": 2}), "unknown type"),
            (json!({"packet": [300]}), "list of bytes"),
            (json!({"delay": "a-b", "rand": 1}), "delay"),
            (json!({"transform": {"args": [{"u64": 1}]}}), "op is required"),
            (json!({"transform": {"op": "add", "args": []}}), "args are required"),
            (json!({"transform": {"op": "add", "args": [{"u64": 1, "reuse": "x"}]}}), "exactly one of bytes"),
            (json!({"transform": {"op": "add", "args": [{"u64": -1}]}}), "u64"),
            (json!({"transform": {"op": "add", "args": [{"transform": {"op": "", "args": []}}]}}), "transform: op"),
        ] {
            let error = tcp(json!({"clients": [[item.clone()]]})).expect_err(&item.to_string());
            assert!(error.starts_with("clients[0][0]: "), "{error}");
            assert!(error.contains(needle), "{item}: {error}");
        }
        // An empty item (delay only) and a `null` transform are fine.
        assert_eq!(tcp(json!({"servers": [[{}, {"transform": null, "rand": 1}]]})), Ok(()));
        assert!(tcp(json!({"errors": [{"rand": 1}]})).unwrap_err().contains("errors[0] must be an array"));
    }

    #[test]
    fn header_custom_udp_mode_is_case_sensitive() {
        assert_eq!(udp(json!({"client": [{"rand": 4}], "server": [{"packet": "AQ=="}]})), Ok(()));
        assert_eq!(udp(json!({"mode": "standalone"})), Ok(()));
        assert!(udp(json!({"mode": "Prefix"})).unwrap_err().contains("unknown mode"));
        // UDP items have no `delay`; the key is ignored like any unknown one.
        assert_eq!(udp(json!({"client": [{"rand": 1, "delay": "x"}]})), Ok(()));
        assert!(udp(json!({"server": [{"rand": 1, "reuse": "v"}]})).unwrap_err().starts_with("server[0]: exactly one"));
    }

    /// Roadmap §2.6 stage 2.3: `measureUDPItems` when the listener / dialer is created.
    #[test]
    fn header_custom_udp_sizes_mirror_measure_udp_items() {
        use StreamDirection::{Inbound, Outbound};
        let sizes = |settings: &Value, direction| validate_header_custom_udp_sizes(settings, direction);
        // `client` captures, `server` reuses (`collectSavedUDPSizes`); fixed-width ops.
        let echo = json!({
            "client": [{"rand": 8, "capture": "n"}, {"type": "str", "packet": "hi"},
                       {"transform": {"op": "be32", "args": [{"u64": 7}]}, "capture": "c"}],
            "server": [{"reuse": "n"},
                       {"transform": {"op": "concat", "args": [{"reuse": "c"}, {"type": "hex", "bytes": "ff"}]}},
                       {"transform": {"op": "truncate", "args": [{"reuse": "n"}, {"u64": 4}]}}]
        });
        for direction in [Inbound, Outbound] {
            assert_eq!(sizes(&echo, direction), Ok(()));
        }
        for (settings, needle) in [
            (json!({"client": [{"reuse": "n"}, {"rand": 1, "capture": "n"}]}), "client[0]: unknown variable \"n\""),
            (json!({"server": [{"reuse": "x"}]}), "server[0]: unknown variable \"x\""),
            (json!({"client": [{"transform": {"op": "xor16", "args": [{"u64": 1}]}}]}), "op \"xor16\" has no fixed byte size"),
            (json!({"client": [{"transform": {"op": "concat", "args": [{"u64": 1}]}}]}), "u64 argument has no byte width"),
            (json!({"client": [{"transform": {"op": "concat", "args": [{"metadata": "remote_ip"}]}}]}), "metadata"),
            (json!({"client": [{"transform": {"op": "slice", "args": [{"reuse": "a"}, {"u64": 0}]}}]}), "slice expects 3 args"),
            (json!({"client": [{"transform": {"op": "pad", "args": [{"bytes": [1]}, {"bytes": [2]}, {"bytes": [0]}]}}]}),
             "pad length must be u64"),
        ] {
            for direction in [Inbound, Outbound] {
                let error = sizes(&settings, direction).expect_err(&settings.to_string());
                assert!(error.contains(needle) && error.contains("xray run -test"), "{settings}: {error}");
            }
        }
        // `standalone`: each side sizes only what it receives — the inbound sizes `client`, the
        // outbound `server`; what a side sends is evaluated per packet, where metadata works.
        let metadata_reply = json!({"mode": "standalone", "client": [{"rand": 4}],
                                    "server": [{"transform": {"op": "concat", "args": [{"metadata": "remote_ip"}]}}]});
        assert_eq!(sizes(&metadata_reply, Inbound), Ok(()));
        assert!(sizes(&metadata_reply, Outbound).unwrap_err().starts_with("server[0]: transform: metadata"));
        let unknown_request = json!({"mode": "standalone", "client": [{"reuse": "z"}]});
        assert!(sizes(&unknown_request, Inbound).unwrap_err().contains("listener"));
        assert_eq!(sizes(&unknown_request, Outbound), Ok(()));
    }
}
