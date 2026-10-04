//! Shape-preserving scalar values for FinalMask layer `settings` (Roadmap §2.6 stage 0.1).
//!
//! Several FinalMask fields accept more than one JSON shape in Xray-core
//! (`infra/conf/common.go`, `infra/conf/transport_finalmask.go`):
//!
//! - `Int32Range` — a JSON number (`int32`) **or** a string parsed by `ParseRangeString`
//!   (`"5"`, `"10-20"`, `"-5-5"`); used by `fragment.length`/`delay`/`maxSplit`,
//!   `noise.rand`/`delay`/`reset`, `salamander.packetSize`, `udphop.interval`, …
//! - `PortList` — a JSON number **or** a string of comma-separated ports/ranges
//!   (`"443"`, `"20000-30000,40000"`, `"env:NAME"`); used by `udphop.remotePorts`.
//! - `packet` — raw JSON whose meaning depends on the sibling `type`
//!   (`array` | `str` | `hex` | `base64`, see `PraseByteSlice`); `array` is a JSON byte array.
//!
//! The typed editors used to read these through a string-only accessor, so a numeric `"maxSplit": 3`
//! or a byte-array `"packet": [1, 2, 3]` was silently dropped on the next write. The types here
//! keep the editable text **and** remember which JSON shape it was read in, so an untouched value
//! is written back byte-for-byte. A shape that cannot be represented as editable text at all
//! (e.g. a float, an object) makes `parse` return `None`; the caller then keeps the whole layer on
//! the raw-JSON editor instead of guessing.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;

// ─── Int32Range ─────────────────────────────────────────────────────────────

/// An `Int32Range` field value: editable `text` plus the JSON shape it was read in.
///
/// Empty `text` means "key absent". A value read as a JSON string is always written back as a
/// string; any other value (read as a number, or newly typed) is written as a JSON number when it
/// is a plain integer and as a string otherwise (`"10-20"`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RangeValue {
    /// Editable text: `"5"`, `"10-20"`, `"-5-5"`; empty = key absent.
    pub text: String,
    /// `true` when the on-disk value was a JSON string (keeps `"100"` quoted on write).
    quoted: bool,
}

impl RangeValue {
    /// A new, not-yet-written value (serialized as a number when `text` is a plain integer).
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            quoted: false,
        }
    }

    /// Reads a field; absent/`null` → empty value. `None` when the JSON shape is not a
    /// representable `Int32Range` (float, bool, array, object).
    pub fn parse(value: Option<&Value>) -> Option<Self> {
        parse_number_or_text(value).map(|(text, quoted)| Self { text, quoted })
    }

    /// The JSON value to write, or `None` when the key should be omitted.
    pub fn to_value(&self) -> Option<Value> {
        number_or_text_to_value(&self.text, self.quoted)
    }

    /// Normalized `(from, to)` bounds (`from <= to`, as Xray's `ensureOrder`); `Ok(None)` when
    /// empty. Mirrors `Int32Range.UnmarshalJSON`, except that values outside `i32` are rejected:
    /// Xray-core rejects them for JSON numbers and silently truncates them inside strings.
    pub fn bounds(&self) -> Result<Option<(i64, i64)>, String> {
        // A plain integer is written as a JSON number, anything else as a string; both shapes
        // share the `ParseRangeString` grammar, so the written text is checked directly.
        let text = self.text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let (left, right) = parse_range_string(text)
            .ok_or_else(|| format!("invalid range \"{text}\" (expected \"N\" or \"FROM-TO\")"))?;
        for bound in [left, right] {
            if i32::try_from(bound).is_err() {
                return Err(format!("range bound {bound} is outside the 32-bit integer range"));
            }
        }
        Ok(Some((left.min(right), left.max(right))))
    }

    /// Validates the value against Xray-core's `Int32Range` grammar (see [`Self::bounds`]).
    pub fn validate(&self) -> Result<(), String> {
        self.bounds().map(|_| ())
    }
}

/// Reads an array of `Int32Range` values (`fragment.lengths[]`/`delays[]`); absent/`null` →
/// empty. `None` when the field is not an array or any element is not a representable range.
pub fn parse_range_values(value: Option<&Value>) -> Option<Vec<RangeValue>> {
    match value {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|item| RangeValue::parse(Some(item))).collect(),
        Some(_) => None,
    }
}

/// Editable one-per-line texts for a range list (the GUI's multiline list widget).
pub fn range_values_to_lines(values: &[RangeValue]) -> Vec<String> {
    values.iter().map(|value| value.text.clone()).collect()
}

/// Rebuilds a range list from edited lines, keeping each line's original JSON shape **by
/// position** (line *n* inherits the shape of `previous[n]`; extra lines are new values). A
/// shifted shape after inserting a line only swaps an equivalent `5` ↔ `"5"`, never the meaning.
pub fn range_values_from_lines(previous: &[RangeValue], lines: Vec<String>) -> Vec<RangeValue> {
    lines
        .into_iter()
        .enumerate()
        .map(|(index, text)| RangeValue {
            text,
            quoted: previous.get(index).is_some_and(|value| value.quoted),
        })
        .collect()
}

// ─── PortList ───────────────────────────────────────────────────────────────

/// A `PortList` field value (`udphop.remotePorts`): editable `text` plus the JSON shape it was
/// read in. Same write rules as [`RangeValue`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PortListValue {
    /// Editable text: `"443"`, `"20000-30000,40000"`, `"env:NAME"`; empty = key absent.
    pub text: String,
    /// `true` when the on-disk value was a JSON string.
    quoted: bool,
}

impl PortListValue {
    /// A new, not-yet-written value.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            quoted: false,
        }
    }

    /// Reads a field; absent/`null` → empty value. `None` for unrepresentable JSON shapes.
    pub fn parse(value: Option<&Value>) -> Option<Self> {
        parse_number_or_text(value).map(|(text, quoted)| Self { text, quoted })
    }

    /// The JSON value to write, or `None` when the key should be omitted.
    pub fn to_value(&self) -> Option<Value> {
        number_or_text_to_value(&self.text, self.quoted)
    }

    /// Validates against Xray-core's `PortList.UnmarshalJSON`: a number `0..=65535`, or
    /// comma-separated segments each `PORT`, `FROM-TO` or `env:NAME` (resolved at runtime).
    pub fn validate(&self) -> Result<(), String> {
        // The number form (`443`) obeys the same `0..=65535` rule as a one-segment string, and a
        // negative number fails the segment grammar just like Xray's `uint32` decode does.
        for segment in self.text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if segment.starts_with("env:") {
                continue;
            }
            let valid = match segment.split_once('-') {
                Some((from, to)) => parse_port(from).is_some() && parse_port(to).is_some(),
                None => parse_port(segment).is_some(),
            };
            if !valid {
                return Err(format!("invalid port or port range \"{segment}\""));
            }
        }
        Ok(())
    }
}

// ─── packet ─────────────────────────────────────────────────────────────────

/// How a `packet` value was stored on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketForm {
    /// A JSON string (`str`/`hex`/`base64`, or base64 under `array` — Go decodes a JSON string
    /// into `[]byte` as base64).
    Text,
    /// A JSON array of bytes (`array`).
    Bytes,
}

/// A FinalMask `packet` payload (`noise[].packet`, later `header-custom` items): editable `text`
/// plus the JSON shape it was read in.
///
/// A byte array is edited as `"1, 2, 255"`. A value read as a string stays a string; a value read
/// as an array stays an array while the text still parses as bytes; a new value becomes an array
/// only when the sibling `type` is `array` (or empty, Xray's default) and the text parses as bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PacketValue {
    /// Editable text; empty = key absent.
    pub text: String,
    /// On-disk shape; `None` for a new value.
    form: Option<PacketForm>,
}

impl PacketValue {
    /// A new, not-yet-written value.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            form: None,
        }
    }

    /// Reads a field; absent/`null` → empty value. `None` when the value is neither a string nor
    /// an array of bytes (`0..=255`).
    pub fn parse(value: Option<&Value>) -> Option<Self> {
        match value {
            None | Some(Value::Null) => Some(Self::default()),
            Some(Value::String(text)) => Some(Self {
                text: text.clone(),
                form: Some(PacketForm::Text),
            }),
            Some(Value::Array(items)) => {
                let bytes = items
                    .iter()
                    .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                    .collect::<Option<Vec<u8>>>()?;
                Some(Self {
                    text: bytes_to_text(&bytes),
                    form: Some(PacketForm::Bytes),
                })
            }
            Some(_) => None,
        }
    }

    /// The JSON value to write for the given sibling `type`, or `None` when the key should be
    /// omitted.
    ///
    /// A string is written verbatim, surrounding whitespace included: the core uses it byte for
    /// byte (a `str` packet ending in a blank line in `header-custom`), so trimming would change
    /// the mask. Only a blank text means "absent".
    pub fn to_value(&self, kind: &str) -> Option<Value> {
        let text = self.text.trim();
        if text.is_empty() {
            return None;
        }
        let as_bytes = match self.form {
            Some(PacketForm::Text) => false,
            Some(PacketForm::Bytes) => true,
            None => is_array_kind(kind),
        };
        if as_bytes && let Some(bytes) = text_to_bytes(text) {
            return Some(Value::Array(bytes.into_iter().map(Value::from).collect()));
        }
        Some(Value::String(self.text.clone()))
    }

    /// Validates the value that would be written against Xray-core's `PraseByteSlice` for the
    /// given sibling `type`.
    pub fn validate(&self, kind: &str) -> Result<(), String> {
        let Some(value) = self.to_value(kind) else {
            return Ok(());
        };
        match (kind.trim().to_ascii_lowercase().as_str(), &value) {
            ("" | "array", Value::Array(_)) => Ok(()),
            ("" | "array", Value::String(text)) => STANDARD
                .decode(text)
                .map(|_| ())
                .map_err(|_| "packet of type \"array\" must be a list of bytes 0–255".to_owned()),
            ("str", Value::String(_)) => Ok(()),
            ("hex", Value::String(text)) if is_hex(text) => Ok(()),
            ("hex", _) => Err("packet of type \"hex\" must be an even-length hex string".to_owned()),
            ("base64", Value::String(text)) if STANDARD.decode(text).is_ok() => Ok(()),
            ("base64", _) => Err("packet of type \"base64\" must be a standard base64 string".to_owned()),
            ("str", _) => Err("packet of type \"str\" must be a string".to_owned()),
            (other, _) => Err(format!(
                "unknown packet type \"{other}\" (expected array, str, hex or base64)"
            )),
        }
    }
}

/// Byte length of a raw `packet` / `bytes` JSON value after Xray-core's `PraseByteSlice` for the
/// sibling `type` (`array`: list length, or base64-decoded length of a string; `str`: UTF-8
/// length; `hex` / `base64`: decoded length; `null`: 0). `None` when it does not decode.
pub fn decoded_packet_len(value: &Value, kind: &str) -> Option<usize> {
    if value.is_null() {
        return Some(0);
    }
    match (kind.to_lowercase().as_str(), value) {
        ("" | "array", Value::Array(items)) => Some(items.len()),
        ("" | "array" | "base64", Value::String(text)) => STANDARD.decode(text).ok().map(|bytes| bytes.len()),
        ("str", Value::String(text)) => Some(text.len()),
        ("hex", Value::String(text)) if is_hex(text) => Some(text.len() / 2),
        _ => None,
    }
}

/// A `str` packet on one line for editing: `\` as `\\`, CR / LF / TAB as `\r` / `\n` / `\t`,
/// other ASCII control characters as `\xHH`. The bytes the core compares (an HTTP-like
/// `"…\r\n\r\n"`) become visible and typeable in a single-line field. Presentation only — the
/// configuration keeps the plain string; [`unescape_packet_text`] is the inverse.
pub fn escape_packet_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_ascii_control() => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// Inverse of [`escape_packet_text`]: `\\`, `\r`, `\n`, `\t` and `\xHH` (`00`–`7f`; a JSON
/// string holds characters, not raw bytes above ASCII). Anything else after `\` is an error, so a
/// half-typed escape is never written.
pub fn unescape_packet_text(text: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                let byte = (hex.len() == 2)
                    .then(|| u8::from_str_radix(&hex, 16).ok())
                    .flatten()
                    .filter(u8::is_ascii)
                    .ok_or_else(|| format!("invalid escape \\x{hex} (expected \\x00–\\x7f)"))?;
                out.push(char::from(byte));
            }
            Some(other) => {
                return Err(format!("unknown escape \\{other} (use \\\\, \\r, \\n, \\t or \\xHH)"));
            }
            None => return Err("trailing backslash (write \\\\ for a backslash)".to_owned()),
        }
    }
    Ok(out)
}

// ─── helpers ────────────────────────────────────────────────────────────────

/// Shared reader for number-or-string fields: `(text, quoted)`; absent/`null` → `("", false)`.
fn parse_number_or_text(value: Option<&Value>) -> Option<(String, bool)> {
    match value {
        None | Some(Value::Null) => Some((String::new(), false)),
        Some(Value::String(text)) => Some((text.clone(), true)),
        Some(Value::Number(number)) => number
            .as_i64()
            .map(|n| n.to_string())
            .or_else(|| number.as_u64().map(|n| n.to_string()))
            .map(|text| (text, false)),
        Some(_) => None,
    }
}

/// Shared writer for number-or-string fields (see [`RangeValue`] for the rules).
fn number_or_text_to_value(text: &str, quoted: bool) -> Option<Value> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if !quoted && let Ok(n) = text.parse::<i64>() {
        return Some(Value::from(n));
    }
    Some(Value::String(text.to_owned()))
}

/// Go `strconv.Atoi`: optional sign, at least one ASCII digit, nothing else.
fn go_atoi(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

/// Xray-core `ParseRangeString`: `"N"` or `"FROM-TO"`, where a leading `-` makes the split happen
/// at the second dash (`"-5-5"`, `"-10--5"`).
pub(super) fn parse_range_string(text: &str) -> Option<(i64, i64)> {
    if let Some(n) = go_atoi(text) {
        return Some((n, n));
    }
    let (left, right) = if let Some(rest) = text.strip_prefix('-') {
        let (left, right) = rest.split_once('-')?;
        (&text[..left.len() + 1], right)
    } else {
        text.split_once('-')?
    };
    Some((go_atoi(left)?, go_atoi(right)?))
}

/// Xray-core `net.PortFromString`: a decimal port `0..=65535`.
fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u16>().ok()
}

fn is_array_kind(kind: &str) -> bool {
    matches!(kind.trim().to_ascii_lowercase().as_str(), "" | "array")
}

fn is_hex(text: &str) -> bool {
    text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn bytes_to_text(bytes: &[u8]) -> String {
    bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
}

/// Parses `"1, 2, 255"` / `"1 2 255"` / `"[1,2,255]"` into bytes; `None` if any token isn't `0..=255`.
fn text_to_bytes(text: &str) -> Option<Vec<u8>> {
    let inner = text.trim().trim_start_matches('[').trim_end_matches(']');
    inner
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|token| !token.is_empty())
        .map(|token| token.parse::<u8>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn range_preserves_number_and_string_shapes() {
        for original in [json!(3), json!(-1), json!("3"), json!("10-20"), json!("-5-5")] {
            let value = RangeValue::parse(Some(&original)).expect("representable");
            assert_eq!(value.to_value(), Some(original));
        }
    }

    #[test]
    fn range_absent_and_null_are_empty() {
        assert_eq!(RangeValue::parse(None), Some(RangeValue::default()));
        assert_eq!(RangeValue::parse(Some(&Value::Null)), Some(RangeValue::default()));
        assert_eq!(RangeValue::default().to_value(), None);
    }

    #[test]
    fn range_rejects_unrepresentable_shapes() {
        assert!(RangeValue::parse(Some(&json!(1.5))).is_none());
        assert!(RangeValue::parse(Some(&json!(true))).is_none());
        assert!(RangeValue::parse(Some(&json!([1]))).is_none());
        assert!(RangeValue::parse(Some(&json!({"from": 1}))).is_none());
    }

    #[test]
    fn range_new_value_writes_integer_as_number() {
        assert_eq!(RangeValue::new(" 42 ").to_value(), Some(json!(42)));
        assert_eq!(RangeValue::new("1-3").to_value(), Some(json!("1-3")));
    }

    #[test]
    fn range_numeric_value_edited_to_range_becomes_string() {
        let mut value = RangeValue::parse(Some(&json!(3))).unwrap();
        value.text = "3-6".to_owned();
        assert_eq!(value.to_value(), Some(json!("3-6")));
    }

    #[test]
    fn range_bounds_follow_parse_range_string() {
        assert_eq!(RangeValue::new("10-20").bounds(), Ok(Some((10, 20))));
        assert_eq!(RangeValue::new("20-10").bounds(), Ok(Some((10, 20))));
        assert_eq!(RangeValue::new("-5-5").bounds(), Ok(Some((-5, 5))));
        assert_eq!(RangeValue::new("-10--5").bounds(), Ok(Some((-10, -5))));
        assert_eq!(RangeValue::new("+7").bounds(), Ok(Some((7, 7))));
        assert_eq!(RangeValue::default().bounds(), Ok(None));
        assert!(RangeValue::new("abc").validate().is_err());
        assert!(RangeValue::new("1-2-3").validate().is_err());
        assert!(RangeValue::new("1 - 2").validate().is_err());
        assert!(RangeValue::new("5000000000").validate().is_err());
    }

    #[test]
    fn range_list_keeps_shapes_by_position() {
        let parsed = parse_range_values(Some(&json!(["1-2", 3]))).expect("list");
        let lines = range_values_to_lines(&parsed);
        assert_eq!(lines, vec!["1-2".to_owned(), "3".to_owned()]);
        let rebuilt = range_values_from_lines(&parsed, vec!["1-2".into(), "3".into(), "7".into()]);
        let written: Vec<_> = rebuilt.iter().filter_map(RangeValue::to_value).collect();
        assert_eq!(written, vec![json!("1-2"), json!(3), json!(7)]);
    }

    #[test]
    fn range_list_rejects_non_array_and_bad_elements() {
        assert!(parse_range_values(Some(&json!("1-2"))).is_none());
        assert!(parse_range_values(Some(&json!([1.5]))).is_none());
        assert_eq!(parse_range_values(None), Some(Vec::new()));
    }

    #[test]
    fn port_list_round_trips_and_validates() {
        for original in [json!(443), json!("443"), json!("20000-30000,40000")] {
            let value = PortListValue::parse(Some(&original)).expect("representable");
            assert_eq!(value.to_value(), Some(original));
            assert_eq!(value.validate(), Ok(()));
        }
        assert_eq!(PortListValue::new("env:HOP_PORTS").validate(), Ok(()));
        assert!(PortListValue::new("70000").validate().is_err());
        assert!(PortListValue::new("1-x").validate().is_err());
        assert!(PortListValue::parse(Some(&json!(true))).is_none());
    }

    #[test]
    fn packet_byte_array_round_trips() {
        let original = json!([1, 2, 255]);
        let value = PacketValue::parse(Some(&original)).expect("bytes");
        assert_eq!(value.text, "1, 2, 255");
        assert_eq!(value.to_value("array"), Some(original.clone()));
        assert_eq!(value.to_value(""), Some(original));
    }

    #[test]
    fn packet_string_stays_string_even_under_array_type() {
        // Go decodes a JSON string into `[]byte` as base64, so this is a valid on-disk form.
        let original = json!("AQID");
        let value = PacketValue::parse(Some(&original)).expect("string");
        assert_eq!(value.to_value(""), Some(original));
        assert_eq!(value.validate(""), Ok(()));
    }

    #[test]
    fn packet_rejects_unrepresentable_shapes() {
        assert!(PacketValue::parse(Some(&json!([256]))).is_none());
        assert!(PacketValue::parse(Some(&json!(["a"]))).is_none());
        assert!(PacketValue::parse(Some(&json!(7))).is_none());
    }

    #[test]
    fn packet_new_value_shape_follows_type() {
        assert_eq!(PacketValue::new("1, 2").to_value("array"), Some(json!([1, 2])));
        assert_eq!(PacketValue::new("[3,4]").to_value(""), Some(json!([3, 4])));
        assert_eq!(PacketValue::new("hello").to_value("str"), Some(json!("hello")));
        assert_eq!(PacketValue::new("1, 2").to_value("str"), Some(json!("1, 2")));
    }

    /// Roadmap §2.6 stage 2.2: an HTTP-like `str` packet keeps its trailing CRLF on write.
    #[test]
    fn packet_string_is_written_verbatim() {
        let original = json!("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let value = PacketValue::parse(Some(&original)).expect("string");
        assert_eq!(value.to_value("str"), Some(original));
        assert_eq!(PacketValue::new(" x ").to_value("str"), Some(json!(" x ")));
        // Blank text is still "absent"; byte lists are still parsed from trimmed text.
        assert_eq!(PacketValue::new(" \r\n ").to_value("str"), None);
        assert_eq!(PacketValue::new(" 1, 2 ").to_value("array"), Some(json!([1, 2])));
    }

    #[test]
    fn decoded_packet_len_mirrors_prase_byte_slice() {
        for (value, kind, len) in [
            (json!([1, 2, 3]), "", Some(3)),
            (json!("AQID"), "array", Some(3)),
            (json!("é\r\n"), "STR", Some(4)),
            (json!("0a0b"), "hex", Some(2)),
            (json!("aGVsbG8="), "base64", Some(5)),
            (Value::Null, "hex", Some(0)),
            (json!("0a0"), "hex", None),
            (json!([1]), "str", None),
            (json!("x"), "utf16", None),
        ] {
            assert_eq!(decoded_packet_len(&value, kind), len, "{value} {kind}");
        }
    }

    #[test]
    fn packet_text_escapes_round_trip() {
        let text = "GET \\ /\r\n\tA\u{1}\u{7f}é";
        let escaped = escape_packet_text(text);
        assert_eq!(escaped, "GET \\\\ /\\r\\n\\tA\\x01\\x7fé");
        assert_eq!(unescape_packet_text(&escaped), Ok(text.to_owned()));
        assert_eq!(unescape_packet_text("a\\x0A"), Ok("a\n".to_owned()));
        for (bad, needle) in [("a\\", "trailing"), ("\\q", "unknown escape"), ("\\x8", "\\x8"), ("\\xff", "\\xff")] {
            let error = unescape_packet_text(bad).expect_err(bad);
            assert!(error.contains(needle), "{bad}: {error}");
        }
    }

    #[test]
    fn packet_validation_mirrors_prase_byte_slice() {
        assert_eq!(PacketValue::new("0a0b").validate("hex"), Ok(()));
        assert!(PacketValue::new("0a0").validate("hex").is_err());
        assert!(PacketValue::new("zz").validate("hex").is_err());
        assert_eq!(PacketValue::new("aGVsbG8=").validate("base64"), Ok(()));
        assert!(PacketValue::new("not base64!").validate("base64").is_err());
        assert!(PacketValue::new("1, 999").validate("array").is_err());
        assert!(PacketValue::new("x").validate("utf16").is_err());
        let bytes = PacketValue::parse(Some(&json!([1, 2]))).unwrap();
        assert!(bytes.validate("str").is_err());
    }
}
