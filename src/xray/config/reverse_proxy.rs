//! VLESS-native reverse proxy `reverse` object (Roadmap §2.1:58).
//!
//! See <https://xtls.github.io/en/document/level-2/vless_reverse.html>. This is the current
//! (non-deprecated) reverse-proxy mechanism, distinct from the legacy root `reverse.bridges[] /
//! reverse.portals[]` section (deprecated by upstream in favor of this one; Feldjäger does not
//! implement the legacy section — see the architecture doc for the scope decision). The `reverse`
//! object has the identical shape in both of its two placements:
//! - portal (public) side: `inbounds[].settings.clients[].reverse` (VLESS inbound client);
//! - bridge (internal) side: `outbounds[].settings.reverse` (VLESS outbound).
//!
//! `{"tag": "…"}` is the minimal form; an optional `sniffing` object (identical `SniffingObject`
//! shape used elsewhere, <https://xtls.github.io/en/config/inbound.html#sniffingobject>) may ride
//! along on the bridge side to let the portal make domain-based routing decisions for reverse
//! traffic. `tag` is a required, non-empty, purely local identifier — the two sides do not need to
//! agree on the same string.

use serde_json::{Map, Value};

use super::inbound_edit::KNOWN_DEST_OVERRIDE;
use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// `reverse.sniffing` — same fields as top-level inbound `sniffing`, nested under `reverse`
/// instead of directly on the inbound object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReverseSniffingDraft {
    /// `enabled`.
    pub enabled: bool,
    /// Known `destOverride` tokens selected in the UI, stable order.
    pub dest_override: Vec<String>,
    /// Unknown `destOverride` entries, preserved verbatim.
    pub unknown_dest_override: Vec<String>,
    /// `metadataOnly`.
    pub metadata_only: bool,
    /// `routeOnly`.
    pub route_only: bool,
    /// Unknown `sniffing` object keys (e.g. `domainsExcluded`).
    pub extras: Map<String, Value>,
}

/// `reverse` object: `{tag, sniffing?}`, placed under either a VLESS inbound client or a VLESS
/// outbound's `settings`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReverseTagDraft {
    /// `tag` — required, local-only identifier tying this side to a routing rule.
    pub tag: String,
    /// Optional `sniffing` (documented on the bridge/outbound side only, but the shape is
    /// generic — preserved/editable wherever it appears).
    pub sniffing: Option<ReverseSniffingDraft>,
    /// Unknown `reverse` object keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

impl ReverseTagDraft {
    /// A fresh, empty draft for turning on reverse via a checkbox in the GUI.
    pub fn new() -> Self {
        Self::default()
    }
}

const KNOWN_REVERSE_KEYS: &[&str] = &["tag", "sniffing"];
const KNOWN_SNIFFING_KEYS: &[&str] = &["enabled", "destOverride", "metadataOnly", "routeOnly"];

/// Parses a `reverse` object (client or outbound `settings.reverse`). `None` when the key is
/// absent, null, or not an object.
pub fn parse_reverse(value: Option<&Value>) -> Option<ReverseTagDraft> {
    let object = value?.as_object()?;

    let tag = object
        .get("tag")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    let sniffing = object
        .get("sniffing")
        .and_then(Value::as_object)
        .map(parse_reverse_sniffing);

    let mut extras = Map::new();
    for (key, value) in object {
        if !KNOWN_REVERSE_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }

    Some(ReverseTagDraft {
        tag,
        sniffing,
        extras,
    })
}

fn parse_reverse_sniffing(object: &Map<String, Value>) -> ReverseSniffingDraft {
    let mut known_dest = Vec::new();
    let mut unknown_dest = Vec::new();
    if let Some(items) = object.get("destOverride").and_then(Value::as_array) {
        for item in items {
            if let Some(token) = item.as_str() {
                if KNOWN_DEST_OVERRIDE.contains(&token) {
                    if !known_dest.iter().any(|t| t == token) {
                        known_dest.push(token.to_owned());
                    }
                } else {
                    unknown_dest.push(token.to_owned());
                }
            }
        }
    }
    let dest_override = KNOWN_DEST_OVERRIDE
        .iter()
        .filter(|token| known_dest.iter().any(|t| t == **token))
        .map(|token| (*token).to_owned())
        .collect();

    let mut extras = Map::new();
    for (key, value) in object {
        if !KNOWN_SNIFFING_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }

    ReverseSniffingDraft {
        enabled: object.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        dest_override,
        unknown_dest_override: unknown_dest,
        metadata_only: object.get("metadataOnly").and_then(Value::as_bool).unwrap_or(false),
        route_only: object.get("routeOnly").and_then(Value::as_bool).unwrap_or(false),
        extras,
    }
}

/// Validates a `reverse` draft before writing: `tag` must be a non-empty, control-character-free
/// string (it is the only field Xray actually requires).
pub fn validate_reverse(draft: &ReverseTagDraft) -> ConfigModifyResult<()> {
    if draft.tag.trim().is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "reverse.tag must not be empty".to_owned(),
        ));
    }
    if draft.tag.chars().any(|c| c.is_control()) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "reverse.tag must not contain control characters".to_owned(),
        ));
    }
    Ok(())
}

/// Builds the `reverse` object `Value` from a draft. Caller is expected to have validated it
/// first via [`validate_reverse`].
pub fn reverse_to_value(draft: &ReverseTagDraft) -> Value {
    let mut object = Map::new();
    object.insert("tag".to_owned(), Value::String(draft.tag.trim().to_owned()));
    if let Some(sniffing) = &draft.sniffing {
        object.insert("sniffing".to_owned(), reverse_sniffing_to_value(sniffing));
    }
    for (key, value) in &draft.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

fn reverse_sniffing_to_value(draft: &ReverseSniffingDraft) -> Value {
    let mut object = Map::new();
    object.insert("enabled".to_owned(), Value::Bool(draft.enabled));
    let mut dest = Vec::new();
    for token in KNOWN_DEST_OVERRIDE {
        if draft.dest_override.iter().any(|t| t == *token) {
            dest.push(Value::String((*token).to_owned()));
        }
    }
    for token in &draft.unknown_dest_override {
        dest.push(Value::String(token.clone()));
    }
    if !dest.is_empty() {
        object.insert("destOverride".to_owned(), Value::Array(dest));
    }
    if draft.metadata_only {
        object.insert("metadataOnly".to_owned(), Value::Bool(true));
    }
    if draft.route_only {
        object.insert("routeOnly".to_owned(), Value::Bool(true));
    }
    for (key, value) in &draft.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_tag_only() {
        let value = json!({"tag": "reverse-out"});
        let draft = parse_reverse(Some(&value)).expect("parsed");
        assert_eq!(draft.tag, "reverse-out");
        assert!(draft.sniffing.is_none());
        assert!(draft.extras.is_empty());
    }

    #[test]
    fn absent_returns_none() {
        assert!(parse_reverse(None).is_none());
        let null = Value::Null;
        assert!(parse_reverse(Some(&null)).is_none());
    }

    #[test]
    fn parses_sniffing_and_preserves_unknown_dest_override() {
        let value = json!({
            "tag": "reverse-in",
            "sniffing": {"enabled": true, "destOverride": ["http", "tls", "futureproto"]}
        });
        let draft = parse_reverse(Some(&value)).expect("parsed");
        let sniffing = draft.sniffing.expect("sniffing");
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override, vec!["http".to_owned(), "tls".to_owned()]);
        assert_eq!(sniffing.unknown_dest_override, vec!["futureproto".to_owned()]);
    }

    #[test]
    fn roundtrips_through_value() {
        let value = json!({
            "tag": "reverse-in",
            "sniffing": {"enabled": true, "destOverride": ["http", "tls"], "metadataOnly": true},
            "futureReverseField": "keep"
        });
        let draft = parse_reverse(Some(&value)).expect("parsed");
        let rebuilt = reverse_to_value(&draft);
        let reparsed = parse_reverse(Some(&rebuilt)).expect("reparsed");
        assert_eq!(reparsed, draft);
        assert_eq!(rebuilt.get("futureReverseField"), Some(&json!("keep")));
    }

    #[test]
    fn validate_rejects_empty_tag() {
        let draft = ReverseTagDraft::new();
        let err = validate_reverse(&draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn validate_accepts_non_empty_tag() {
        let mut draft = ReverseTagDraft::new();
        draft.tag = "reverse-out".to_owned();
        assert!(validate_reverse(&draft).is_ok());
    }
}
