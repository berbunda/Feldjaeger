//! VLESS outbound Protocol tab — bridge side of VLESS-native reverse proxy (Roadmap §2.1:58),
//! plus a plain forward VLESS outbound.
//!
//! <https://xtls.github.io/en/document/level-2/vless_reverse.html> documents this outbound with a
//! **flat** `settings` object — `address`/`port`/`id`/`encryption`/`flow` sit directly on
//! `settings`, not nested under `vnext[]`/`users[]` as the general VLESS outbound schema allows.
//! Feldjäger only edits this flat form (deliberately narrower than the eventual full "Outbounds
//! Shell: VLESS (+ stream/security matrix)", Roadmap §4.2 — this pass is scoped to what reverse
//! proxying and outbound chaining need, not full transport/security parity with the VLESS inbound
//! Shell). An outbound already using the legacy `vnext[]` array is left alone —
//! [`is_legacy_vnext_form`] makes [`super::parse_outbound_settings`] return `None` for it, the
//! same "not shell-editable" signal already used for out-of-scope protocols; Raw JSON remains
//! available regardless.
//!
//! `streamSettings`/`mux` are untouched siblings, same as the other three outbound Shells —
//! `apply_vless_settings` only ever touches keys under `settings`.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::config::reverse_proxy::{ReverseTagDraft, parse_reverse, reverse_to_value, validate_reverse};

/// `true` when `settings.vnext` is an array — the traditional multi-server/multi-user VLESS
/// outbound schema this editor does not attempt to parse or preserve field-by-field.
pub fn is_legacy_vnext_form(outbound: &Value) -> bool {
    outbound
        .get("settings")
        .and_then(|s| s.get("vnext"))
        .is_some_and(Value::is_array)
}

/// VLESS outbound Protocol-tab draft (flat `settings` form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessOutboundSettings {
    /// `settings.address` — the server this outbound dials. Required.
    pub address: String,
    /// `settings.port`, kept as free text and validated as 1-65535 on apply. Required.
    pub port: String,
    /// `settings.id` — client UUID matching a `clients[]` entry on the far end. Required.
    pub id: String,
    /// `settings.encryption` — VLESS post-quantum encryption string; empty = key absent
    /// (pre-encryption / matches inbound `decryption: "none"`).
    pub encryption: String,
    /// `settings.flow`; empty = key absent.
    pub flow: String,
    /// `settings.reverse` — bridge-side registration (Roadmap §2.1:58); `None` = plain forward
    /// VLESS outbound.
    pub reverse: Option<ReverseTagDraft>,
}

impl VlessOutboundSettings {
    /// Default for Add VLESS outbound: everything blank, no reverse. The GUI is expected to
    /// offer a "Generate UUID" action for `id`, same as the inbound Users Add dialog.
    pub fn default_draft() -> Self {
        Self {
            address: String::new(),
            port: String::new(),
            id: String::new(),
            encryption: String::new(),
            flow: String::new(),
            reverse: None,
        }
    }
}

/// Parses a VLESS outbound's flat `settings` into a draft. Returns `None` for the legacy
/// `vnext[]` form — see [`is_legacy_vnext_form`].
pub fn parse_vless_outbound_settings(outbound: &Value) -> Option<VlessOutboundSettings> {
    if is_legacy_vnext_form(outbound) {
        return None;
    }
    let settings = outbound.get("settings").and_then(Value::as_object);
    Some(VlessOutboundSettings {
        address: string_field(settings.and_then(|s| s.get("address"))),
        port: numeric_or_string_field(settings.and_then(|s| s.get("port"))),
        id: string_field(settings.and_then(|s| s.get("id"))),
        encryption: string_field(settings.and_then(|s| s.get("encryption"))),
        flow: string_field(settings.and_then(|s| s.get("flow"))),
        reverse: parse_reverse(settings.and_then(|s| s.get("reverse"))),
    })
}

/// Applies a VLESS outbound draft onto `settings` in place — only `address`/`port`/`id`/
/// `encryption`/`flow`/`reverse` are touched; any other existing `settings` keys (and outbound
/// siblings like `streamSettings`/`mux`/`proxySettings`) are preserved untouched.
pub fn apply_vless_outbound_settings(
    outbound: &mut Value,
    draft: &VlessOutboundSettings,
) -> ConfigModifyResult<()> {
    let address = draft.address.trim();
    if address.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound address must not be empty".to_owned(),
        ));
    }
    let id = draft.id.trim();
    if id.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound id must not be empty".to_owned(),
        ));
    }
    let port_trimmed = draft.port.trim();
    let port: u32 = port_trimmed.parse().map_err(|_| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound port must be a valid port number (1-65535)".to_owned(),
        )
    })?;
    if port == 0 || port > 65535 {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound port must be between 1 and 65535".to_owned(),
        ));
    }
    if let Some(reverse) = &draft.reverse {
        validate_reverse(reverse)?;
    }

    let object = outbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound must be a JSON object".to_owned(),
        )
    })?;
    if !object.contains_key("settings") || object.get("settings").is_some_and(Value::is_null) {
        object.insert("settings".to_owned(), Value::Object(Map::new()));
    }
    let settings = object
        .get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "settings must be a JSON object".to_owned(),
            )
        })?;

    settings.insert("address".to_owned(), Value::String(address.to_owned()));
    settings.insert("port".to_owned(), Value::Number(port.into()));
    settings.insert("id".to_owned(), Value::String(id.to_owned()));
    apply_optional_string(settings, "encryption", &draft.encryption);
    apply_optional_string(settings, "flow", &draft.flow);
    match &draft.reverse {
        Some(reverse) => {
            settings.insert("reverse".to_owned(), reverse_to_value(reverse));
        }
        None => {
            settings.remove("reverse");
        }
    }

    Ok(())
}

fn apply_optional_string(settings: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        settings.remove(key);
    } else {
        settings.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

fn string_field(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").trim().to_owned()
}

fn numeric_or_string_field(value: Option<&Value>) -> String {
    match value {
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(text)) => text.trim().to_owned(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "protocol": "vless",
            "settings": {
                "address": "yourserver.com",
                "port": 8443,
                "id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
                "flow": "xtls-rprx-vision",
                "encryption": "mlkem768x25519plus.native.0rtt.2PcBa3Yz0zBdt4p8-PkJMzx9hIj2Ve-UmrnmZRPnpRk",
                "reverse": {"tag": "reverse-in"}
            }
        })
    }

    #[test]
    fn parses_flat_form_with_reverse() {
        let draft = parse_vless_outbound_settings(&sample()).expect("parsed");
        assert_eq!(draft.address, "yourserver.com");
        assert_eq!(draft.port, "8443");
        assert_eq!(draft.id, "ac04551d-6ebf-4685-86e2-17c12491f7f4");
        assert_eq!(draft.flow, "xtls-rprx-vision");
        assert!(draft.encryption.starts_with("mlkem768x25519plus"));
        assert_eq!(draft.reverse.expect("reverse").tag, "reverse-in");
    }

    #[test]
    fn legacy_vnext_form_is_not_parsed() {
        let outbound = json!({
            "protocol": "vless",
            "settings": {"vnext": [{"address": "a", "port": 443, "users": [{"id": "u"}]}]}
        });
        assert!(is_legacy_vnext_form(&outbound));
        assert!(parse_vless_outbound_settings(&outbound).is_none());
    }

    #[test]
    fn apply_roundtrip_preserves_unknown_and_siblings() {
        let mut outbound = json!({
            "protocol": "vless",
            "settings": {"futureField": "keep"},
            "streamSettings": {"network": "tcp"},
            "mux": {"enabled": true}
        });
        let draft = VlessOutboundSettings {
            address: "host.example".to_owned(),
            port: "443".to_owned(),
            id: "11111111-1111-1111-1111-111111111111".to_owned(),
            encryption: String::new(),
            flow: String::new(),
            reverse: None,
        };
        apply_vless_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["address"], "host.example");
        assert_eq!(outbound["settings"]["port"], 443);
        assert_eq!(outbound["settings"]["id"], "11111111-1111-1111-1111-111111111111");
        assert!(outbound["settings"].get("encryption").is_none());
        assert!(outbound["settings"].get("flow").is_none());
        assert!(outbound["settings"].get("reverse").is_none());
        assert_eq!(outbound["settings"]["futureField"], "keep");
        assert_eq!(outbound["streamSettings"]["network"], "tcp");
        assert_eq!(outbound["mux"]["enabled"], true);
    }

    #[test]
    fn apply_writes_reverse_with_sniffing() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let draft = VlessOutboundSettings {
            address: "host.example".to_owned(),
            port: "443".to_owned(),
            id: "11111111-1111-1111-1111-111111111111".to_owned(),
            encryption: String::new(),
            flow: String::new(),
            reverse: Some(ReverseTagDraft {
                tag: "reverse-in".to_owned(),
                sniffing: None,
                extras: Map::new(),
            }),
        };
        apply_vless_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["reverse"]["tag"], "reverse-in");
    }

    #[test]
    fn apply_rejects_empty_address() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.id = "11111111-1111-1111-1111-111111111111".to_owned();
        draft.port = "443".to_owned();
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn apply_rejects_empty_id() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.address = "host.example".to_owned();
        draft.port = "443".to_owned();
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn apply_rejects_invalid_port() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.address = "host.example".to_owned();
        draft.id = "11111111-1111-1111-1111-111111111111".to_owned();
        draft.port = "70000".to_owned();
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn apply_rejects_reverse_with_empty_tag() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.address = "host.example".to_owned();
        draft.id = "11111111-1111-1111-1111-111111111111".to_owned();
        draft.port = "443".to_owned();
        draft.reverse = Some(ReverseTagDraft::new());
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }
}
