//! Trojan outbound Protocol tab (Roadmap §4.2) —
//! <https://xtls.github.io/en/config/outbounds/trojan.html>.
//!
//! Verified against Xray-core v26.9.30 (`infra/conf/trojan.go`, `TrojanClientConfig.Build()`) and
//! `xray run -test` 26.9.30:
//! - The documented form is flat: `address` / `port` / `password` / `email` / `level` on
//!   `settings`. A non-null `address` makes `Build()` build the one server from the flat keys and
//!   ignore `servers`; otherwise `servers[]` must hold exactly one entry.
//! - Decoding is strict per field: `port` is a JSON `uint16` (a string fails), `level` a `uint8`
//!   (256 fails), `email` / `password` strings. `Build()` refuses port 0, an empty `password`
//!   (a single space is accepted, so it is never trimmed) and any non-empty `flow` ("The feature
//!   Flow for Trojan has been removed").
//! - Every load logs that Trojan is deprecated in favour of VLESS (non-removal warning).
//!
//! The editor writes the flat form. A `servers[]` outbound the core reads (no flat `address`) with
//! one server whose keys all exist in the flat form opens with
//! [`TrojanOutboundSettings::legacy_servers`] set, and Save rewrites it into the flat form — same
//! server for the core. Any other `servers[]` shape is Raw JSON only ([`legacy_servers_blocker`]).
//! `streamSettings` / `mux` are untouched siblings; unknown `settings` keys are preserved.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// `settings` keys of the flat form — and the only keys a `servers[0]` entry may have to be
/// converted (they are the same fields of `TrojanServerTarget`).
const FLAT_KEYS: &[&str] = &["address", "port", "level", "email", "password", "flow"];

/// Trojan outbound Protocol-tab draft (flat `settings` form).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrojanOutboundSettings {
    /// `address` — server IP or domain. Required.
    pub address: String,
    /// `port`, free text validated as 1-65535 on apply. Required.
    pub port: String,
    /// `password`, kept exactly as typed (the core compares it byte for byte). Required.
    pub password: String,
    /// `level` — index into `policy.levels`, free text validated as 0-255 on apply; empty = key
    /// absent (level 0).
    pub level: String,
    /// `email` — user label in logs and statistics; empty = key absent.
    pub email: String,
    /// `flow` as found on disk — a removed feature: any non-empty value fails the load. The editor
    /// never sets it; clearing it ("Remove flow") deletes the key.
    pub flow: String,
    /// The draft was read from the legacy `servers[0]` form; apply removes `settings.servers` and
    /// writes the flat keys instead.
    pub legacy_servers: bool,
}

/// `true` when the core reads `servers[]`: no non-null flat `address`, and `servers` present.
fn reads_servers(settings: &Map<String, Value>) -> bool {
    settings.get("address").is_none_or(Value::is_null) && settings.get("servers").is_some_and(|s| !s.is_null())
}

/// Why a `servers[]` Trojan outbound cannot be converted to the flat form (and so is Raw JSON
/// only); `None` when it can, or when it is not in that form.
pub fn legacy_servers_blocker(outbound: &Value) -> Option<String> {
    let settings = outbound.get("settings").and_then(Value::as_object)?;
    if !reads_servers(settings) {
        return None;
    }
    legacy_server_entry(settings).err()
}

/// The single `servers[0]` entry, when every key has a flat-form equivalent of the right type.
fn legacy_server_entry(settings: &Map<String, Value>) -> Result<&Map<String, Value>, String> {
    let servers = settings
        .get("servers")
        .and_then(Value::as_array)
        .ok_or_else(|| "settings.servers is not a JSON array".to_owned())?;
    let [server] = servers.as_slice() else {
        return Err(format!(
            "Xray-core requires exactly one servers[] entry (found {}) — use one outbound per \
             server and a balancer",
            servers.len()
        ));
    };
    let server = server
        .as_object()
        .ok_or_else(|| "servers[0] is not a JSON object".to_owned())?;
    if let Some(key) = server.keys().find(|key| !FLAT_KEYS.contains(&key.as_str())) {
        return Err(format!("servers[0].{key} has no flat-form equivalent"));
    }
    // A value of another type would read as empty and be lost on Save.
    if let Some(key) = ["address", "password", "email", "flow"]
        .iter()
        .find(|key| server.get(**key).is_some_and(|value| !value.is_string()))
    {
        return Err(format!("servers[0].{key} is not a string"));
    }
    Ok(server)
}

/// Parses a Trojan outbound's `settings`: the flat form, or a convertible `servers[]` form.
/// `None` for any other `servers[]` shape — see [`legacy_servers_blocker`].
pub fn parse_trojan_outbound_settings(outbound: &Value) -> Option<TrojanOutboundSettings> {
    let empty = Map::new();
    let settings = outbound.get("settings").and_then(Value::as_object).unwrap_or(&empty);
    let (entry, legacy_servers) = if reads_servers(settings) {
        (legacy_server_entry(settings).ok()?, true)
    } else {
        (settings, false)
    };
    Some(TrojanOutboundSettings {
        address: string_field(entry.get("address")),
        port: numeric_or_string_field(entry.get("port")),
        password: entry.get("password").and_then(Value::as_str).unwrap_or("").to_owned(),
        level: numeric_or_string_field(entry.get("level")),
        email: string_field(entry.get("email")),
        flow: string_field(entry.get("flow")),
        legacy_servers,
    })
}

/// Applies a Trojan draft onto `settings` in place: the flat keys are owned by the draft (with
/// [`TrojanOutboundSettings::legacy_servers`], `servers` is removed); every other `settings` key
/// and the outbound's siblings are preserved.
pub fn apply_trojan_outbound_settings(
    outbound: &mut Value,
    draft: &TrojanOutboundSettings,
) -> ConfigModifyResult<()> {
    let address = draft.address.trim();
    if address.is_empty() {
        return Err(invalid("Trojan outbound address must not be empty"));
    }
    let port = draft
        .port
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("Trojan outbound port must be a number from 1 to 65535"))?;
    if draft.password.is_empty() {
        return Err(invalid("Trojan outbound password must not be empty — Xray-core refuses it"));
    }
    let level = match draft.level.trim() {
        "" => None,
        text => Some(text.parse::<u8>().map_err(|_| {
            invalid("Trojan outbound level must be a whole number from 0 to 255 — Xray-core refuses anything else")
        })?),
    };
    if !draft.flow.trim().is_empty() {
        return Err(invalid(
            "Trojan flow is a removed feature — Xray-core refuses any value; use \"Remove flow\" \
             (VLESS has flow)",
        ));
    }

    let object = outbound
        .as_object_mut()
        .ok_or_else(|| invalid("outbound must be a JSON object"))?;
    if object.get("settings").is_none_or(Value::is_null) {
        object.insert("settings".to_owned(), Value::Object(Map::new()));
    }
    let settings = object
        .get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("settings must be a JSON object"))?;

    settings.insert("address".to_owned(), Value::String(address.to_owned()));
    settings.insert("port".to_owned(), Value::Number(port.into()));
    settings.insert("password".to_owned(), Value::String(draft.password.clone()));
    match level {
        Some(level) => {
            settings.insert("level".to_owned(), Value::Number(level.into()));
        }
        None => {
            settings.remove("level");
        }
    }
    match draft.email.trim() {
        "" => {
            settings.remove("email");
        }
        email => {
            settings.insert("email".to_owned(), Value::String(email.to_owned()));
        }
    }
    settings.remove("flow");
    if draft.legacy_servers {
        // `legacy_server_entry` admits only keys carried into the flat form above.
        settings.remove("servers");
    }
    Ok(())
}

fn invalid(message: &str) -> ConfigModifyError {
    ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message.to_owned())
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

    fn draft() -> TrojanOutboundSettings {
        TrojanOutboundSettings {
            address: "example.com".to_owned(),
            port: "443".to_owned(),
            password: " secret ".to_owned(),
            ..TrojanOutboundSettings::default()
        }
    }

    #[test]
    fn flat_form_round_trips_and_keeps_foreign_keys() {
        let original = json!({"protocol": "trojan", "tag": "t", "mux": {"enabled": true},
            "streamSettings": {"security": "tls"},
            "settings": {"address": "example.com", "port": 443, "password": " secret ",
                         "level": 1, "email": "a@b", "future": [1]}});
        let parsed = parse_trojan_outbound_settings(&original).expect("flat");
        assert_eq!(parsed.password, " secret ", "never trimmed");
        assert_eq!(parsed.level, "1");
        assert!(!parsed.legacy_servers);
        let mut outbound = original.clone();
        apply_trojan_outbound_settings(&mut outbound, &parsed).expect("apply");
        assert_eq!(outbound, original);
    }

    #[test]
    fn apply_writes_numbers_and_drops_empty_optionals() {
        let mut outbound = json!({"protocol": "trojan", "settings": {"level": 3, "email": "x"}});
        apply_trojan_outbound_settings(&mut outbound, &draft()).expect("apply");
        assert_eq!(outbound["settings"], json!({"address": "example.com", "port": 443, "password": " secret "}));
        let mut with_level = draft();
        with_level.level = "255".to_owned();
        with_level.email = " user@example ".to_owned();
        apply_trojan_outbound_settings(&mut outbound, &with_level).expect("level");
        assert_eq!(outbound["settings"]["level"], 255);
        assert_eq!(outbound["settings"]["email"], "user@example");
    }

    /// Values `xray run -test` 26.9.30 refuses.
    #[test]
    fn apply_refuses_what_the_core_refuses() {
        let cases: [(&str, fn(&mut TrojanOutboundSettings)); 7] = [
            ("address", |d| d.address = " ".to_owned()),
            ("port 0", |d| d.port = "0".to_owned()),
            ("port 65536", |d| d.port = "65536".to_owned()),
            ("password", |d| d.password.clear()),
            ("level 256", |d| d.level = "256".to_owned()),
            ("level -1", |d| d.level = "-1".to_owned()),
            ("flow", |d| d.flow = "xtls-rprx-direct".to_owned()),
        ];
        for (name, edit) in cases {
            let mut draft = draft();
            edit(&mut draft);
            let mut outbound = json!({"protocol": "trojan", "settings": {}});
            let error = apply_trojan_outbound_settings(&mut outbound, &draft).unwrap_err();
            assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed, "{name}");
            assert_eq!(outbound["settings"], json!({}), "{name}: nothing written");
        }
    }

    #[test]
    fn removing_flow_deletes_the_key() {
        let original = json!({"protocol": "trojan", "settings": {"address": "a", "port": 1, "password": "p", "flow": "xtls-rprx-direct"}});
        let mut parsed = parse_trojan_outbound_settings(&original).expect("flat");
        assert_eq!(parsed.flow, "xtls-rprx-direct");
        parsed.flow.clear();
        let mut outbound = original.clone();
        apply_trojan_outbound_settings(&mut outbound, &parsed).expect("apply");
        assert!(outbound["settings"].get("flow").is_none());
    }

    #[test]
    fn single_server_converts_to_the_flat_form() {
        let original = json!({"protocol": "trojan", "settings": {"address": null, "keep": 1,
            "servers": [{"address": "10.0.0.1", "port": "443", "password": "p", "level": 2, "email": "e"}]}});
        let parsed = parse_trojan_outbound_settings(&original).expect("convertible");
        assert!(parsed.legacy_servers);
        assert_eq!(parsed.port, "443");
        let mut outbound = original.clone();
        apply_trojan_outbound_settings(&mut outbound, &parsed).expect("apply");
        assert_eq!(
            outbound["settings"],
            json!({"address": "10.0.0.1", "keep": 1, "port": 443, "password": "p", "level": 2, "email": "e"})
        );
        let reparsed = parse_trojan_outbound_settings(&outbound).expect("flat");
        assert!(!reparsed.legacy_servers);
    }

    #[test]
    fn flat_address_wins_over_servers_like_the_core() {
        let outbound = json!({"protocol": "trojan", "settings": {"address": "a", "port": 1, "password": "p",
            "servers": [{"address": "x"}, {"address": "y"}]}});
        let parsed = parse_trojan_outbound_settings(&outbound).expect("flat");
        assert!(!parsed.legacy_servers);
        assert_eq!(parsed.address, "a");
        assert!(legacy_servers_blocker(&outbound).is_none());
        let mut written = outbound.clone();
        apply_trojan_outbound_settings(&mut written, &parsed).expect("apply");
        assert_eq!(written["settings"]["servers"], outbound["settings"]["servers"], "ignored, kept");
    }

    #[test]
    fn unconvertible_servers_are_raw_json_only() {
        for (settings, reason) in [
            (json!({"servers": []}), "exactly one"),
            (json!({"servers": [{"address": "a"}, {"address": "b"}]}), "exactly one"),
            (json!({"servers": [{"address": "a", "ota": true}]}), "servers[0].ota"),
            (json!({"servers": [{"address": "a", "password": 5}]}), "not a string"),
            (json!({"servers": ["a"]}), "not a JSON object"),
            (json!({"servers": {"address": "a"}}), "not a JSON array"),
        ] {
            let outbound = json!({"protocol": "trojan", "settings": settings});
            assert!(parse_trojan_outbound_settings(&outbound).is_none(), "{settings}");
            let blocker = legacy_servers_blocker(&outbound).expect("blocker");
            assert!(blocker.contains(reason), "{settings}: {blocker}");
        }
    }
}
