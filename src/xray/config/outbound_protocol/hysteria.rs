//! Hysteria outbound Protocol tab (Roadmap §4.2) —
//! <https://xtls.github.io/en/config/outbounds/hysteria.html>.
//!
//! Verified against Xray-core v26.9.30 (`infra/conf/hysteria.go`, `HysteriaClientConfig`) and
//! `xray run -test` 26.9.30: `settings` holds only `version` (a JSON integer that must be 2 —
//! missing, 1 or `"2"` fail the load), `address` and `port` (a JSON `uint16`: a string or a
//! `"443-445"` range fail). Missing `address` / `port` pass `-test` but leave the outbound with
//! no server. The password (`auth`), the transport and TLS live in `streamSettings` (the shared
//! stream editor): without the `hysteria` transport Xray fails to start ("not hysteria
//! transport"), without TLS every connection fails ("tls config is nil", live check). Unknown
//! `settings` keys are preserved; `streamSettings` / `mux` are untouched siblings.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// The only `settings.version` Xray-core accepts.
pub const HYSTERIA_OUTBOUND_VERSION: u64 = 2;

/// Hysteria outbound Protocol-tab draft.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HysteriaOutboundSettings {
    /// `address` — server IP or domain. Required.
    pub address: String,
    /// `port`, free text validated as 1-65535 on apply. Required.
    pub port: String,
    /// `version` as found on disk when it is not the number 2 (`None` = fine, or a new outbound).
    /// Save always writes 2.
    pub version_on_disk: Option<Value>,
}

impl HysteriaOutboundSettings {
    /// `version` as on disk in a short form for the GUI: `missing`, or the JSON value.
    pub fn version_on_disk_label(&self) -> Option<String> {
        self.version_on_disk.as_ref().map(|value| match value {
            Value::Null => "missing".to_owned(),
            other => other.to_string(),
        })
    }
}

/// Reads a Hysteria outbound's `settings` into a draft.
pub fn parse_hysteria_outbound_settings(outbound: &Value) -> HysteriaOutboundSettings {
    let settings = outbound.get("settings").and_then(Value::as_object);
    let version = settings.and_then(|s| s.get("version")).cloned().unwrap_or(Value::Null);
    HysteriaOutboundSettings {
        address: settings
            .and_then(|s| s.get("address"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned(),
        port: match settings.and_then(|s| s.get("port")) {
            Some(Value::Number(number)) => number.to_string(),
            Some(Value::String(text)) => text.trim().to_owned(),
            _ => String::new(),
        },
        version_on_disk: (version.as_u64() != Some(HYSTERIA_OUTBOUND_VERSION)).then_some(version),
    }
}

/// Applies a Hysteria draft onto `settings` in place: `version` (always 2), `address`, `port`;
/// every other `settings` key and the outbound's siblings are preserved.
pub fn apply_hysteria_outbound_settings(
    outbound: &mut Value,
    draft: &HysteriaOutboundSettings,
) -> ConfigModifyResult<()> {
    let address = draft.address.trim();
    if address.is_empty() {
        return Err(invalid("Hysteria outbound address must not be empty"));
    }
    let port = draft
        .port
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            invalid(
                "Hysteria outbound port must be one number from 1 to 65535 — Xray-core refuses a \
                 range here (port hopping is the udphop mask in Stream / FinalMask)",
            )
        })?;

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
    settings.insert("version".to_owned(), Value::Number(HYSTERIA_OUTBOUND_VERSION.into()));
    settings.insert("address".to_owned(), Value::String(address.to_owned()));
    settings.insert("port".to_owned(), Value::Number(port.into()));
    Ok(())
}

fn invalid(message: &str) -> ConfigModifyError {
    ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn save_without_edits_is_byte_for_byte_and_keeps_foreign_keys() {
        let original = json!({"protocol": "hysteria", "tag": "h", "mux": {"enabled": false},
            "streamSettings": {"network": "hysteria", "security": "tls"},
            "settings": {"version": 2, "address": "example.com", "port": 443, "future": 1}});
        let draft = parse_hysteria_outbound_settings(&original);
        assert!(draft.version_on_disk.is_none());
        let mut outbound = original.clone();
        apply_hysteria_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound, original);
    }

    /// `version` other than the number 2 — refused by `xray run -test` 26.9.30 — is noted and
    /// replaced on Save.
    #[test]
    fn wrong_version_is_reported_and_fixed_on_save() {
        for (version, label) in [(json!(null), "missing"), (json!(1), "1"), (json!("2"), "\"2\"")] {
            let mut settings = json!({"address": "a", "port": 1});
            if !version.is_null() {
                settings["version"] = version.clone();
            }
            let original = json!({"protocol": "hysteria", "settings": settings});
            let draft = parse_hysteria_outbound_settings(&original);
            assert_eq!(draft.version_on_disk_label().as_deref(), Some(label), "{version}");
            let mut outbound = original.clone();
            apply_hysteria_outbound_settings(&mut outbound, &draft).expect("apply");
            assert_eq!(outbound["settings"]["version"], 2);
        }
    }

    #[test]
    fn new_outbound_gets_version_address_and_numeric_port() {
        let mut outbound = json!({"protocol": "hysteria", "settings": {}});
        let draft = HysteriaOutboundSettings {
            address: " 10.0.0.1 ".to_owned(),
            port: "8443".to_owned(),
            version_on_disk: None,
        };
        apply_hysteria_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"], json!({"version": 2, "address": "10.0.0.1", "port": 8443}));
    }

    #[test]
    fn apply_refuses_what_the_core_refuses() {
        for (address, port) in [("", "443"), ("a", ""), ("a", "0"), ("a", "65536"), ("a", "443-445")] {
            let draft = HysteriaOutboundSettings {
                address: address.to_owned(),
                port: port.to_owned(),
                version_on_disk: None,
            };
            let mut outbound = json!({"protocol": "hysteria", "settings": {}});
            let error = apply_hysteria_outbound_settings(&mut outbound, &draft).unwrap_err();
            assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed, "{address} {port}");
            assert_eq!(outbound["settings"], json!({}));
        }
    }
}
