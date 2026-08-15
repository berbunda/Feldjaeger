//! `streamSettings.finalmask` `tcp[]` / `udp[]` masking-layer chains (Roadmap §2.3:86).
//!
//! FinalMask is Xray-core's reworked TCP/UDP packet-masking subsystem: a sibling of
//! `realitySettings`/`tlsSettings` under `streamSettings`, applying the final layer of
//! disguise after transport and security processing. Each array holds ordered layers of
//! `{ "type": string, "settings": object }`; the first element is the innermost layer.
//! See <https://xtls.github.io/ru/config/transports/finalmask.html>.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Documented `finalmask.tcp[].type` values.
pub const TCP_FINALMASK_TYPES: &[&str] = &["header-custom", "fragment", "sudoku"];

/// Documented `finalmask.udp[].type` values.
pub const UDP_FINALMASK_TYPES: &[&str] = &[
    "header-custom",
    "mkcp-legacy",
    "noise",
    "salamander",
    "sudoku",
    "xdns",
    "xicmp",
    "realm",
];

/// One `finalmask.tcp[]` / `finalmask.udp[]` masking layer.
///
/// `settings` is preserved as a raw JSON object (same trust boundary as
/// [`crate::xray::config::inbound_security::TlsSettingsDraft::ech_sockopt`]) — FinalMask layer
/// types have many type-specific sub-fields, so Feldjäger models the layer chain (type +
/// ordering) as typed data while leaving each layer's settings as opaque JSON per
/// `docs/rules.md`'s "rare/advanced fields may be displayed through generic JSON" allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalMaskLayerDraft {
    /// `type` (preset from [`TCP_FINALMASK_TYPES`] / [`UDP_FINALMASK_TYPES`], or free text for
    /// unlisted/future types).
    pub layer_type: String,
    /// `settings` object (defaults to an empty object).
    pub settings: Value,
}

impl Default for FinalMaskLayerDraft {
    fn default() -> Self {
        Self {
            layer_type: String::new(),
            settings: Value::Object(Map::new()),
        }
    }
}

/// Parses a `finalmask.tcp` / `finalmask.udp` array into typed layers.
///
/// Returns `None` when any element doesn't match `{ "type": string, "settings"?: object }` —
/// callers should then leave the array untouched/preserved-raw instead of "owning" it, matching
/// the existing `finalmask` non-object preservation fallback for `quicParams`.
pub fn parse_finalmask_layers(array: &[Value]) -> Option<Vec<FinalMaskLayerDraft>> {
    array
        .iter()
        .map(|entry| {
            let object = entry.as_object()?;
            let layer_type = object.get("type")?.as_str()?.to_owned();
            let settings = match object.get("settings") {
                Some(value) if value.is_object() => value.clone(),
                Some(_) => return None,
                None => Value::Object(Map::new()),
            };
            Some(FinalMaskLayerDraft {
                layer_type,
                settings,
            })
        })
        .collect()
}

/// Builds the `finalmask.tcp` / `finalmask.udp` array `Value` from typed layers.
pub fn finalmask_layers_to_value(layers: &[FinalMaskLayerDraft]) -> Value {
    Value::Array(
        layers
            .iter()
            .map(|layer| {
                let mut object = Map::new();
                object.insert(
                    "type".to_owned(),
                    Value::String(layer.layer_type.trim().to_owned()),
                );
                object.insert("settings".to_owned(), layer.settings.clone());
                Value::Object(object)
            })
            .collect(),
    )
}

/// Validates that every layer has a non-empty `type` before writing.
pub fn validate_finalmask_layers(layers: &[FinalMaskLayerDraft]) -> ConfigModifyResult<()> {
    if layers.iter().any(|layer| layer.layer_type.trim().is_empty()) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "FinalMask layers require a non-empty type".to_owned(),
        ));
    }
    Ok(())
}

/// Detects a `salamander` `finalmask.udp[]` layer (Hysteria2-compatible obfuscation, per
/// <https://xtls.github.io/ru/config/transports/finalmask.html>) and returns its password.
///
/// Read-only inference from preserved raw JSON — Feldjäger does not yet offer a FinalMask UDP
/// editor for Hysteria inbounds (`InboundStreamDraft.finalmask_udp` is VLESS/Trojan-only), so
/// this only surfaces whatever is already configured on disk into the Share URI (Roadmap
/// §3:121). Takes the **full inbound object**, not just the finalmask array.
pub fn hysteria_salamander_obfs_password(inbound: &Value) -> Option<String> {
    let layers = inbound
        .get("streamSettings")?
        .get("finalmask")?
        .get("udp")?
        .as_array()?;
    for layer in layers {
        let is_salamander = layer
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.eq_ignore_ascii_case("salamander"));
        if !is_salamander {
            continue;
        }
        let password = layer
            .get("settings")
            .and_then(|s| s.get("password"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(password) = password {
            return Some(password.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_typed_layers_with_default_settings() {
        let array = vec![
            json!({"type": "fragment", "settings": {"packets": "tlshello"}}),
            json!({"type": "sudoku"}),
        ];
        let layers = parse_finalmask_layers(&array).expect("layers");
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].layer_type, "fragment");
        assert_eq!(layers[0].settings, json!({"packets": "tlshello"}));
        assert_eq!(layers[1].layer_type, "sudoku");
        assert_eq!(layers[1].settings, json!({}));
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(parse_finalmask_layers(&[json!("not-an-object")]).is_none());
        assert!(parse_finalmask_layers(&[json!({"settings": {}})]).is_none());
        assert!(parse_finalmask_layers(&[json!({"type": "fragment", "settings": "bad"})]).is_none());
    }

    #[test]
    fn roundtrips_layers_to_value() {
        let layers = vec![FinalMaskLayerDraft {
            layer_type: "salamander".to_owned(),
            settings: json!({"password": "secret"}),
        }];
        let value = finalmask_layers_to_value(&layers);
        assert_eq!(
            value,
            json!([{"type": "salamander", "settings": {"password": "secret"}}])
        );
        let parsed = parse_finalmask_layers(value.as_array().unwrap()).expect("layers");
        assert_eq!(parsed, layers);
    }

    #[test]
    fn validate_rejects_empty_type() {
        let layers = vec![FinalMaskLayerDraft::default()];
        let err = validate_finalmask_layers(&layers).unwrap_err();
        assert!(err.message().contains("type"));
    }

    #[test]
    fn validate_accepts_non_empty_type() {
        let layers = vec![FinalMaskLayerDraft {
            layer_type: "noise".to_owned(),
            settings: json!({}),
        }];
        assert!(validate_finalmask_layers(&layers).is_ok());
    }

    #[test]
    fn salamander_obfs_password_found() {
        let inbound = json!({
            "streamSettings": {
                "finalmask": {
                    "udp": [{"type": "salamander", "settings": {"password": "cat"}}]
                }
            }
        });
        assert_eq!(
            hysteria_salamander_obfs_password(&inbound),
            Some("cat".to_owned())
        );
    }

    #[test]
    fn salamander_obfs_password_case_insensitive_type() {
        let inbound = json!({
            "streamSettings": {
                "finalmask": {"udp": [{"type": "Salamander", "settings": {"password": "cat"}}]}
            }
        });
        assert_eq!(
            hysteria_salamander_obfs_password(&inbound),
            Some("cat".to_owned())
        );
    }

    #[test]
    fn salamander_obfs_password_absent_when_no_salamander_layer() {
        let inbound = json!({
            "streamSettings": {
                "finalmask": {"udp": [{"type": "noise", "settings": {}}]}
            }
        });
        assert_eq!(hysteria_salamander_obfs_password(&inbound), None);
    }

    #[test]
    fn salamander_obfs_password_absent_when_no_finalmask() {
        assert_eq!(hysteria_salamander_obfs_password(&json!({})), None);
    }
}
