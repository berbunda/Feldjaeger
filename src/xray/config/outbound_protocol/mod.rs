//! Outbound Protocol tab (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
//!
//! See <https://xtls.github.io/en/config/outbounds/freedom.html> and
//! <https://xtls.github.io/en/config/outbounds/blackhole.html>. Freedom's `domainStrategy`
//! reuses the same preset list as `streamSettings.sockopt.domainStrategy`
//! ([`crate::xray::config::inbound_stream::DOMAIN_STRATEGIES`]) — same wire values, different
//! JSON location.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Documented `settings.noises[].type` values (free text also accepted).
pub const FREEDOM_NOISE_TYPES: &[&str] = &["rand", "str", "hex", "base64"];

/// Documented `settings.response.type` values for Blackhole (free text also accepted).
pub const BLACKHOLE_RESPONSE_TYPES: &[&str] = &["none", "http"];

/// Outbound protocols currently reachable through the Outbound Shell (Add/Edit).
pub fn is_shell_editable_protocol(protocol: &str) -> bool {
    matches!(protocol.trim().to_ascii_lowercase().as_str(), "freedom" | "blackhole")
}

/// Freedom `settings.fragment` (packet fragmentation for DPI evasion).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FragmentDraft {
    /// `packets` (e.g. `"1-3"` or `"tlshello"`); empty = key absent.
    pub packets: String,
    /// `length` `Int32Range` (e.g. `"100-200"`); empty = key absent.
    pub length: String,
    /// `interval` `Int32Range` in ms (e.g. `"10-20"`); empty = key absent.
    pub interval: String,
    /// Unknown `fragment` keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// One `settings.noises[]` entry (traffic padding noise).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoiseDraft {
    /// `type` (`rand` | `str` | `hex` | `base64`; free text accepted).
    pub kind: String,
    /// `packet` payload spec (shape depends on `kind`).
    pub packet: String,
    /// `delay` `Int32Range` in ms (e.g. `"10-16"`); empty = key absent.
    pub delay: String,
    /// Unknown `noises[]` entry keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// Outbound Protocol-tab draft (non-General settings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundSettingsDraft {
    /// Freedom: direct/passthrough outbound.
    Freedom {
        /// `settings.domainStrategy`; empty = key absent (Xray default `AsIs`).
        domain_strategy: String,
        /// `settings.redirect` (`host:port` / `:port`); empty = key absent.
        redirect: String,
        /// `settings.userLevel`; `0` = key absent (Xray default).
        user_level: u64,
        /// `settings.fragment`; `None` = key absent.
        fragment: Option<FragmentDraft>,
        /// `settings.noises[]`; empty = key absent.
        noises: Vec<NoiseDraft>,
    },
    /// Blackhole: drops all traffic (optionally with a fake response before close).
    Blackhole {
        /// `settings.response.type` (`none` | `http`); empty = `response` key/object absent
        /// (Xray default `none`).
        response_type: String,
        /// Unknown `settings.response` keys, preserved verbatim.
        response_extras: Map<String, Value>,
    },
}

impl OutboundSettingsDraft {
    /// Default for Add Freedom.
    pub fn freedom_default() -> Self {
        Self::Freedom {
            domain_strategy: String::new(),
            redirect: String::new(),
            user_level: 0,
            fragment: None,
            noises: Vec::new(),
        }
    }

    /// Default for Add Blackhole.
    pub fn blackhole_default() -> Self {
        Self::Blackhole {
            response_type: String::new(),
            response_extras: Map::new(),
        }
    }
}

/// Reads a Protocol draft from an outbound object, when the protocol is shell-editable.
pub fn parse_outbound_settings(outbound: &Value) -> Option<OutboundSettingsDraft> {
    let protocol = outbound
        .get("protocol")
        .and_then(Value::as_str)?
        .trim()
        .to_ascii_lowercase();
    match protocol.as_str() {
        "freedom" => Some(parse_freedom_settings(outbound)),
        "blackhole" => Some(parse_blackhole_settings(outbound)),
        _ => None,
    }
}

fn parse_freedom_settings(outbound: &Value) -> OutboundSettingsDraft {
    let settings = outbound.get("settings").and_then(Value::as_object);
    let fragment = settings
        .and_then(|s| s.get("fragment"))
        .and_then(Value::as_object)
        .map(parse_fragment);
    let noises = settings
        .and_then(|s| s.get("noises"))
        .and_then(Value::as_array)
        .map(|array| array.iter().filter_map(Value::as_object).map(parse_noise).collect())
        .unwrap_or_default();
    OutboundSettingsDraft::Freedom {
        domain_strategy: string_field(settings.and_then(|s| s.get("domainStrategy"))),
        redirect: string_field(settings.and_then(|s| s.get("redirect"))),
        user_level: settings
            .and_then(|s| s.get("userLevel"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        fragment,
        noises,
    }
}

fn parse_blackhole_settings(outbound: &Value) -> OutboundSettingsDraft {
    let response = outbound
        .get("settings")
        .and_then(Value::as_object)
        .and_then(|s| s.get("response"))
        .and_then(Value::as_object);
    let mut response_extras = Map::new();
    if let Some(response) = response {
        for (key, value) in response {
            if key != "type" {
                response_extras.insert(key.clone(), value.clone());
            }
        }
    }
    OutboundSettingsDraft::Blackhole {
        response_type: string_field(response.and_then(|r| r.get("type"))),
        response_extras,
    }
}

const KNOWN_FRAGMENT_KEYS: &[&str] = &["packets", "length", "interval"];
const KNOWN_NOISE_KEYS: &[&str] = &["type", "packet", "delay"];

fn parse_fragment(object: &Map<String, Value>) -> FragmentDraft {
    let mut extras = Map::new();
    for (key, value) in object {
        if !KNOWN_FRAGMENT_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    FragmentDraft {
        packets: string_field(object.get("packets")),
        length: string_field(object.get("length")),
        interval: string_field(object.get("interval")),
        extras,
    }
}

fn parse_noise(object: &Map<String, Value>) -> NoiseDraft {
    let mut extras = Map::new();
    for (key, value) in object {
        if !KNOWN_NOISE_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    NoiseDraft {
        kind: string_field(object.get("type")),
        packet: string_field(object.get("packet")),
        delay: string_field(object.get("delay")),
        extras,
    }
}

fn string_field(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").trim().to_owned()
}

/// Applies a Protocol draft into `settings` **in place** — only the known top-level keys are
/// touched, so unrelated `settings` keys (and outbound siblings like `mux` / `streamSettings`)
/// are preserved untouched.
pub fn apply_outbound_settings(
    outbound: &mut Value,
    draft: &OutboundSettingsDraft,
) -> ConfigModifyResult<()> {
    match draft {
        OutboundSettingsDraft::Freedom {
            domain_strategy,
            redirect,
            user_level,
            fragment,
            noises,
        } => apply_freedom_settings(outbound, domain_strategy, redirect, *user_level, fragment, noises),
        OutboundSettingsDraft::Blackhole {
            response_type,
            response_extras,
        } => apply_blackhole_settings(outbound, response_type, response_extras),
    }
}

fn apply_blackhole_settings(
    outbound: &mut Value,
    response_type: &str,
    response_extras: &Map<String, Value>,
) -> ConfigModifyResult<()> {
    let settings = ensure_settings_object(outbound)?;
    let trimmed = response_type.trim();
    if trimmed.is_empty() && response_extras.is_empty() {
        settings.remove("response");
    } else {
        let mut response = Map::new();
        if !trimmed.is_empty() {
            response.insert("type".to_owned(), Value::String(trimmed.to_owned()));
        }
        for (key, value) in response_extras {
            if !response.contains_key(key) {
                response.insert(key.clone(), value.clone());
            }
        }
        settings.insert("response".to_owned(), Value::Object(response));
    }
    Ok(())
}

fn apply_freedom_settings(
    outbound: &mut Value,
    domain_strategy: &str,
    redirect: &str,
    user_level: u64,
    fragment: &Option<FragmentDraft>,
    noises: &[NoiseDraft],
) -> ConfigModifyResult<()> {
    validate_freedom_noises(noises)?;

    let settings = ensure_settings_object(outbound)?;
    apply_optional_string(settings, "domainStrategy", domain_strategy);
    apply_optional_string(settings, "redirect", redirect);
    if user_level != 0 {
        settings.insert("userLevel".to_owned(), Value::Number(user_level.into()));
    } else {
        settings.remove("userLevel");
    }
    match fragment {
        Some(fragment) => {
            settings.insert("fragment".to_owned(), fragment_to_value(fragment));
        }
        None => {
            settings.remove("fragment");
        }
    }
    if noises.is_empty() {
        settings.remove("noises");
    } else {
        settings.insert(
            "noises".to_owned(),
            Value::Array(noises.iter().map(noise_to_value).collect()),
        );
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

fn fragment_to_value(draft: &FragmentDraft) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "packets", &draft.packets);
    apply_optional_string(&mut object, "length", &draft.length);
    apply_optional_string(&mut object, "interval", &draft.interval);
    for (key, value) in &draft.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

fn noise_to_value(draft: &NoiseDraft) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "type", &draft.kind);
    apply_optional_string(&mut object, "packet", &draft.packet);
    apply_optional_string(&mut object, "delay", &draft.delay);
    for (key, value) in &draft.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

fn validate_freedom_noises(noises: &[NoiseDraft]) -> ConfigModifyResult<()> {
    for noise in noises {
        if noise.kind.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "Freedom noise type must not be empty".to_owned(),
            ));
        }
        if noise.packet.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "Freedom noise packet must not be empty".to_owned(),
            ));
        }
    }
    Ok(())
}

fn ensure_settings_object(outbound: &mut Value) -> ConfigModifyResult<&mut Map<String, Value>> {
    let root = outbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound must be a JSON object".to_owned(),
        )
    })?;
    if !root.contains_key("settings") || root.get("settings").is_some_and(Value::is_null) {
        root.insert("settings".to_owned(), Value::Object(Map::new()));
    }
    root.get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "settings must be a JSON object".to_owned(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn freedom_parse_apply_roundtrip_preserves_unknown() {
        let mut outbound = json!({
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIP",
                "redirect": "127.0.0.1:3366",
                "userLevel": 1,
                "fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20", "futureFragmentField": "keep"},
                "noises": [{"type": "rand", "packet": "10-20", "delay": "10-16", "futureNoiseField": "keep"}],
                "futureSettingsField": "keep"
            },
            "mux": {"enabled": true}
        });
        let draft = parse_outbound_settings(&outbound).expect("parse");
        apply_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["domainStrategy"], "UseIP");
        assert_eq!(outbound["settings"]["redirect"], "127.0.0.1:3366");
        assert_eq!(outbound["settings"]["userLevel"], 1);
        assert_eq!(outbound["settings"]["fragment"]["packets"], "tlshello");
        assert_eq!(outbound["settings"]["fragment"]["futureFragmentField"], "keep");
        assert_eq!(outbound["settings"]["noises"][0]["type"], "rand");
        assert_eq!(outbound["settings"]["noises"][0]["futureNoiseField"], "keep");
        assert_eq!(outbound["settings"]["futureSettingsField"], "keep");
        assert_eq!(outbound["mux"]["enabled"], true);
    }

    #[test]
    fn apply_omits_default_fields() {
        let mut outbound = json!({"protocol": "freedom"});
        apply_outbound_settings(&mut outbound, &OutboundSettingsDraft::freedom_default()).expect("apply");
        assert_eq!(outbound["settings"], json!({}));
    }

    #[test]
    fn apply_rejects_noise_with_empty_type() {
        let mut outbound = json!({"protocol": "freedom", "settings": {}});
        let draft = OutboundSettingsDraft::Freedom {
            domain_strategy: String::new(),
            redirect: String::new(),
            user_level: 0,
            fragment: None,
            noises: vec![NoiseDraft {
                kind: String::new(),
                packet: "10-20".to_owned(),
                delay: String::new(),
                extras: Map::new(),
            }],
        };
        let err = apply_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(err.to_string().contains("type"));
    }

    #[test]
    fn non_freedom_protocol_is_not_parsed() {
        let outbound = json!({"protocol": "wireguard", "settings": {}});
        assert!(parse_outbound_settings(&outbound).is_none());
    }

    #[test]
    fn blackhole_parse_apply_roundtrip_preserves_unknown() {
        let mut outbound = json!({
            "protocol": "blackhole",
            "settings": {
                "response": {"type": "http", "futureResponseField": "keep"},
                "futureSettingsField": "keep"
            },
            "mux": {"enabled": true}
        });
        let draft = parse_outbound_settings(&outbound).expect("parse");
        apply_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["response"]["type"], "http");
        assert_eq!(outbound["settings"]["response"]["futureResponseField"], "keep");
        assert_eq!(outbound["settings"]["futureSettingsField"], "keep");
        assert_eq!(outbound["mux"]["enabled"], true);
    }

    #[test]
    fn blackhole_apply_omits_default_response() {
        let mut outbound = json!({"protocol": "blackhole"});
        apply_outbound_settings(&mut outbound, &OutboundSettingsDraft::blackhole_default()).expect("apply");
        assert_eq!(outbound["settings"], json!({}));
    }

    #[test]
    fn blackhole_apply_keeps_extras_only_response() {
        let mut outbound = json!({"protocol": "blackhole", "settings": {}});
        let draft = OutboundSettingsDraft::Blackhole {
            response_type: String::new(),
            response_extras: Map::from_iter([("futureResponseField".to_owned(), json!("keep"))]),
        };
        apply_outbound_settings(&mut outbound, &draft).expect("apply");
        assert!(outbound["settings"]["response"].get("type").is_none());
        assert_eq!(outbound["settings"]["response"]["futureResponseField"], "keep");
    }
}
