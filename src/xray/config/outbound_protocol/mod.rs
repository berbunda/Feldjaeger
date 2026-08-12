//! Outbound Protocol tab (Freedom, Blackhole, DNS; Roadmap §2.4:94, §2.4:95, §2.4:96).
//!
//! See <https://xtls.github.io/en/config/outbounds/freedom.html>,
//! <https://xtls.github.io/en/config/outbounds/blackhole.html>, and
//! <https://xtls.github.io/en/config/outbounds/dns.html>. Freedom's `domainStrategy`
//! reuses the same preset list as `streamSettings.sockopt.domainStrategy`
//! ([`crate::xray::config::inbound_stream::DOMAIN_STRATEGIES`]) — same wire values, different
//! JSON location.
//!
//! The DNS outbound has no `streamSettings`/security; it rewrites/filters DNS queries received
//! from routing via a flat `settings` object plus an ordered `rules[]` list (first match wins).
//! It supports only traditional UDP/TCP DNS (no DoH/DoT/DoQ).

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Documented `settings.noises[].type` values (free text also accepted).
pub const FREEDOM_NOISE_TYPES: &[&str] = &["rand", "str", "hex", "base64"];

/// Documented `settings.response.type` values for Blackhole (free text also accepted).
pub const BLACKHOLE_RESPONSE_TYPES: &[&str] = &["none", "http"];

/// Documented `settings.rules[].action` values for DNS (free text also accepted).
pub const DNS_RULE_ACTIONS: &[&str] = &["direct", "hijack", "drop", "return"];

/// Documented `settings.rewriteNetwork` values for DNS (free text also accepted).
pub const DNS_REWRITE_NETWORKS: &[&str] = &["tcp", "udp"];

/// Outbound protocols currently reachable through the Outbound Shell (Add/Edit).
pub fn is_shell_editable_protocol(protocol: &str) -> bool {
    matches!(protocol.trim().to_ascii_lowercase().as_str(), "freedom" | "blackhole" | "dns")
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

/// One `settings.rules[]` entry for the DNS outbound (query filtering / rewriting).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsRuleDraft {
    /// `action` (`direct` | `hijack` | `drop` | `return`; free text accepted). Required by Xray.
    pub action: String,
    /// `qType` — integer, numeric string, or range/comma-list (e.g. `"11,13,15-17"`); empty = key
    /// absent. Written back as a JSON number when the trimmed text is a plain non-negative
    /// integer, otherwise as a JSON string.
    pub q_type: String,
    /// `rCode` (0-65535); relevant for `action = "return"`. `0` = key absent (Xray default).
    pub r_code: u32,
    /// `domain` matcher list (routing domain-matcher syntax; one entry per GUI line); empty = key
    /// absent.
    pub domain: Vec<String>,
    /// Unknown `rules[]` entry keys, preserved verbatim.
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
    /// DNS: rule-based DNS query rewriting/forwarding outbound (Roadmap §2.4:96). No
    /// `streamSettings`/security.
    Dns {
        /// `settings.rewriteNetwork` (`tcp` | `udp`); empty = key absent (unchanged transport).
        rewrite_network: String,
        /// `settings.rewriteAddress`; empty = key absent (unchanged target).
        rewrite_address: String,
        /// `settings.rewritePort`; empty = key absent (unchanged port). Validated as 1-65535 on
        /// apply.
        rewrite_port: String,
        /// `settings.userLevel`; `0` = key absent (Xray default).
        user_level: u64,
        /// `settings.rules[]`, evaluated in order (first match wins); empty = key absent.
        rules: Vec<DnsRuleDraft>,
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

    /// Default for Add DNS.
    pub fn dns_default() -> Self {
        Self::Dns {
            rewrite_network: String::new(),
            rewrite_address: String::new(),
            rewrite_port: String::new(),
            user_level: 0,
            rules: Vec::new(),
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
        "dns" => Some(parse_dns_settings(outbound)),
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

fn parse_dns_settings(outbound: &Value) -> OutboundSettingsDraft {
    let settings = outbound.get("settings").and_then(Value::as_object);
    let rules = settings
        .and_then(|s| s.get("rules"))
        .and_then(Value::as_array)
        .map(|array| array.iter().filter_map(Value::as_object).map(parse_dns_rule).collect())
        .unwrap_or_default();
    OutboundSettingsDraft::Dns {
        rewrite_network: string_field(settings.and_then(|s| s.get("rewriteNetwork"))),
        rewrite_address: string_field(settings.and_then(|s| s.get("rewriteAddress"))),
        rewrite_port: numeric_or_string_field(settings.and_then(|s| s.get("rewritePort"))),
        user_level: settings
            .and_then(|s| s.get("userLevel"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        rules,
    }
}

const KNOWN_FRAGMENT_KEYS: &[&str] = &["packets", "length", "interval"];
const KNOWN_NOISE_KEYS: &[&str] = &["type", "packet", "delay"];
const KNOWN_DNS_RULE_KEYS: &[&str] = &["action", "qType", "rCode", "domain"];

fn parse_dns_rule(object: &Map<String, Value>) -> DnsRuleDraft {
    let mut extras = Map::new();
    for (key, value) in object {
        if !KNOWN_DNS_RULE_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    let domain = object
        .get("domain")
        .and_then(Value::as_array)
        .map(|array| array.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    DnsRuleDraft {
        action: string_field(object.get("action")),
        q_type: numeric_or_string_field(object.get("qType")),
        r_code: object.get("rCode").and_then(Value::as_u64).unwrap_or(0) as u32,
        domain,
        extras,
    }
}

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

/// Reads a field that may be a JSON number or string on disk into a free-text draft field
/// (used for DNS `rewritePort` / `qType`, which accept both shapes).
fn numeric_or_string_field(value: Option<&Value>) -> String {
    match value {
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(text)) => text.trim().to_owned(),
        _ => String::new(),
    }
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
        OutboundSettingsDraft::Dns {
            rewrite_network,
            rewrite_address,
            rewrite_port,
            user_level,
            rules,
        } => apply_dns_settings(outbound, rewrite_network, rewrite_address, rewrite_port, *user_level, rules),
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

fn apply_dns_settings(
    outbound: &mut Value,
    rewrite_network: &str,
    rewrite_address: &str,
    rewrite_port: &str,
    user_level: u64,
    rules: &[DnsRuleDraft],
) -> ConfigModifyResult<()> {
    validate_dns_rules(rules)?;

    let settings = ensure_settings_object(outbound)?;
    apply_optional_string(settings, "rewriteNetwork", rewrite_network);
    apply_optional_string(settings, "rewriteAddress", rewrite_address);
    apply_optional_port(settings, "rewritePort", rewrite_port)?;
    if user_level != 0 {
        settings.insert("userLevel".to_owned(), Value::Number(user_level.into()));
    } else {
        settings.remove("userLevel");
    }
    if rules.is_empty() {
        settings.remove("rules");
    } else {
        settings.insert(
            "rules".to_owned(),
            Value::Array(rules.iter().map(dns_rule_to_value).collect()),
        );
    }
    Ok(())
}

/// Writes an optional 1-65535 port field as a JSON number; empty text removes the key.
fn apply_optional_port(settings: &mut Map<String, Value>, key: &str, value: &str) -> ConfigModifyResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        settings.remove(key);
        return Ok(());
    }
    let port: u32 = trimmed.parse().map_err(|_| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{key} must be a valid port number (1-65535)"),
        )
    })?;
    if port == 0 || port > 65535 {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{key} must be between 1 and 65535"),
        ));
    }
    settings.insert(key.to_owned(), Value::Number(port.into()));
    Ok(())
}

/// Writes `qType` as a JSON number when the trimmed text is a plain non-negative integer,
/// otherwise as a JSON string (covers ranges/comma-lists, e.g. `"11,13,15-17"`).
fn apply_qtype(rule: &mut Map<String, Value>, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        rule.remove("qType");
    } else if let Ok(number) = trimmed.parse::<u64>() {
        rule.insert("qType".to_owned(), Value::Number(number.into()));
    } else {
        rule.insert("qType".to_owned(), Value::String(trimmed.to_owned()));
    }
}

fn apply_domain(rule: &mut Map<String, Value>, domain: &[String]) {
    let filtered: Vec<Value> = domain
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(|entry| Value::String(entry.to_owned()))
        .collect();
    if filtered.is_empty() {
        rule.remove("domain");
    } else {
        rule.insert("domain".to_owned(), Value::Array(filtered));
    }
}

fn dns_rule_to_value(draft: &DnsRuleDraft) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "action", &draft.action);
    apply_qtype(&mut object, &draft.q_type);
    if draft.r_code != 0 {
        object.insert("rCode".to_owned(), Value::Number(draft.r_code.into()));
    }
    apply_domain(&mut object, &draft.domain);
    for (key, value) in &draft.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

fn validate_dns_rules(rules: &[DnsRuleDraft]) -> ConfigModifyResult<()> {
    for rule in rules {
        if rule.action.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "DNS rule action must not be empty".to_owned(),
            ));
        }
        if rule.r_code > 65535 {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "DNS rule rCode must be between 0 and 65535".to_owned(),
            ));
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

    #[test]
    fn dns_parse_apply_roundtrip_preserves_unknown() {
        let mut outbound = json!({
            "protocol": "dns",
            "settings": {
                "rewriteNetwork": "udp",
                "rewriteAddress": "1.1.1.1",
                "rewritePort": 53,
                "userLevel": 1,
                "rules": [
                    {"action": "return", "rCode": 5, "domain": ["domain:example.com"], "futureRuleField": "keep"},
                    {"action": "direct", "qType": 65, "domain": ["geosite:geolocation-!cn"]}
                ],
                "futureSettingsField": "keep"
            },
            "mux": {"enabled": true}
        });
        let draft = parse_outbound_settings(&outbound).expect("parse");
        apply_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["rewriteNetwork"], "udp");
        assert_eq!(outbound["settings"]["rewriteAddress"], "1.1.1.1");
        assert_eq!(outbound["settings"]["rewritePort"], 53);
        assert_eq!(outbound["settings"]["userLevel"], 1);
        assert_eq!(outbound["settings"]["rules"][0]["action"], "return");
        assert_eq!(outbound["settings"]["rules"][0]["rCode"], 5);
        assert_eq!(outbound["settings"]["rules"][0]["domain"][0], "domain:example.com");
        assert_eq!(outbound["settings"]["rules"][0]["futureRuleField"], "keep");
        assert_eq!(outbound["settings"]["rules"][1]["qType"], 65);
        assert_eq!(outbound["settings"]["futureSettingsField"], "keep");
        assert_eq!(outbound["mux"]["enabled"], true);
    }

    #[test]
    fn dns_apply_omits_default_fields() {
        let mut outbound = json!({"protocol": "dns"});
        apply_outbound_settings(&mut outbound, &OutboundSettingsDraft::dns_default()).expect("apply");
        assert_eq!(outbound["settings"], json!({}));
    }

    #[test]
    fn dns_apply_rejects_rule_with_empty_action() {
        let mut outbound = json!({"protocol": "dns", "settings": {}});
        let draft = OutboundSettingsDraft::Dns {
            rewrite_network: String::new(),
            rewrite_address: String::new(),
            rewrite_port: String::new(),
            user_level: 0,
            rules: vec![DnsRuleDraft {
                action: String::new(),
                q_type: String::new(),
                r_code: 0,
                domain: vec!["domain:example.com".to_owned()],
                extras: Map::new(),
            }],
        };
        let err = apply_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(err.to_string().contains("action"));
    }

    #[test]
    fn dns_qtype_numeric_vs_string_round_trip() {
        let mut outbound = json!({"protocol": "dns", "settings": {}});
        let draft = OutboundSettingsDraft::Dns {
            rewrite_network: String::new(),
            rewrite_address: String::new(),
            rewrite_port: String::new(),
            user_level: 0,
            rules: vec![
                DnsRuleDraft {
                    action: "direct".to_owned(),
                    q_type: "65".to_owned(),
                    r_code: 0,
                    domain: Vec::new(),
                    extras: Map::new(),
                },
                DnsRuleDraft {
                    action: "direct".to_owned(),
                    q_type: "11,13,15-17".to_owned(),
                    r_code: 0,
                    domain: Vec::new(),
                    extras: Map::new(),
                },
            ],
        };
        apply_outbound_settings(&mut outbound, &draft).expect("apply");
        assert!(outbound["settings"]["rules"][0]["qType"].is_number());
        assert_eq!(outbound["settings"]["rules"][0]["qType"], 65);
        assert!(outbound["settings"]["rules"][1]["qType"].is_string());
        assert_eq!(outbound["settings"]["rules"][1]["qType"], "11,13,15-17");
    }

    #[test]
    fn dns_apply_rejects_invalid_rewrite_port() {
        let mut outbound = json!({"protocol": "dns", "settings": {}});
        let mut draft = OutboundSettingsDraft::dns_default();
        if let OutboundSettingsDraft::Dns { rewrite_port, .. } = &mut draft {
            *rewrite_port = "70000".to_owned();
        }
        let err = apply_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn dns_protocol_is_parsed() {
        let outbound = json!({"protocol": "dns", "settings": {}});
        assert!(matches!(
            parse_outbound_settings(&outbound),
            Some(OutboundSettingsDraft::Dns { .. })
        ));
    }
}
