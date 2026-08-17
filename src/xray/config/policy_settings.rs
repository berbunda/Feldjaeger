//! Typed editor model for the Xray top-level `policy` object (Roadmap §2.1:49).
//!
//! Field semantics follow the official PolicyObject / LevelPolicyObject / SystemPolicyObject
//! documentation: <https://xtls.github.io/ru/config/policy.html>
//!
//! This is the *editing* counterpart to the read-only [`super::PolicySummary`] used elsewhere in
//! the crate (e.g. `LoadedConfigSnapshot::Loaded.policy`, the Policy page's browsing table);
//! `PolicySummary` is left untouched. This module covers every documented field of both
//! `LevelPolicyObject` (8 fields) and `SystemPolicyObject` (4 fields), mirroring the `dns`/
//! `fakedns`/`routing` editor pattern (`dns_settings.rs`, `fakedns_settings.rs`,
//! `routing_settings.rs`) — `levels` is a JSON object keyed by a numeric-string level, the same
//! "map keyed by a stringly-typed identifier" shape `hosts{}` has in `dns_settings.rs`, so this
//! module owns the same list-not-map in-memory representation (stable UI order) plus duplicate-key
//! validation on save.
//!
//! Every numeric field (`handshake`/`connIdle`/`uplinkOnly`/`downlinkOnly`/`bufferSize`) has a
//! documented Xray-side default, so `None` omits the key and lets Xray apply its own default —
//! the same idiom `DnsServerEntry::port`/`timeout_ms` already use. Every boolean field
//! (`statsUserUplink`/`statsUserDownlink`/`statsUserOnline`/all four `SystemPolicyObject` flags)
//! defaults to `false` and is always written explicitly, the same choice `DnsSettings::disable_cache`
//! etc. already make for top-level boolean flags with no "inherit" concept to preserve.

use std::collections::HashSet;

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;
use super::summary::cmp_policy_level;

/// One `policy.levels{}` entry (`LevelPolicyObject`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLevelEntry {
    /// The level identifier — a non-negative integer in string form, and the JSON object key.
    pub level: String,
    /// `handshake` (seconds). `None` omits the key (documented Xray default: 4).
    pub handshake: Option<u64>,
    /// `connIdle` (seconds). `None` omits the key (documented Xray default: 300).
    pub conn_idle: Option<u64>,
    /// `uplinkOnly` (seconds). `None` omits the key (documented Xray default: 2).
    pub uplink_only: Option<u64>,
    /// `downlinkOnly` (seconds). `None` omits the key (documented Xray default: 5).
    pub downlink_only: Option<u64>,
    /// `statsUserUplink`. Always written (default `false`).
    pub stats_user_uplink: bool,
    /// `statsUserDownlink`. Always written (default `false`).
    pub stats_user_downlink: bool,
    /// `statsUserOnline`. Always written (default `false`).
    pub stats_user_online: bool,
    /// `bufferSize` (KB). `None` omits the key (documented Xray default is platform-dependent:
    /// 0 on ARM, 4 on ARM64, 512 otherwise).
    pub buffer_size: Option<u64>,
}

impl PolicyLevelEntry {
    /// A blank level for the GUI's "Add level" action — an empty `level` key fails
    /// [`validate_policy_settings`] until the user fills it in, same idiom as
    /// `DnsServerEntry::blank()`'s empty `address`.
    pub fn blank() -> Self {
        Self {
            level: String::new(),
            handshake: None,
            conn_idle: None,
            uplink_only: None,
            downlink_only: None,
            stats_user_uplink: false,
            stats_user_downlink: false,
            stats_user_online: false,
            buffer_size: None,
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        if let Some(handshake) = self.handshake {
            object.insert("handshake".to_owned(), Value::from(handshake));
        }
        if let Some(conn_idle) = self.conn_idle {
            object.insert("connIdle".to_owned(), Value::from(conn_idle));
        }
        if let Some(uplink_only) = self.uplink_only {
            object.insert("uplinkOnly".to_owned(), Value::from(uplink_only));
        }
        if let Some(downlink_only) = self.downlink_only {
            object.insert("downlinkOnly".to_owned(), Value::from(downlink_only));
        }
        object.insert(
            "statsUserUplink".to_owned(),
            Value::Bool(self.stats_user_uplink),
        );
        object.insert(
            "statsUserDownlink".to_owned(),
            Value::Bool(self.stats_user_downlink),
        );
        object.insert(
            "statsUserOnline".to_owned(),
            Value::Bool(self.stats_user_online),
        );
        if let Some(buffer_size) = self.buffer_size {
            object.insert("bufferSize".to_owned(), Value::from(buffer_size));
        }
        Value::Object(object)
    }
}

/// `policy.system` (`SystemPolicyObject`). Modeled as a whole optional block — the object either
/// exists (all four flags meaningful, default `false` each) or is entirely absent, unlike per-level
/// entries which always exist once added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPolicyEntry {
    /// `statsInboundUplink`. Always written (default `false`).
    pub stats_inbound_uplink: bool,
    /// `statsInboundDownlink`. Always written (default `false`).
    pub stats_inbound_downlink: bool,
    /// `statsOutboundUplink`. Always written (default `false`).
    pub stats_outbound_uplink: bool,
    /// `statsOutboundDownlink`. Always written (default `false`).
    pub stats_outbound_downlink: bool,
}

impl SystemPolicyEntry {
    /// A blank system policy (all flags `false`) for the GUI's "Add system policy" action.
    pub fn blank() -> Self {
        Self {
            stats_inbound_uplink: false,
            stats_inbound_downlink: false,
            stats_outbound_uplink: false,
            stats_outbound_downlink: false,
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "statsInboundUplink".to_owned(),
            Value::Bool(self.stats_inbound_uplink),
        );
        object.insert(
            "statsInboundDownlink".to_owned(),
            Value::Bool(self.stats_inbound_downlink),
        );
        object.insert(
            "statsOutboundUplink".to_owned(),
            Value::Bool(self.stats_outbound_uplink),
        );
        object.insert(
            "statsOutboundDownlink".to_owned(),
            Value::Bool(self.stats_outbound_downlink),
        );
        Value::Object(object)
    }
}

/// Typed view of the Xray `policy` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySettings {
    /// Configured user levels, sorted numerically by level on load (`cmp_policy_level`, the same
    /// order the read-only Policy page already uses) — edit order thereafter is append order.
    pub levels: Vec<PolicyLevelEntry>,
    /// `system`. `None` omits the key.
    pub system: Option<SystemPolicyEntry>,
    /// `true` when a top-level `policy` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `policy` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (unknown values, malformed optional fields/entries).
    pub warnings: Vec<String>,
}

impl PolicySettings {
    /// Effective defaults when the `policy` object is absent (display only).
    pub fn defaults() -> Self {
        Self {
            levels: Vec::new(),
            system: None,
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`PolicySettings`] from an optional sourced `policy` section.
pub fn policy_settings_from_section(section: Option<&SourcedSection<Value>>) -> PolicySettings {
    let Some(section) = section else {
        return PolicySettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed policy object: expected a JSON object.".to_owned());
        return PolicySettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..PolicySettings::defaults()
        };
    }

    let levels = parse_levels(value.get("levels"), &mut warnings);
    let system = value
        .get("system")
        .and_then(Value::as_object)
        .map(system_from_object);
    if value.get("system").is_some_and(|v| !v.is_object()) {
        warnings.push("Malformed policy.system: expected a JSON object.".to_owned());
    }

    PolicySettings {
        levels,
        system,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
}

fn parse_levels(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<PolicyLevelEntry> {
    let Some(object) = value.and_then(Value::as_object) else {
        return Vec::new();
    };

    let mut levels: Vec<PolicyLevelEntry> = object
        .iter()
        .filter_map(|(level, entry)| match entry.as_object() {
            Some(entry) => Some(level_from_object(level, entry)),
            None => {
                warnings.push(format!(
                    "policy.levels[{level}] has an unsupported shape and was skipped."
                ));
                None
            }
        })
        .collect();
    levels.sort_by(|left, right| cmp_policy_level(&left.level, &right.level));
    levels
}

fn level_from_object(level: &str, object: &Map<String, Value>) -> PolicyLevelEntry {
    PolicyLevelEntry {
        level: level.to_owned(),
        handshake: u64_field(object.get("handshake")),
        conn_idle: u64_field(object.get("connIdle")),
        uplink_only: u64_field(object.get("uplinkOnly")),
        downlink_only: u64_field(object.get("downlinkOnly")),
        stats_user_uplink: bool_field(object.get("statsUserUplink")),
        stats_user_downlink: bool_field(object.get("statsUserDownlink")),
        stats_user_online: bool_field(object.get("statsUserOnline")),
        buffer_size: u64_field(object.get("bufferSize")),
    }
}

fn system_from_object(object: &Map<String, Value>) -> SystemPolicyEntry {
    SystemPolicyEntry {
        stats_inbound_uplink: bool_field(object.get("statsInboundUplink")),
        stats_inbound_downlink: bool_field(object.get("statsInboundDownlink")),
        stats_outbound_uplink: bool_field(object.get("statsOutboundUplink")),
        stats_outbound_downlink: bool_field(object.get("statsOutboundDownlink")),
    }
}

/// Applies typed settings onto a `policy` JSON object, preserving unknown keys.
pub fn apply_policy_settings_to_value(
    target: &mut Value,
    settings: &PolicySettings,
) -> ConfigModifyResult<()> {
    let object = match target {
        Value::Object(map) => map,
        Value::Null => {
            *target = Value::Object(Map::new());
            target.as_object_mut().expect("just created object")
        }
        _ => {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "policy section must be a JSON object".to_owned(),
            ));
        }
    };

    if settings.levels.is_empty() {
        object.remove("levels");
    } else {
        let mut levels_map = Map::new();
        for level in &settings.levels {
            levels_map.insert(level.level.clone(), level.to_value());
        }
        object.insert("levels".to_owned(), Value::Object(levels_map));
    }

    match &settings.system {
        Some(system) => {
            object.insert("system".to_owned(), system.to_value());
        }
        None => {
            object.remove("system");
        }
    }

    Ok(())
}

/// Creates a fresh `policy` object from settings (no unknown keys).
pub fn policy_settings_to_new_value(settings: &PolicySettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_policy_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn policy_settings_change_summary(before: &PolicySettings, after: &PolicySettings) -> Vec<String> {
    let mut lines = Vec::new();

    if before.levels != after.levels {
        lines.push(format!(
            "User policy levels:\n{} → {} configured (see Preview changes for full detail)",
            before.levels.len(),
            after.levels.len()
        ));
    }
    if before.system != after.system {
        lines.push(format!(
            "System policy:\n{} → {}",
            display_system_presence(&before.system),
            display_system_presence(&after.system)
        ));
    }

    lines
}

fn display_system_presence(system: &Option<SystemPolicyEntry>) -> &'static str {
    if system.is_some() { "configured" } else { "(none)" }
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient (`rules.md`: "prefer compatibility over convenience") — the one
/// unambiguous structural rule enforced is the documented one: `levels` is a map, so every level
/// key must be a non-negative integer in string form (per the spec) and unique.
pub fn validate_policy_settings(settings: &PolicySettings) -> ConfigModifyResult<()> {
    let mut seen_levels = HashSet::new();
    for (index, level) in settings.levels.iter().enumerate() {
        let position = index + 1;
        let trimmed = level.level.trim();
        if trimmed.is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Policy level {position} must have a level number"),
            ));
        }
        if trimmed.parse::<u64>().is_err() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Policy level {position} (\"{trimmed}\") must be a non-negative integer"),
            ));
        }
        if !seen_levels.insert(trimmed.to_owned()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("duplicate policy level: {trimmed}"),
            ));
        }
    }
    Ok(())
}

fn u64_field(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}

fn bool_field(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(value: Value) -> SourcedSection<Value> {
        SourcedSection::new("/etc/xray/config.json", value)
    }

    #[test]
    fn missing_policy_object_uses_defaults() {
        let settings = policy_settings_from_section(None);
        assert!(!settings.section_present);
        assert!(settings.levels.is_empty());
        assert!(settings.system.is_none());
    }

    #[test]
    fn malformed_policy_object_warns() {
        let settings = policy_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed policy object"))
        );
    }

    #[test]
    fn level_round_trips_all_fields() {
        let settings = policy_settings_from_section(Some(&section(json!({
            "levels": {
                "0": {
                    "handshake": 4,
                    "connIdle": 300,
                    "uplinkOnly": 2,
                    "downlinkOnly": 5,
                    "statsUserUplink": true,
                    "statsUserDownlink": false,
                    "statsUserOnline": true,
                    "bufferSize": 512
                }
            }
        }))));
        assert_eq!(settings.levels.len(), 1);
        let level = &settings.levels[0];
        assert_eq!(level.level, "0");
        assert_eq!(level.handshake, Some(4));
        assert_eq!(level.conn_idle, Some(300));
        assert_eq!(level.uplink_only, Some(2));
        assert_eq!(level.downlink_only, Some(5));
        assert!(level.stats_user_uplink);
        assert!(!level.stats_user_downlink);
        assert!(level.stats_user_online);
        assert_eq!(level.buffer_size, Some(512));

        let mut value = json!({});
        apply_policy_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["levels"]["0"]["handshake"], 4);
        assert_eq!(value["levels"]["0"]["statsUserUplink"], true);
        assert_eq!(value["levels"]["0"]["statsUserDownlink"], false);
        assert_eq!(value["levels"]["0"]["bufferSize"], 512);
    }

    #[test]
    fn levels_sorted_numerically_on_load() {
        let settings = policy_settings_from_section(Some(&section(json!({
            "levels": { "10": {}, "2": {} }
        }))));
        assert_eq!(settings.levels[0].level, "2");
        assert_eq!(settings.levels[1].level, "10");
    }

    #[test]
    fn missing_optional_numeric_fields_omit_keys() {
        let settings = policy_settings_from_section(Some(&section(json!({
            "levels": { "0": {} }
        }))));
        let level = &settings.levels[0];
        assert_eq!(level.handshake, None);
        assert_eq!(level.buffer_size, None);
        assert!(!level.stats_user_uplink);

        let mut value = json!({});
        apply_policy_settings_to_value(&mut value, &settings).unwrap();
        assert!(value["levels"]["0"].get("handshake").is_none());
        assert!(value["levels"]["0"].get("bufferSize").is_none());
        assert_eq!(value["levels"]["0"]["statsUserUplink"], false);
    }

    #[test]
    fn unsupported_level_shape_is_skipped_with_warning() {
        let settings = policy_settings_from_section(Some(&section(json!({
            "levels": { "0": 42 }
        }))));
        assert!(settings.levels.is_empty());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("levels[0]") && w.contains("unsupported shape"))
        );
    }

    #[test]
    fn system_policy_round_trips() {
        let settings = policy_settings_from_section(Some(&section(json!({
            "system": {
                "statsInboundUplink": true,
                "statsInboundDownlink": false,
                "statsOutboundUplink": true,
                "statsOutboundDownlink": false
            }
        }))));
        let system = settings.system.as_ref().unwrap();
        assert!(system.stats_inbound_uplink);
        assert!(!system.stats_inbound_downlink);
        assert!(system.stats_outbound_uplink);
        assert!(!system.stats_outbound_downlink);

        let mut value = json!({});
        apply_policy_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["system"]["statsInboundUplink"], true);
        assert_eq!(value["system"]["statsOutboundDownlink"], false);
    }

    #[test]
    fn malformed_system_warns() {
        let settings = policy_settings_from_section(Some(&section(json!({
            "system": "not-an-object"
        }))));
        assert!(settings.system.is_none());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed policy.system"))
        );
    }

    #[test]
    fn missing_system_is_none_without_warning() {
        let settings = policy_settings_from_section(Some(&section(json!({ "levels": {} }))));
        assert!(settings.system.is_none());
        assert!(settings.warnings.is_empty());
    }

    #[test]
    fn apply_preserves_unrelated_json_keys() {
        let mut value = json!({ "futureField": 42, "nested": { "a": 1 } });
        let settings = PolicySettings::defaults();
        apply_policy_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
    }

    #[test]
    fn levels_empty_removes_key_on_apply() {
        let mut value = json!({ "levels": { "0": {} } });
        let settings = PolicySettings::defaults();
        apply_policy_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("levels").is_none());
    }

    #[test]
    fn system_none_removes_key_on_apply() {
        let mut value = json!({ "system": { "statsInboundUplink": true } });
        let settings = PolicySettings::defaults();
        apply_policy_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("system").is_none());
    }

    #[test]
    fn change_summary_reports_levels_and_system() {
        let before = PolicySettings::defaults();
        let mut after = before.clone();
        after.levels.push(PolicyLevelEntry {
            level: "0".to_owned(),
            ..PolicyLevelEntry::blank()
        });
        after.system = Some(SystemPolicyEntry::blank());
        let summary = policy_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 2);
        assert!(summary[0].contains("0 → 1"));
        assert!(summary[1].contains("(none) → configured"));
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = PolicySettings::defaults();
        assert!(policy_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_accepts_defaults_and_valid_levels() {
        assert!(validate_policy_settings(&PolicySettings::defaults()).is_ok());
        let mut settings = PolicySettings::defaults();
        settings.levels.push(PolicyLevelEntry {
            level: "0".to_owned(),
            ..PolicyLevelEntry::blank()
        });
        settings.levels.push(PolicyLevelEntry {
            level: "1".to_owned(),
            ..PolicyLevelEntry::blank()
        });
        assert!(validate_policy_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_blank_level() {
        let mut settings = PolicySettings::defaults();
        settings.levels.push(PolicyLevelEntry::blank());
        let error = validate_policy_settings(&settings).unwrap_err();
        assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn validation_rejects_non_numeric_level() {
        let mut settings = PolicySettings::defaults();
        settings.levels.push(PolicyLevelEntry {
            level: "abc".to_owned(),
            ..PolicyLevelEntry::blank()
        });
        assert!(validate_policy_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_negative_level() {
        let mut settings = PolicySettings::defaults();
        settings.levels.push(PolicyLevelEntry {
            level: "-1".to_owned(),
            ..PolicyLevelEntry::blank()
        });
        assert!(validate_policy_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_duplicate_level() {
        let mut settings = PolicySettings::defaults();
        settings.levels.push(PolicyLevelEntry {
            level: "0".to_owned(),
            ..PolicyLevelEntry::blank()
        });
        settings.levels.push(PolicyLevelEntry {
            level: "0".to_owned(),
            ..PolicyLevelEntry::blank()
        });
        let error = validate_policy_settings(&settings).unwrap_err();
        assert!(error.message().contains("duplicate policy level"));
    }
}
