//! Typed editor model for the Xray top-level `stats` object (Roadmap §2.1:52).
//!
//! Field semantics follow the official StatsObject documentation:
//! <https://xtls.github.io/ru/config/stats.html>
//!
//! `StatsObject` is, by design, empty — the documentation states plainly that no fields are
//! currently required or supported: "В настоящее время для статистики не требуется никаких
//! параметров." Presence of the top-level `stats` key is itself the only meaningful state: an
//! empty `stats: {}` enables the statistics module (actual data collection is then driven by
//! `policy`/`api`/`metrics` wiring — already cross-checked read-only by
//! [`super::stats_wiring_warnings`], untouched by this module), and the key's absence disables it.
//!
//! Because of this, this editor is a presence toggle rather than a field-by-field editor like its
//! five siblings (`dns_settings.rs`, `routing_settings.rs`, `policy_settings.rs`,
//! `observatory_settings.rs`, `burst_observatory_settings.rs`) — but it still follows the same
//! "never invent semantics for what's already there" rule: any keys already present in an
//! on-disk `stats` object (there should be none per the spec, but a future Xray-core version or a
//! hand-edited config could add some) are preserved verbatim in [`StatsSettings::extra`] and
//! round-tripped on save, exactly like [`super::FakeDnsPoolEntry::extra`].

use serde_json::{Map, Value};

use super::modify_error::ConfigModifyResult;
use super::sourced_section::SourcedSection;

/// Typed view of the Xray `stats` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSettings {
    /// Whether the top-level `stats` object should exist at all — the only meaningful setting
    /// for this section.
    pub enabled: bool,
    /// Unrecognized JSON keys already present on the `stats` object (none are documented, but
    /// preserved verbatim if found), round-tripped when `enabled` is `true`.
    pub extra: Map<String, Value>,
    /// `true` when a top-level `stats` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `stats` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (malformed section shape).
    pub warnings: Vec<String>,
}

impl StatsSettings {
    /// Effective defaults when the `stats` object is absent (display only).
    pub fn defaults() -> Self {
        Self {
            enabled: false,
            extra: Map::new(),
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`StatsSettings`] from an optional sourced `stats` section.
pub fn stats_settings_from_section(section: Option<&SourcedSection<Value>>) -> StatsSettings {
    let Some(section) = section else {
        return StatsSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    let extra = match value {
        Value::Object(object) => object.clone(),
        _ => {
            warnings.push("Malformed stats object: expected a JSON object.".to_owned());
            Map::new()
        }
    };

    StatsSettings {
        enabled: true,
        extra,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
}

/// Builds the JSON value to write for the `stats` key: `None` removes the key entirely
/// (`enabled == false`), `Some` writes an object carrying any preserved [`StatsSettings::extra`]
/// fields (`enabled == true`).
pub fn stats_settings_to_value(settings: &StatsSettings) -> Option<Value> {
    if !settings.enabled {
        return None;
    }
    Some(Value::Object(settings.extra.clone()))
}

/// Human-readable change lines for the save confirmation summary.
pub fn stats_settings_change_summary(before: &StatsSettings, after: &StatsSettings) -> Vec<String> {
    if before.enabled == after.enabled {
        return Vec::new();
    }
    vec![format!(
        "stats:\n{} → {}",
        if before.enabled { "enabled" } else { "disabled" },
        if after.enabled { "enabled" } else { "disabled" }
    )]
}

/// Validates draft settings before they are written remotely.
///
/// Always succeeds: `StatsObject` has no documented fields to validate, and preserved `extra`
/// keys are round-tripped verbatim without reinterpretation. Kept for API symmetry with the
/// other five root-section editors, and as the natural place to add checks if Xray-core ever
/// documents fields for this section.
pub fn validate_stats_settings(_settings: &StatsSettings) -> ConfigModifyResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(value: Value) -> SourcedSection<Value> {
        SourcedSection::new("/etc/xray/config.json", value)
    }

    #[test]
    fn missing_stats_object_is_disabled_by_default() {
        let settings = stats_settings_from_section(None);
        assert!(!settings.section_present);
        assert!(!settings.enabled);
        assert!(settings.extra.is_empty());
    }

    #[test]
    fn present_empty_stats_object_is_enabled() {
        let settings = stats_settings_from_section(Some(&section(json!({}))));
        assert!(settings.section_present);
        assert!(settings.enabled);
        assert!(settings.extra.is_empty());
        assert!(settings.warnings.is_empty());
    }

    #[test]
    fn malformed_stats_object_warns_but_stays_enabled() {
        let settings = stats_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(settings.enabled);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed stats object"))
        );
    }

    #[test]
    fn unknown_fields_are_preserved_in_extra() {
        let settings =
            stats_settings_from_section(Some(&section(json!({ "futureField": 42 }))));
        assert_eq!(settings.extra.get("futureField"), Some(&json!(42)));
    }

    #[test]
    fn to_value_disabled_is_none() {
        let settings = StatsSettings::defaults();
        assert_eq!(stats_settings_to_value(&settings), None);
    }

    #[test]
    fn to_value_enabled_round_trips_extra() {
        let mut settings = StatsSettings::defaults();
        settings.enabled = true;
        settings.extra.insert("futureField".to_owned(), json!(42));
        let value = stats_settings_to_value(&settings).unwrap();
        assert_eq!(value, json!({ "futureField": 42 }));
    }

    #[test]
    fn change_summary_reports_enabled_toggle() {
        let before = StatsSettings::defaults();
        let mut after = before.clone();
        after.enabled = true;
        let summary = stats_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 1);
        assert!(summary[0].contains("disabled → enabled"));
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = StatsSettings::defaults();
        assert!(stats_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_always_succeeds() {
        assert!(validate_stats_settings(&StatsSettings::defaults()).is_ok());
        let mut settings = StatsSettings::defaults();
        settings.enabled = true;
        settings.extra.insert("anything".to_owned(), json!("weird value"));
        assert!(validate_stats_settings(&settings).is_ok());
    }
}
