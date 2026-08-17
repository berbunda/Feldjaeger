//! Typed editor model for the Xray top-level `observatory` object (Roadmap §2.1:50).
//!
//! Field semantics follow the official ObservatoryObject documentation:
//! <https://xtls.github.io/ru/config/observatory.html>
//!
//! This is the *editing* counterpart to the read-only [`super::ObservatorySummary`] used
//! elsewhere in the crate (e.g. `LoadedConfigSnapshot::Loaded.observatory`, the Observatory
//! page's browsing view); `ObservatorySummary` is left untouched. This module covers all four
//! documented `ObservatoryObject` fields (`subjectSelector`/`probeUrl`/`probeInterval`/
//! `enableConcurrency`) — one more than `ObservatorySummary` currently projects
//! (`enableConcurrency` was never read-only-displayed), the same "editor covers 100%, summary
//! covers a display subset" split already established by every other root-section editor
//! (`dns_settings.rs`, `routing_settings.rs`, `policy_settings.rs`).
//!
//! **Wire casing note.** Xray-core's own Go struct tags this field `probeURL` (capital URL) in
//! `infra/conf/observatory.go`, but the official documentation and every example config use
//! `probeUrl`. Both are accepted by Xray-core on read (Go's `encoding/json` falls back to a
//! case-insensitive key match), but this crate's own [`super::ObservatorySummary`] reads
//! `probeUrl` case-sensitively via `serde_json` — so this module writes `probeUrl` too, matching
//! the documentation and staying internally consistent with the existing read-only parser (writing
//! `probeURL` here would make Feldjäger's own Observatory page immediately warn "probeUrl is
//! missing" about a value it just saved).
//!
//! `burstObservatory` (a separate, still-read-only Roadmap item, §2.1:51) is out of scope here.

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// Typed view of the Xray `observatory` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatorySettings {
    /// `subjectSelector` — outbound tag prefixes to observe, in source/edit order.
    pub subject_selectors: Vec<String>,
    /// `probeUrl`. `None` omits the key.
    pub probe_url: Option<String>,
    /// `probeInterval` (Xray duration string, e.g. `10s`). `None` omits the key.
    pub probe_interval: Option<String>,
    /// `enableConcurrency`. Always written (default `false`).
    pub enable_concurrency: bool,
    /// `true` when a top-level `observatory` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `observatory` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (unknown values, malformed optional fields).
    pub warnings: Vec<String>,
}

impl ObservatorySettings {
    /// Effective defaults when the `observatory` object is absent (display only).
    pub fn defaults() -> Self {
        Self {
            subject_selectors: Vec::new(),
            probe_url: None,
            probe_interval: None,
            enable_concurrency: false,
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`ObservatorySettings`] from an optional sourced `observatory` section.
pub fn observatory_settings_from_section(
    section: Option<&SourcedSection<Value>>,
) -> ObservatorySettings {
    let Some(section) = section else {
        return ObservatorySettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed observatory object: expected a JSON object.".to_owned());
        return ObservatorySettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..ObservatorySettings::defaults()
        };
    }

    let subject_selectors = parse_subject_selectors(value.get("subjectSelector"), &mut warnings);
    let probe_url = string_field(value.get("probeUrl"));
    let probe_interval = string_field(value.get("probeInterval"));
    let enable_concurrency = bool_field(value.get("enableConcurrency"));

    ObservatorySettings {
        subject_selectors,
        probe_url,
        probe_interval,
        enable_concurrency,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
}

fn parse_subject_selectors(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<String> {
    let Some(array) = value.and_then(Value::as_array) else {
        if let Some(value) = value
            && !value.is_array()
        {
            warnings.push("`subjectSelector` has an unsupported type.".to_owned());
        }
        return Vec::new();
    };

    array
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| match entry.as_str() {
            Some(text) => Some(text.to_owned()),
            None => {
                warnings.push(format!(
                    "`subjectSelector` entry #{} has an unsupported type and was skipped.",
                    index + 1
                ));
                None
            }
        })
        .collect()
}

/// Applies typed settings onto an `observatory` JSON object, preserving unknown keys.
pub fn apply_observatory_settings_to_value(
    target: &mut Value,
    settings: &ObservatorySettings,
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
                "observatory section must be a JSON object".to_owned(),
            ));
        }
    };

    if settings.subject_selectors.is_empty() {
        object.remove("subjectSelector");
    } else {
        object.insert(
            "subjectSelector".to_owned(),
            Value::Array(
                settings
                    .subject_selectors
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    match &settings.probe_url {
        Some(probe_url) => {
            object.insert("probeUrl".to_owned(), Value::String(probe_url.clone()));
        }
        None => {
            object.remove("probeUrl");
        }
    }

    match &settings.probe_interval {
        Some(probe_interval) => {
            object.insert(
                "probeInterval".to_owned(),
                Value::String(probe_interval.clone()),
            );
        }
        None => {
            object.remove("probeInterval");
        }
    }

    object.insert(
        "enableConcurrency".to_owned(),
        Value::Bool(settings.enable_concurrency),
    );

    Ok(())
}

/// Creates a fresh `observatory` object from settings (no unknown keys).
pub fn observatory_settings_to_new_value(settings: &ObservatorySettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_observatory_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn observatory_settings_change_summary(
    before: &ObservatorySettings,
    after: &ObservatorySettings,
) -> Vec<String> {
    let mut lines = Vec::new();

    if before.subject_selectors != after.subject_selectors {
        lines.push(format!(
            "subjectSelector:\n{} → {} configured (see Preview changes for full detail)",
            before.subject_selectors.len(),
            after.subject_selectors.len()
        ));
    }
    if before.probe_url != after.probe_url {
        lines.push(format!(
            "probeUrl:\n{} → {}",
            before.probe_url.as_deref().unwrap_or("(none)"),
            after.probe_url.as_deref().unwrap_or("(none)")
        ));
    }
    if before.probe_interval != after.probe_interval {
        lines.push(format!(
            "probeInterval:\n{} → {}",
            before.probe_interval.as_deref().unwrap_or("(none)"),
            after.probe_interval.as_deref().unwrap_or("(none)")
        ));
    }
    if before.enable_concurrency != after.enable_concurrency {
        lines.push(format!(
            "enableConcurrency:\n{} → {}",
            before.enable_concurrency, after.enable_concurrency
        ));
    }

    lines
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient (`rules.md`: "prefer compatibility over convenience") — only control
/// characters are rejected. An empty `subjectSelector` is allowed to be saved (the section is
/// simply inert until a selector is added — the read-only page already surfaces this as an
/// informational, non-blocking state), and `probeUrl`/`probeInterval` grammars are not
/// re-validated here (`xray run -test` already runs after every save).
pub fn validate_observatory_settings(settings: &ObservatorySettings) -> ConfigModifyResult<()> {
    for (index, selector) in settings.subject_selectors.iter().enumerate() {
        validate_control_chars(selector, &format!("subjectSelector entry {}", index + 1))?;
    }
    validate_optional_control_chars(&settings.probe_url, "probeUrl")?;
    validate_optional_control_chars(&settings.probe_interval, "probeInterval")?;
    Ok(())
}

fn validate_control_chars(value: &str, field: &str) -> ConfigModifyResult<()> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field} must not contain control characters"),
        ));
    }
    Ok(())
}

fn validate_optional_control_chars(value: &Option<String>, field: &str) -> ConfigModifyResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    validate_control_chars(value, field)
}

fn string_field(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        _ => None,
    }
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
    fn missing_observatory_object_uses_defaults() {
        let settings = observatory_settings_from_section(None);
        assert!(!settings.section_present);
        assert!(settings.subject_selectors.is_empty());
        assert_eq!(settings.probe_url, None);
        assert!(!settings.enable_concurrency);
    }

    #[test]
    fn malformed_observatory_object_warns() {
        let settings = observatory_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed observatory object"))
        );
    }

    #[test]
    fn all_fields_round_trip() {
        let settings = observatory_settings_from_section(Some(&section(json!({
            "subjectSelector": ["proxy", "warp"],
            "probeUrl": "https://www.google.com/generate_204",
            "probeInterval": "10s",
            "enableConcurrency": true
        }))));
        assert_eq!(settings.subject_selectors, vec!["proxy".to_owned(), "warp".to_owned()]);
        assert_eq!(
            settings.probe_url.as_deref(),
            Some("https://www.google.com/generate_204")
        );
        assert_eq!(settings.probe_interval.as_deref(), Some("10s"));
        assert!(settings.enable_concurrency);

        let mut value = json!({});
        apply_observatory_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["subjectSelector"], json!(["proxy", "warp"]));
        assert_eq!(value["probeUrl"], "https://www.google.com/generate_204");
        assert_eq!(value["probeInterval"], "10s");
        assert_eq!(value["enableConcurrency"], true);
    }

    #[test]
    fn missing_optional_fields_are_none_without_warning() {
        let settings = observatory_settings_from_section(Some(&section(json!({
            "subjectSelector": ["proxy"]
        }))));
        assert_eq!(settings.probe_url, None);
        assert_eq!(settings.probe_interval, None);
        assert!(!settings.enable_concurrency);
        assert!(settings.warnings.is_empty());
    }

    #[test]
    fn unsupported_selector_entry_is_skipped_with_warning() {
        let settings = observatory_settings_from_section(Some(&section(json!({
            "subjectSelector": ["proxy", 42]
        }))));
        assert_eq!(settings.subject_selectors, vec!["proxy".to_owned()]);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("entry #2"))
        );
    }

    #[test]
    fn unsupported_selector_shape_warns() {
        let settings = observatory_settings_from_section(Some(&section(json!({
            "subjectSelector": "not-an-array"
        }))));
        assert!(settings.subject_selectors.is_empty());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("subjectSelector"))
        );
    }

    #[test]
    fn apply_preserves_unrelated_json_keys() {
        let mut value = json!({ "futureField": 42, "nested": { "a": 1 } });
        let settings = ObservatorySettings::defaults();
        apply_observatory_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
        assert_eq!(value["enableConcurrency"], false);
    }

    #[test]
    fn empty_selectors_removes_key_on_apply() {
        let mut value = json!({ "subjectSelector": ["old"] });
        let settings = ObservatorySettings::defaults();
        apply_observatory_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("subjectSelector").is_none());
    }

    #[test]
    fn change_summary_reports_touched_fields_only() {
        let before = ObservatorySettings::defaults();
        let mut after = before.clone();
        after.enable_concurrency = true;
        after.probe_url = Some("https://example.com".to_owned());
        let summary = observatory_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 2);
        assert!(summary[0].contains("probeUrl"));
        assert!(summary[1].contains("enableConcurrency"));
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = ObservatorySettings::defaults();
        assert!(observatory_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_accepts_defaults_and_full_settings() {
        assert!(validate_observatory_settings(&ObservatorySettings::defaults()).is_ok());
        let settings = ObservatorySettings {
            subject_selectors: vec!["proxy".to_owned()],
            probe_url: Some("https://example.com".to_owned()),
            probe_interval: Some("10s".to_owned()),
            enable_concurrency: true,
            ..ObservatorySettings::defaults()
        };
        assert!(validate_observatory_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_control_characters_in_selector() {
        let settings = ObservatorySettings {
            subject_selectors: vec!["bad\nselector".to_owned()],
            ..ObservatorySettings::defaults()
        };
        assert!(validate_observatory_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_control_characters_in_probe_url() {
        let settings = ObservatorySettings {
            probe_url: Some("https://example.com\n".to_owned()),
            ..ObservatorySettings::defaults()
        };
        assert!(validate_observatory_settings(&settings).is_err());
    }

    #[test]
    fn validation_accepts_empty_selectors() {
        let settings = ObservatorySettings::defaults();
        assert!(validate_observatory_settings(&settings).is_ok());
    }

    #[test]
    fn to_new_value_creates_object_without_optional_keys() {
        let settings = ObservatorySettings::defaults();
        let value = observatory_settings_to_new_value(&settings);
        assert!(value.get("subjectSelector").is_none());
        assert!(value.get("probeUrl").is_none());
        assert_eq!(value["enableConcurrency"], false);
    }
}
