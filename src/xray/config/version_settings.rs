//! Typed editor model for the Xray top-level `version` object (Roadmap §2.1:56).
//!
//! Field semantics follow the official documentation of the root config object
//! (<https://xtls.github.io/ru/config/>, section `version`) — there is no dedicated
//! `version.html` page (unlike `env`/`log`/`api`/…); the object is documented inline on the
//! config-file overview page.
//!
//! `version` is a guard rail exchanged alongside a config file: `{ "version": { "min": "x.y.z",
//! "max": "x.y.z" } }` lets Xray-core refuse to start on an unwanted client version. Both `min`
//! and `max` are optional strings; leaving either unset (or the whole object absent) means "no
//! restriction" on that bound. The documented version syntax is `x.y.z` — but, per the official
//! text, the specified version does not need to actually exist, only to match that syntax; this
//! module does not turn that into a hard grammar check (`rules.md`: "prefer compatibility over
//! convenience"), the same stance taken for `metrics.listen`/`api.listen` elsewhere in the
//! project. Version-constraint checking itself was added in Xray-core 25.8.3 — older running
//! binaries silently ignore this object entirely, which this editor does not attempt to detect
//! (no local knowledge of the remote binary's exact version at edit time).
//!
//! Like `env` (Roadmap §2.1:55), `version` was not previously a recognized top-level section in
//! [`super::sections::XrayConfigSections`] — this module's registration required the same new
//! parser/sections plumbing as `env`, not just an app/GUI-layer addition.

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// Typed view of the Xray `version` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSettings {
    /// `version.min` — lowest Xray-core version this config is allowed to run on. `None` omits
    /// the key (no lower bound).
    pub min: Option<String>,
    /// `version.max` — highest Xray-core version this config is allowed to run on. `None` omits
    /// the key (no upper bound).
    pub max: Option<String>,
    /// `true` when a top-level `version` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `version` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (malformed section shape).
    pub warnings: Vec<String>,
}

impl VersionSettings {
    /// Effective defaults when the `version` object is absent (display only) — Save is what
    /// actually creates the object, the same "enable by saving" UX as API/Metrics Settings.
    pub fn defaults() -> Self {
        Self {
            min: None,
            max: None,
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`VersionSettings`] from an optional sourced `version` section.
pub fn version_settings_from_section(section: Option<&SourcedSection<Value>>) -> VersionSettings {
    let Some(section) = section else {
        return VersionSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed version object: expected a JSON object.".to_owned());
        return VersionSettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..VersionSettings::defaults()
        };
    }

    let min = string_field(value.get("min"));
    let max = string_field(value.get("max"));

    VersionSettings {
        min,
        max,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
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

/// Applies typed settings onto a `version` JSON object, preserving unknown keys.
pub fn apply_version_settings_to_value(
    target: &mut Value,
    settings: &VersionSettings,
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
                "version section must be a JSON object".to_owned(),
            ));
        }
    };

    match &settings.min {
        Some(min) => {
            object.insert("min".to_owned(), Value::String(min.clone()));
        }
        None => {
            object.remove("min");
        }
    }
    match &settings.max {
        Some(max) => {
            object.insert("max".to_owned(), Value::String(max.clone()));
        }
        None => {
            object.remove("max");
        }
    }

    Ok(())
}

/// Creates a fresh `version` object from settings (no unknown keys).
pub fn version_settings_to_new_value(settings: &VersionSettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_version_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn version_settings_change_summary(
    before: &VersionSettings,
    after: &VersionSettings,
) -> Vec<String> {
    let mut lines = Vec::new();

    if before.min != after.min {
        lines.push(format!(
            "min:\n{} → {}",
            before.min.as_deref().unwrap_or("(none)"),
            after.min.as_deref().unwrap_or("(none)")
        ));
    }
    if before.max != after.max {
        lines.push(format!(
            "max:\n{} → {}",
            before.max.as_deref().unwrap_or("(none)"),
            after.max.as_deref().unwrap_or("(none)")
        ));
    }

    lines
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient — `rules.md`: "prefer compatibility over convenience". The documented
/// `x.y.z` version syntax is not re-validated here (Xray-core itself does not require the
/// version to actually exist, only to match the syntax); only control characters that could
/// break the config-file JSON are rejected.
pub fn validate_version_settings(settings: &VersionSettings) -> ConfigModifyResult<()> {
    validate_field(&settings.min, "min")?;
    validate_field(&settings.max, "max")?;
    Ok(())
}

fn validate_field(value: &Option<String>, field: &str) -> ConfigModifyResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field} must not be blank — clear it instead to omit the key"),
        ));
    }
    if value.contains(['\n', '\r', '\0']) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field} must not contain control characters"),
        ));
    }
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
    fn missing_version_object_uses_defaults() {
        let settings = version_settings_from_section(None);
        assert!(!settings.section_present);
        assert_eq!(settings.min, None);
        assert_eq!(settings.max, None);
    }

    #[test]
    fn malformed_version_object_warns() {
        let settings = version_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed version object"))
        );
    }

    #[test]
    fn parses_min_and_max() {
        let settings = version_settings_from_section(Some(&section(json!({
            "min": "25.8.3",
            "max": "26.0.0"
        }))));
        assert_eq!(settings.min.as_deref(), Some("25.8.3"));
        assert_eq!(settings.max.as_deref(), Some("26.0.0"));
        assert!(settings.section_present);
    }

    #[test]
    fn blank_min_and_max_are_absent() {
        let settings = version_settings_from_section(Some(&section(json!({
            "min": "  ",
            "max": ""
        }))));
        assert_eq!(settings.min, None);
        assert_eq!(settings.max, None);
    }

    #[test]
    fn apply_preserves_unrelated_json_keys() {
        let mut value = json!({ "min": "25.8.3", "futureField": 42, "nested": { "a": 1 } });
        let settings = VersionSettings {
            min: Some("25.9.0".to_owned()),
            max: Some("26.0.0".to_owned()),
            section_present: true,
            source_file: None,
            warnings: Vec::new(),
        };
        apply_version_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
        assert_eq!(value["min"], "25.9.0");
        assert_eq!(value["max"], "26.0.0");
    }

    #[test]
    fn clearing_min_removes_the_key() {
        let mut value = json!({ "min": "25.8.3", "max": "26.0.0" });
        let settings = VersionSettings {
            min: None,
            max: Some("26.0.0".to_owned()),
            section_present: true,
            source_file: None,
            warnings: Vec::new(),
        };
        apply_version_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("min").is_none());
        assert_eq!(value["max"], "26.0.0");
    }

    #[test]
    fn change_summary_only_related_fields() {
        let before = VersionSettings::defaults();
        let mut after = before.clone();
        after.min = Some("25.8.3".to_owned());
        after.max = Some("26.0.0".to_owned());
        let summary = version_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 2);
        assert!(summary[0].contains("min"));
        assert!(summary[1].contains("max"));
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = VersionSettings::defaults();
        assert!(version_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_accepts_defaults_and_full_settings() {
        assert!(validate_version_settings(&VersionSettings::defaults()).is_ok());
        let settings = VersionSettings {
            min: Some("25.8.3".to_owned()),
            max: Some("26.0.0".to_owned()),
            ..VersionSettings::defaults()
        };
        assert!(validate_version_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_blank_min() {
        let mut settings = VersionSettings::defaults();
        settings.min = Some("   ".to_owned());
        assert!(validate_version_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_control_characters() {
        let mut settings = VersionSettings::defaults();
        settings.max = Some("26.0.0\n".to_owned());
        assert!(validate_version_settings(&settings).is_err());
    }
}
