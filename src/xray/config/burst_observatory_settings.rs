//! Typed editor model for the Xray top-level `burstObservatory` object (Roadmap §2.1:51).
//!
//! Field semantics follow the official BurstObservatoryObject / PingConfigObject documentation
//! (same page as `observatory`): <https://xtls.github.io/ru/config/observatory.html>
//!
//! This is the *editing* counterpart to the read-only [`super::BurstObservatorySummary`]/
//! [`super::BurstPingConfigSummary`] used elsewhere in the crate; those types are left untouched.
//! This module covers both documented `subjectSelector` and `pingConfig` (all 6 `PingConfigObject`
//! fields: `destination`/`connectivity`/`interval`/`sampling`/`timeout`/`httpMethod`) — the same
//! shape as the read-only summary already projects, so unlike `observatory_settings.rs` (which
//! added one field, `enableConcurrency`, beyond its summary) there is no coverage gap to close
//! here.
//!
//! `pingConfig` is documented as required at the `BurstObservatoryObject` level, but every one of
//! its own fields has a documented Xray-side default — so an empty `pingConfig: {}` is a
//! structurally complete, if maximally-defaulted, value. Mirrors the "prefer compatibility over
//! convenience" choice already made for the sibling `observatory` editor (§54.2): this module does
//! not hard-require `pingConfig`'s presence on save, matching the already-lenient read-only page,
//! which treats a missing ping configuration as an informational, non-blocking state
//! (`NoPingConfigurations`) rather than an error.

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// `burstObservatory.pingConfig` (`PingConfigObject`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstPingConfigEntry {
    /// `destination`. `None` omits the key (documented Xray default:
    /// `https://connectivitycheck.gstatic.com/generate_204`).
    pub destination: Option<String>,
    /// `connectivity`. `None` omits the key (documented Xray default: empty string = no check).
    pub connectivity: Option<String>,
    /// `interval` (Xray duration string). `None` omits the key (documented Xray default: `1m`).
    pub interval: Option<String>,
    /// `sampling`. `None` omits the key (documented Xray default: `10`).
    pub sampling: Option<u64>,
    /// `timeout` (Xray duration string). `None` omits the key (documented Xray default: `5s`).
    pub timeout: Option<String>,
    /// `httpMethod`. `None` omits the key (documented Xray default: `HEAD`); the field accepts
    /// any HTTP method string, not just the two documented examples (`HEAD`/`GET`).
    pub http_method: Option<String>,
}

impl BurstPingConfigEntry {
    /// A blank ping configuration (every field defaulted by Xray) for the GUI's "Add ping
    /// configuration" action.
    pub fn blank() -> Self {
        Self {
            destination: None,
            connectivity: None,
            interval: None,
            sampling: None,
            timeout: None,
            http_method: None,
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        if let Some(destination) = &self.destination {
            object.insert("destination".to_owned(), Value::String(destination.clone()));
        }
        if let Some(connectivity) = &self.connectivity {
            object.insert(
                "connectivity".to_owned(),
                Value::String(connectivity.clone()),
            );
        }
        if let Some(interval) = &self.interval {
            object.insert("interval".to_owned(), Value::String(interval.clone()));
        }
        if let Some(sampling) = self.sampling {
            object.insert("sampling".to_owned(), Value::from(sampling));
        }
        if let Some(timeout) = &self.timeout {
            object.insert("timeout".to_owned(), Value::String(timeout.clone()));
        }
        if let Some(http_method) = &self.http_method {
            object.insert(
                "httpMethod".to_owned(),
                Value::String(http_method.clone()),
            );
        }
        Value::Object(object)
    }
}

/// Typed view of the Xray `burstObservatory` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstObservatorySettings {
    /// `subjectSelector` — outbound tag prefixes to observe, in source/edit order.
    pub subject_selectors: Vec<String>,
    /// `pingConfig`. `None` omits the key.
    pub ping_config: Option<BurstPingConfigEntry>,
    /// `true` when a top-level `burstObservatory` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `burstObservatory` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (unknown values, malformed optional fields).
    pub warnings: Vec<String>,
}

impl BurstObservatorySettings {
    /// Effective defaults when the `burstObservatory` object is absent (display only).
    pub fn defaults() -> Self {
        Self {
            subject_selectors: Vec::new(),
            ping_config: None,
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`BurstObservatorySettings`] from an optional sourced `burstObservatory` section.
pub fn burst_observatory_settings_from_section(
    section: Option<&SourcedSection<Value>>,
) -> BurstObservatorySettings {
    let Some(section) = section else {
        return BurstObservatorySettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed burstObservatory object: expected a JSON object.".to_owned());
        return BurstObservatorySettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..BurstObservatorySettings::defaults()
        };
    }

    let subject_selectors = parse_subject_selectors(value.get("subjectSelector"), &mut warnings);
    let ping_config = parse_ping_config(value.get("pingConfig"), &mut warnings);

    BurstObservatorySettings {
        subject_selectors,
        ping_config,
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

fn parse_ping_config(
    value: Option<&Value>,
    warnings: &mut Vec<String>,
) -> Option<BurstPingConfigEntry> {
    let value = value?;
    let Some(object) = value.as_object() else {
        warnings.push("`pingConfig` has an unsupported type.".to_owned());
        return None;
    };

    Some(BurstPingConfigEntry {
        destination: string_field(object.get("destination")),
        connectivity: string_field(object.get("connectivity")),
        interval: string_field(object.get("interval")),
        sampling: object.get("sampling").and_then(Value::as_u64),
        timeout: string_field(object.get("timeout")),
        http_method: string_field(object.get("httpMethod")),
    })
}

/// Applies typed settings onto a `burstObservatory` JSON object, preserving unknown keys.
pub fn apply_burst_observatory_settings_to_value(
    target: &mut Value,
    settings: &BurstObservatorySettings,
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
                "burstObservatory section must be a JSON object".to_owned(),
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

    match &settings.ping_config {
        Some(ping_config) => {
            object.insert("pingConfig".to_owned(), ping_config.to_value());
        }
        None => {
            object.remove("pingConfig");
        }
    }

    Ok(())
}

/// Creates a fresh `burstObservatory` object from settings (no unknown keys).
pub fn burst_observatory_settings_to_new_value(settings: &BurstObservatorySettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_burst_observatory_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn burst_observatory_settings_change_summary(
    before: &BurstObservatorySettings,
    after: &BurstObservatorySettings,
) -> Vec<String> {
    let mut lines = Vec::new();

    if before.subject_selectors != after.subject_selectors {
        lines.push(format!(
            "subjectSelector:\n{} → {} configured (see Preview changes for full detail)",
            before.subject_selectors.len(),
            after.subject_selectors.len()
        ));
    }
    if before.ping_config != after.ping_config {
        lines.push(format!(
            "pingConfig:\n{} → {}",
            display_ping_presence(&before.ping_config),
            display_ping_presence(&after.ping_config)
        ));
    }

    lines
}

fn display_ping_presence(ping_config: &Option<BurstPingConfigEntry>) -> &'static str {
    if ping_config.is_some() {
        "configured"
    } else {
        "(none)"
    }
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient (`rules.md`: "prefer compatibility over convenience") — only control
/// characters are rejected; an empty `subjectSelector` and an absent `pingConfig` are both
/// allowed to be saved (see module docs), and duration/URL grammars are not re-validated here
/// (`xray run -test` already runs after every save).
pub fn validate_burst_observatory_settings(settings: &BurstObservatorySettings) -> ConfigModifyResult<()> {
    for (index, selector) in settings.subject_selectors.iter().enumerate() {
        validate_control_chars(selector, &format!("subjectSelector entry {}", index + 1))?;
    }
    if let Some(ping_config) = &settings.ping_config {
        validate_optional_control_chars(&ping_config.destination, "pingConfig.destination")?;
        validate_optional_control_chars(&ping_config.connectivity, "pingConfig.connectivity")?;
        validate_optional_control_chars(&ping_config.interval, "pingConfig.interval")?;
        validate_optional_control_chars(&ping_config.timeout, "pingConfig.timeout")?;
        validate_optional_control_chars(&ping_config.http_method, "pingConfig.httpMethod")?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(value: Value) -> SourcedSection<Value> {
        SourcedSection::new("/etc/xray/config.json", value)
    }

    #[test]
    fn missing_burst_observatory_object_uses_defaults() {
        let settings = burst_observatory_settings_from_section(None);
        assert!(!settings.section_present);
        assert!(settings.subject_selectors.is_empty());
        assert!(settings.ping_config.is_none());
    }

    #[test]
    fn malformed_burst_observatory_object_warns() {
        let settings =
            burst_observatory_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed burstObservatory object"))
        );
    }

    #[test]
    fn subject_selector_round_trips() {
        let settings = burst_observatory_settings_from_section(Some(&section(json!({
            "subjectSelector": ["proxy", "warp"]
        }))));
        assert_eq!(
            settings.subject_selectors,
            vec!["proxy".to_owned(), "warp".to_owned()]
        );

        let mut value = json!({});
        apply_burst_observatory_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["subjectSelector"], json!(["proxy", "warp"]));
    }

    #[test]
    fn ping_config_round_trips_all_fields() {
        let settings = burst_observatory_settings_from_section(Some(&section(json!({
            "pingConfig": {
                "destination": "https://example.com/generate_204",
                "connectivity": "https://connectivity.example.com",
                "interval": "30s",
                "sampling": 20,
                "timeout": "3s",
                "httpMethod": "GET"
            }
        }))));
        let ping = settings.ping_config.as_ref().unwrap();
        assert_eq!(
            ping.destination.as_deref(),
            Some("https://example.com/generate_204")
        );
        assert_eq!(
            ping.connectivity.as_deref(),
            Some("https://connectivity.example.com")
        );
        assert_eq!(ping.interval.as_deref(), Some("30s"));
        assert_eq!(ping.sampling, Some(20));
        assert_eq!(ping.timeout.as_deref(), Some("3s"));
        assert_eq!(ping.http_method.as_deref(), Some("GET"));

        let mut value = json!({});
        apply_burst_observatory_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(
            value["pingConfig"]["destination"],
            "https://example.com/generate_204"
        );
        assert_eq!(value["pingConfig"]["sampling"], 20);
        assert_eq!(value["pingConfig"]["httpMethod"], "GET");
    }

    #[test]
    fn missing_ping_config_fields_omit_keys() {
        let settings = burst_observatory_settings_from_section(Some(&section(json!({
            "pingConfig": {}
        }))));
        let ping = settings.ping_config.as_ref().unwrap();
        assert_eq!(ping.destination, None);
        assert_eq!(ping.sampling, None);

        let mut value = json!({});
        apply_burst_observatory_settings_to_value(&mut value, &settings).unwrap();
        assert!(value["pingConfig"].get("destination").is_none());
        assert!(value["pingConfig"].get("sampling").is_none());
    }

    #[test]
    fn missing_ping_config_is_none_without_warning() {
        let settings = burst_observatory_settings_from_section(Some(&section(json!({
            "subjectSelector": ["proxy"]
        }))));
        assert!(settings.ping_config.is_none());
        assert!(settings.warnings.is_empty());
    }

    #[test]
    fn malformed_ping_config_warns() {
        let settings = burst_observatory_settings_from_section(Some(&section(json!({
            "pingConfig": "not-an-object"
        }))));
        assert!(settings.ping_config.is_none());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("`pingConfig`"))
        );
    }

    #[test]
    fn unsupported_selector_entry_is_skipped_with_warning() {
        let settings = burst_observatory_settings_from_section(Some(&section(json!({
            "subjectSelector": ["proxy", 42]
        }))));
        assert_eq!(settings.subject_selectors, vec!["proxy".to_owned()]);
        assert!(settings.warnings.iter().any(|w| w.contains("entry #2")));
    }

    #[test]
    fn apply_preserves_unrelated_json_keys() {
        let mut value = json!({ "futureField": 42, "nested": { "a": 1 } });
        let settings = BurstObservatorySettings::defaults();
        apply_burst_observatory_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
    }

    #[test]
    fn empty_selectors_and_absent_ping_config_remove_keys_on_apply() {
        let mut value = json!({ "subjectSelector": ["old"], "pingConfig": { "sampling": 5 } });
        let settings = BurstObservatorySettings::defaults();
        apply_burst_observatory_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("subjectSelector").is_none());
        assert!(value.get("pingConfig").is_none());
    }

    #[test]
    fn change_summary_reports_touched_fields_only() {
        let before = BurstObservatorySettings::defaults();
        let mut after = before.clone();
        after.subject_selectors.push("proxy".to_owned());
        after.ping_config = Some(BurstPingConfigEntry::blank());
        let summary = burst_observatory_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 2);
        assert!(summary[0].contains("0 → 1"));
        assert!(summary[1].contains("(none) → configured"));
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = BurstObservatorySettings::defaults();
        assert!(burst_observatory_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_accepts_defaults_and_full_settings() {
        assert!(validate_burst_observatory_settings(&BurstObservatorySettings::defaults()).is_ok());
        let settings = BurstObservatorySettings {
            subject_selectors: vec!["proxy".to_owned()],
            ping_config: Some(BurstPingConfigEntry {
                destination: Some("https://example.com".to_owned()),
                connectivity: Some("https://example.com/conn".to_owned()),
                interval: Some("30s".to_owned()),
                sampling: Some(10),
                timeout: Some("5s".to_owned()),
                http_method: Some("HEAD".to_owned()),
            }),
            ..BurstObservatorySettings::defaults()
        };
        assert!(validate_burst_observatory_settings(&settings).is_ok());
    }

    #[test]
    fn validation_accepts_empty_selectors_and_absent_ping_config() {
        let settings = BurstObservatorySettings::defaults();
        assert!(validate_burst_observatory_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_control_characters_in_selector() {
        let settings = BurstObservatorySettings {
            subject_selectors: vec!["bad\nselector".to_owned()],
            ..BurstObservatorySettings::defaults()
        };
        assert!(validate_burst_observatory_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_control_characters_in_ping_config() {
        let settings = BurstObservatorySettings {
            ping_config: Some(BurstPingConfigEntry {
                destination: Some("https://example.com\n".to_owned()),
                ..BurstPingConfigEntry::blank()
            }),
            ..BurstObservatorySettings::defaults()
        };
        assert!(validate_burst_observatory_settings(&settings).is_err());
    }

    #[test]
    fn to_new_value_creates_object_without_optional_keys() {
        let settings = BurstObservatorySettings::defaults();
        let value = burst_observatory_settings_to_new_value(&settings);
        assert!(value.get("subjectSelector").is_none());
        assert!(value.get("pingConfig").is_none());
    }
}
