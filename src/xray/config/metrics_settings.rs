//! Typed editor model for the Xray top-level `metrics` object (Roadmap §2.1:53).
//!
//! Field semantics follow the official MetricsObject documentation:
//! <https://xtls.github.io/ru/config/metrics.html>
//!
//! This module is for configuration *editing* — enabling/disabling the `metrics` object and its
//! `tag` / `listen` fields, the exact same two fields as `api.tag`/`api.listen`
//! (`api_settings.rs`, Roadmap §2.1:54) minus `services[]` — `MetricsObject` has no equivalent
//! field. Runtime scraping of an already-configured endpoint lives in
//! `crate::xray::remote_cli::run_metrics_scrape` / `crate::app::metrics_ops` (Roadmap §3:130, the
//! Metrics page) — a deliberately separate concern (config-file edit vs. live HTTP scrape), the
//! same split already drawn between `api_settings.rs` and the API Console.
//!
//! **Both fields are optional, but the official documentation is explicit that leaving both
//! unset (once the `metrics` object exists) prevents Xray-core from starting**: "Если при
//! установке этого поля `tag` пустой, он автоматически устанавливается в `Metrics`. Если оба поля
//! не заданы, ядро не запустится." This module does not turn that into a hard validation error —
//! consistent with every other editor's "prefer compatibility over convenience" stance
//! (`rules.md`), `xray run -test` already runs after every save and would catch it — but the GUI
//! surfaces it as an inline hint (mirrors `api_settings`'s "without `listen`, only reachable via
//! routing" note).

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// Typed view of the Xray `metrics` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSettings {
    /// `metrics.tag` — the outbound tag Xray auto-creates for the metrics endpoint. `None` omits
    /// the key; Xray itself then defaults it to `"Metrics"` once `listen` (or the object) makes
    /// the endpoint meaningful.
    pub tag: Option<String>,
    /// `metrics.listen` — address (typically `host:port`) to listen on directly. `None` omits
    /// the key (the endpoint is then only reachable by routing an inbound to `tag`, which this
    /// editor does not attempt to wire automatically — same boundary as `api_settings.rs`).
    pub listen: Option<String>,
    /// `true` when a top-level `metrics` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `metrics` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (malformed section shape).
    pub warnings: Vec<String>,
}

impl MetricsSettings {
    /// Effective defaults when the `metrics` object is absent (display only) — Save is what
    /// actually creates the object, the same "enable by saving" UX as API Settings.
    pub fn defaults() -> Self {
        Self {
            tag: None,
            listen: None,
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`MetricsSettings`] from an optional sourced `metrics` section.
pub fn metrics_settings_from_section(section: Option<&SourcedSection<Value>>) -> MetricsSettings {
    let Some(section) = section else {
        return MetricsSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed metrics object: expected a JSON object.".to_owned());
        return MetricsSettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..MetricsSettings::defaults()
        };
    }

    let tag = string_field(value.get("tag"));
    let listen = string_field(value.get("listen"));

    MetricsSettings {
        tag,
        listen,
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

/// Applies typed settings onto a `metrics` JSON object, preserving unknown keys.
pub fn apply_metrics_settings_to_value(
    target: &mut Value,
    settings: &MetricsSettings,
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
                "metrics section must be a JSON object".to_owned(),
            ));
        }
    };

    match &settings.tag {
        Some(tag) => {
            object.insert("tag".to_owned(), Value::String(tag.clone()));
        }
        None => {
            object.remove("tag");
        }
    }
    match &settings.listen {
        Some(listen) => {
            object.insert("listen".to_owned(), Value::String(listen.clone()));
        }
        None => {
            object.remove("listen");
        }
    }

    Ok(())
}

/// Creates a fresh `metrics` object from settings (no unknown keys).
pub fn metrics_settings_to_new_value(settings: &MetricsSettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_metrics_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn metrics_settings_change_summary(before: &MetricsSettings, after: &MetricsSettings) -> Vec<String> {
    let mut lines = Vec::new();

    if before.tag != after.tag {
        lines.push(format!(
            "tag:\n{} → {}",
            before.tag.as_deref().unwrap_or("(none)"),
            after.tag.as_deref().unwrap_or("(none)")
        ));
    }
    if before.listen != after.listen {
        lines.push(format!(
            "listen:\n{} → {}",
            before.listen.as_deref().unwrap_or("(none)"),
            after.listen.as_deref().unwrap_or("(none)")
        ));
    }

    lines
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient — `rules.md`: "prefer compatibility over convenience". Xray's exact
/// `listen` grammar (bare `host:port`, IPv6 `[::1]:port`, …) is not re-validated here; only
/// control characters that could break the config-file JSON or a later CLI invocation
/// (`metrics.listen` also becomes the scrape target used by the Metrics page, Roadmap §3:130)
/// are rejected. The documented "both fields unset breaks startup" constraint is intentionally
/// not enforced here — see module docs.
pub fn validate_metrics_settings(settings: &MetricsSettings) -> ConfigModifyResult<()> {
    validate_field(&settings.tag, "tag")?;
    validate_field(&settings.listen, "listen")?;
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
    fn missing_metrics_object_uses_defaults() {
        let settings = metrics_settings_from_section(None);
        assert!(!settings.section_present);
        assert_eq!(settings.tag, None);
        assert_eq!(settings.listen, None);
    }

    #[test]
    fn malformed_metrics_object_warns() {
        let settings = metrics_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed metrics object"))
        );
    }

    #[test]
    fn parses_tag_and_listen() {
        let settings = metrics_settings_from_section(Some(&section(json!({
            "tag": "Metrics",
            "listen": "127.0.0.1:11111"
        }))));
        assert_eq!(settings.tag.as_deref(), Some("Metrics"));
        assert_eq!(settings.listen.as_deref(), Some("127.0.0.1:11111"));
        assert!(settings.section_present);
    }

    #[test]
    fn blank_tag_and_listen_are_absent() {
        let settings = metrics_settings_from_section(Some(&section(json!({
            "tag": "  ",
            "listen": ""
        }))));
        assert_eq!(settings.tag, None);
        assert_eq!(settings.listen, None);
    }

    #[test]
    fn apply_preserves_unrelated_json_keys() {
        let mut value = json!({ "tag": "Metrics", "futureField": 42, "nested": { "a": 1 } });
        let settings = MetricsSettings {
            tag: Some("Metrics-renamed".to_owned()),
            listen: Some("127.0.0.1:11111".to_owned()),
            section_present: true,
            source_file: None,
            warnings: Vec::new(),
        };
        apply_metrics_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
        assert_eq!(value["tag"], "Metrics-renamed");
        assert_eq!(value["listen"], "127.0.0.1:11111");
    }

    #[test]
    fn clearing_tag_removes_the_key() {
        let mut value = json!({ "tag": "Metrics", "listen": "127.0.0.1:11111" });
        let settings = MetricsSettings {
            tag: None,
            listen: Some("127.0.0.1:11111".to_owned()),
            section_present: true,
            source_file: None,
            warnings: Vec::new(),
        };
        apply_metrics_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("tag").is_none());
        assert_eq!(value["listen"], "127.0.0.1:11111");
    }

    #[test]
    fn change_summary_only_related_fields() {
        let before = MetricsSettings::defaults();
        let mut after = before.clone();
        after.tag = Some("Metrics".to_owned());
        after.listen = Some("127.0.0.1:11111".to_owned());
        let summary = metrics_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 2);
        assert!(summary[0].contains("tag"));
        assert!(summary[1].contains("listen"));
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = MetricsSettings::defaults();
        assert!(metrics_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_accepts_defaults_and_full_settings() {
        assert!(validate_metrics_settings(&MetricsSettings::defaults()).is_ok());
        let settings = MetricsSettings {
            tag: Some("Metrics".to_owned()),
            listen: Some("127.0.0.1:11111".to_owned()),
            ..MetricsSettings::defaults()
        };
        assert!(validate_metrics_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_blank_tag() {
        let mut settings = MetricsSettings::defaults();
        settings.tag = Some("   ".to_owned());
        // `MetricsSettings` construction itself never produces a `Some("   ")`, but a
        // hand-built draft (e.g. from a not-yet-trimmed GUI text field) must still be rejected.
        assert!(validate_metrics_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_control_characters() {
        let mut settings = MetricsSettings::defaults();
        settings.listen = Some("127.0.0.1:11111\n".to_owned());
        assert!(validate_metrics_settings(&settings).is_err());
    }
}
