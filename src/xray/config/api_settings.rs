//! Typed editor model for the Xray top-level `api` object (Roadmap §2.1:54).
//!
//! Field semantics follow the official API Interface documentation:
//! <https://xtls.github.io/en/config/api.html>
//!
//! This module is for configuration *editing* — enabling/disabling the `api` object and its
//! `tag` / `listen` / `services` fields. Runtime calls against an already-configured API
//! endpoint live in `crate::xray::remote_cli::run_xray_api` / `crate::app::api_ops` (Roadmap
//! §3:128, the API Console page) — a deliberately separate concern (config-file edit vs. live
//! gRPC operations), the same split already drawn between this module and `crate::xray::logs`
//! for the `log` object.

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// Known JSON keys inside the `api` object.
const KNOWN_KEYS: &[&str] = &["tag", "listen", "services"];

/// Documented `api.services[]` values
/// (<https://xtls.github.io/en/config/api.html>). The editor offers these as toggles; any other
/// on-disk value is preserved as free text — unknown/future entries round-trip verbatim, the
/// same "never invent semantics for what's already there" rule as every other section.
pub const KNOWN_API_SERVICES: &[&str] = &[
    "HandlerService",
    "LoggerService",
    "StatsService",
    "RoutingService",
    "ReflectionService",
];

/// Typed view of the Xray `api` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiSettings {
    /// `api.tag` — the outbound tag Xray auto-creates for the API endpoint. `None` = key absent.
    pub tag: Option<String>,
    /// `api.listen` — address (typically `host:port`) to listen on directly. `None` = key
    /// absent (the endpoint is then only reachable by routing an inbound to `tag`, which this
    /// editor does not attempt to wire automatically — same "structured editors show only
    /// supported fields, never invent routing" boundary as everywhere else).
    pub listen: Option<String>,
    /// `api.services[]`, verbatim and in on-disk order (unknown/future values preserved).
    pub services: Vec<String>,
    /// `true` when a top-level `api` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `api` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (malformed optional fields).
    pub warnings: Vec<String>,
}

impl ApiSettings {
    /// Effective defaults when the `api` object is absent (display only) — Save is what
    /// actually creates the object, the same "enable by saving" UX as Log Settings.
    pub fn defaults() -> Self {
        Self {
            tag: None,
            listen: None,
            services: Vec::new(),
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`ApiSettings`] from an optional sourced `api` section.
pub fn api_settings_from_section(section: Option<&SourcedSection<Value>>) -> ApiSettings {
    let Some(section) = section else {
        return ApiSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed api object: expected a JSON object.".to_owned());
        return ApiSettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..ApiSettings::defaults()
        };
    }

    let tag = string_field(value.get("tag"));
    let listen = string_field(value.get("listen"));
    let services = parse_services(value.get("services"), &mut warnings);

    ApiSettings {
        tag,
        listen,
        services,
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

fn parse_services(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(array) = value.as_array() else {
        warnings.push(
            "Unsupported `services` value: expected a JSON array; treating as empty.".to_owned(),
        );
        return Vec::new();
    };
    array
        .iter()
        .filter_map(|v| {
            v.as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

/// Applies typed settings onto an `api` JSON object, preserving unknown keys.
pub fn apply_api_settings_to_value(
    target: &mut Value,
    settings: &ApiSettings,
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
                "api section must be a JSON object".to_owned(),
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
    if settings.services.is_empty() {
        object.remove("services");
    } else {
        object.insert(
            "services".to_owned(),
            Value::Array(
                settings
                    .services
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    let _ = KNOWN_KEYS;
    Ok(())
}

/// Creates a fresh `api` object from settings (no unknown keys).
pub fn api_settings_to_new_value(settings: &ApiSettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_api_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn api_settings_change_summary(before: &ApiSettings, after: &ApiSettings) -> Vec<String> {
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
    if before.services != after.services {
        lines.push(format!(
            "services:\n{} → {}",
            if before.services.is_empty() {
                "(none)".to_owned()
            } else {
                before.services.join(", ")
            },
            if after.services.is_empty() {
                "(none)".to_owned()
            } else {
                after.services.join(", ")
            }
        ));
    }

    lines
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient — `rules.md`: "prefer compatibility over convenience". Xray's exact
/// `listen` grammar (bare `host:port`, IPv6 `[::1]:port`, …) is not re-validated here; only
/// control characters that could break the config-file JSON or a later CLI invocation
/// (`api.listen` also becomes the `-s` argument used by the API Console, Roadmap §3:128) are
/// rejected.
pub fn validate_api_settings(settings: &ApiSettings) -> ConfigModifyResult<()> {
    validate_field(&settings.tag, "tag")?;
    validate_field(&settings.listen, "listen")?;
    for service in &settings.services {
        if service.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "service name must not be empty".to_owned(),
            ));
        }
        if service.contains(['\n', '\r', '\0']) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "service name must not contain control characters".to_owned(),
            ));
        }
    }
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
    fn missing_api_object_uses_defaults() {
        let settings = api_settings_from_section(None);
        assert!(!settings.section_present);
        assert_eq!(settings.tag, None);
        assert_eq!(settings.listen, None);
        assert!(settings.services.is_empty());
    }

    #[test]
    fn parses_tag_listen_services() {
        let settings = api_settings_from_section(Some(&section(json!({
            "tag": "api",
            "listen": "127.0.0.1:8080",
            "services": ["HandlerService", "LoggerService"]
        }))));
        assert_eq!(settings.tag.as_deref(), Some("api"));
        assert_eq!(settings.listen.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(
            settings.services,
            vec!["HandlerService".to_owned(), "LoggerService".to_owned()]
        );
        assert!(settings.section_present);
    }

    #[test]
    fn blank_tag_and_listen_are_absent() {
        let settings = api_settings_from_section(Some(&section(json!({
            "tag": "  ",
            "listen": ""
        }))));
        assert_eq!(settings.tag, None);
        assert_eq!(settings.listen, None);
    }

    #[test]
    fn unknown_service_values_are_preserved() {
        let settings = api_settings_from_section(Some(&section(json!({
            "services": ["HandlerService", "FutureService"]
        }))));
        assert_eq!(
            settings.services,
            vec!["HandlerService".to_owned(), "FutureService".to_owned()]
        );
    }

    #[test]
    fn non_array_services_value_warns_and_treats_as_empty() {
        let settings =
            api_settings_from_section(Some(&section(json!({ "services": "HandlerService" }))));
        assert!(settings.services.is_empty());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("expected a JSON array"))
        );
    }

    #[test]
    fn unknown_fields_preserved_on_apply() {
        let mut value = json!({
            "tag": "api",
            "futureField": 42,
            "nested": { "a": 1 }
        });
        let settings = ApiSettings {
            tag: Some("api-renamed".to_owned()),
            listen: Some("127.0.0.1:8080".to_owned()),
            services: vec!["HandlerService".to_owned()],
            section_present: true,
            source_file: None,
            warnings: Vec::new(),
        };
        apply_api_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
        assert_eq!(value["tag"], "api-renamed");
        assert_eq!(value["listen"], "127.0.0.1:8080");
        assert_eq!(value["services"], json!(["HandlerService"]));
    }

    #[test]
    fn clearing_tag_removes_the_key() {
        let mut value = json!({ "tag": "api", "listen": "127.0.0.1:8080" });
        let settings = ApiSettings {
            tag: None,
            listen: Some("127.0.0.1:8080".to_owned()),
            services: Vec::new(),
            section_present: true,
            source_file: None,
            warnings: Vec::new(),
        };
        apply_api_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("tag").is_none());
        assert!(value.get("services").is_none());
    }

    #[test]
    fn change_summary_only_related_fields() {
        let before = ApiSettings::defaults();
        let mut after = before.clone();
        after.tag = Some("api".to_owned());
        after.listen = Some("127.0.0.1:8080".to_owned());
        let summary = api_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 2);
        assert!(summary[0].contains("tag"));
        assert!(summary[1].contains("listen"));
    }

    #[test]
    fn validation_rejects_control_characters() {
        let mut settings = ApiSettings::defaults();
        settings.listen = Some("127.0.0.1:8080\n".to_owned());
        assert!(validate_api_settings(&settings).is_err());
    }

    #[test]
    fn validation_accepts_defaults_and_full_settings() {
        assert!(validate_api_settings(&ApiSettings::defaults()).is_ok());
        let settings = ApiSettings {
            tag: Some("api".to_owned()),
            listen: Some("127.0.0.1:8080".to_owned()),
            services: KNOWN_API_SERVICES.iter().map(|s| s.to_string()).collect(),
            ..ApiSettings::defaults()
        };
        assert!(validate_api_settings(&settings).is_ok());
    }
}
