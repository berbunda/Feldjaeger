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

/// `api.services[]` values Xray-core understands (`infra/conf/api.go` v26.9.30, which matches
/// them case-insensitively and silently ignores anything else). The editor offers these as
/// toggles; any other on-disk value is preserved as free text — unknown/future entries
/// round-trip verbatim, the same "never invent semantics for what's already there" rule as
/// every other section.
pub const KNOWN_API_SERVICES: &[&str] = &[
    "HandlerService",
    "LoggerService",
    "StatsService",
    "RoutingService",
    "ReflectionService",
    OBSERVATORY_API_SERVICE,
];

/// The API service that needs an `observatory` or `burstObservatory` section: without one Xray
/// does not start ("core: not all dependencies are resolved", `xray run -test` 26.9.30,
/// Architecture §119).
pub const OBSERVATORY_API_SERVICE: &str = "ObservatoryService";

/// Error text for an `api` object without `tag` (Architecture §119).
const TAG_REQUIRED: &str = "tag is required: Xray-core refuses to load an api object without it \
                            (\"API tag can't be empty.\"), even when listen is set.";

/// Error text for `ObservatoryService` without an observatory section (Architecture §119).
const OBSERVATORY_SERVICE_NEEDS_OBSERVATORY: &str =
    "ObservatoryService needs an observatory or burstObservatory section: without one Xray does \
     not start (\"not all dependencies are resolved\"). Configure Observatory or BurstObservatory \
     first, or remove the service.";

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

    /// These settings as the start of an edit draft: an `api` object that does not exist yet
    /// starts with `tag: "api"`, which Xray-core requires. An existing object without `tag` is
    /// left as is — Save explains what is missing.
    pub fn into_edit_draft(mut self) -> Self {
        if !self.section_present {
            self.tag.get_or_insert_with(|| "api".to_owned());
        }
        self
    }

    /// Whether `services` lists [`OBSERVATORY_API_SERVICE`] (case-insensitively, like the core).
    pub fn uses_observatory_service(&self) -> bool {
        self.services
            .iter()
            .any(|service| service.eq_ignore_ascii_case(OBSERVATORY_API_SERVICE))
    }

    /// Problems that stop Xray-core from loading or starting with these settings, for the
    /// read-only view; `observatory_present` = an `observatory` or `burstObservatory` section
    /// exists. Save rejects the same cases ([`validate_api_settings`],
    /// [`validate_api_settings_against_config`]).
    pub fn core_problems(&self, observatory_present: bool) -> Vec<String> {
        let mut problems = Vec::new();
        if self.section_present && self.tag.is_none() {
            problems.push(TAG_REQUIRED.to_owned());
        }
        if self.uses_observatory_service() && !observatory_present {
            problems.push(OBSERVATORY_SERVICE_NEEDS_OBSERVATORY.to_owned());
        }
        problems
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
/// rejected. The one exception is `tag`, which Xray-core requires (Architecture §119).
pub fn validate_api_settings(settings: &ApiSettings) -> ConfigModifyResult<()> {
    if settings.tag.is_none() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            TAG_REQUIRED.to_owned(),
        ));
    }
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

/// [`validate_api_settings`] plus the checks that depend on the rest of the config:
/// `ObservatoryService` needs an `observatory` or `burstObservatory` section
/// (`observatory_present`), otherwise Xray does not start (Architecture §119).
pub fn validate_api_settings_against_config(
    settings: &ApiSettings,
    observatory_present: bool,
) -> ConfigModifyResult<()> {
    validate_api_settings(settings)?;
    if settings.uses_observatory_service() && !observatory_present {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            OBSERVATORY_SERVICE_NEEDS_OBSERVATORY.to_owned(),
        ));
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
        settings.tag = Some("api".to_owned());
        settings.listen = Some("127.0.0.1:8080\n".to_owned());
        let error = validate_api_settings(&settings).unwrap_err();
        assert!(error.message().contains("listen"), "{}", error.message());
    }

    #[test]
    fn validation_accepts_tag_only_and_full_settings() {
        let tag_only = ApiSettings {
            tag: Some("api".to_owned()),
            ..ApiSettings::defaults()
        };
        assert!(validate_api_settings(&tag_only).is_ok());
        let settings = ApiSettings {
            tag: Some("api".to_owned()),
            listen: Some("127.0.0.1:8080".to_owned()),
            services: KNOWN_API_SERVICES.iter().map(|s| s.to_string()).collect(),
            ..ApiSettings::defaults()
        };
        assert!(validate_api_settings(&settings).is_ok());
        assert!(validate_api_settings_against_config(&settings, true).is_ok());
    }

    #[test]
    fn validation_requires_tag() {
        // Xray-core v26.9.30 `APIConfig.Build()`: "API tag can't be empty." — `{}` and
        // `{"listen": …}` both fail `xray run -test` (Architecture §119).
        let listen_only = ApiSettings {
            listen: Some("127.0.0.1:10085".to_owned()),
            ..ApiSettings::defaults()
        };
        let error = validate_api_settings(&listen_only).unwrap_err();
        assert!(error.message().contains("tag is required"), "{}", error.message());
        assert!(validate_api_settings(&ApiSettings::defaults()).is_err());
    }

    #[test]
    fn edit_draft_of_new_section_starts_with_tag() {
        let draft = api_settings_from_section(None).into_edit_draft();
        assert_eq!(draft.tag.as_deref(), Some("api"));
        assert!(validate_api_settings(&draft).is_ok());
        assert_eq!(api_settings_to_new_value(&draft), json!({"tag": "api"}));

        // An existing object is not silently changed: Save reports the missing tag.
        let existing = api_settings_from_section(Some(&section(json!({
            "listen": "127.0.0.1:10085"
        }))))
        .into_edit_draft();
        assert_eq!(existing.tag, None);
        assert!(validate_api_settings(&existing).is_err());
    }

    #[test]
    fn observatory_service_needs_an_observatory_section() {
        // Without observatory / burstObservatory Xray does not start: "core: not all
        // dependencies are resolved" (`xray run -test` 26.9.30, Architecture §119). The core
        // matches service names case-insensitively, so this does too.
        assert!(KNOWN_API_SERVICES.contains(&OBSERVATORY_API_SERVICE));
        let settings = ApiSettings {
            tag: Some("api".to_owned()),
            services: vec!["observatoryservice".to_owned()],
            ..ApiSettings::defaults()
        };
        assert!(validate_api_settings(&settings).is_ok());
        let error = validate_api_settings_against_config(&settings, false).unwrap_err();
        assert!(error.message().contains("ObservatoryService needs"), "{}", error.message());
        assert!(validate_api_settings_against_config(&settings, true).is_ok());

        let without = ApiSettings {
            services: vec!["StatsService".to_owned()],
            ..settings
        };
        assert!(validate_api_settings_against_config(&without, false).is_ok());
    }

    #[test]
    fn core_problems_report_missing_tag_and_observatory() {
        let settings = api_settings_from_section(Some(&section(json!({
            "services": ["ObservatoryService"]
        }))));
        let problems = settings.core_problems(false);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].contains("tag is required"));
        assert!(problems[1].contains("ObservatoryService needs"));
        assert!(settings.core_problems(true).len() == 1);

        // No api object at all: nothing for the core to reject.
        assert!(api_settings_from_section(None).core_problems(false).is_empty());
    }
}
