//! Typed editor model for the Xray top-level `env` object (Roadmap §2.1:55).
//!
//! Field semantics follow the official environment variable documentation:
//! <https://xtls.github.io/ru/config/env.html>
//!
//! Unlike every other root-section editor in this crate, `env` has no fixed schema at all — the
//! documentation states plainly: "Каждая переменная окружения должна быть строкой" (each
//! environment variable must be a string). The object is a free-form name→string map, structurally
//! closer to `dns.hosts{}` (`dns_settings.rs`) than to any fixed-field object like `api`/
//! `metrics`/`policy`. So this module has no notion of "known object fields" — only a preset list
//! of documented *variable names* (see [`KNOWN_ENV_VARS`]) offered as a convenience dropdown for
//! each entry's name, the same "checkboxes/dropdown for known values + free text for anything
//! else" idiom already used for `api.services[]`/`routing.rules[].protocol`.
//!
//! **Three documented variable names are deliberately excluded from [`KNOWN_ENV_VARS`]** —
//! `XRAY_LOCATION_CONFIG`, `XRAY_LOCATION_CONFDIR`, `XRAY_JSON_STRICT`. The official documentation
//! states, verbatim, three times, that setting each of these inside the config file's `env`
//! object has **no effect**: Xray-core locates and parses the config file (and decides which JSON
//! parser to use) *before* it ever reads the `env` section, so by the time these three variables
//! would take effect, it's already too late — they only work as real OS/systemd environment
//! variables set before the process starts. Offering them as presets here would suggest they do
//! something through this editor when they provably do not (confirmed with the user before
//! implementation, since this contradicts the "editor covers every documented field" precedent
//! set by every prior root-section editor). Feldjäger's own remote config-location logic already
//! lives entirely in the systemd unit's `ExecStart` (`init/unit.rs`: `run -config <path>` /
//! `run -confdir <path>`), independent of and unrelated to this `env` object.
//!
//! The remaining ~11 documented names (`XRAY_LOCATION_ASSET`/`XRAY_LOCATION_CERT`/
//! `XRAY_BUF_READV`/`XRAY_BUF_SPLICE`/`XRAY_VMESS_PADDING`/`XRAY_CONE_DISABLED`/
//! `XRAY_RAY_BUFFER_SIZE`/`XRAY_BROWSER_DIALER`/`XRAY_XUDP_SHOW`/`XRAY_XUDP_BASEKEY`/
//! `XRAY_TUN_FD`) have no documented value grammar beyond "string" — the page explicitly says most
//! are "для специализированных сценариев" (for specialized scenarios) with their exact meaning
//! left to the Xray-core source. No boolean/enum widget is invented for their values; only the
//! variable *name* gets dropdown presets, never the value.

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// Documented `env{}` variable names that are meaningful when set inside the config file's `env`
/// object, offered as a preset dropdown for each entry's name (any other name — including the
/// three excluded no-op names below — remains fully editable as free text; nothing is blocked).
///
/// Deliberately excludes `XRAY_LOCATION_CONFIG`, `XRAY_LOCATION_CONFDIR`, `XRAY_JSON_STRICT` —
/// see module docs for why.
pub const KNOWN_ENV_VARS: &[&str] = &[
    "XRAY_LOCATION_ASSET",
    "XRAY_LOCATION_CERT",
    "XRAY_BUF_READV",
    "XRAY_BUF_SPLICE",
    "XRAY_VMESS_PADDING",
    "XRAY_CONE_DISABLED",
    "XRAY_RAY_BUFFER_SIZE",
    "XRAY_BROWSER_DIALER",
    "XRAY_XUDP_SHOW",
    "XRAY_XUDP_BASEKEY",
    "XRAY_TUN_FD",
];

/// One `env{}` entry: a variable name and its (always-string) value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVarEntry {
    /// The JSON object key — the environment variable name.
    pub name: String,
    /// The JSON string value. Official docs: every entry must be a string, even for
    /// boolean-looking variables (e.g. `"XRAY_BUF_READV": "true"`).
    pub value: String,
}

impl EnvVarEntry {
    /// A blank entry for the GUI's "Add variable" action.
    pub fn blank() -> Self {
        Self {
            name: String::new(),
            value: String::new(),
        }
    }
}

/// Typed view of the Xray `env` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSettings {
    /// Configured variables, in source/edit order (JSON object keys are alphabetical on disk
    /// since this crate's `serde_json` does not enable `preserve_order` — same note as
    /// `dns_settings.rs`'s `hosts{}`).
    pub variables: Vec<EnvVarEntry>,
    /// `true` when a top-level `env` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `env` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (malformed section shape, non-string entry values).
    pub warnings: Vec<String>,
}

impl EnvSettings {
    /// Effective defaults when the `env` object is absent (display only).
    pub fn defaults() -> Self {
        Self {
            variables: Vec::new(),
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`EnvSettings`] from an optional sourced `env` section.
pub fn env_settings_from_section(section: Option<&SourcedSection<Value>>) -> EnvSettings {
    let Some(section) = section else {
        return EnvSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    let Some(object) = value.as_object() else {
        warnings.push("Malformed env object: expected a JSON object.".to_owned());
        return EnvSettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..EnvSettings::defaults()
        };
    };

    let mut variables: Vec<EnvVarEntry> = Vec::new();
    for (name, entry) in object {
        match entry {
            Value::String(text) => variables.push(EnvVarEntry {
                name: name.clone(),
                value: text.clone(),
            }),
            _ => warnings.push(format!(
                "`{name}` has an unsupported type; expected a string and was skipped."
            )),
        }
    }

    EnvSettings {
        variables,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
}

/// Applies typed settings onto an `env` JSON object. Unlike most other editors, this replaces
/// the object's contents wholesale rather than merging — `env` has no fixed fields and no
/// unrecognized-but-preserved sub-structure beyond the name→string entries [`EnvSettings::variables`]
/// already fully represents (a non-string entry is a spec violation the parser already dropped
/// with a warning, so there is nothing else to carry forward — same reasoning
/// `routing_settings.rs` documents for `rules[]`/`balancers[]`).
pub fn apply_env_settings_to_value(target: &mut Value, settings: &EnvSettings) -> ConfigModifyResult<()> {
    let object = match target {
        Value::Object(map) => map,
        Value::Null => {
            *target = Value::Object(Map::new());
            target.as_object_mut().expect("just created object")
        }
        _ => {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "env section must be a JSON object".to_owned(),
            ));
        }
    };

    object.clear();
    for var in &settings.variables {
        object.insert(var.name.clone(), Value::String(var.value.clone()));
    }

    Ok(())
}

/// Creates a fresh `env` object from settings (no unknown keys).
pub fn env_settings_to_new_value(settings: &EnvSettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_env_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn env_settings_change_summary(before: &EnvSettings, after: &EnvSettings) -> Vec<String> {
    if before.variables == after.variables {
        return Vec::new();
    }
    vec![format!(
        "env variables:\n{} → {} configured (see Preview changes for full detail)",
        before.variables.len(),
        after.variables.len()
    )]
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient (`rules.md`: "prefer compatibility over convenience") — variable name
/// *grammar* (e.g. the conventional `[A-Z_][A-Z0-9_]*` shape real environment variables follow)
/// is not enforced, since the documentation does not restrict custom names to it either. Only
/// structural requirements are checked: a non-empty, unique name per entry (JSON object keys must
/// be unique — a duplicate would silently collapse on save) and no control characters in either
/// the name or the value.
pub fn validate_env_settings(settings: &EnvSettings) -> ConfigModifyResult<()> {
    let mut seen_names = std::collections::HashSet::new();
    for (index, var) in settings.variables.iter().enumerate() {
        let position = index + 1;
        if var.name.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("env variable {position} must have a name"),
            ));
        }
        validate_control_chars(&var.name, &format!("env variable {position} name"))?;
        if !seen_names.insert(var.name.clone()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("duplicate env variable name: {}", var.name),
            ));
        }
        validate_control_chars(&var.value, &format!("env variable {position} ({}) value", var.name))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(value: Value) -> SourcedSection<Value> {
        SourcedSection::new("/etc/xray/config.json", value)
    }

    #[test]
    fn missing_env_object_uses_defaults() {
        let settings = env_settings_from_section(None);
        assert!(!settings.section_present);
        assert!(settings.variables.is_empty());
    }

    #[test]
    fn malformed_env_object_warns() {
        let settings = env_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed env object"))
        );
    }

    #[test]
    fn parses_string_variables() {
        let settings = env_settings_from_section(Some(&section(json!({
            "XRAY_LOCATION_ASSET": "/usr/local/share/xray",
            "XRAY_BUF_READV": "true"
        }))));
        assert_eq!(settings.variables.len(), 2);
        assert!(
            settings
                .variables
                .iter()
                .any(|v| v.name == "XRAY_LOCATION_ASSET" && v.value == "/usr/local/share/xray")
        );
        assert!(
            settings
                .variables
                .iter()
                .any(|v| v.name == "XRAY_BUF_READV" && v.value == "true")
        );
    }

    #[test]
    fn non_string_value_is_skipped_with_warning() {
        let settings = env_settings_from_section(Some(&section(json!({
            "XRAY_RAY_BUFFER_SIZE": 2,
            "XRAY_BUF_READV": "true"
        }))));
        assert_eq!(settings.variables.len(), 1);
        assert_eq!(settings.variables[0].name, "XRAY_BUF_READV");
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("XRAY_RAY_BUFFER_SIZE") && w.contains("unsupported type"))
        );
    }

    #[test]
    fn apply_replaces_object_contents_wholesale() {
        let mut value = json!({ "OLD_VAR": "old", "XRAY_BUF_READV": "false" });
        let settings = EnvSettings {
            variables: vec![EnvVarEntry {
                name: "XRAY_BUF_READV".to_owned(),
                value: "true".to_owned(),
            }],
            ..EnvSettings::defaults()
        };
        apply_env_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("OLD_VAR").is_none());
        assert_eq!(value["XRAY_BUF_READV"], "true");
        assert_eq!(value.as_object().unwrap().len(), 1);
    }

    #[test]
    fn empty_variables_produce_empty_object_not_removed_key() {
        let mut value = json!({ "OLD_VAR": "old" });
        let settings = EnvSettings::defaults();
        apply_env_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value, json!({}));
    }

    #[test]
    fn change_summary_reports_count_change() {
        let before = EnvSettings::defaults();
        let mut after = before.clone();
        after.variables.push(EnvVarEntry {
            name: "XRAY_BUF_READV".to_owned(),
            value: "true".to_owned(),
        });
        let summary = env_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 1);
        assert!(summary[0].contains("0 → 1"));
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = EnvSettings::defaults();
        assert!(env_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_accepts_defaults_and_valid_variables() {
        assert!(validate_env_settings(&EnvSettings::defaults()).is_ok());
        let settings = EnvSettings {
            variables: vec![
                EnvVarEntry {
                    name: "XRAY_BUF_READV".to_owned(),
                    value: "true".to_owned(),
                },
                EnvVarEntry {
                    name: "CUSTOM_FUTURE_VAR".to_owned(),
                    value: "anything".to_owned(),
                },
            ],
            ..EnvSettings::defaults()
        };
        assert!(validate_env_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_blank_name() {
        let mut settings = EnvSettings::defaults();
        settings.variables.push(EnvVarEntry::blank());
        let error = validate_env_settings(&settings).unwrap_err();
        assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn validation_rejects_duplicate_name() {
        let mut settings = EnvSettings::defaults();
        settings.variables.push(EnvVarEntry {
            name: "DUP".to_owned(),
            value: "1".to_owned(),
        });
        settings.variables.push(EnvVarEntry {
            name: "DUP".to_owned(),
            value: "2".to_owned(),
        });
        let error = validate_env_settings(&settings).unwrap_err();
        assert!(error.message().contains("duplicate env variable name"));
    }

    #[test]
    fn validation_rejects_control_characters_in_name_and_value() {
        let mut settings = EnvSettings::defaults();
        settings.variables.push(EnvVarEntry {
            name: "BAD\nNAME".to_owned(),
            value: "ok".to_owned(),
        });
        assert!(validate_env_settings(&settings).is_err());

        let mut settings = EnvSettings::defaults();
        settings.variables.push(EnvVarEntry {
            name: "OK_NAME".to_owned(),
            value: "bad\nvalue".to_owned(),
        });
        assert!(validate_env_settings(&settings).is_err());
    }

    #[test]
    fn known_env_vars_excludes_the_three_no_op_names() {
        assert!(!KNOWN_ENV_VARS.contains(&"XRAY_LOCATION_CONFIG"));
        assert!(!KNOWN_ENV_VARS.contains(&"XRAY_LOCATION_CONFDIR"));
        assert!(!KNOWN_ENV_VARS.contains(&"XRAY_JSON_STRICT"));
        assert!(KNOWN_ENV_VARS.contains(&"XRAY_LOCATION_ASSET"));
    }
}
