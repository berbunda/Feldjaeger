//! Typed editor model for the Xray top-level `log` object.
//!
//! Field semantics follow the official LogObject documentation:
//! <https://xtls.github.io/en/config/log.html>
//!
//! This module is for configuration *editing*. Runtime log *viewing*
//! (`crate::xray::logs`) may apply additional viewer-only rules
//! (for example `loglevel: none` forcing streams off).

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// Known JSON keys inside the `log` object.
const KNOWN_KEYS: &[&str] = &["access", "error", "loglevel", "dnsLog", "maskAddress"];

/// Access / error log destination for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOutput {
    /// Missing or empty string → stdout.
    Stdout,
    /// Absolute or other file path string.
    File(String),
    /// Explicit `"none"`.
    Disabled,
    /// Unsupported existing value preserved verbatim.
    Unknown(String),
}

impl LogOutput {
    /// Short display label for view mode.
    pub fn display_label(&self) -> String {
        match self {
            Self::Stdout => "Standard Output".to_owned(),
            Self::File(path) => format!("File ({path})"),
            Self::Disabled => "Disabled".to_owned(),
            Self::Unknown(raw) => format!("Unknown ({raw})"),
        }
    }

    /// Compact change-summary label.
    pub fn summary_label(&self) -> String {
        match self {
            Self::Stdout => "stdout".to_owned(),
            Self::File(path) => path.clone(),
            Self::Disabled => "disabled".to_owned(),
            Self::Unknown(raw) => format!("unknown:{raw}"),
        }
    }

    fn parse(value: Option<&Value>) -> Self {
        let Some(value) = value else {
            return Self::Stdout;
        };
        match value {
            Value::Null => Self::Stdout,
            Value::String(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    Self::Stdout
                } else if trimmed.eq_ignore_ascii_case("none") {
                    Self::Disabled
                } else if trimmed.starts_with('/') {
                    Self::File(trimmed.to_owned())
                } else {
                    Self::Unknown(trimmed.to_owned())
                }
            }
            other => Self::Unknown(other.to_string()),
        }
    }

    fn write_to(&self, object: &mut Map<String, Value>, key: &str) {
        match self {
            Self::Stdout => {
                object.remove(key);
            }
            Self::File(path) => {
                object.insert(key.to_owned(), Value::String(path.clone()));
            }
            Self::Disabled => {
                object.insert(key.to_owned(), Value::String("none".to_owned()));
            }
            Self::Unknown(raw) => {
                object.insert(key.to_owned(), Value::String(raw.clone()));
            }
        }
    }
}

/// Error-log verbosity (`loglevel`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    None,
    /// Unsupported existing value preserved verbatim.
    Unknown(String),
}

impl LogLevel {
    /// Effective default when the field is omitted (Xray default).
    pub fn default_effective() -> Self {
        Self::Warning
    }

    /// Stable wire value for supported levels.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::None => "none",
            Self::Unknown(raw) => raw.as_str(),
        }
    }

    /// Display label for UI.
    pub fn display_label(&self) -> String {
        match self {
            Self::Debug => "Debug".to_owned(),
            Self::Info => "Info".to_owned(),
            Self::Warning => "Warning".to_owned(),
            Self::Error => "Error".to_owned(),
            Self::None => "None".to_owned(),
            Self::Unknown(raw) => format!("Unknown ({raw})"),
        }
    }

    fn parse(value: Option<&Value>) -> Self {
        let Some(value) = value else {
            return Self::default_effective();
        };
        match value {
            Value::Null => Self::default_effective(),
            Value::String(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Self::default_effective();
                }
                match trimmed.to_ascii_lowercase().as_str() {
                    "debug" => Self::Debug,
                    "info" => Self::Info,
                    "warning" | "warn" => Self::Warning,
                    "error" => Self::Error,
                    "none" => Self::None,
                    _ => Self::Unknown(trimmed.to_owned()),
                }
            }
            other => Self::Unknown(other.to_string()),
        }
    }

    fn write_to(&self, object: &mut Map<String, Value>) {
        match self {
            Self::Unknown(raw) => {
                object.insert("loglevel".to_owned(), Value::String(raw.clone()));
            }
            other => {
                object.insert(
                    "loglevel".to_owned(),
                    Value::String(other.as_str().to_owned()),
                );
            }
        }
    }
}

/// IP masking (`maskAddress`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskAddress {
    /// Empty / omitted.
    Disabled,
    Quarter,
    Half,
    Full,
    /// Custom `/v4+/v6` format (official flexible mask).
    Custom(String),
    /// Unsupported existing value preserved verbatim.
    Unknown(String),
}

impl MaskAddress {
    /// Display label for UI.
    pub fn display_label(&self) -> String {
        match self {
            Self::Disabled => "Disabled".to_owned(),
            Self::Quarter => "Quarter".to_owned(),
            Self::Half => "Half".to_owned(),
            Self::Full => "Full".to_owned(),
            Self::Custom(raw) => format!("Custom ({raw})"),
            Self::Unknown(raw) => format!("Unknown ({raw})"),
        }
    }

    /// Compact summary label.
    pub fn summary_label(&self) -> String {
        match self {
            Self::Disabled => "disabled".to_owned(),
            Self::Quarter => "quarter".to_owned(),
            Self::Half => "half".to_owned(),
            Self::Full => "full".to_owned(),
            Self::Custom(raw) => raw.clone(),
            Self::Unknown(raw) => format!("unknown:{raw}"),
        }
    }

    /// Wire string written to JSON, or `None` to omit the field.
    pub fn to_wire(&self) -> Option<&str> {
        match self {
            Self::Disabled => None,
            Self::Quarter => Some("quarter"),
            Self::Half => Some("half"),
            Self::Full => Some("full"),
            Self::Custom(raw) | Self::Unknown(raw) => Some(raw.as_str()),
        }
    }

    fn parse(value: Option<&Value>) -> Self {
        let Some(value) = value else {
            return Self::Disabled;
        };
        match value {
            Value::Null => Self::Disabled,
            Value::String(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    Self::Disabled
                } else {
                    match trimmed.to_ascii_lowercase().as_str() {
                        "quarter" => Self::Quarter,
                        "half" => Self::Half,
                        "full" => Self::Full,
                        _ if is_custom_mask_format(trimmed) => Self::Custom(trimmed.to_owned()),
                        _ => Self::Unknown(trimmed.to_owned()),
                    }
                }
            }
            other => Self::Unknown(other.to_string()),
        }
    }

    fn write_to(&self, object: &mut Map<String, Value>) {
        match self.to_wire() {
            Some(wire) => {
                object.insert("maskAddress".to_owned(), Value::String(wire.to_owned()));
            }
            None => {
                object.remove("maskAddress");
            }
        }
    }
}

/// Typed view of the Xray `log` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSettings {
    /// Access log destination.
    pub access: LogOutput,
    /// Error log destination.
    pub error: LogOutput,
    /// Error log level (`loglevel`).
    pub log_level: LogLevel,
    /// Whether DNS query logging is enabled (`dnsLog`).
    pub dns_log: bool,
    /// IP address masking (`maskAddress`).
    pub mask_address: MaskAddress,
    /// `true` when a top-level `log` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `log` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (unknown values, malformed optional fields).
    pub warnings: Vec<String>,
}

impl LogSettings {
    /// Effective defaults when the `log` object is absent (display only).
    pub fn defaults() -> Self {
        Self {
            access: LogOutput::Stdout,
            error: LogOutput::Stdout,
            log_level: LogLevel::default_effective(),
            dns_log: false,
            mask_address: MaskAddress::Disabled,
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }

    /// Returns `true` when any unknown enum variant is present.
    pub fn has_unknown_values(&self) -> bool {
        matches!(self.access, LogOutput::Unknown(_))
            || matches!(self.error, LogOutput::Unknown(_))
            || matches!(self.log_level, LogLevel::Unknown(_))
            || matches!(self.mask_address, MaskAddress::Unknown(_))
    }
}

/// Builds [`LogSettings`] from an optional sourced `log` section.
pub fn log_settings_from_section(section: Option<&SourcedSection<Value>>) -> LogSettings {
    let Some(section) = section else {
        return LogSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed log object: expected a JSON object.".to_owned());
        let mut settings = LogSettings::defaults();
        settings.section_present = true;
        settings.source_file = Some(section.source_file().to_owned());
        settings.warnings = warnings;
        return settings;
    }

    let access = LogOutput::parse(value.get("access"));
    let error = LogOutput::parse(value.get("error"));
    let log_level = LogLevel::parse(value.get("loglevel"));
    let dns_log = parse_dns_log(value.get("dnsLog"), &mut warnings);
    let mask_address = MaskAddress::parse(value.get("maskAddress"));

    if let LogOutput::Unknown(raw) = &access {
        warnings.push(format!("Unknown access log value: {raw}"));
    }
    if let LogOutput::Unknown(raw) = &error {
        warnings.push(format!("Unknown error log value: {raw}"));
    }
    if let LogLevel::Unknown(raw) = &log_level {
        warnings.push(format!("Unknown log level: {raw}"));
    }
    if let MaskAddress::Unknown(raw) = &mask_address {
        warnings.push(format!("Unknown maskAddress value: {raw}"));
    }

    LogSettings {
        access,
        error,
        log_level,
        dns_log,
        mask_address,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
}

/// Applies typed settings onto a `log` JSON object, preserving unknown keys.
pub fn apply_log_settings_to_value(target: &mut Value, settings: &LogSettings) -> ConfigModifyResult<()> {
    let object = match target {
        Value::Object(map) => map,
        Value::Null => {
            *target = Value::Object(Map::new());
            target.as_object_mut().expect("just created object")
        }
        _ => {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::MalformedLogObject,
                "log section must be a JSON object".to_owned(),
            ));
        }
    };

    settings.access.write_to(object, "access");
    settings.error.write_to(object, "error");
    settings.log_level.write_to(object);
    object.insert("dnsLog".to_owned(), Value::Bool(settings.dns_log));
    settings.mask_address.write_to(object);

    // Drop accidental non-object pollution is already handled; unknown keys stay.
    let _ = KNOWN_KEYS;
    Ok(())
}

/// Creates a fresh `log` object from settings (no unknown keys).
pub fn log_settings_to_new_value(settings: &LogSettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_log_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn log_settings_change_summary(before: &LogSettings, after: &LogSettings) -> Vec<String> {
    let mut lines = Vec::new();

    if before.access != after.access {
        lines.push(format!(
            "Access log:\n{} → {}",
            before.access.summary_label(),
            after.access.summary_label()
        ));
    }
    if before.error != after.error {
        lines.push(format!(
            "Error log:\n{} → {}",
            before.error.summary_label(),
            after.error.summary_label()
        ));
    }
    if before.log_level.as_str() != after.log_level.as_str()
        || std::mem::discriminant(&before.log_level) != std::mem::discriminant(&after.log_level)
    {
        lines.push(format!(
            "Error log level:\n{} → {}",
            before.log_level.as_str(),
            after.log_level.as_str()
        ));
    }
    if before.dns_log != after.dns_log {
        lines.push(format!(
            "DNS logging:\n{} → {}",
            if before.dns_log { "enabled" } else { "disabled" },
            if after.dns_log { "enabled" } else { "disabled" }
        ));
    }
    if before.mask_address != after.mask_address {
        lines.push(format!(
            "IP masking:\n{} → {}",
            before.mask_address.summary_label(),
            after.mask_address.summary_label()
        ));
    }

    lines
}

/// Validates draft settings before they are written remotely.
pub fn validate_log_settings(settings: &LogSettings) -> ConfigModifyResult<()> {
    validate_output_path(&settings.access, "access")?;
    validate_output_path(&settings.error, "error")?;
    validate_mask_for_save(&settings.mask_address)?;
    Ok(())
}

fn validate_output_path(output: &LogOutput, field: &str) -> ConfigModifyResult<()> {
    match output {
        LogOutput::Stdout | LogOutput::Disabled | LogOutput::Unknown(_) => Ok(()),
        LogOutput::File(path) => {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::InvalidFilePath,
                    format!("{field} file path must not be empty"),
                ));
            }
            if trimmed.contains('\0') {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::InvalidFilePath,
                    format!("{field} file path must not contain null bytes"),
                ));
            }
            if !trimmed.starts_with('/') {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::InvalidFilePath,
                    format!("{field} file path must be an absolute Linux path"),
                ));
            }
            if trimmed.contains('\n') || trimmed.contains('\r') {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::InvalidFilePath,
                    format!("{field} file path must not contain newlines"),
                ));
            }
            Ok(())
        }
    }
}

fn validate_mask_for_save(mask: &MaskAddress) -> ConfigModifyResult<()> {
    match mask {
        MaskAddress::Disabled | MaskAddress::Quarter | MaskAddress::Half | MaskAddress::Full => {
            Ok(())
        }
        MaskAddress::Unknown(_) => Ok(()), // preserved until the user changes it
        MaskAddress::Custom(raw) => validate_custom_mask_format(raw),
    }
}

/// Returns `true` when `raw` matches the official custom mask grammar `/v4+/v6`.
pub fn is_custom_mask_format(raw: &str) -> bool {
    parse_custom_mask(raw).is_ok()
}

/// Validates a custom `maskAddress` value against the official Xray format.
///
/// Format: `/N+/M` where `N` is IPv4 prefix length (0–32, divisible by 8)
/// and `M` is IPv6 prefix length (0–128). Matches `ParseMaskAddress` in Xray-core.
pub fn validate_custom_mask_format(raw: &str) -> ConfigModifyResult<()> {
    parse_custom_mask(raw).map(|_| ())
}

fn parse_custom_mask(raw: &str) -> ConfigModifyResult<(u32, u32)> {
    let trimmed = raw.trim();
    let parts: Vec<&str> = trimmed.split('+').collect();
    if parts.len() != 2 {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::InvalidMaskFormat,
            "custom maskAddress must look like /16+/32".to_owned(),
        ));
    }

    let v4 = parse_mask_part(parts[0], true)?;
    let v6 = parse_mask_part(parts[1], false)?;

    if !(0..=32).contains(&v4) || v4 % 8 != 0 {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::InvalidMaskFormat,
            "IPv4 mask must be divisible by 8 and between 0-32".to_owned(),
        ));
    }
    if !(0..=128).contains(&v6) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::InvalidMaskFormat,
            "IPv6 mask must be between 0-128".to_owned(),
        ));
    }

    Ok((v4, v6))
}

fn parse_mask_part(part: &str, _ipv4: bool) -> ConfigModifyResult<u32> {
    let stripped = part.strip_prefix('/').unwrap_or(part);
    if stripped.is_empty() || !stripped.chars().all(|c| c.is_ascii_digit()) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::InvalidMaskFormat,
            "custom maskAddress must look like /16+/32".to_owned(),
        ));
    }
    stripped.parse::<u32>().map_err(|_| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::InvalidMaskFormat,
            "custom maskAddress must look like /16+/32".to_owned(),
        )
    })
}

fn parse_dns_log(value: Option<&Value>, warnings: &mut Vec<String>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(other) => {
            warnings.push(format!("Unsupported dnsLog value: {other}; treating as disabled"));
            false
        }
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
    fn missing_log_object_uses_defaults() {
        let settings = log_settings_from_section(None);
        assert!(!settings.section_present);
        assert_eq!(settings.access, LogOutput::Stdout);
        assert_eq!(settings.error, LogOutput::Stdout);
        assert_eq!(settings.log_level, LogLevel::Warning);
        assert!(!settings.dns_log);
        assert_eq!(settings.mask_address, MaskAddress::Disabled);
    }

    #[test]
    fn access_modes() {
        assert_eq!(
            log_settings_from_section(Some(&section(json!({})))).access,
            LogOutput::Stdout
        );
        assert_eq!(
            log_settings_from_section(Some(&section(json!({ "access": "" })))).access,
            LogOutput::Stdout
        );
        assert_eq!(
            log_settings_from_section(Some(&section(json!({ "access": "none" })))).access,
            LogOutput::Disabled
        );
        assert_eq!(
            log_settings_from_section(Some(&section(
                json!({ "access": "/var/log/xray/access.log" })
            )))
            .access,
            LogOutput::File("/var/log/xray/access.log".to_owned())
        );
    }

    #[test]
    fn error_modes() {
        assert_eq!(
            log_settings_from_section(Some(&section(json!({ "error": "none" })))).error,
            LogOutput::Disabled
        );
        assert_eq!(
            log_settings_from_section(Some(&section(
                json!({ "error": "/var/log/xray/error.log" })
            )))
            .error,
            LogOutput::File("/var/log/xray/error.log".to_owned())
        );
    }

    #[test]
    fn every_log_level() {
        for (raw, expected) in [
            ("debug", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("warning", LogLevel::Warning),
            ("error", LogLevel::Error),
            ("none", LogLevel::None),
        ] {
            let settings =
                log_settings_from_section(Some(&section(json!({ "loglevel": raw }))));
            assert_eq!(settings.log_level, expected);
        }
    }

    #[test]
    fn dns_log_bool() {
        assert!(
            log_settings_from_section(Some(&section(json!({ "dnsLog": true })))).dns_log
        );
        assert!(
            !log_settings_from_section(Some(&section(json!({ "dnsLog": false })))).dns_log
        );
    }

    #[test]
    fn every_mask_mode() {
        assert_eq!(
            log_settings_from_section(Some(&section(json!({})))).mask_address,
            MaskAddress::Disabled
        );
        assert_eq!(
            log_settings_from_section(Some(&section(json!({ "maskAddress": "quarter" }))))
                .mask_address,
            MaskAddress::Quarter
        );
        assert_eq!(
            log_settings_from_section(Some(&section(json!({ "maskAddress": "half" }))))
                .mask_address,
            MaskAddress::Half
        );
        assert_eq!(
            log_settings_from_section(Some(&section(json!({ "maskAddress": "full" }))))
                .mask_address,
            MaskAddress::Full
        );
        assert_eq!(
            log_settings_from_section(Some(&section(json!({ "maskAddress": "/16+/32" }))))
                .mask_address,
            MaskAddress::Custom("/16+/32".to_owned())
        );
    }

    #[test]
    fn invalid_custom_mask_rejected() {
        assert!(validate_custom_mask_format("/16+/32").is_ok());
        assert!(validate_custom_mask_format("/12+/32").is_err());
        assert!(validate_custom_mask_format("not-a-mask").is_err());
        assert!(validate_custom_mask_format("/16+").is_err());
    }

    #[test]
    fn unknown_log_level_preserved() {
        let settings =
            log_settings_from_section(Some(&section(json!({ "loglevel": "verbose" }))));
        assert_eq!(settings.log_level, LogLevel::Unknown("verbose".to_owned()));
        assert!(settings
            .warnings
            .iter()
            .any(|w| w.contains("Unknown log level: verbose")));
    }

    #[test]
    fn unknown_mask_preserved() {
        let settings =
            log_settings_from_section(Some(&section(json!({ "maskAddress": "weird" }))));
        assert_eq!(
            settings.mask_address,
            MaskAddress::Unknown("weird".to_owned())
        );
    }

    #[test]
    fn unknown_fields_preserved_on_apply() {
        let mut value = json!({
            "loglevel": "warning",
            "futureField": 42,
            "nested": { "a": 1 }
        });
        let settings = LogSettings {
            access: LogOutput::File("/var/log/xray/access.log".to_owned()),
            error: LogOutput::Stdout,
            log_level: LogLevel::Info,
            dns_log: true,
            mask_address: MaskAddress::Half,
            section_present: true,
            source_file: None,
            warnings: Vec::new(),
        };
        apply_log_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
        assert_eq!(value["access"], "/var/log/xray/access.log");
        assert_eq!(value["loglevel"], "info");
        assert_eq!(value["dnsLog"], true);
        assert_eq!(value["maskAddress"], "half");
        assert!(value.get("error").is_none());
    }

    #[test]
    fn invalid_file_path_rejected() {
        let settings = LogSettings {
            access: LogOutput::File("relative.log".to_owned()),
            ..LogSettings::defaults()
        };
        let err = validate_log_settings(&settings).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::InvalidFilePath);
    }

    #[test]
    fn change_summary_only_related_fields() {
        let before = LogSettings::defaults();
        let mut after = before.clone();
        after.access = LogOutput::File("/var/log/xray/access.log".to_owned());
        after.log_level = LogLevel::Info;
        after.dns_log = true;
        let summary = log_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 3);
        assert!(summary[0].contains("Access log"));
        assert!(summary[1].contains("Error log level"));
        assert!(summary[2].contains("DNS logging"));
    }

    #[test]
    fn loglevel_none_does_not_force_access_disabled_in_editor() {
        let settings = log_settings_from_section(Some(&section(json!({
            "access": "/var/log/xray/access.log",
            "loglevel": "none"
        }))));
        assert_eq!(
            settings.access,
            LogOutput::File("/var/log/xray/access.log".to_owned())
        );
        assert_eq!(settings.log_level, LogLevel::None);
    }
}
