//! Parse Xray `log` section destinations from the loaded configuration model.
//!
//! Semantics follow the official LogObject documentation:
//! <https://xtls.github.io/en/config/log.html>
//!
//! - missing / empty `access` or `error` → stdout
//! - `"none"` → disabled
//! - any other non-empty string → file path (absolute paths preferred)
//! - `loglevel: "none"` forces both access and error streams off

use serde_json::Value;

use super::model::XrayLogDestination;
use crate::xray::config::SourcedSection;

/// Parsed view of the Xray `log` object relevant to runtime log viewing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayLogConfigView {
    /// Access log destination.
    pub access: XrayLogDestination,
    /// Error log destination.
    pub error: XrayLogDestination,
    /// Raw `loglevel` string when present.
    pub loglevel: Option<String>,
    /// File that contributed the `log` section, when known.
    pub source_file: Option<String>,
}

impl XrayLogConfigView {
    /// Defaults when no `log` section exists (both streams → stdout).
    pub fn defaults() -> Self {
        Self {
            access: XrayLogDestination::Stdout,
            error: XrayLogDestination::Stdout,
            loglevel: None,
            source_file: None,
        }
    }
}

/// Builds a [`XrayLogConfigView`] from an optional sourced `log` section.
pub fn log_config_view(section: Option<&SourcedSection<Value>>) -> XrayLogConfigView {
    let Some(section) = section else {
        return XrayLogConfigView::defaults();
    };

    let value = section.value();
    let loglevel = string_field(value, "loglevel");
    let force_disabled = loglevel
        .as_deref()
        .is_some_and(|level| level.eq_ignore_ascii_case("none"));

    let mut access = parse_destination(value.get("access"), "access");
    let mut error = parse_destination(value.get("error"), "error");

    if force_disabled {
        access = XrayLogDestination::Disabled;
        error = XrayLogDestination::Disabled;
    }

    XrayLogConfigView {
        access,
        error,
        loglevel,
        source_file: Some(section.source_file().to_owned()),
    }
}

fn parse_destination(value: Option<&Value>, field: &str) -> XrayLogDestination {
    let Some(value) = value else {
        return XrayLogDestination::Stdout;
    };

    match value {
        Value::Null => XrayLogDestination::Stdout,
        Value::String(raw) => parse_destination_string(raw),
        other => XrayLogDestination::Unsupported {
            raw: format!("{field}={other}"),
        },
    }
}

fn parse_destination_string(raw: &str) -> XrayLogDestination {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return XrayLogDestination::Stdout;
    }

    if trimmed.eq_ignore_ascii_case("none") {
        return XrayLogDestination::Disabled;
    }

    if trimmed.eq_ignore_ascii_case("stdout") {
        return XrayLogDestination::Stdout;
    }

    if trimmed.eq_ignore_ascii_case("stderr") {
        return XrayLogDestination::Stderr;
    }

    // Absolute Unix path — only form we will open remotely.
    if trimmed.starts_with('/') {
        return XrayLogDestination::File {
            path: trimmed.to_owned(),
        };
    }

    XrayLogDestination::Unsupported {
        raw: trimmed.to_owned(),
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(value: Value) -> SourcedSection<Value> {
        SourcedSection::new("/etc/xray/config.json", value)
    }

    #[test]
    fn missing_section_defaults_to_stdout() {
        let view = log_config_view(None);
        assert_eq!(view.access, XrayLogDestination::Stdout);
        assert_eq!(view.error, XrayLogDestination::Stdout);
    }

    #[test]
    fn none_disables_stream() {
        let view = log_config_view(Some(&section(json!({
            "access": "none",
            "error": "/var/log/xray/error.log"
        }))));
        assert_eq!(view.access, XrayLogDestination::Disabled);
        assert!(matches!(view.error, XrayLogDestination::File { .. }));
    }

    #[test]
    fn loglevel_none_disables_both() {
        let view = log_config_view(Some(&section(json!({
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log",
            "loglevel": "none"
        }))));
        assert_eq!(view.access, XrayLogDestination::Disabled);
        assert_eq!(view.error, XrayLogDestination::Disabled);
    }

    #[test]
    fn absolute_file_paths() {
        let view = log_config_view(Some(&section(json!({
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log"
        }))));
        assert_eq!(
            view.access,
            XrayLogDestination::File {
                path: "/var/log/xray/access.log".to_owned()
            }
        );
        assert_eq!(
            view.error,
            XrayLogDestination::File {
                path: "/var/log/xray/error.log".to_owned()
            }
        );
    }

    #[test]
    fn relative_path_unsupported() {
        let view = log_config_view(Some(&section(json!({
            "access": "access.log"
        }))));
        assert!(matches!(
            view.access,
            XrayLogDestination::Unsupported { raw } if raw == "access.log"
        ));
    }

    #[test]
    fn empty_string_is_stdout() {
        let view = log_config_view(Some(&section(json!({
            "access": "",
            "error": "  "
        }))));
        assert_eq!(view.access, XrayLogDestination::Stdout);
        assert_eq!(view.error, XrayLogDestination::Stdout);
    }

    #[test]
    fn does_not_hardcode_common_paths_when_absent() {
        let view = log_config_view(Some(&section(json!({ "loglevel": "warning" }))));
        assert_eq!(view.access, XrayLogDestination::Stdout);
        assert_eq!(view.error, XrayLogDestination::Stdout);
        assert_ne!(view.access.display_source(), "/var/log/xray/access.log");
        assert_ne!(view.error.display_source(), "/var/log/xray/error.log");
    }
}
