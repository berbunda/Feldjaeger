//! Typed editor model for the Xray top-level `geodata` object (Roadmap §2.1:57, GeoData row of
//! the Tier 2 §2.1 table).
//!
//! Field semantics follow the official documentation:
//! <https://xtls.github.io/ru/config/geodata.html>
//!
//! **Not to be confused with the existing GeoData page** (`app/geodata.rs`,
//! `gui/pages/geodata.rs`, Roadmap Tier 1) — that page performs live SSH file operations
//! (download/replace `geoip.dat`/`geosite.dat` on the remote host right now, via
//! `crate::remote::GeoDataManager`) and never touches the configuration file. This module edits
//! the *configuration*: a `geodata` object that tells the **running Xray-core process** to
//! periodically re-download/reload those same files on its own schedule (`cron`), optionally via
//! a specific outbound (`outbound`). Same config-file-vs-live-operation boundary already drawn
//! between API Settings/API Console, Stats Settings/Statistics, Metrics Settings/Metrics.
//!
//! `GeodataObject` has three fields, all optional at the top level:
//! - `cron` — standard 5-field cron expression (local timezone). Unset disables scheduling.
//! - `outbound` — outbound tag used when downloading; unset lets the routing module decide.
//! - `assets` — array of `{ url, file }` pairs to download and replace. Unset (or empty) means
//!   the scheduled reload only re-reads already-present files without downloading anything.
//!
//! `AssetObject.url`/`AssetObject.file` are both documented as required strings (`url` "должен
//! быть HTTPS URL"). Per `rules.md` ("prefer compatibility over convenience", the same stance
//! already taken for `metrics.listen`/`api.listen`/`version.min`/`.max`), this module does not
//! hard-enforce the HTTPS scheme — only blank values and control characters are rejected, plus a
//! duplicate-`file` check (two assets targeting the same on-disk filename is a real conflict, the
//! same class of check as `env`'s duplicate-name rejection). Unknown per-asset JSON keys are
//! preserved verbatim in [`GeodataAssetEntry::extra`], the same "never invent semantics for
//! what's already there" guarantee as `FakeDnsPoolEntry::extra`.

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// One `AssetObject` entry in `geodata.assets[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeodataAssetEntry {
    /// `url` — HTTPS URL to download the resource from. Required; blank is allowed to *exist* in
    /// memory (an incomplete entry loaded from disk stays visible & fixable) but
    /// [`validate_geodata_settings`] rejects saving with a blank value.
    pub url: String,
    /// `file` — resource filename to write (e.g. `geoip.dat`, `geosite.dat`), resolved within the
    /// resource directory. Required; same blank-is-visible-but-not-savable handling as `url`.
    pub file: String,
    /// Unrecognized JSON keys on this asset object, preserved verbatim and round-tripped on save.
    pub extra: Map<String, Value>,
}

impl GeodataAssetEntry {
    /// A blank asset entry for the GUI's "Add asset" action — blank `url`/`file` fail
    /// [`validate_geodata_settings`] until filled in, same idiom as `EnvVarEntry::blank()`.
    pub fn blank() -> Self {
        Self {
            url: String::new(),
            file: String::new(),
            extra: Map::new(),
        }
    }

    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let url = object
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let file = object
            .get("file")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let mut extra = object.clone();
        extra.remove("url");
        extra.remove("file");
        Some(Self { url, file, extra })
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("url".to_owned(), Value::String(self.url.clone()));
        object.insert("file".to_owned(), Value::String(self.file.clone()));
        for (key, value) in &self.extra {
            object.insert(key.clone(), value.clone());
        }
        Value::Object(object)
    }
}

/// Typed view of the Xray `geodata` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeodataSettings {
    /// `geodata.cron` — 5-field cron expression (local timezone). `None` omits the key (no
    /// scheduled reload/download).
    pub cron: Option<String>,
    /// `geodata.outbound` — outbound tag used when downloading assets. `None` omits the key (the
    /// routing module decides).
    pub outbound: Option<String>,
    /// `geodata.assets` — files to download and replace. Empty omits the key (scheduled reload,
    /// if `cron` is set, only re-reads already-present files without downloading).
    pub assets: Vec<GeodataAssetEntry>,
    /// `true` when a top-level `geodata` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `geodata` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (malformed section shape).
    pub warnings: Vec<String>,
}

impl GeodataSettings {
    /// Effective defaults when the `geodata` object is absent (display only) — Save is what
    /// actually creates the object, the same "enable by saving" UX as API/Metrics/Env/Version
    /// Settings.
    pub fn defaults() -> Self {
        Self {
            cron: None,
            outbound: None,
            assets: Vec::new(),
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`GeodataSettings`] from an optional sourced `geodata` section.
pub fn geodata_settings_from_section(section: Option<&SourcedSection<Value>>) -> GeodataSettings {
    let Some(section) = section else {
        return GeodataSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed geodata object: expected a JSON object.".to_owned());
        return GeodataSettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..GeodataSettings::defaults()
        };
    }

    let cron = string_field(value.get("cron"));
    let outbound = string_field(value.get("outbound"));

    let mut assets = Vec::new();
    match value.get("assets") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                match GeodataAssetEntry::from_value(item) {
                    Some(entry) => assets.push(entry),
                    None => warnings
                        .push("geodata.assets contains a non-object entry; skipped.".to_owned()),
                }
            }
        }
        Some(_) => warnings.push("geodata.assets is not an array; ignored.".to_owned()),
    }

    GeodataSettings {
        cron,
        outbound,
        assets,
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

/// Applies typed settings onto a `geodata` JSON object, preserving unknown keys.
pub fn apply_geodata_settings_to_value(
    target: &mut Value,
    settings: &GeodataSettings,
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
                "geodata section must be a JSON object".to_owned(),
            ));
        }
    };

    match &settings.cron {
        Some(cron) => {
            object.insert("cron".to_owned(), Value::String(cron.clone()));
        }
        None => {
            object.remove("cron");
        }
    }
    match &settings.outbound {
        Some(outbound) => {
            object.insert("outbound".to_owned(), Value::String(outbound.clone()));
        }
        None => {
            object.remove("outbound");
        }
    }
    if settings.assets.is_empty() {
        object.remove("assets");
    } else {
        let assets = settings
            .assets
            .iter()
            .map(GeodataAssetEntry::to_value)
            .collect();
        object.insert("assets".to_owned(), Value::Array(assets));
    }

    Ok(())
}

/// Creates a fresh `geodata` object from settings (no unknown keys).
pub fn geodata_settings_to_new_value(settings: &GeodataSettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_geodata_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn geodata_settings_change_summary(
    before: &GeodataSettings,
    after: &GeodataSettings,
) -> Vec<String> {
    let mut lines = Vec::new();

    if before.cron != after.cron {
        lines.push(format!(
            "cron:\n{} → {}",
            before.cron.as_deref().unwrap_or("(none)"),
            after.cron.as_deref().unwrap_or("(none)")
        ));
    }
    if before.outbound != after.outbound {
        lines.push(format!(
            "outbound:\n{} → {}",
            before.outbound.as_deref().unwrap_or("(none)"),
            after.outbound.as_deref().unwrap_or("(none)")
        ));
    }
    if before.assets.len() != after.assets.len() {
        lines.push(format!(
            "assets: {} → {} entries",
            before.assets.len(),
            after.assets.len()
        ));
    } else if before.assets != after.assets {
        lines.push("assets: entries changed".to_owned());
    }

    lines
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient — `rules.md`: "prefer compatibility over convenience". The documented
/// "`url` must be HTTPS" constraint is not re-validated here; only blank required fields,
/// duplicate `file` targets, and control characters are rejected.
pub fn validate_geodata_settings(settings: &GeodataSettings) -> ConfigModifyResult<()> {
    validate_optional_field(&settings.cron, "cron")?;
    validate_optional_field(&settings.outbound, "outbound")?;

    let mut seen_files = std::collections::HashSet::new();
    for (index, asset) in settings.assets.iter().enumerate() {
        if asset.url.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("assets[{index}].url must not be blank"),
            ));
        }
        if asset.file.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("assets[{index}].file must not be blank"),
            ));
        }
        validate_control_chars(&asset.url, &format!("assets[{index}].url"))?;
        validate_control_chars(&asset.file, &format!("assets[{index}].file"))?;
        if !seen_files.insert(asset.file.trim().to_owned()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("assets[{index}].file duplicates an earlier entry: {}", asset.file),
            ));
        }
    }

    Ok(())
}

fn validate_optional_field(value: &Option<String>, field: &str) -> ConfigModifyResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field} must not be blank — clear it instead to omit the key"),
        ));
    }
    validate_control_chars(value, field)
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
    fn missing_geodata_object_uses_defaults() {
        let settings = geodata_settings_from_section(None);
        assert!(!settings.section_present);
        assert_eq!(settings.cron, None);
        assert_eq!(settings.outbound, None);
        assert!(settings.assets.is_empty());
    }

    #[test]
    fn malformed_geodata_object_warns() {
        let settings = geodata_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed geodata object"))
        );
    }

    #[test]
    fn parses_cron_outbound_and_assets() {
        let settings = geodata_settings_from_section(Some(&section(json!({
            "cron": "0 4 * * *",
            "outbound": "proxy",
            "assets": [
                { "url": "https://example.com/geoip.dat", "file": "geoip.dat" },
                { "url": "https://example.com/geosite.dat", "file": "geosite.dat" }
            ]
        }))));
        assert_eq!(settings.cron.as_deref(), Some("0 4 * * *"));
        assert_eq!(settings.outbound.as_deref(), Some("proxy"));
        assert_eq!(settings.assets.len(), 2);
        assert_eq!(settings.assets[0].url, "https://example.com/geoip.dat");
        assert_eq!(settings.assets[0].file, "geoip.dat");
        assert!(settings.section_present);
    }

    #[test]
    fn preserves_unknown_asset_fields() {
        let settings = geodata_settings_from_section(Some(&section(json!({
            "assets": [
                { "url": "https://example.com/geoip.dat", "file": "geoip.dat", "futureField": 42 }
            ]
        }))));
        assert_eq!(settings.assets[0].extra.get("futureField"), Some(&json!(42)));
    }

    #[test]
    fn non_object_asset_entry_is_skipped_with_warning() {
        let settings = geodata_settings_from_section(Some(&section(json!({
            "assets": ["not-an-object"]
        }))));
        assert!(settings.assets.is_empty());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("non-object entry"))
        );
    }

    #[test]
    fn blank_cron_and_outbound_are_absent() {
        let settings = geodata_settings_from_section(Some(&section(json!({
            "cron": "  ",
            "outbound": ""
        }))));
        assert_eq!(settings.cron, None);
        assert_eq!(settings.outbound, None);
    }

    #[test]
    fn apply_preserves_unrelated_json_keys_and_round_trips_extra() {
        let mut value = json!({ "cron": "0 4 * * *", "futureField": 42, "nested": { "a": 1 } });
        let settings = GeodataSettings {
            cron: Some("30 3 * * 1".to_owned()),
            outbound: Some("proxy".to_owned()),
            assets: vec![GeodataAssetEntry {
                url: "https://example.com/geoip.dat".to_owned(),
                file: "geoip.dat".to_owned(),
                extra: Map::new(),
            }],
            section_present: true,
            source_file: None,
            warnings: Vec::new(),
        };
        apply_geodata_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
        assert_eq!(value["cron"], "30 3 * * 1");
        assert_eq!(value["outbound"], "proxy");
        assert_eq!(value["assets"][0]["url"], "https://example.com/geoip.dat");
        assert_eq!(value["assets"][0]["file"], "geoip.dat");
    }

    #[test]
    fn clearing_assets_removes_the_key() {
        let mut value = json!({ "assets": [{ "url": "u", "file": "f" }] });
        let settings = GeodataSettings {
            assets: Vec::new(),
            ..GeodataSettings::defaults()
        };
        apply_geodata_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("assets").is_none());
    }

    #[test]
    fn change_summary_reports_field_and_asset_changes() {
        let before = GeodataSettings::defaults();
        let mut after = before.clone();
        after.cron = Some("0 4 * * *".to_owned());
        after.assets.push(GeodataAssetEntry::blank());
        let summary = geodata_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 2);
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = GeodataSettings::defaults();
        assert!(geodata_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_accepts_defaults_and_full_settings() {
        assert!(validate_geodata_settings(&GeodataSettings::defaults()).is_ok());
        let settings = GeodataSettings {
            cron: Some("0 4 * * *".to_owned()),
            outbound: Some("proxy".to_owned()),
            assets: vec![GeodataAssetEntry {
                url: "https://example.com/geoip.dat".to_owned(),
                file: "geoip.dat".to_owned(),
                extra: Map::new(),
            }],
            ..GeodataSettings::defaults()
        };
        assert!(validate_geodata_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_blank_asset_url() {
        let mut settings = GeodataSettings::defaults();
        settings.assets.push(GeodataAssetEntry {
            url: String::new(),
            file: "geoip.dat".to_owned(),
            extra: Map::new(),
        });
        assert!(validate_geodata_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_blank_asset_file() {
        let mut settings = GeodataSettings::defaults();
        settings.assets.push(GeodataAssetEntry {
            url: "https://example.com/geoip.dat".to_owned(),
            file: String::new(),
            extra: Map::new(),
        });
        assert!(validate_geodata_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_duplicate_asset_file() {
        let mut settings = GeodataSettings::defaults();
        settings.assets.push(GeodataAssetEntry {
            url: "https://example.com/a.dat".to_owned(),
            file: "geoip.dat".to_owned(),
            extra: Map::new(),
        });
        settings.assets.push(GeodataAssetEntry {
            url: "https://example.com/b.dat".to_owned(),
            file: "geoip.dat".to_owned(),
            extra: Map::new(),
        });
        assert!(validate_geodata_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_control_characters() {
        let mut settings = GeodataSettings::defaults();
        settings.cron = Some("0 4 * * *\n".to_owned());
        assert!(validate_geodata_settings(&settings).is_err());
    }
}
