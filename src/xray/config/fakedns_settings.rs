//! Typed editor model for the Xray top-level `fakedns` value (Roadmap §2.1:47).
//!
//! Field semantics follow the official FakeDnsObject documentation:
//! <https://xtls.github.io/en/config/fakedns.html>
//!
//! This is the *editing* counterpart to the read-only [`super::FakeDnsSummary`] used elsewhere in
//! the crate (e.g. `LoadedConfigSnapshot::Loaded.fakedns`); `FakeDnsSummary` is left untouched.
//! This module covers both documented `FakeDnsObject` fields (`ipPool`, `poolSize`) and the
//! top-level single-object-or-array shape: `fakedns` may be one `FakeDnsObject`, or an array of
//! them (multiple simultaneous pools, e.g. one IPv4 + one IPv6 range). Unlike `log`/`api`/`dns`,
//! this section's root JSON value is not always an object, so [`FakeDnsSettings`] always owns the
//! whole value rather than mutating an existing object in place — [`apply_fakedns_settings_to_value`]
//! picks the object form when there is exactly one pool and the array form otherwise (0 or 2+),
//! the same "collapse to the simplest equivalent shape" rule `dns_settings.rs` already applies to
//! `servers[]`/`hosts{}`.
//!
//! Per-pool unknown JSON keys are preserved verbatim in [`FakeDnsPoolEntry::extra`] and merged back
//! in on save, the same "never invent semantics for what's already there" guarantee every other
//! section editor in this crate provides.

use std::net::IpAddr;

use serde_json::{Map, Number, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// One `FakeDnsObject` pool entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsPoolEntry {
    /// `ipPool` — CIDR block FakeDNS allocates addresses from. Required; empty is allowed to
    /// *exist* in memory (an incomplete entry loaded from disk stays visible & fixable) but
    /// [`validate_fakedns_settings`] rejects saving with a blank or unparsable value.
    pub ip_pool: String,
    /// `poolSize` — maximum domain-IP mappings retained (LRU eviction beyond this). `None` omits
    /// the key, accepting Xray's own built-in default (documented as 65535).
    pub pool_size: Option<u64>,
    /// Unrecognized JSON keys on this pool object, preserved verbatim and round-tripped on save.
    pub extra: Map<String, Value>,
}

impl FakeDnsPoolEntry {
    /// A blank pool entry for the GUI's "Add pool" action — an empty `ipPool` fails
    /// [`validate_fakedns_settings`] until the user fills it in, same idiom as
    /// `DnsServerEntry::blank()`/`DnsHostEntry::blank()`.
    pub fn blank() -> Self {
        Self {
            ip_pool: String::new(),
            pool_size: None,
            extra: Map::new(),
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("ipPool".to_owned(), Value::String(self.ip_pool.clone()));
        if let Some(size) = self.pool_size {
            object.insert("poolSize".to_owned(), Value::Number(Number::from(size)));
        }
        for (key, value) in &self.extra {
            object.entry(key.clone()).or_insert_with(|| value.clone());
        }
        Value::Object(object)
    }
}

/// Typed view of the Xray `fakedns` value for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsSettings {
    /// Configured pools, in source/edit order. Empty means no pool is configured (an empty JSON
    /// array is a structurally valid, if unusual, `fakedns` value — the read side already
    /// tolerates it).
    pub pools: Vec<FakeDnsPoolEntry>,
    /// `true` when a top-level `fakedns` value existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `fakedns` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (unknown values, malformed optional fields).
    pub warnings: Vec<String>,
}

impl FakeDnsSettings {
    /// Effective defaults when no `fakedns` value is present (display only).
    pub fn defaults() -> Self {
        Self {
            pools: Vec::new(),
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`FakeDnsSettings`] from an optional sourced `fakedns` section.
pub fn fakedns_settings_from_section(section: Option<&SourcedSection<Value>>) -> FakeDnsSettings {
    let Some(section) = section else {
        return FakeDnsSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    let pools = match value {
        Value::Object(object) => vec![pool_from_object(object, &mut warnings, None)],
        Value::Array(items) => {
            if items.is_empty() {
                warnings.push("FakeDNS pool array is empty.".to_owned());
            }
            items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| match item {
                    Value::Object(object) => {
                        Some(pool_from_object(object, &mut warnings, Some(index + 1)))
                    }
                    _ => {
                        warnings.push(format!(
                            "FakeDNS pool #{} has an unsupported shape and was skipped.",
                            index + 1
                        ));
                        None
                    }
                })
                .collect()
        }
        _ => {
            warnings.push(
                "Malformed fakedns section: expected an object or an array of objects.".to_owned(),
            );
            Vec::new()
        }
    };

    FakeDnsSettings {
        pools,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
}

fn pool_from_object(
    object: &Map<String, Value>,
    warnings: &mut Vec<String>,
    pool_number: Option<usize>,
) -> FakeDnsPoolEntry {
    let prefix = match pool_number {
        Some(number) => format!("FakeDNS pool #{number}: "),
        None => String::new(),
    };

    let ip_pool = match object.get("ipPool") {
        None => {
            warnings.push(format!("{prefix}`ipPool` is missing."));
            String::new()
        }
        Some(Value::String(text)) => text.clone(),
        Some(_) => {
            warnings.push(format!("{prefix}`ipPool` has an unsupported type."));
            String::new()
        }
    };

    let pool_size = match object.get("poolSize") {
        None => None,
        Some(value) => match u64_from_value(value) {
            Some(size) => Some(size),
            None => {
                warnings.push(format!("{prefix}`poolSize` has an unsupported type."));
                None
            }
        },
    };

    let extra: Map<String, Value> = object
        .iter()
        .filter(|(key, _)| key.as_str() != "ipPool" && key.as_str() != "poolSize")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    FakeDnsPoolEntry {
        ip_pool,
        pool_size,
        extra,
    }
}

fn u64_from_value(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    if let Some(number) = value.as_i64() {
        return u64::try_from(number).ok();
    }
    value.as_str()?.parse().ok()
}

/// Replaces `target` wholesale with the JSON form of `settings.pools`: a single object when there
/// is exactly one pool, an array otherwise (0 or 2+) — the simplest shape equivalent to what the
/// user configured, matching how a hand-written config typically looks.
pub fn apply_fakedns_settings_to_value(target: &mut Value, settings: &FakeDnsSettings) -> ConfigModifyResult<()> {
    *target = match settings.pools.as_slice() {
        [only] => only.to_value(),
        many => Value::Array(many.iter().map(FakeDnsPoolEntry::to_value).collect()),
    };
    Ok(())
}

/// Creates a fresh `fakedns` value from settings.
pub fn fakedns_settings_to_new_value(settings: &FakeDnsSettings) -> Value {
    let mut value = Value::Null;
    let _ = apply_fakedns_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn fakedns_settings_change_summary(before: &FakeDnsSettings, after: &FakeDnsSettings) -> Vec<String> {
    if before.pools == after.pools {
        return Vec::new();
    }
    vec![format!(
        "FakeDNS pools:\n{} → {} configured (see Preview changes for full detail)",
        before.pools.len(),
        after.pools.len()
    )]
}

/// Validates draft settings before they are written remotely.
///
/// Lenient (`rules.md`: "prefer compatibility over convenience") beyond the one thing that's
/// unambiguous: `ipPool` must be a real CIDR block, since FakeDNS cannot allocate addresses from
/// anything else. `poolSize` is intentionally not cross-checked against the pool's address
/// capacity — that's a runtime constraint Xray itself enforces (and `xray run -test` already runs
/// after every save), not something worth re-implementing here.
pub fn validate_fakedns_settings(settings: &FakeDnsSettings) -> ConfigModifyResult<()> {
    for (index, pool) in settings.pools.iter().enumerate() {
        let position = index + 1;
        if pool.ip_pool.contains(['\n', '\r', '\0']) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("FakeDNS pool {position}: ipPool must not contain control characters"),
            ));
        }
        validate_cidr(&pool.ip_pool, position)?;
    }
    Ok(())
}

fn validate_cidr(ip_pool: &str, position: usize) -> ConfigModifyResult<()> {
    let trimmed = ip_pool.trim();
    let Some((address_text, prefix_text)) = trimmed.split_once('/') else {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("FakeDNS pool {position}: ipPool must be a CIDR block (e.g. 198.18.0.0/15)"),
        ));
    };
    let address: IpAddr = address_text.parse().map_err(|_| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("FakeDNS pool {position}: `{address_text}` is not a valid IP address"),
        )
    })?;
    let prefix: u32 = prefix_text.parse().map_err(|_| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("FakeDNS pool {position}: `{prefix_text}` is not a valid CIDR prefix length"),
        )
    })?;
    let max_bits = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_bits {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("FakeDNS pool {position}: CIDR prefix must be between 0 and {max_bits}"),
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

    fn pool(ip_pool: &str, pool_size: Option<u64>) -> FakeDnsPoolEntry {
        FakeDnsPoolEntry {
            ip_pool: ip_pool.to_owned(),
            pool_size,
            extra: Map::new(),
        }
    }

    #[test]
    fn missing_section_uses_defaults() {
        let settings = fakedns_settings_from_section(None);
        assert!(!settings.section_present);
        assert!(settings.pools.is_empty());
    }

    #[test]
    fn single_object_form_parses_one_pool() {
        let settings = fakedns_settings_from_section(Some(&section(json!({
            "ipPool": "198.18.0.0/15",
            "poolSize": 65535
        }))));
        assert_eq!(settings.pools.len(), 1);
        assert_eq!(settings.pools[0].ip_pool, "198.18.0.0/15");
        assert_eq!(settings.pools[0].pool_size, Some(65535));
        assert!(settings.warnings.is_empty());
    }

    #[test]
    fn array_form_parses_multiple_pools() {
        let settings = fakedns_settings_from_section(Some(&section(json!([
            { "ipPool": "198.18.0.0/15", "poolSize": 65535 },
            { "ipPool": "fc00::/18", "poolSize": 65535 }
        ]))));
        assert_eq!(settings.pools.len(), 2);
        assert_eq!(settings.pools[1].ip_pool, "fc00::/18");
    }

    #[test]
    fn empty_array_warns_but_is_not_fatal() {
        let settings = fakedns_settings_from_section(Some(&section(json!([]))));
        assert!(settings.pools.is_empty());
        assert!(settings.warnings.iter().any(|w| w.contains("empty")));
    }

    #[test]
    fn unsupported_top_level_shape_warns() {
        let settings = fakedns_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.pools.is_empty());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed fakedns section"))
        );
    }

    #[test]
    fn unsupported_array_item_shape_is_skipped_with_warning() {
        let settings = fakedns_settings_from_section(Some(&section(json!([
            { "ipPool": "198.18.0.0/15" },
            "not-an-object"
        ]))));
        assert_eq!(settings.pools.len(), 1);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("unsupported shape"))
        );
    }

    #[test]
    fn missing_ip_pool_is_kept_with_warning() {
        let settings = fakedns_settings_from_section(Some(&section(json!({ "poolSize": 100 }))));
        assert_eq!(settings.pools.len(), 1);
        assert_eq!(settings.pools[0].ip_pool, "");
        assert!(settings.warnings.iter().any(|w| w.contains("`ipPool`")));
    }

    #[test]
    fn missing_pool_size_is_none_without_warning() {
        let settings =
            fakedns_settings_from_section(Some(&section(json!({ "ipPool": "198.18.0.0/15" }))));
        assert_eq!(settings.pools[0].pool_size, None);
        assert!(settings.warnings.is_empty());
    }

    #[test]
    fn unknown_pool_fields_are_preserved_as_extra() {
        let settings = fakedns_settings_from_section(Some(&section(json!({
            "ipPool": "198.18.0.0/15",
            "futureField": 42
        }))));
        assert_eq!(settings.pools[0].extra.get("futureField"), Some(&json!(42)));
    }

    #[test]
    fn single_pool_collapses_to_object_form() {
        let settings = FakeDnsSettings {
            pools: vec![pool("198.18.0.0/15", Some(65535))],
            ..FakeDnsSettings::defaults()
        };
        let value = fakedns_settings_to_new_value(&settings);
        assert!(value.is_object());
        assert_eq!(value["ipPool"], "198.18.0.0/15");
        assert_eq!(value["poolSize"], 65535);
    }

    #[test]
    fn multiple_pools_serialize_as_array() {
        let settings = FakeDnsSettings {
            pools: vec![pool("198.18.0.0/15", None), pool("fc00::/18", None)],
            ..FakeDnsSettings::defaults()
        };
        let value = fakedns_settings_to_new_value(&settings);
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 2);
    }

    #[test]
    fn zero_pools_serialize_as_empty_array() {
        let settings = FakeDnsSettings::defaults();
        let value = fakedns_settings_to_new_value(&settings);
        assert_eq!(value, json!([]));
    }

    #[test]
    fn extra_fields_round_trip_on_apply() {
        let mut entry = pool("198.18.0.0/15", Some(65535));
        entry.extra.insert("futureField".to_owned(), json!(42));
        let settings = FakeDnsSettings {
            pools: vec![entry],
            ..FakeDnsSettings::defaults()
        };
        let value = fakedns_settings_to_new_value(&settings);
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["ipPool"], "198.18.0.0/15");
    }

    #[test]
    fn omitting_pool_size_omits_the_key() {
        let settings = FakeDnsSettings {
            pools: vec![pool("198.18.0.0/15", None)],
            ..FakeDnsSettings::defaults()
        };
        let value = fakedns_settings_to_new_value(&settings);
        assert!(value.get("poolSize").is_none());
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = FakeDnsSettings {
            pools: vec![pool("198.18.0.0/15", Some(65535))],
            ..FakeDnsSettings::defaults()
        };
        assert!(fakedns_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn change_summary_reports_pool_count_change() {
        let before = FakeDnsSettings::defaults();
        let after = FakeDnsSettings {
            pools: vec![pool("198.18.0.0/15", Some(65535))],
            ..FakeDnsSettings::defaults()
        };
        let summary = fakedns_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 1);
        assert!(summary[0].contains("0 → 1"));
    }

    #[test]
    fn validation_accepts_defaults_and_valid_pools() {
        assert!(validate_fakedns_settings(&FakeDnsSettings::defaults()).is_ok());
        let settings = FakeDnsSettings {
            pools: vec![pool("198.18.0.0/15", Some(65535)), pool("fc00::/18", None)],
            ..FakeDnsSettings::defaults()
        };
        assert!(validate_fakedns_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_blank_ip_pool() {
        let settings = FakeDnsSettings {
            pools: vec![pool("", None)],
            ..FakeDnsSettings::defaults()
        };
        assert!(validate_fakedns_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_non_cidr_ip_pool() {
        let settings = FakeDnsSettings {
            pools: vec![pool("not-a-cidr", None)],
            ..FakeDnsSettings::defaults()
        };
        assert!(validate_fakedns_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_out_of_range_prefix() {
        let settings = FakeDnsSettings {
            pools: vec![pool("198.18.0.0/64", None)],
            ..FakeDnsSettings::defaults()
        };
        assert!(validate_fakedns_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_control_characters() {
        let settings = FakeDnsSettings {
            pools: vec![pool("198.18.0.0/15\n", None)],
            ..FakeDnsSettings::defaults()
        };
        assert!(validate_fakedns_settings(&settings).is_err());
    }
}
