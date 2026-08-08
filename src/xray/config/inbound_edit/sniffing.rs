//! SniffingObject parse/write for inbound shell edit.

use serde_json::{Map, Value};

use crate::xray::config::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Known `destOverride` tokens (editable checkboxes), stable write order.
pub const KNOWN_DEST_OVERRIDE: &[&str] = &["http", "tls", "quic", "fakedns"];

/// Parsed / draft sniffing settings.
#[derive(Debug, Clone, PartialEq)]
pub struct SniffingSettings {
    /// Whether sniffing is enabled.
    pub enabled: Option<bool>,
    /// Known destOverride tokens selected in the UI.
    pub dest_override: Vec<String>,
    /// metadataOnly flag.
    pub metadata_only: Option<bool>,
    /// routeOnly flag.
    pub route_only: Option<bool>,
    /// Unknown sniffing object keys (domainsExcluded, …).
    pub extras: Map<String, Value>,
    /// Unknown destOverride entries preserved across write.
    pub unknown_dest_override: Vec<String>,
}

impl Default for SniffingSettings {
    fn default() -> Self {
        Self {
            enabled: Some(false),
            dest_override: Vec::new(),
            metadata_only: Some(false),
            route_only: Some(false),
            extras: Map::new(),
            unknown_dest_override: Vec::new(),
        }
    }
}

/// Result of applying sniffing to an inbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffingWriteOutcome {
    /// No change written (absent + defaults).
    NoWrite,
    /// Sniffing object created or patched.
    Written,
}

/// True when the draft matches absent-defaults (no write if sniffing key absent).
pub fn sniffing_is_absent_defaults(settings: &SniffingSettings) -> bool {
    let enabled = settings.enabled.unwrap_or(false);
    let metadata = settings.metadata_only.unwrap_or(false);
    let route = settings.route_only.unwrap_or(false);
    !enabled
        && !metadata
        && !route
        && settings.dest_override.is_empty()
        && settings.unknown_dest_override.is_empty()
}

/// Parses sniffing from an inbound object (absent / null → defaults).
pub fn parse_sniffing_settings(inbound: &Value) -> SniffingSettings {
    let Some(sniffing) = inbound.get("sniffing") else {
        return SniffingSettings::default();
    };
    if sniffing.is_null() {
        return SniffingSettings::default();
    }
    let Some(object) = sniffing.as_object() else {
        return SniffingSettings::default();
    };

    let mut extras = Map::new();
    let mut known_dest = Vec::new();
    let mut unknown_dest = Vec::new();

    for (key, value) in object {
        match key.as_str() {
            "enabled" => {}
            "destOverride" => {
                if let Some(items) = value.as_array() {
                    for item in items {
                        if let Some(token) = item.as_str() {
                            if KNOWN_DEST_OVERRIDE.contains(&token) {
                                if !known_dest.iter().any(|t| t == token) {
                                    known_dest.push(token.to_owned());
                                }
                            } else {
                                unknown_dest.push(token.to_owned());
                            }
                        }
                    }
                } else {
                    extras.insert(key.clone(), value.clone());
                }
            }
            "metadataOnly" | "routeOnly" => {}
            _ => {
                extras.insert(key.clone(), value.clone());
            }
        }
    }

    // Stable known order for UI.
    let dest_override = KNOWN_DEST_OVERRIDE
        .iter()
        .filter(|token| known_dest.iter().any(|t| t == **token))
        .map(|token| (*token).to_owned())
        .collect();

    SniffingSettings {
        enabled: object.get("enabled").and_then(Value::as_bool).or(Some(false)),
        dest_override,
        metadata_only: object
            .get("metadataOnly")
            .and_then(Value::as_bool)
            .or(Some(false)),
        route_only: object
            .get("routeOnly")
            .and_then(Value::as_bool)
            .or(Some(false)),
        extras,
        unknown_dest_override: unknown_dest,
    }
}

/// Applies sniffing draft onto inbound in place.
pub fn apply_inbound_sniffing(
    inbound: &mut Value,
    settings: &SniffingSettings,
) -> ConfigModifyResult<SniffingWriteOutcome> {
    let object = inbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound is not a JSON object".to_owned(),
        )
    })?;

    let existing = object.get("sniffing");
    let absent = existing.is_none() || existing.is_some_and(Value::is_null);

    if absent && sniffing_is_absent_defaults(settings) {
        return Ok(SniffingWriteOutcome::NoWrite);
    }

    for token in &settings.dest_override {
        if !KNOWN_DEST_OVERRIDE.contains(&token.as_str()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("unsupported destOverride token: {token}"),
            ));
        }
    }

    let mut sniffing = Map::new();
    sniffing.insert(
        "enabled".to_owned(),
        Value::Bool(settings.enabled.unwrap_or(false)),
    );

    let mut dest = Vec::new();
    for token in KNOWN_DEST_OVERRIDE {
        if settings.dest_override.iter().any(|t| t == *token) {
            dest.push(Value::String((*token).to_owned()));
        }
    }
    for token in &settings.unknown_dest_override {
        dest.push(Value::String(token.clone()));
    }
    if !dest.is_empty() || !absent {
        // Always write destOverride when object exists or selection non-empty.
        sniffing.insert("destOverride".to_owned(), Value::Array(dest));
    }

    if settings.metadata_only.unwrap_or(false) || !absent {
        sniffing.insert(
            "metadataOnly".to_owned(),
            Value::Bool(settings.metadata_only.unwrap_or(false)),
        );
    }
    if settings.route_only.unwrap_or(false) || !absent {
        sniffing.insert(
            "routeOnly".to_owned(),
            Value::Bool(settings.route_only.unwrap_or(false)),
        );
    }

    for (key, value) in &settings.extras {
        sniffing.insert(key.clone(), value.clone());
    }

    // Minimal create: only non-default keys when creating from absent.
    if absent {
        let mut minimal = Map::new();
        if settings.enabled.unwrap_or(false) {
            minimal.insert("enabled".to_owned(), Value::Bool(true));
        }
        let mut dest = Vec::new();
        for token in KNOWN_DEST_OVERRIDE {
            if settings.dest_override.iter().any(|t| t == *token) {
                dest.push(Value::String((*token).to_owned()));
            }
        }
        for token in &settings.unknown_dest_override {
            dest.push(Value::String(token.clone()));
        }
        if !dest.is_empty() {
            minimal.insert("destOverride".to_owned(), Value::Array(dest));
        }
        if settings.metadata_only.unwrap_or(false) {
            minimal.insert("metadataOnly".to_owned(), Value::Bool(true));
        }
        if settings.route_only.unwrap_or(false) {
            minimal.insert("routeOnly".to_owned(), Value::Bool(true));
        }
        for (key, value) in &settings.extras {
            minimal.insert(key.clone(), value.clone());
        }
        if minimal.is_empty() {
            return Ok(SniffingWriteOutcome::NoWrite);
        }
        object.insert("sniffing".to_owned(), Value::Object(minimal));
        return Ok(SniffingWriteOutcome::Written);
    }

    object.insert("sniffing".to_owned(), Value::Object(sniffing));
    Ok(SniffingWriteOutcome::Written)
}
