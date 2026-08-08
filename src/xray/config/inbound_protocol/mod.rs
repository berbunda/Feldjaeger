//! Inbound Protocol tab helpers (VLESS / Hysteria / Tunnel).

use serde_json::{Map, Value};

use crate::xray::config::inbound_fallbacks::{
    FallbackObject, apply_fallbacks, parse_fallbacks,
};
use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Allowed Tunnel `settings.allowedNetwork` values.
pub const TUNNEL_NETWORKS: &[&str] = &["tcp", "udp", "tcp,udp"];

/// Protocol-tab draft (non-client settings).
#[derive(Debug, Clone, PartialEq)]
pub enum InboundProtocolDraft {
    /// VLESS: `settings.decryption` required (default `"none"`).
    Vless {
        /// Server decryption string.
        decryption: String,
        /// Shared `settings.fallbacks` (TCP+TLS/Reality only; stripped on Save otherwise).
        fallbacks: Vec<FallbackObject>,
    },
    /// Trojan: shared `settings.fallbacks` (clients live under Users).
    Trojan {
        /// Shared `settings.fallbacks` (TCP+TLS/Reality only; stripped on Save otherwise).
        fallbacks: Vec<FallbackObject>,
    },
    /// Hysteria: `settings.version` must be 2.
    Hysteria {
        /// Hysteria version (Wave A: always 2).
        version: u64,
    },
    /// Tunnel (`dokodemo-door` successor): port forward / transparent proxy settings.
    Tunnel {
        /// `settings.allowedNetwork` (tcp | udp | tcp,udp).
        allowed_network: String,
        /// `settings.rewriteAddress` (default localhost).
        rewrite_address: String,
        /// `settings.rewritePort` (`None` / 0 = listen port).
        rewrite_port: Option<u64>,
        /// `settings.portMap` entries (`localPort` → target).
        port_map: Vec<(String, String)>,
        /// `settings.followRedirect`.
        follow_redirect: bool,
        /// `settings.userLevel` (default 0).
        user_level: u64,
    },
}

impl InboundProtocolDraft {
    /// Default for Add VLESS.
    pub fn vless_default() -> Self {
        Self::Vless {
            decryption: "none".to_owned(),
            fallbacks: Vec::new(),
        }
    }

    /// Default for Add Trojan.
    pub fn trojan_default() -> Self {
        Self::Trojan {
            fallbacks: Vec::new(),
        }
    }

    /// Default for Add Hysteria.
    pub fn hysteria_default() -> Self {
        Self::Hysteria { version: 2 }
    }

    /// Default for Add Tunnel.
    pub fn tunnel_default() -> Self {
        Self::Tunnel {
            allowed_network: "tcp".to_owned(),
            rewrite_address: "localhost".to_owned(),
            rewrite_port: None,
            port_map: Vec::new(),
            follow_redirect: false,
            user_level: 0,
        }
    }

    /// Shared fallbacks slice when protocol supports them.
    pub fn fallbacks(&self) -> Option<&[FallbackObject]> {
        match self {
            Self::Vless { fallbacks, .. } | Self::Trojan { fallbacks } => Some(fallbacks),
            Self::Hysteria { .. } | Self::Tunnel { .. } => None,
        }
    }

    /// Mutable shared fallbacks when protocol supports them.
    pub fn fallbacks_mut(&mut self) -> Option<&mut Vec<FallbackObject>> {
        match self {
            Self::Vless { fallbacks, .. } | Self::Trojan { fallbacks } => Some(fallbacks),
            Self::Hysteria { .. } | Self::Tunnel { .. } => None,
        }
    }
}

/// Reads Protocol draft from inbound.
pub fn parse_inbound_protocol(inbound: &Value) -> Option<InboundProtocolDraft> {
    let protocol = inbound
        .get("protocol")
        .and_then(Value::as_str)?
        .trim()
        .to_ascii_lowercase();
    match protocol.as_str() {
        "vless" => {
            let decryption = inbound
                .get("settings")
                .and_then(|s| s.get("decryption"))
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_owned();
            Some(InboundProtocolDraft::Vless {
                decryption,
                fallbacks: parse_fallbacks(inbound),
            })
        }
        "trojan" => Some(InboundProtocolDraft::Trojan {
            fallbacks: parse_fallbacks(inbound),
        }),
        "hysteria" => {
            let version = inbound
                .get("settings")
                .and_then(|s| s.get("version"))
                .and_then(Value::as_u64)
                .unwrap_or(2);
            Some(InboundProtocolDraft::Hysteria { version })
        }
        "tunnel" => Some(parse_tunnel_protocol(inbound)),
        _ => None,
    }
}

fn parse_tunnel_protocol(inbound: &Value) -> InboundProtocolDraft {
    let settings = inbound.get("settings").and_then(Value::as_object);
    let allowed_network = settings
        .and_then(|s| s.get("allowedNetwork"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("tcp")
        .to_owned();
    let rewrite_address = settings
        .and_then(|s| s.get("rewriteAddress"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("localhost")
        .to_owned();
    let rewrite_port = settings
        .and_then(|s| s.get("rewritePort"))
        .and_then(Value::as_u64)
        .filter(|p| *p != 0);
    let follow_redirect = settings
        .and_then(|s| s.get("followRedirect"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let user_level = settings
        .and_then(|s| s.get("userLevel"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut port_map = Vec::new();
    if let Some(map) = settings.and_then(|s| s.get("portMap")).and_then(Value::as_object) {
        for (local, target) in map {
            if let Some(target) = target.as_str() {
                port_map.push((local.clone(), target.to_owned()));
            }
        }
        port_map.sort_by(|a, b| a.0.cmp(&b.0));
    }
    InboundProtocolDraft::Tunnel {
        allowed_network,
        rewrite_address,
        rewrite_port,
        port_map,
        follow_redirect,
        user_level,
    }
}

/// Applies Protocol draft into `settings` **in place** (never replaces settings object;
/// never rewrites clients/users arrays).
pub fn apply_inbound_protocol(
    inbound: &mut Value,
    draft: &InboundProtocolDraft,
) -> ConfigModifyResult<()> {
    match draft {
        InboundProtocolDraft::Trojan { fallbacks } => apply_fallbacks(inbound, fallbacks),
        InboundProtocolDraft::Vless {
            decryption,
            fallbacks,
        } => {
            let trimmed = decryption.trim();
            if trimmed.is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "VLESS decryption must not be empty".to_owned(),
                ));
            }
            let settings = ensure_settings_object(inbound)?;
            settings.insert(
                "decryption".to_owned(),
                Value::String(trimmed.to_owned()),
            );
            apply_fallbacks(inbound, fallbacks)
        }
        InboundProtocolDraft::Hysteria { version } => {
            if *version != 2 {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "Hysteria settings.version must be 2".to_owned(),
                ));
            }
            let settings = ensure_settings_object(inbound)?;
            settings.insert("version".to_owned(), Value::Number((*version).into()));
            if !settings.contains_key("users") || settings.get("users").is_some_and(Value::is_null)
            {
                settings.insert("users".to_owned(), Value::Array(Vec::new()));
            }
            Ok(())
        }
        InboundProtocolDraft::Tunnel {
            allowed_network,
            rewrite_address,
            rewrite_port,
            port_map,
            follow_redirect,
            user_level,
        } => apply_tunnel_protocol(
            inbound,
            allowed_network,
            rewrite_address,
            *rewrite_port,
            port_map,
            *follow_redirect,
            *user_level,
        ),
    }
}

fn apply_tunnel_protocol(
    inbound: &mut Value,
    allowed_network: &str,
    rewrite_address: &str,
    rewrite_port: Option<u64>,
    port_map: &[(String, String)],
    follow_redirect: bool,
    user_level: u64,
) -> ConfigModifyResult<()> {
    let network = normalize_tunnel_network(allowed_network)?;
    let address = rewrite_address.trim();
    if address.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Tunnel rewriteAddress must not be empty".to_owned(),
        ));
    }
    if let Some(port) = rewrite_port {
        if port > 65535 {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "Tunnel rewritePort must be in 0..=65535".to_owned(),
            ));
        }
    }
    validate_port_map(port_map)?;

    let settings = ensure_settings_object(inbound)?;
    settings.insert(
        "allowedNetwork".to_owned(),
        Value::String(network.to_owned()),
    );
    settings.insert(
        "rewriteAddress".to_owned(),
        Value::String(address.to_owned()),
    );
    match rewrite_port.filter(|p| *p != 0) {
        Some(port) => {
            settings.insert("rewritePort".to_owned(), Value::Number(port.into()));
        }
        None => {
            settings.remove("rewritePort");
        }
    }
    settings.insert("followRedirect".to_owned(), Value::Bool(follow_redirect));
    settings.insert("userLevel".to_owned(), Value::Number(user_level.into()));

    let mut map = Map::new();
    for (local, target) in port_map {
        map.insert(local.trim().to_owned(), Value::String(target.trim().to_owned()));
    }
    if map.is_empty() {
        settings.remove("portMap");
    } else {
        settings.insert("portMap".to_owned(), Value::Object(map));
    }
    Ok(())
}

fn normalize_tunnel_network(value: &str) -> ConfigModifyResult<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "tcp" => Ok("tcp"),
        "udp" => Ok("udp"),
        "tcp,udp" | "udp,tcp" => Ok("tcp,udp"),
        _ => Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Tunnel allowedNetwork must be tcp, udp, or tcp,udp".to_owned(),
        )),
    }
}

/// Validates Tunnel `portMap` local keys and SoT target forms.
pub fn validate_port_map(port_map: &[(String, String)]) -> ConfigModifyResult<()> {
    let mut seen = std::collections::BTreeSet::new();
    for (local, target) in port_map {
        let local = local.trim();
        if local.is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "Tunnel portMap local port must not be empty".to_owned(),
            ));
        }
        if !local.chars().all(|c| c.is_ascii_digit()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Tunnel portMap local port is invalid: {local}"),
            ));
        }
        let local_port: u64 = local.parse().map_err(|_| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Tunnel portMap local port is invalid: {local}"),
            )
        })?;
        if local_port == 0 || local_port > 65535 {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Tunnel portMap local port must be in 1..=65535: {local}"),
            ));
        }
        if !seen.insert(local.to_owned()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Tunnel portMap duplicate local port: {local}"),
            ));
        }
        validate_port_map_target(target.trim())?;
    }
    Ok(())
}

/// Accepts `host:port`, `:port`, or `host:` (host or port required).
pub fn validate_port_map_target(target: &str) -> ConfigModifyResult<()> {
    if target.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Tunnel portMap target must not be empty".to_owned(),
        ));
    }
    let Some((host, port)) = target.rsplit_once(':') else {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("Tunnel portMap target must be host:port, :port, or host: ({target})"),
        ));
    };
    let host = host.trim();
    let port = port.trim();
    if host.is_empty() && port.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Tunnel portMap target must override address and/or port".to_owned(),
        ));
    }
    if !port.is_empty() {
        let parsed: u64 = port.parse().map_err(|_| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Tunnel portMap target port is invalid: {port}"),
            )
        })?;
        if parsed == 0 || parsed > 65535 {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Tunnel portMap target port must be in 1..=65535: {port}"),
            ));
        }
    }
    Ok(())
}

fn ensure_settings_object(inbound: &mut Value) -> ConfigModifyResult<&mut Map<String, Value>> {
    let root = inbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        )
    })?;
    if !root.contains_key("settings") || root.get("settings").is_some_and(Value::is_null) {
        root.insert("settings".to_owned(), Value::Object(Map::new()));
    }
    root.get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "settings must be a JSON object".to_owned(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tunnel_parse_apply_roundtrip_preserves_unknown() {
        let mut inbound = json!({
            "protocol": "tunnel",
            "settings": {
                "allowedNetwork": "tcp,udp",
                "rewriteAddress": "8.8.8.8",
                "rewritePort": 53,
                "followRedirect": true,
                "userLevel": 1,
                "portMap": {
                    "5555": "1.1.1.1:7777",
                    "5556": ":8888",
                    "5557": "example.com:"
                },
                "futureField": "keep"
            }
        });
        let draft = parse_inbound_protocol(&inbound).expect("parse");
        apply_inbound_protocol(&mut inbound, &draft).expect("apply");
        assert_eq!(inbound["settings"]["allowedNetwork"], "tcp,udp");
        assert_eq!(inbound["settings"]["rewriteAddress"], "8.8.8.8");
        assert_eq!(inbound["settings"]["rewritePort"], 53);
        assert_eq!(inbound["settings"]["followRedirect"], true);
        assert_eq!(inbound["settings"]["userLevel"], 1);
        assert_eq!(inbound["settings"]["portMap"]["5555"], "1.1.1.1:7777");
        assert_eq!(inbound["settings"]["portMap"]["5556"], ":8888");
        assert_eq!(inbound["settings"]["portMap"]["5557"], "example.com:");
        assert_eq!(inbound["settings"]["futureField"], "keep");
    }

    #[test]
    fn port_map_target_forms() {
        validate_port_map_target("1.1.1.1:7777").expect("full");
        validate_port_map_target(":8888").expect("port only");
        validate_port_map_target("example.com:").expect("host only");
        assert!(validate_port_map_target(":").is_err());
        assert!(validate_port_map_target("").is_err());
        assert!(validate_port_map_target("no-colon").is_err());
    }

    #[test]
    fn dokodemo_door_is_not_parsed_as_tunnel_draft() {
        let inbound = json!({"protocol":"dokodemo-door","settings":{}});
        assert!(parse_inbound_protocol(&inbound).is_none());
    }
}
