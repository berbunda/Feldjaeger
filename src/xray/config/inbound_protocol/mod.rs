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
    /// TUN: local network-interface inbound (no `port`, no `streamSettings`/security, no
    /// clients). Schema per Xray-core `infra/conf/tun.go` (v26.9.x; `autoSystemRoutingTable` /
    /// `autoOutboundsInterface` extended to FreeBSD in XTLS/Xray-core#6691).
    Tun {
        /// `settings.name` — interface name; empty = key absent (Xray picks one).
        name: String,
        /// `settings.desc` — interface description (Windows); empty = key absent.
        desc: String,
        /// `settings.mtu`; `0` = key absent (Xray default).
        mtu: u32,
        /// `settings.gateway[]` — gateway IPs to assign; empty = key absent.
        gateway: Vec<String>,
        /// `settings.dns[]` — DNS servers to assign to the interface; empty = key absent.
        dns: Vec<String>,
        /// `settings.userLevel`; `0` = key absent (Xray default).
        user_level: u64,
        /// `settings.autoSystemRoutingTable[]` — platforms to auto-manage the system routing
        /// table on (e.g. `linux`, `windows`, `darwin`, `freebsd`); empty = key absent.
        auto_system_routing_table: Vec<String>,
        /// `settings.autoOutboundsInterface` — free-form outbound-interface selection; empty =
        /// key absent.
        auto_outbounds_interface: String,
        /// `settings.autoSystemDnsToGateway` (Linux, v26.9.30+) — point the system DNS at
        /// `gateway`; `false` = key absent (an explicit `false` on disk is kept).
        auto_system_dns_to_gateway: bool,
        /// `settings.autoSystemWfpBlockLeak[]` (Windows, v26.9.30+) — `dns` / `misconfigtun`;
        /// empty = key absent.
        auto_system_wfp_block_leak: Vec<String>,
    },
}

/// Values `TunConfig.Build()` accepts in `autoSystemWfpBlockLeak` (compared lower-cased).
pub const TUN_WFP_BLOCK_LEAK_VALUES: &[&str] = &["dns", "misconfigtun"];

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

    /// Default for Add TUN.
    pub fn tun_default() -> Self {
        Self::Tun {
            name: String::new(),
            desc: String::new(),
            mtu: 0,
            gateway: Vec::new(),
            dns: Vec::new(),
            user_level: 0,
            auto_system_routing_table: Vec::new(),
            auto_outbounds_interface: String::new(),
            auto_system_dns_to_gateway: false,
            auto_system_wfp_block_leak: Vec::new(),
        }
    }

    /// Shared fallbacks slice when protocol supports them.
    pub fn fallbacks(&self) -> Option<&[FallbackObject]> {
        match self {
            Self::Vless { fallbacks, .. } | Self::Trojan { fallbacks } => Some(fallbacks),
            Self::Hysteria { .. } | Self::Tunnel { .. } | Self::Tun { .. } => None,
        }
    }

    /// Mutable shared fallbacks when protocol supports them.
    pub fn fallbacks_mut(&mut self) -> Option<&mut Vec<FallbackObject>> {
        match self {
            Self::Vless { fallbacks, .. } | Self::Trojan { fallbacks } => Some(fallbacks),
            Self::Hysteria { .. } | Self::Tunnel { .. } | Self::Tun { .. } => None,
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
        "tun" => Some(parse_tun_protocol(inbound)),
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

fn parse_tun_protocol(inbound: &Value) -> InboundProtocolDraft {
    let settings = inbound.get("settings").and_then(Value::as_object);
    let name = settings
        .and_then(|s| s.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
        .to_owned();
    let desc = settings
        .and_then(|s| s.get("desc"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
        .to_owned();
    let mtu = settings
        .and_then(|s| s.get("mtu"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0);
    let gateway = string_array(settings.and_then(|s| s.get("gateway")));
    let dns = string_array(settings.and_then(|s| s.get("dns")));
    let user_level = settings
        .and_then(|s| s.get("userLevel"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let auto_system_routing_table = string_array(settings.and_then(|s| s.get("autoSystemRoutingTable")));
    let auto_outbounds_interface = settings
        .and_then(|s| s.get("autoOutboundsInterface"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
        .to_owned();
    let auto_system_dns_to_gateway = settings
        .and_then(|s| s.get("autoSystemDnsToGateway"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let auto_system_wfp_block_leak = string_array(settings.and_then(|s| s.get("autoSystemWfpBlockLeak")));
    InboundProtocolDraft::Tun {
        name,
        desc,
        mtu,
        gateway,
        dns,
        user_level,
        auto_system_routing_table,
        auto_outbounds_interface,
        auto_system_dns_to_gateway,
        auto_system_wfp_block_leak,
    }
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
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
        InboundProtocolDraft::Tun {
            name,
            desc,
            mtu,
            gateway,
            dns,
            user_level,
            auto_system_routing_table,
            auto_outbounds_interface,
            auto_system_dns_to_gateway,
            auto_system_wfp_block_leak,
        } => apply_tun_protocol(
            inbound,
            TunSettings {
                name,
                desc,
                mtu: *mtu,
                gateway,
                dns,
                user_level: *user_level,
                auto_system_routing_table,
                auto_outbounds_interface,
                auto_system_dns_to_gateway: *auto_system_dns_to_gateway,
                auto_system_wfp_block_leak,
            },
        ),
    }
}

/// Borrowed TUN draft fields for [`apply_tun_protocol`].
struct TunSettings<'a> {
    name: &'a str,
    desc: &'a str,
    mtu: u32,
    gateway: &'a [String],
    dns: &'a [String],
    user_level: u64,
    auto_system_routing_table: &'a [String],
    auto_outbounds_interface: &'a str,
    auto_system_dns_to_gateway: bool,
    auto_system_wfp_block_leak: &'a [String],
}

/// The checks of `TunConfig.Build()` (`infra/conf/tun.go`, v26.9.30) that fail the load on a
/// Linux server: an unknown `autoSystemWfpBlockLeak` value (any OS), and `autoSystemDnsToGateway`
/// without a gateway (Linux). The Windows-only conditions of the same function never apply here.
pub fn validate_tun_settings(
    gateway: &[String],
    auto_system_dns_to_gateway: bool,
    auto_system_wfp_block_leak: &[String],
) -> ConfigModifyResult<()> {
    for value in auto_system_wfp_block_leak {
        let value = value.trim();
        if !value.is_empty() && !TUN_WFP_BLOCK_LEAK_VALUES.contains(&value.to_ascii_lowercase().as_str()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("TUN autoSystemWfpBlockLeak: unknown value \"{value}\" (allowed: dns, misconfigtun)"),
            ));
        }
    }
    if auto_system_dns_to_gateway && gateway.iter().all(|g| g.trim().is_empty()) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "TUN autoSystemDnsToGateway needs gateway to be set".to_owned(),
        ));
    }
    Ok(())
}

fn apply_tun_protocol(inbound: &mut Value, tun: TunSettings<'_>) -> ConfigModifyResult<()> {
    let TunSettings {
        name,
        desc,
        mtu,
        gateway,
        dns,
        user_level,
        auto_system_routing_table,
        auto_outbounds_interface,
        auto_system_dns_to_gateway,
        auto_system_wfp_block_leak,
    } = tun;
    validate_tun_settings(gateway, auto_system_dns_to_gateway, auto_system_wfp_block_leak)?;
    let settings = ensure_settings_object(inbound)?;
    apply_optional_string(settings, "name", name);
    apply_optional_string(settings, "desc", desc);
    if mtu != 0 {
        settings.insert("mtu".to_owned(), Value::Number(mtu.into()));
    } else {
        settings.remove("mtu");
    }
    apply_string_array(settings, "gateway", gateway);
    apply_string_array(settings, "dns", dns);
    if user_level != 0 {
        settings.insert("userLevel".to_owned(), Value::Number(user_level.into()));
    } else {
        settings.remove("userLevel");
    }
    apply_string_array(settings, "autoSystemRoutingTable", auto_system_routing_table);
    apply_optional_string(settings, "autoOutboundsInterface", auto_outbounds_interface);
    if auto_system_dns_to_gateway {
        settings.insert("autoSystemDnsToGateway".to_owned(), Value::Bool(true));
    } else if settings.get("autoSystemDnsToGateway") != Some(&Value::Bool(false)) {
        settings.remove("autoSystemDnsToGateway");
    }
    apply_string_array(settings, "autoSystemWfpBlockLeak", auto_system_wfp_block_leak);
    Ok(())
}

fn apply_optional_string(object: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        object.remove(key);
    } else {
        object.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

fn apply_string_array(object: &mut Map<String, Value>, key: &str, values: &[String]) {
    let cleaned: Vec<Value> = values
        .iter()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| Value::String(v.to_owned()))
        .collect();
    if cleaned.is_empty() {
        object.remove(key);
    } else {
        object.insert(key.to_owned(), Value::Array(cleaned));
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

    #[test]
    fn tun_parse_apply_roundtrip_preserves_unknown() {
        let mut inbound = json!({
            "protocol": "tun",
            "settings": {
                "name": "tun0",
                "desc": "Feldjaeger TUN",
                "mtu": 1500,
                "gateway": ["10.0.0.1"],
                "dns": ["1.1.1.1"],
                "userLevel": 1,
                "autoSystemRoutingTable": ["linux", "windows"],
                "autoOutboundsInterface": "auto",
                "futureField": "keep"
            }
        });
        let draft = parse_inbound_protocol(&inbound).expect("parse");
        apply_inbound_protocol(&mut inbound, &draft).expect("apply");
        assert_eq!(inbound["settings"]["name"], "tun0");
        assert_eq!(inbound["settings"]["mtu"], 1500);
        assert_eq!(inbound["settings"]["gateway"], json!(["10.0.0.1"]));
        assert_eq!(inbound["settings"]["dns"], json!(["1.1.1.1"]));
        assert_eq!(inbound["settings"]["userLevel"], 1);
        assert_eq!(
            inbound["settings"]["autoSystemRoutingTable"],
            json!(["linux", "windows"])
        );
        assert_eq!(inbound["settings"]["autoOutboundsInterface"], "auto");
        assert_eq!(inbound["settings"]["futureField"], "keep");
    }

    #[test]
    fn tun_default_apply_omits_empty_fields() {
        let mut inbound = json!({"protocol": "tun"});
        apply_inbound_protocol(&mut inbound, &InboundProtocolDraft::tun_default()).expect("apply");
        assert_eq!(inbound["settings"], json!({}));
    }

    #[test]
    fn tun_v26_9_30_keys_round_trip_unchanged() {
        let original = json!({
            "protocol": "tun",
            "settings": {
                "gateway": ["10.0.0.1"],
                "dns": ["1.1.1.1"],
                "autoSystemRoutingTable": ["linux", "windows"],
                "autoSystemDnsToGateway": true,
                "autoSystemWfpBlockLeak": ["DNS", "misconfigtun"]
            }
        });
        let mut inbound = original.clone();
        let draft = parse_inbound_protocol(&inbound).expect("parse");
        let InboundProtocolDraft::Tun { auto_system_dns_to_gateway, auto_system_wfp_block_leak, .. } = &draft else {
            panic!("tun draft");
        };
        assert!(*auto_system_dns_to_gateway);
        assert_eq!(auto_system_wfp_block_leak, &["DNS".to_owned(), "misconfigtun".to_owned()]);
        apply_inbound_protocol(&mut inbound, &draft).expect("apply");
        assert_eq!(inbound, original, "no edits must leave the JSON byte-identical");
    }

    #[test]
    fn tun_dns_to_gateway_false_keeps_an_explicit_false_and_drops_true() {
        let mut explicit = json!({"protocol": "tun", "settings": {"autoSystemDnsToGateway": false}});
        let draft = parse_inbound_protocol(&explicit).expect("parse");
        apply_inbound_protocol(&mut explicit, &draft).expect("apply");
        assert_eq!(explicit["settings"]["autoSystemDnsToGateway"], json!(false));

        let mut enabled = json!({"protocol": "tun", "settings": {"gateway": ["10.0.0.1"], "autoSystemDnsToGateway": true}});
        let mut draft = parse_inbound_protocol(&enabled).expect("parse");
        if let InboundProtocolDraft::Tun { auto_system_dns_to_gateway, .. } = &mut draft {
            *auto_system_dns_to_gateway = false;
        }
        apply_inbound_protocol(&mut enabled, &draft).expect("apply");
        assert!(enabled["settings"].get("autoSystemDnsToGateway").is_none());
    }

    #[test]
    fn tun_validation_mirrors_tun_config_build() {
        // Unknown leak value: refused on every OS (`unknown autoSystemWfpBlockLeak value`).
        let err = validate_tun_settings(&[], false, &["dns".to_owned(), "routes".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("routes"), "{err}");
        // Case does not matter, blanks are skipped.
        assert!(validate_tun_settings(&[], false, &["DNS".into(), "MisconfigTun".into(), " ".into()]).is_ok());
        // Linux: autoSystemDnsToGateway needs a gateway.
        let err = validate_tun_settings(&[" ".to_owned()], true, &[]).unwrap_err();
        assert!(err.to_string().contains("gateway"), "{err}");
        assert!(validate_tun_settings(&["10.0.0.1".to_owned()], true, &[]).is_ok());

        let mut inbound = json!({"protocol": "tun", "settings": {"autoSystemDnsToGateway": true}});
        let draft = parse_inbound_protocol(&inbound).expect("parse");
        assert!(apply_inbound_protocol(&mut inbound, &draft).is_err(), "Save is blocked");
    }
}
