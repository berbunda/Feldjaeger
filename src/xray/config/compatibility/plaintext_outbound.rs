//! Unencrypted VLESS / Trojan outbounds to public addresses (XTLS/Xray-core#6303, v26.7.11).
//!
//! Mirrors `validateOutboundTransportSecurity` in `infra/conf/xray.go` (`XTLS/Xray-core@main`):
//! an outbound with no transport security (`streamSettings.security` absent, `""` or `none`) is
//! refused at load when its server address is public — for VLESS unless `encryption` is set and
//! not `none`. "Private" is the core's fixed list (`common/geodata/consts.go`): the reserved IP
//! ranges below, and the domains `lan`, `localdomain`, `example`, `invalid`, `localhost`, `test`,
//! `local`, `home.arpa`, `internal` (with their subdomains) or any dotless name.
//!
//! The address and `encryption` are read the way `VLessOutboundConfig.Build()` /
//! `TrojanClientConfig.Build()` normalize them: the flat `settings.address` form first, else the
//! single `vnext[0]` / `servers[0]` entry.

use std::net::IpAddr;

use serde_json::Value;

/// `GetPrivateIPMatcher()` ranges as (address, prefix length).
const PRIVATE_IP_RANGES: &[(&str, u8)] = &[
    ("0.0.0.0", 8),
    ("10.0.0.0", 8),
    ("100.64.0.0", 10),
    ("127.0.0.0", 8),
    ("169.254.0.0", 16),
    ("172.16.0.0", 12),
    ("192.0.0.0", 24),
    ("192.0.2.0", 24),
    ("192.88.99.0", 24),
    ("192.168.0.0", 16),
    ("198.18.0.0", 15),
    ("198.51.100.0", 24),
    ("203.0.113.0", 24),
    ("224.0.0.0", 3),
    ("::", 127),
    ("fc00::", 7),
    ("fe80::", 10),
    ("ff00::", 8),
];

/// `GetPrivateDomainMatcher()` domain rules (each matches the name and its subdomains).
const PRIVATE_DOMAINS: &[&str] = &[
    "lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal",
];

/// Whether the core requires transport security for this server address (`requiresTransportSecurity`).
pub(super) fn requires_transport_security(address: &str) -> bool {
    let trimmed = address.trim();
    let unbracketed = trimmed.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(trimmed);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return !is_private_ip(ip);
    }
    let domain = trimmed.to_ascii_lowercase();
    let domain = domain.strip_suffix('.').unwrap_or(&domain);
    !is_private_domain(domain)
}

pub(super) fn is_private_ip(ip: IpAddr) -> bool {
    // An IPv4-mapped IPv6 address is matched as IPv4, as Go's `net.IP` does.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    PRIVATE_IP_RANGES.iter().any(|(network, prefix)| {
        match (ip, network.parse::<IpAddr>()) {
            (IpAddr::V4(ip), Ok(IpAddr::V4(net))) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
                u32::from(ip) & mask == u32::from(net) & mask
            }
            (IpAddr::V6(ip), Ok(IpAddr::V6(net))) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(*prefix)).unwrap_or(0);
                u128::from(ip) & mask == u128::from(net) & mask
            }
            _ => false,
        }
    })
}

fn is_private_domain(domain: &str) -> bool {
    PRIVATE_DOMAINS
        .iter()
        .any(|rule| domain == *rule || domain.strip_suffix(rule).is_some_and(|head| head.ends_with('.')))
        || is_dotless_label(domain)
}

/// `^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`
fn is_dotless_label(domain: &str) -> bool {
    let bytes = domain.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    first.is_ascii_lowercase()
        && rest.len() <= 62
        && rest.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && rest.last().is_none_or(|last| *last != b'-')
}

/// The JSON location of the address the core would refuse for an unencrypted VLESS / Trojan
/// outbound, or `None` when it is allowed (security set, VLESS encryption, private address,
/// other protocol, or no readable address).
pub(super) fn forbidden_plaintext_address(outbound: &Value) -> Option<String> {
    let protocol = outbound.get("protocol")?.as_str()?.trim().to_ascii_lowercase();
    let security = outbound
        .pointer("/streamSettings/security")
        .and_then(Value::as_str)
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !matches!(security.as_str(), "" | "none") {
        return None;
    }
    let settings = outbound.get("settings")?;
    let (list_key, location) = match protocol.as_str() {
        "vless" => ("vnext", "settings.vnext[0].address"),
        "trojan" => ("servers", "settings.servers[0].address"),
        _ => return None,
    };
    let (address, location, encryption) = match settings.get("address").filter(|value| !value.is_null()) {
        Some(address) => (address, "settings.address", settings.get("encryption")),
        None => {
            let entry = settings.get(list_key)?.as_array()?.first()?;
            let encryption = entry.pointer("/users/0/encryption");
            (entry.get("address")?, location, encryption)
        }
    };
    if protocol == "vless" {
        let encrypted = encryption
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty() && value != "none");
        if encrypted {
            return None;
        }
    }
    requires_transport_security(address.as_str()?).then(|| location.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn private_addresses_match_the_core_lists() {
        for private in [
            "10.1.2.3", "127.0.0.1", "100.64.0.1", "192.168.1.1", "172.31.255.255", "198.19.0.1",
            "::1", "[fd00::1]", "fe80::1", "::ffff:10.0.0.1", "localhost", "router.lan", "x.home.arpa",
            "nas.local", "a.example", "server", "Server.", "my-host",
        ] {
            assert!(!requires_transport_security(private), "{private} is private");
        }
        // `example.com` is not under `example`; `-x` / `x-` fail the dotless-name pattern.
        for public in ["1.1.1.1", "172.32.0.1", "2001:db8::1", "example.com", "mylan.com", "a.b", "-x", "x-"] {
            assert!(requires_transport_security(public), "{public} is public");
        }
    }

    #[test]
    fn flags_only_unencrypted_vless_and_trojan_to_public_addresses() {
        let vless = |settings: Value, stream: Value| {
            forbidden_plaintext_address(&json!({"protocol": "vless", "settings": settings, "streamSettings": stream}))
        };
        let flat = json!({"address": "example.com", "port": 443, "id": "x"});
        assert_eq!(vless(flat.clone(), json!({})).as_deref(), Some("settings.address"));
        assert_eq!(vless(flat.clone(), json!({"security": "none"})).as_deref(), Some("settings.address"));
        assert_eq!(vless(flat.clone(), json!({"security": "tls"})), None);
        let encrypted = json!({"address": "example.com", "encryption": "mlkem768x25519plus.native.0rtt.x"});
        assert_eq!(vless(encrypted, json!({})), None);
        assert_eq!(vless(json!({"address": "10.0.0.1"}), json!({})), None);
        let vnext = json!({"vnext": [{"address": "1.1.1.1", "port": 443, "users": [{"id": "x", "encryption": "none"}]}]});
        assert_eq!(vless(vnext, json!({})).as_deref(), Some("settings.vnext[0].address"));

        let trojan = json!({"protocol": "trojan", "settings": {"servers": [{"address": "1.1.1.1"}]}});
        assert_eq!(forbidden_plaintext_address(&trojan).as_deref(), Some("settings.servers[0].address"));
        let vmess = json!({"protocol": "vmess", "settings": {"address": "1.1.1.1"}});
        assert_eq!(forbidden_plaintext_address(&vmess), None);
    }
}
