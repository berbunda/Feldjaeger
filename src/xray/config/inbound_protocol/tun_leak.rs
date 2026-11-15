//! Syntax checks for Xray's TUN `autoSystemWfpBlockLeak` strings (#7315, v26.11.9).
//! This does not install WFP rules or expand/normalize the configuration on write.

use std::net::IpAddr;

/// Keyword selectors; a port/range or CIDR-prefixed selector can also be entered as text.
pub const TUN_WFP_BLOCK_LEAK_VALUES: &[&str] = &[
    "dns",
    "windnsclient",
    "misconfigtun",
    "all",
    "allexceptlan",
    "tcp",
    "udp",
    "icmp",
];

/// Checks the grammar of `proxy/tun/wfp_leak.go::parseLeak` on Xray v26.11.9.
/// Prefix host bits and the original spelling are retained; IPv4-mapped IPv6 is rejected.
pub fn is_valid_tun_wfp_block_leak(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    // Prefix parsing precedes selector parsing: a colon is never a host:port shorthand here.
    let selector = if let Some(bracketed) = value.strip_prefix('[') {
        let Some((cidr, selector)) = bracketed.split_once("]:") else {
            return false;
        };
        if !valid_cidr(cidr, true) {
            return false;
        }
        selector
    } else if let Some((cidr, selector)) = value.split_once(':') {
        if !valid_cidr(cidr, false) {
            return false;
        }
        selector
    } else {
        value.as_str()
    };
    if TUN_WFP_BLOCK_LEAK_VALUES.contains(&selector) {
        return true;
    }
    match selector.split_once('/') {
        Some(("tcp" | "udp", ports)) => valid_ports(ports),
        Some(_) => false,
        None => valid_ports(selector),
    }
}

/// Forms accepted by v26.10.31, for version warnings (not a second write validator).
pub(crate) fn is_legacy_tun_wfp_block_leak(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    if ["dns", "windnsclient", "misconfigtun"].contains(&value.as_str()) {
        return true;
    }
    value.split_once('/').is_some_and(|(protocol, port)| {
        matches!(protocol, "tcp" | "udp") && decimal_port(port).is_some()
    })
}

fn decimal_port(value: &str) -> Option<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u16>().ok().filter(|port| *port > 0)
}

fn valid_ports(value: &str) -> bool {
    let (low, high) = value.split_once('-').unwrap_or((value, value));
    match (decimal_port(low), decimal_port(high)) {
        (Some(low), Some(high)) => low <= high,
        _ => false,
    }
}

fn valid_cidr(value: &str, ipv6: bool) -> bool {
    let Some((address, bits)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    if bits.is_empty()
        || !bits.bytes().all(|byte| byte.is_ascii_digit())
        || (bits.len() > 1 && bits.starts_with('0'))
    {
        return false;
    }
    let max_bits = match address {
        IpAddr::V4(_) if !ipv6 => 32,
        IpAddr::V6(ip) if ipv6 && ip.to_ipv4_mapped().is_none() => 128,
        _ => return false,
    };
    bits.parse::<u8>().is_ok_and(|bits| bits <= max_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VALID: &[&str] = &[
        "dns",
        "misconfigtun",
        "windnsclient",
        "TCP/053",
        "udp/65535",
        "all",
        "AllExceptLAN",
        "TCP",
        "udp",
        "icmp",
        "53",
        "1-65535",
        "tcp/8000-9000",
        "udp/01-02",
        "1.1.1.1/24:TCP/853",
        "0.0.0.0/0:dns",
        "[2001:DB8::1/32]:udp/10-20",
        "[::/0]:all",
        "[::/128]:misconfigtun",
    ];
    const INVALID: &[&str] = &[
        "",
        "0",
        "65536",
        "20-10",
        "tcp/0-10",
        "tcp/+53",
        "tcp/ 53",
        "udp/20-10",
        "icmp/1",
        "dns/53",
        "all/53",
        "sctp/53",
        "tcp/",
        "53/tcp",
        "1-2-3",
        "1,2",
        "1.1.1.1:53",
        "2001:db8::/32:53",
        "[1.1.1.0/24]:53",
        "[::ffff:1.1.1.0/120]:53",
        "[fe80::1%eth0/64]:tcp",
        "1.1.1.0/33:53",
        "[::/129]:53",
        "[::/0]53",
        "1.1.1.0/+24:53",
        "1.1.1.0/024:53",
        "tcp/-1",
        " all",
    ];

    #[test]
    fn selector_grammar_matches_core_examples_and_boundaries() {
        for value in VALID {
            assert!(is_valid_tun_wfp_block_leak(value), "{value}");
        }
        for value in INVALID {
            assert!(!is_valid_tun_wfp_block_leak(value), "{value}");
        }
    }

    #[test]
    fn tun_leak_parity_with_local_xray() {
        let Some(binary) = crate::xray::local_xray::local_xray_bin() else {
            eprintln!("no local Xray — skipping TUN leak grammar parity");
            return;
        };
        let version = std::process::Command::new(&binary)
            .arg("version")
            .output()
            .unwrap();
        let version =
            crate::xray::XrayCoreVersion::parse(&String::from_utf8_lossy(&version.stdout)).unwrap();
        let modern = version >= crate::xray::XrayCoreVersion::new(26, 11, 9);
        let directory =
            std::env::temp_dir().join(format!("feldjaeger-tun-leak-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("config.json");
        let mut failures = Vec::new();
        for value in VALID.iter().chain(INVALID) {
            let config = json!({"inbounds": [{"protocol": "tun", "settings": {
                "name": "xray0", "dns": ["1.1.1.1"], "autoSystemRoutingTable": ["0.0.0.0/0"],
                "autoSystemWfpBlockLeak": [value]
            }}]});
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            let result = std::process::Command::new(&binary)
                .args(["run", "-test", "-c"])
                .arg(&path)
                .output()
                .unwrap();
            let expected = if modern {
                is_valid_tun_wfp_block_leak(value)
            } else {
                is_legacy_tun_wfp_block_leak(value)
            };
            if result.status.success() != expected {
                failures.push(*value);
            }
        }
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            failures.is_empty(),
            "TUN grammar parity mismatches: {failures:?}"
        );
    }
}
