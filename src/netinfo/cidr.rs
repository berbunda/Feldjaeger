//! IPv4 CIDR host enumeration (follow-up to Roadmap §3:131 — AS-range REALITY candidate scan).

use std::net::Ipv4Addr;

use super::{NetInfoError, NetInfoErrorKind, NetInfoResult};

/// Host IPv4 addresses within a CIDR prefix, plus how many exist in total (before any cap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrHosts {
    /// Enumerated host addresses, capped at the caller-supplied limit.
    pub hosts: Vec<Ipv4Addr>,
    /// True host count in the prefix, before capping — lets the caller say "showing N of M".
    pub total: usize,
}

/// Enumerates up to `cap` host addresses in `cidr` (e.g. `"216.90.108.0/24"`), IPv4 only.
///
/// Excludes the network and broadcast addresses for prefix lengths 0..=30 (standard host-count
/// convention); /31 and /32 have no network/broadcast distinction and are returned as-is (RFC
/// 3021 point-to-point / single-host conventions). The address part is masked down to the network
/// address before enumerating — callers may pass a BGP prefix whose address part is already
/// network-aligned, but this doesn't rely on that.
pub fn enumerate_cidr_hosts(cidr: &str, cap: usize) -> NetInfoResult<CidrHosts> {
    let (network, prefix_len) = parse_ipv4_cidr(cidr)?;

    let host_bits = 32 - u32::from(prefix_len);
    let block_size: u64 = 1u64 << host_bits;
    let network_u32 = u32::from(network);

    let (first_offset, last_offset): (u64, u64) = if prefix_len >= 31 {
        (0, block_size - 1)
    } else {
        (1, block_size - 2)
    };

    let total = (last_offset - first_offset + 1) as usize;
    let take = total.min(cap);

    let hosts = (first_offset..first_offset + take as u64)
        .map(|offset| Ipv4Addr::from(network_u32.wrapping_add(offset as u32)))
        .collect();

    Ok(CidrHosts { hosts, total })
}

fn parse_ipv4_cidr(cidr: &str) -> NetInfoResult<(Ipv4Addr, u8)> {
    let (addr_part, len_part) = cidr.trim().split_once('/').ok_or_else(|| {
        NetInfoError::new(
            NetInfoErrorKind::InvalidHost,
            format!("`{cidr}` is not a CIDR prefix (expected `a.b.c.d/n`)"),
        )
    })?;
    let addr: Ipv4Addr = addr_part.trim().parse().map_err(|_| {
        NetInfoError::new(
            NetInfoErrorKind::InvalidHost,
            format!("`{addr_part}` is not a valid IPv4 address"),
        )
    })?;
    let prefix_len: u8 = len_part.trim().parse().map_err(|_| {
        NetInfoError::new(
            NetInfoErrorKind::InvalidHost,
            format!("`{len_part}` is not a valid prefix length"),
        )
    })?;
    if prefix_len > 32 {
        return Err(NetInfoError::new(
            NetInfoErrorKind::InvalidHost,
            format!("prefix length {prefix_len} is out of range (0-32)"),
        ));
    }

    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    let network = Ipv4Addr::from(u32::from(addr) & mask);

    Ok((network, prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_24_excludes_network_and_broadcast() {
        let result = enumerate_cidr_hosts("216.90.108.0/24", 1000).expect("parse");
        assert_eq!(result.total, 254);
        assert_eq!(result.hosts.len(), 254);
        assert_eq!(result.hosts[0], "216.90.108.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            result.hosts.last().unwrap(),
            &"216.90.108.254".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn slash_31_has_no_network_broadcast_distinction() {
        let result = enumerate_cidr_hosts("10.0.0.0/31", 1000).expect("parse");
        assert_eq!(result.total, 2);
        assert_eq!(
            result.hosts,
            vec![
                "10.0.0.0".parse::<Ipv4Addr>().unwrap(),
                "10.0.0.1".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn slash_32_is_a_single_host() {
        let result = enumerate_cidr_hosts("10.0.0.5/32", 1000).expect("parse");
        assert_eq!(result.total, 1);
        assert_eq!(result.hosts, vec!["10.0.0.5".parse::<Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn cap_limits_returned_hosts_but_not_reported_total() {
        let result = enumerate_cidr_hosts("10.0.0.0/24", 5).expect("parse");
        assert_eq!(result.total, 254);
        assert_eq!(result.hosts.len(), 5);
        assert_eq!(result.hosts[4], "10.0.0.5".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn non_network_aligned_address_is_normalized() {
        let result = enumerate_cidr_hosts("10.0.0.130/24", 1000).expect("parse");
        assert_eq!(result.hosts[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn rejects_missing_slash() {
        let error = enumerate_cidr_hosts("10.0.0.0", 10).unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::InvalidHost);
    }

    #[test]
    fn rejects_invalid_address() {
        let error = enumerate_cidr_hosts("not-an-ip/24", 10).unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::InvalidHost);
    }

    #[test]
    fn rejects_out_of_range_prefix_length() {
        let error = enumerate_cidr_hosts("10.0.0.0/33", 10).unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::InvalidHost);
    }

    #[test]
    fn slash_16_total_is_65534() {
        let result = enumerate_cidr_hosts("10.0.0.0/16", 10).expect("parse");
        assert_eq!(result.total, 65_534);
        assert_eq!(result.hosts.len(), 10);
    }
}
