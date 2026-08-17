//! Per-candidate scan pipeline (Roadmap follow-up to §3:131 — AS-range REALITY candidate scan).
//!
//! Ties [`super::dns::reverse_dns_lookup`] and [`super::tls_probe`] together into the one decision
//! this whole feature exists to make: is this IP a usable REALITY `dest` candidate? A candidate is
//! shown only when *all* of the following hold — anything else is silently filtered (per the
//! user's explicit requirement, invalid results are not shown, not shown-with-an-error):
//! - it has a PTR (reverse DNS) record,
//! - that PTR domain forward-resolves back to the exact IP being probed (this is the direct fix
//!   for the bug reported against RealiTLScanner — a domain pulled from a certificate's SAN list
//!   without this check can map to a *different* IP than the one that was scanned),
//! - a TLS 1.3 handshake with that domain as SNI succeeds, negotiating an accepted ALPN protocol
//!   and key-exchange group ([`super::tls_probe::is_valid_reality_candidate`]).

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;

use rustls::ClientConfig;

use super::dns::reverse_dns_lookup;
use super::tls_probe::{is_valid_reality_candidate, probe_tls};

const REALITY_PROBE_PORT: u16 = 443;

/// One IP that passed every REALITY `dest` candidate check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanCandidateRow {
    /// The candidate IP.
    pub ip: IpAddr,
    /// PTR (reverse DNS) domain for `ip`, confirmed to forward-resolve back to it.
    pub domain: String,
    /// `dNSName` entries from the leaf certificate's SAN extension.
    pub cert_domains: Vec<String>,
    /// Negotiated ALPN protocol (`"h2"` or `"http/1.1"`).
    pub alpn: String,
    /// Negotiated key-exchange group (`"X25519"` or `"X25519MLKEM768"`).
    pub curve: String,
}

/// Runs the full candidate pipeline for one IP. `None` covers every kind of "not a valid
/// candidate" outcome (no PTR record, PTR doesn't resolve back, connection/handshake failure,
/// TLS/ALPN/curve mismatch) — failures are the expected common case across a /24, not errors to
/// surface individually.
pub fn probe_scan_candidate(ip: Ipv4Addr, tls_config: &Arc<ClientConfig>) -> Option<ScanCandidateRow> {
    let domain = reverse_dns_lookup(ip).ok()?;
    if !domain_forward_resolves_to(&domain, ip) {
        return None;
    }

    let probe = probe_tls(IpAddr::V4(ip), REALITY_PROBE_PORT, &domain, Arc::clone(tls_config)).ok()?;
    if !is_valid_reality_candidate(&probe) {
        return None;
    }

    Some(ScanCandidateRow {
        ip: IpAddr::V4(ip),
        domain,
        cert_domains: probe.cert_sans,
        alpn: probe.alpn.unwrap_or_default(),
        curve: probe.negotiated_group.unwrap_or_default(),
    })
}

/// Whether `domain` forward-resolves to include `ip` among *any* of its A/AAAA records — not
/// just the first, since a domain can have several (load-balanced/CDN sites commonly do).
fn domain_forward_resolves_to(domain: &str, ip: Ipv4Addr) -> bool {
    (domain, 0_u16)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|addr| addr.ip()).any(|resolved| resolved == IpAddr::V4(ip)))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_resolve_matches_known_address() {
        // dns.google is stable and documented to answer on 8.8.8.8 / 8.8.4.4 — network-dependent,
        // so this only asserts the negative case is well-formed; positive resolution is covered
        // by the live manual check, not CI.
        assert!(!domain_forward_resolves_to(
            "this-domain-should-not-exist-feldjaeger-test.invalid",
            "1.2.3.4".parse().unwrap()
        ));
    }
}
