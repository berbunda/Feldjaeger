//! SNI / Dest / host target lookup — resolve a domain or IP to its origin ASN
//! (Roadmap §3:131 — "SNI / Dest / host target search by ASN"), plus an AS-range REALITY
//! candidate scan built on top of it (`cidr`/`dns`/`tls_probe`/`scan` submodules — follow-up
//! roadmap item, see `Feldjaeger-Архитектура.md` for the full design discussion: why the scan
//! runs locally rather than via SSH-exec on the managed host, why `rustls`+`aws-lc-rs` rather than
//! the `ring` provider already used elsewhere in this workspace, and why reverse DNS is hand-rolled
//! rather than a new dependency).
//!
//! Scope confirmed with the user before the original single-host lookup (three disputed points):
//! - **Direction**: forward lookup only (`host` → IP → ASN/organization), not a reverse
//!   "search domains by ASN" — a mature-tool-duplicating feature (`bgp.he.net`, Shodan, Censys
//!   already do this well; `rules.md`: "does not duplicate functionality of another mature
//!   application") with no clean lightweight data source.
//! - **Data source**: Team Cymru's public IP-to-ASN whois service
//!   (<https://team-cymru.com/community-services/ip-asn-mapping/>) over the raw whois protocol
//!   (`whois.cymru.com:43`) — free, no API key, no bundled/licensed database (unlike e.g. MaxMind
//!   GeoLite2-ASN), and implementable with `std::net` alone (no new dependency, consistent with
//!   this project's preference for hand-rolled solutions over new crates, e.g. `qr_code`/
//!   `sparkline`, Roadmap §3:122/§3:129).
//! - This is the **only** feature in Feldjäger that reaches out to the public internet from the
//!   operator's workstation rather than to the managed SSH host — confirmed explicitly with the
//!   user, since it sits outside "SSH is the primary management channel" (`rules.md`). It never
//!   touches the managed Xray host, `ApplicationService`'s SSH session, or any configuration —
//!   purely an authoring aid for picking/checking REALITY `dest`, TLS `serverName`, or routing
//!   `domain` values, run independently of any SSH connection state.

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

mod cidr;
mod dns;
mod scan;
mod tls_probe;

pub use cidr::{CidrHosts, enumerate_cidr_hosts};
pub use dns::reverse_dns_lookup;
pub use scan::{ScanCandidateRow, probe_scan_candidate};
pub use tls_probe::{TlsProbeResult, build_probe_tls_client_config, is_valid_reality_candidate, probe_tls};

const WHOIS_HOST: &str = "whois.cymru.com";
const WHOIS_PORT: u16 = 43;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);
/// Defensive cap on the whois response body — real responses are a few hundred bytes.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Classifies a target lookup failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetInfoErrorKind {
    /// Empty or otherwise unusable input.
    InvalidHost,
    /// The host did not resolve to any IP address.
    ResolutionFailed,
    /// Could not reach or read from `whois.cymru.com`.
    ConnectionFailed,
    /// The whois response did not contain a recognizable data line.
    ParseFailed,
}

impl NetInfoErrorKind {
    /// Stable UI label.
    pub fn label(self) -> &'static str {
        match self {
            Self::InvalidHost => "Invalid host",
            Self::ResolutionFailed => "DNS resolution failed",
            Self::ConnectionFailed => "Whois lookup failed",
            Self::ParseFailed => "Unexpected whois response",
        }
    }
}

/// Error returned by target-lookup helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInfoError {
    kind: NetInfoErrorKind,
    detail: String,
}

impl NetInfoError {
    fn new(kind: NetInfoErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Error kind.
    pub fn kind(&self) -> NetInfoErrorKind {
        self.kind
    }

    /// Combined message for Status Bar / GUI display.
    pub fn message(&self) -> String {
        if self.detail.is_empty() {
            self.kind.label().to_owned()
        } else {
            format!("{}: {}", self.kind.label(), self.detail)
        }
    }
}

impl fmt::Display for NetInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for NetInfoError {}

/// Result alias for target-lookup helpers.
pub type NetInfoResult<T> = Result<T, NetInfoError>;

/// One Team Cymru whois record — `AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnRecord {
    /// Origin ASN, or `None` when the server reports `NA` (unrouted / private address space).
    pub asn: Option<u32>,
    /// Announced BGP prefix covering the queried IP.
    pub bgp_prefix: String,
    /// ISO country code of the registrant.
    pub country_code: String,
    /// Regional Internet Registry (arin/ripe/apnic/lacnic/afrinic).
    pub registry: String,
    /// Allocation date, as reported by the registry.
    pub allocated: String,
    /// Human-readable AS holder name.
    pub as_name: String,
}

/// Result of a full target lookup: the original input, the IP it resolved to, and the ASN
/// record for that IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnLookupResult {
    /// Exactly what the caller typed in (domain or IP), trimmed.
    pub queried_host: String,
    /// The IP address that was actually looked up (identical to `queried_host` when that was
    /// already an IP literal).
    pub resolved_ip: IpAddr,
    /// The parsed ASN record.
    pub record: AsnRecord,
}

/// Resolves `host` (domain or IP literal) and looks up its origin ASN via Team Cymru whois.
///
/// Blocking — intended to run on a background thread (`ApplicationService::start_target_lookup`
/// mirrors every other background read in this crate: `thread::spawn` + `mpsc::channel`).
pub fn lookup_target_asn(host: &str) -> NetInfoResult<AsnLookupResult> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(NetInfoError::new(
            NetInfoErrorKind::InvalidHost,
            "enter a domain or IP address".to_owned(),
        ));
    }

    let resolved_ip = resolve_host_to_ip(trimmed)?;
    let body = query_whois_cymru(resolved_ip)?;
    let record = parse_whois_cymru_response(&body)?;

    Ok(AsnLookupResult {
        queried_host: trimmed.to_owned(),
        resolved_ip,
        record,
    })
}

/// Resolves `host` to an IP address: parsed directly when it's already an IP literal, otherwise
/// resolved via the OS resolver (`std::net` — no DNS crate dependency). Prefers IPv4 when both
/// families are returned, purely for predictable/stable output; Team Cymru's whois service
/// answers IPv6 queries the same way, so IPv6-only hosts still work.
fn resolve_host_to_ip(host: &str) -> NetInfoResult<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    let addrs = (host, 0_u16).to_socket_addrs().map_err(|error| {
        NetInfoError::new(
            NetInfoErrorKind::ResolutionFailed,
            format!("could not resolve `{host}`: {error}"),
        )
    })?;

    let mut first_v6 = None;
    for addr in addrs {
        match addr.ip() {
            ip @ IpAddr::V4(_) => return Ok(ip),
            ip @ IpAddr::V6(_) if first_v6.is_none() => first_v6 = Some(ip),
            IpAddr::V6(_) => {}
        }
    }

    first_v6.ok_or_else(|| {
        NetInfoError::new(
            NetInfoErrorKind::ResolutionFailed,
            format!("`{host}` did not resolve to any address"),
        )
    })
}

/// Sends a single verbose query (`-v <ip>`) to `whois.cymru.com:43` and returns the raw response
/// body. The server answers with one line and closes the connection — no bulk `begin`/`end`
/// framing needed for a single-host lookup.
fn query_whois_cymru(ip: IpAddr) -> NetInfoResult<String> {
    let addr = (WHOIS_HOST, WHOIS_PORT)
        .to_socket_addrs()
        .map_err(|error| {
            NetInfoError::new(
                NetInfoErrorKind::ConnectionFailed,
                format!("could not resolve {WHOIS_HOST}: {error}"),
            )
        })?
        .next()
        .ok_or_else(|| {
            NetInfoError::new(
                NetInfoErrorKind::ConnectionFailed,
                format!("no address found for {WHOIS_HOST}"),
            )
        })?;

    let mut stream = TcpStream::connect_timeout(&addr, NETWORK_TIMEOUT).map_err(|error| {
        NetInfoError::new(
            NetInfoErrorKind::ConnectionFailed,
            format!("could not connect to {WHOIS_HOST}: {error}"),
        )
    })?;
    stream.set_read_timeout(Some(NETWORK_TIMEOUT)).ok();
    stream.set_write_timeout(Some(NETWORK_TIMEOUT)).ok();

    let query = format!(" -v {ip}\r\n");
    stream.write_all(query.as_bytes()).map_err(|error| {
        NetInfoError::new(
            NetInfoErrorKind::ConnectionFailed,
            format!("could not send query to {WHOIS_HOST}: {error}"),
        )
    })?;

    let mut body = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES as u64)
        .read_to_end(&mut body)
        .map_err(|error| {
            NetInfoError::new(
                NetInfoErrorKind::ConnectionFailed,
                format!("could not read response from {WHOIS_HOST}: {error}"),
            )
        })?;

    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Parses the first well-formed data line out of a Team Cymru whois response.
///
/// A verbose (`-v`) response line has exactly 7 pipe-delimited fields:
/// `AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name`. A bulk-mode response would
/// prepend a literal header line with the same shape but a non-numeric `AS` field (`"AS"`
/// itself) — naturally skipped here because it fails the "first field is an integer or `NA`"
/// check, so this same parser handles both single and (if ever needed) bulk framing without a
/// special case.
fn parse_whois_cymru_response(body: &str) -> NetInfoResult<AsnRecord> {
    for line in body.lines() {
        let fields: Vec<&str> = line.split('|').map(str::trim).collect();
        if fields.len() != 7 {
            continue;
        }
        let asn = if fields[0].eq_ignore_ascii_case("NA") {
            None
        } else if let Ok(asn) = fields[0].parse::<u32>() {
            Some(asn)
        } else {
            continue;
        };
        return Ok(AsnRecord {
            asn,
            bgp_prefix: fields[2].to_owned(),
            country_code: fields[3].to_owned(),
            registry: fields[4].to_owned(),
            allocated: fields[5].to_owned(),
            as_name: fields[6].to_owned(),
        });
    }
    Err(NetInfoError::new(
        NetInfoErrorKind::ParseFailed,
        "no recognizable AS record in whois response".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verbose_single_line_response() {
        let body = "23028|216.90.108.31|216.90.108.0/24|US|arin|1998-09-25|TEAM-CYMRU - Team Cymru Inc., US\n";
        let record = parse_whois_cymru_response(body).expect("parse");
        assert_eq!(record.asn, Some(23028));
        assert_eq!(record.bgp_prefix, "216.90.108.0/24");
        assert_eq!(record.country_code, "US");
        assert_eq!(record.registry, "arin");
        assert_eq!(record.allocated, "1998-09-25");
        assert_eq!(record.as_name, "TEAM-CYMRU - Team Cymru Inc., US");
    }

    #[test]
    fn skips_bulk_header_line_before_data_line() {
        let body = "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n\
                    23028   | 216.90.108.31    | 216.90.108.0/24     | US | arin     | 1998-09-25 | TEAM-CYMRU - Team Cymru Inc., US\n";
        let record = parse_whois_cymru_response(body).expect("parse");
        assert_eq!(record.asn, Some(23028));
    }

    #[test]
    fn na_asn_is_none_not_an_error() {
        let body = "NA | 10.0.0.1 | NA | NA | NA | NA | NA\n";
        let record = parse_whois_cymru_response(body).expect("parse");
        assert_eq!(record.asn, None);
    }

    #[test]
    fn rejects_response_with_no_data_line() {
        let error = parse_whois_cymru_response("garbage\n\n").unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::ParseFailed);
    }

    #[test]
    fn wrong_field_count_is_skipped() {
        let body = "not|enough|fields\n23028|216.90.108.31|216.90.108.0/24|US|arin|1998-09-25|TEAM-CYMRU\n";
        let record = parse_whois_cymru_response(body).expect("parse");
        assert_eq!(record.asn, Some(23028));
    }

    #[test]
    fn resolve_host_to_ip_parses_ip_literal_without_dns() {
        let ip = resolve_host_to_ip("8.8.8.8").expect("literal parses without DNS");
        assert_eq!(ip, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn empty_host_is_invalid() {
        let error = lookup_target_asn("   ").unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::InvalidHost);
    }

    #[test]
    fn error_message_combines_label_and_detail() {
        let error = NetInfoError::new(NetInfoErrorKind::ParseFailed, "boom".to_owned());
        assert_eq!(error.message(), "Unexpected whois response: boom");
    }
}
