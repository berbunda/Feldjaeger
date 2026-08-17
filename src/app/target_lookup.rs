//! Target Lookup page view model (Roadmap §3:131 — "SNI / Dest / host target search by ASN").
//!
//! Unlike every other page in this crate, Target Lookup has **no SSH precondition** — it never
//! touches the managed Xray host, `ApplicationService`'s SSH session, or any loaded
//! configuration. It is a standalone authoring aid: type a domain or IP you're considering for a
//! REALITY `dest`, a TLS `serverName`, or a routing `domain` matcher, and see which
//! organization/ASN actually owns it (`crate::netinfo::lookup_target_asn`) — helps judge whether
//! a candidate target is a plausible camouflage host before wiring it into a config. Usable with
//! or without an active connection.

use crate::netinfo::{AsnLookupResult, ScanCandidateRow};

/// Formatted result row for the Target Lookup page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetLookupResultDisplay {
    /// Exactly what the user typed in.
    pub queried_host: String,
    /// The IP address that was actually looked up.
    pub resolved_ip: String,
    /// Origin ASN, formatted (`"AS23028"`), or `"—"` when unrouted/private (`NA`).
    pub asn: String,
    /// AS holder name, or `"—"` when unavailable.
    pub as_name: String,
    /// Announced BGP prefix, or `"—"`.
    pub bgp_prefix: String,
    /// Registrant country code, or `"—"`.
    pub country_code: String,
    /// Registry (arin/ripe/apnic/lacnic/afrinic), or `"—"`.
    pub registry: String,
    /// Allocation date, as reported by the registry, or `"—"`.
    pub allocated: String,
}

fn display_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("NA") {
        "—".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Formats a raw [`AsnLookupResult`] for display.
pub fn target_lookup_result_display(result: &AsnLookupResult) -> TargetLookupResultDisplay {
    TargetLookupResultDisplay {
        queried_host: result.queried_host.clone(),
        resolved_ip: result.resolved_ip.to_string(),
        asn: result
            .record
            .asn
            .map(|asn| format!("AS{asn}"))
            .unwrap_or_else(|| "—".to_owned()),
        as_name: display_field(&result.record.as_name),
        bgp_prefix: display_field(&result.record.bgp_prefix),
        country_code: display_field(&result.record.country_code),
        registry: display_field(&result.record.registry),
        allocated: display_field(&result.record.allocated),
    }
}

/// Read-only model exposed to the Target Lookup page.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetLookupPageModel {
    /// `true` while a lookup is in flight.
    pub is_running: bool,
    /// The host the last lookup was started for (kept even after failure, so the GUI can show
    /// "no result for X" rather than blanking the last input).
    pub last_queried_host: Option<String>,
    /// Formatted result of the last successful lookup.
    pub result: Option<TargetLookupResultDisplay>,
    /// Error message from the last failed lookup.
    pub error: Option<String>,
}

/// Snapshot of the lookup channel, as tracked by [`super::ApplicationService`].
pub struct TargetLookupSnapshot<'a> {
    /// `true` while a lookup is in flight.
    pub is_running: bool,
    /// Host the in-flight or last-completed lookup was started for.
    pub host: Option<&'a str>,
    /// Result of the last completed lookup, if any.
    pub last_result: Option<&'a Result<AsnLookupResult, String>>,
}

/// Builds the Target Lookup page model.
pub fn build_target_lookup_page_model(snapshot: TargetLookupSnapshot<'_>) -> TargetLookupPageModel {
    let (result, error) = match snapshot.last_result {
        Some(Ok(lookup)) => (Some(target_lookup_result_display(lookup)), None),
        Some(Err(message)) => (None, Some(message.clone())),
        None => (None, None),
    };
    TargetLookupPageModel {
        is_running: snapshot.is_running,
        last_queried_host: snapshot.host.map(str::to_owned),
        result,
        error,
    }
}

// ─── AS-range REALITY candidate scan (Roadmap §3:131 follow-up) ───────────────

/// One valid REALITY `dest` candidate, formatted for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRowDisplay {
    /// The candidate IP.
    pub ip: String,
    /// PTR (reverse DNS) domain, confirmed to forward-resolve back to `ip`.
    pub domain: String,
    /// `dNSName` entries from the certificate's SAN extension, joined for display.
    pub cert_domains: String,
    /// Negotiated ALPN protocol.
    pub alpn: String,
    /// Negotiated key-exchange group.
    pub curve: String,
}

fn scan_row_display(row: &ScanCandidateRow) -> ScanRowDisplay {
    ScanRowDisplay {
        ip: row.ip.to_string(),
        domain: row.domain.clone(),
        cert_domains: if row.cert_domains.is_empty() {
            "—".to_owned()
        } else {
            row.cert_domains.join(", ")
        },
        alpn: row.alpn.clone(),
        curve: row.curve.clone(),
    }
}

/// Reads a usable BGP prefix out of an ASN lookup result, `None` when absent/`NA` (mirrors
/// [`display_field`]'s blank/`NA` handling, but returns `Option` instead of a display string —
/// this feeds a `bool`/button-enablement decision, not a label).
pub(crate) fn candidate_prefix(result: &AsnLookupResult) -> Option<String> {
    let prefix = result.record.bgp_prefix.trim();
    if prefix.is_empty() || prefix.eq_ignore_ascii_case("NA") {
        None
    } else {
        Some(prefix.to_owned())
    }
}

/// Read-only model for the AS-range scan section (below the ASN lookup result on the same page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetScanPageModel {
    /// `true` only when the *current* ASN lookup result carries a usable BGP prefix — controls
    /// whether the Scan button is enabled at all.
    pub available: bool,
    /// The prefix a click on Scan would target right now (from the current ASN result) —
    /// independent of `scanned_prefix` below, which reflects what's actually shown.
    pub available_prefix: Option<String>,
    /// The prefix the progress/rows below actually belong to — captured at the moment Scan was
    /// last clicked, so it doesn't shift under the user if they run a new ASN lookup mid-scan.
    pub scanned_prefix: Option<String>,
    /// True host count in `scanned_prefix` (before the 256 cap).
    pub prefix_total: Option<usize>,
    /// How many addresses this run actually checks (`min(prefix_total, 256)`).
    pub capped_total: usize,
    /// `true` while a scan is in flight.
    pub is_running: bool,
    /// How many addresses have been checked so far in the current/last run.
    pub checked: usize,
    /// Valid candidates found so far, in discovery order.
    pub rows: Vec<ScanRowDisplay>,
}

/// Snapshot of the scan channel plus the prefix it was started for, as tracked by
/// [`super::ApplicationService`].
pub struct TargetScanSnapshot<'a> {
    /// The prefix the current/last scan run targeted (`None` before the first run).
    pub scanned_prefix: Option<&'a str>,
    /// True host count in `scanned_prefix`.
    pub prefix_total: Option<usize>,
    /// How many addresses this run actually checks.
    pub capped_total: usize,
    /// `true` while a scan is in flight.
    pub is_running: bool,
    /// How many addresses have been checked so far.
    pub checked: usize,
    /// Valid candidates found so far.
    pub rows: &'a [ScanCandidateRow],
}

/// Builds the scan section's model from the current ASN lookup result (for button
/// availability/target prefix) and the scan channel's snapshot (for progress/rows).
pub fn build_target_scan_page_model(
    asn_result: Option<&AsnLookupResult>,
    scan: TargetScanSnapshot<'_>,
) -> TargetScanPageModel {
    let available_prefix = asn_result.and_then(candidate_prefix);
    TargetScanPageModel {
        available: available_prefix.is_some(),
        available_prefix,
        scanned_prefix: scan.scanned_prefix.map(str::to_owned),
        prefix_total: scan.prefix_total,
        capped_total: scan.capped_total,
        is_running: scan.is_running,
        checked: scan.checked,
        rows: scan.rows.iter().map(scan_row_display).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netinfo::AsnRecord;
    use std::net::IpAddr;

    fn sample_result() -> AsnLookupResult {
        AsnLookupResult {
            queried_host: "example.com".to_owned(),
            resolved_ip: "93.184.216.34".parse::<IpAddr>().unwrap(),
            record: AsnRecord {
                asn: Some(23028),
                bgp_prefix: "93.184.216.0/24".to_owned(),
                country_code: "US".to_owned(),
                registry: "arin".to_owned(),
                allocated: "1998-09-25".to_owned(),
                as_name: "TEAM-CYMRU - Team Cymru Inc., US".to_owned(),
            },
        }
    }

    #[test]
    fn formats_successful_result() {
        let display = target_lookup_result_display(&sample_result());
        assert_eq!(display.asn, "AS23028");
        assert_eq!(display.resolved_ip, "93.184.216.34");
        assert_eq!(display.as_name, "TEAM-CYMRU - Team Cymru Inc., US");
    }

    #[test]
    fn na_fields_display_as_dash() {
        let mut result = sample_result();
        result.record.asn = None;
        result.record.bgp_prefix = "NA".to_owned();
        let display = target_lookup_result_display(&result);
        assert_eq!(display.asn, "—");
        assert_eq!(display.bgp_prefix, "—");
    }

    #[test]
    fn model_idle_by_default() {
        let model = build_target_lookup_page_model(TargetLookupSnapshot {
            is_running: false,
            host: None,
            last_result: None,
        });
        assert!(!model.is_running);
        assert!(model.result.is_none());
        assert!(model.error.is_none());
        assert!(model.last_queried_host.is_none());
    }

    #[test]
    fn model_surfaces_error() {
        let last: Result<AsnLookupResult, String> = Err("DNS resolution failed".to_owned());
        let model = build_target_lookup_page_model(TargetLookupSnapshot {
            is_running: false,
            host: Some("bad-host"),
            last_result: Some(&last),
        });
        assert_eq!(model.last_queried_host.as_deref(), Some("bad-host"));
        assert_eq!(model.error.as_deref(), Some("DNS resolution failed"));
        assert!(model.result.is_none());
    }

    #[test]
    fn model_surfaces_success() {
        let last: Result<AsnLookupResult, String> = Ok(sample_result());
        let model = build_target_lookup_page_model(TargetLookupSnapshot {
            is_running: true,
            host: Some("example.com"),
            last_result: Some(&last),
        });
        assert!(model.is_running);
        assert!(model.error.is_none());
        assert_eq!(model.last_queried_host.as_deref(), Some("example.com"));
        assert_eq!(model.result.unwrap().asn, "AS23028");
    }

    // ─── AS-range scan model ────────────────────────────────────────────────

    fn sample_scan_row() -> ScanCandidateRow {
        ScanCandidateRow {
            ip: "93.184.216.5".parse().unwrap(),
            domain: "example.com".to_owned(),
            cert_domains: vec!["example.com".to_owned(), "*.example.com".to_owned()],
            alpn: "h2".to_owned(),
            curve: "X25519MLKEM768".to_owned(),
        }
    }

    #[test]
    fn scan_unavailable_without_a_bgp_prefix() {
        let mut result = sample_result();
        result.record.bgp_prefix = "NA".to_owned();
        let model = build_target_scan_page_model(
            Some(&result),
            TargetScanSnapshot {
                scanned_prefix: None,
                prefix_total: None,
                capped_total: 0,
                is_running: false,
                checked: 0,
                rows: &[],
            },
        );
        assert!(!model.available);
        assert!(model.available_prefix.is_none());
    }

    #[test]
    fn scan_available_when_asn_result_has_a_prefix() {
        let result = sample_result();
        let model = build_target_scan_page_model(
            Some(&result),
            TargetScanSnapshot {
                scanned_prefix: None,
                prefix_total: None,
                capped_total: 0,
                is_running: false,
                checked: 0,
                rows: &[],
            },
        );
        assert!(model.available);
        assert_eq!(model.available_prefix.as_deref(), Some("93.184.216.0/24"));
    }

    #[test]
    fn scanned_prefix_is_independent_of_the_current_asn_result() {
        // Simulates: scan was started for one prefix, then the user looked up a different host —
        // the scan section should keep showing the prefix it actually scanned.
        let new_lookup = AsnLookupResult {
            queried_host: "other.example".to_owned(),
            resolved_ip: "1.2.3.4".parse().unwrap(),
            record: AsnRecord {
                asn: Some(999),
                bgp_prefix: "1.2.3.0/24".to_owned(),
                country_code: "US".to_owned(),
                registry: "arin".to_owned(),
                allocated: "2000-01-01".to_owned(),
                as_name: "OTHER".to_owned(),
            },
        };
        let rows = vec![sample_scan_row()];
        let model = build_target_scan_page_model(
            Some(&new_lookup),
            TargetScanSnapshot {
                scanned_prefix: Some("93.184.216.0/24"),
                prefix_total: Some(254),
                capped_total: 254,
                is_running: false,
                checked: 254,
                rows: &rows,
            },
        );
        assert_eq!(model.available_prefix.as_deref(), Some("1.2.3.0/24"));
        assert_eq!(model.scanned_prefix.as_deref(), Some("93.184.216.0/24"));
        assert_eq!(model.rows.len(), 1);
    }

    #[test]
    fn scan_row_display_joins_cert_domains_and_dashes_when_empty() {
        let row = scan_row_display(&sample_scan_row());
        assert_eq!(row.cert_domains, "example.com, *.example.com");

        let mut empty = sample_scan_row();
        empty.cert_domains = Vec::new();
        assert_eq!(scan_row_display(&empty).cert_domains, "—");
    }

    #[test]
    fn scan_progress_and_rows_reflected_in_model() {
        let result = sample_result();
        let rows = vec![sample_scan_row()];
        let model = build_target_scan_page_model(
            Some(&result),
            TargetScanSnapshot {
                scanned_prefix: Some("93.184.216.0/24"),
                prefix_total: Some(254),
                capped_total: 254,
                is_running: true,
                checked: 42,
                rows: &rows,
            },
        );
        assert!(model.is_running);
        assert_eq!(model.checked, 42);
        assert_eq!(model.prefix_total, Some(254));
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].ip, "93.184.216.5");
    }
}
