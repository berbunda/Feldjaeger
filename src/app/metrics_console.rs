//! Metrics page view model — `metrics` HTTP endpoint (`/debug/vars`) scrape + dashboard
//! (Roadmap §3:130 — "Metrics scrape / dashboard integration").
//!
//! The Xray `metrics` section (`metrics.listen` / `metrics.tag`) has no structured editor yet
//! (Roadmap §2.1:53 is a separate, unchecked Tier‑2 item) — like `api`, it is preserved as an
//! opaque JSON object (`XrayConfigSections::metrics`). This page treats a configured
//! `metrics.listen` address as a *precondition* it cannot set up itself, mirroring the API
//! Console (`app::api_console`) — but it does **not** reuse that page's state machine, because
//! the precondition differs in a way that matters for this page's transport specifically: the
//! general wiring check (`stats_wiring_warnings`, Roadmap §2.5:106) treats a `metrics` section
//! reachable via `tag` + a routing rule as "wired correctly" in the general Xray sense (a real
//! Xray client could dial through that outbound tag), but Feldjäger's own scrape
//! (`xray::run_metrics_scrape`, SSH-exec `curl`/`wget` on the remote host) can only ever hit a
//! literal `listen` address — it has no way to become an Xray client of a routing-tag-based
//! outbound. So this page requires `metrics.listen` specifically, even in configurations the
//! wiring check would otherwise call "reachable".
//!
//! Once `metrics.listen` resolves, this page fetches `/debug/vars` (Go's `expvar` JSON, not
//! Prometheus text format — see `xray::remote_cli::metrics` doc) and exposes three sections built
//! from that single response:
//! - **Traffic**: reuses `app::stats_console`'s grouping/charting types (`TrafficCategory`,
//!   `TrafficSeriesDisplay`, `build_traffic_series`, `record_stats_sample`) against a *separate*
//!   history (`metrics_history` on `ApplicationService`, not `stats_history`) — same shape of
//!   dashboard as the Statistics page (Roadmap §3:129), reached through the `metrics` HTTP
//!   transport instead of `xray api statsquery`'s gRPC/SSH-exec transport (scope confirmed with
//!   the user).
//! - **Observatory**: live outbound health-check results — data unavailable anywhere else in
//!   Feldjäger (the read-only Observatory page, Roadmap §23, only shows static configuration).
//!   Free to include alongside the Traffic mirror: it comes from the same single fetch, at no
//!   extra SSH round trip.
//! - **Runtime**: a small subset of Go's default `memstats`/`cmdline` expvars — distinct from,
//!   and not a byte-for-byte match with, the Statistics page's `statssys` (a custom Xray RPC with
//!   different fields); labelled separately in the GUI so the two are never confused.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use super::inbounds::LoadedConfigSnapshot;
use super::stats_console::{
    StatDirection, TrafficCategory, TrafficSeriesDisplay, build_traffic_series, format_duration_nanos,
};
use super::status::SshStatus;
use crate::xray::{
    DebugVars, DiscoveryState, HealthPingMeasurement, MetricsMemStats, ObservatoryOutboundStatus,
    RemoteCliResult, StatCounter, XrayConfigSections, stats_wiring_warnings,
};

/// High-level state shown by the Metrics page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded, but `metrics.listen` is absent or empty.
    MetricsNotConfigured,
    /// `metrics.listen` resolved — the endpoint can be scraped.
    Ready,
}

impl MetricsPageState {
    /// User-facing explanation for this state.
    pub fn message(self) -> &'static str {
        match self {
            Self::NoSshConnection => {
                "No SSH connection. Connect to a server on the Connection page first."
            }
            Self::XrayNotDiscovered => {
                "Xray installation not discovered. Run Discover Xray on the Connection page."
            }
            Self::ConfigurationNotLoaded => {
                "Configuration not loaded. Discover Xray again after the config becomes readable."
            }
            Self::MetricsNotConfigured => {
                "No `metrics.listen` address in the loaded configuration. A `tag`-only `metrics` \
                 section cannot be scraped by Feldjäger (it would require acting as an Xray \
                 client dialed through routing, not a plain HTTP fetch) — add `listen` through \
                 the Raw JSON editor (the Outbounds page's Raw JSON action on any outbound, or \
                 add the `metrics` object directly to a confdir file), e.g. `\"metrics\": \
                 {\"listen\": \"127.0.0.1:11111\"}`, then restart or reload Xray."
            }
            Self::Ready => "Connected to the live Xray metrics endpoint.",
        }
    }
}

/// Reads `metrics.listen` from the loaded configuration's `metrics` section, if present and
/// non-empty.
pub fn resolve_metrics_listen(sections: &XrayConfigSections) -> Option<String> {
    let listen = sections.metrics()?.value().get("listen")?.as_str()?;
    let trimmed = listen.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Derives the Metrics page state from connection, discovery, and config state.
pub fn derive_metrics_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> MetricsPageState {
    if ssh != SshStatus::Connected {
        return MetricsPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => MetricsPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                MetricsPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded { editable, .. } => {
                let Some(editable) = editable else {
                    return MetricsPageState::ConfigurationNotLoaded;
                };
                match resolve_metrics_listen(editable.sections()) {
                    Some(_) => MetricsPageState::Ready,
                    None => MetricsPageState::MetricsNotConfigured,
                }
            }
        },
    }
}

/// Live snapshot of the scrape channel, as tracked by [`super::ApplicationService`].
pub struct MetricsScrapeSnapshot<'a> {
    /// `true` while a scrape is in flight.
    pub is_running: bool,
    /// Result of the last completed scrape, already parsed.
    pub last_result: Option<&'a RemoteCliResult<DebugVars>>,
    /// Accumulated per-counter traffic history, separate from the Statistics page's
    /// `stats_history` (different transport — kept apart so one page's refresh cadence never
    /// perturbs the other's charts).
    pub history: &'a HashMap<String, VecDeque<(Instant, i64)>>,
}

/// One outbound's live Observatory status, formatted for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryRowDisplay {
    /// Outbound tag under observation.
    pub outbound_tag: String,
    /// Whether the outbound currently passes its health check.
    pub alive: bool,
    /// Probe round-trip time, e.g. `"42 ms"`, or `"—"` when unavailable.
    pub delay_display: String,
    /// Last probe failure reason, or `"—"`.
    pub last_error_reason: String,
    /// Last time this outbound was seen alive, formatted, or `"—"`.
    pub last_seen_display: String,
    /// Last time this outbound was probed at all, formatted, or `"—"`.
    pub last_try_display: String,
    /// Aggregate ping measurement summary, when published.
    pub health_ping_display: Option<String>,
}

fn format_unix_seconds(unix: i64) -> String {
    if unix <= 0 {
        return "—".to_owned();
    }
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| unix.to_string())
}

fn health_ping_display(ping: &HealthPingMeasurement) -> String {
    format!(
        "avg {} ms · min {} ms · max {} ms · {}/{} failed",
        ping.average, ping.min, ping.max, ping.fail, ping.all
    )
}

fn observatory_row_display(status: &ObservatoryOutboundStatus) -> ObservatoryRowDisplay {
    ObservatoryRowDisplay {
        outbound_tag: status.outbound_tag.clone(),
        alive: status.alive,
        delay_display: if status.delay_ms > 0 {
            format!("{} ms", status.delay_ms)
        } else {
            "—".to_owned()
        },
        last_error_reason: if status.last_error_reason.is_empty() {
            "—".to_owned()
        } else {
            status.last_error_reason.clone()
        },
        last_seen_display: format_unix_seconds(status.last_seen_time),
        last_try_display: format_unix_seconds(status.last_try_time),
        health_ping_display: status.health_ping.as_ref().map(health_ping_display),
    }
}

/// Runtime memory/GC snapshot, formatted for display (from the default `memstats` expvar — not
/// the Statistics page's `statssys`, see module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemStatsDisplay {
    /// Bytes of heap objects currently in use.
    pub alloc: String,
    /// Cumulative bytes allocated over the process lifetime.
    pub total_alloc: String,
    /// Total bytes obtained from the OS.
    pub sys: String,
    /// Cumulative heap object allocation count.
    pub mallocs: String,
    /// Cumulative heap object free count.
    pub frees: String,
    /// Live heap object count.
    pub heap_objects: String,
    /// Completed GC cycle count.
    pub num_gc: String,
    /// Cumulative time spent in GC stop-the-world pauses.
    pub pause_total: String,
}

fn memstats_display(stats: &MetricsMemStats) -> MemStatsDisplay {
    MemStatsDisplay {
        alloc: super::geodata::format_size(stats.alloc),
        total_alloc: super::geodata::format_size(stats.total_alloc),
        sys: super::geodata::format_size(stats.sys),
        mallocs: stats.mallocs.to_string(),
        frees: stats.frees.to_string(),
        heap_objects: stats.heap_objects.to_string(),
        num_gc: stats.num_gc.to_string(),
        pause_total: format_duration_nanos(stats.pause_total_ns),
    }
}

/// Read-only model exposed to the Metrics page.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricsPageModel {
    /// Coarse page state.
    pub state: MetricsPageState,
    /// Resolved `metrics.listen` address, present only when `state == Ready`.
    pub listen_addr: Option<String>,
    /// `stats` ↔ `policy` ↔ `api` ↔ `metrics` wiring warnings (Roadmap §2.5:106) — explains why a
    /// traffic counter might read "No data yet" even though the scrape itself succeeds.
    pub wiring_warnings: Vec<String>,
    /// `true` while a scrape is in flight.
    pub is_running: bool,
    /// Error from the last scrape, if it failed.
    pub last_error: Option<String>,
    /// One row per known inbound/outbound tag × direction — same shape as the Statistics page.
    pub traffic: Vec<TrafficSeriesDisplay>,
    /// Counters that don't match a known inbound/outbound tag (per-user counters, stale tags).
    pub other_counters: Vec<StatCounter>,
    /// Live Observatory status, one row per outbound under observation, sorted by tag.
    pub observatory: Vec<ObservatoryRowDisplay>,
    /// Runtime memory/GC snapshot, when `memstats` was published in the last successful scrape.
    pub memstats: Option<MemStatsDisplay>,
    /// Process argv (`cmdline` expvar), joined with spaces, when published.
    pub cmdline: Option<String>,
}

/// Builds the Metrics page model from connection/discovery/config state plus the scrape
/// channel's current snapshot.
pub fn build_metrics_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    scrape: MetricsScrapeSnapshot<'_>,
) -> MetricsPageModel {
    let state = derive_metrics_page_state(ssh, discovery, config);
    let sections = config.editable().map(|editable| editable.sections());
    let listen_addr = sections.and_then(resolve_metrics_listen);
    let wiring_warnings = sections.map(stats_wiring_warnings).unwrap_or_default();

    let mut known_names: HashSet<String> = HashSet::new();
    let mut traffic = Vec::new();
    for (category, tags) in [
        (
            TrafficCategory::Inbound,
            config
                .inbounds()
                .iter()
                .filter_map(|i| i.tag.as_deref())
                .collect::<Vec<_>>(),
        ),
        (
            TrafficCategory::Outbound,
            config
                .outbounds()
                .iter()
                .filter_map(|o| o.tag.as_deref())
                .collect::<Vec<_>>(),
        ),
    ] {
        for tag in tags {
            for direction in [StatDirection::Uplink, StatDirection::Downlink] {
                let name = super::stats_console::traffic_counter_name(category, tag, direction);
                known_names.insert(name.clone());
                traffic.push(build_traffic_series(category, tag, direction, &name, scrape.history));
            }
        }
    }

    let (last_error, other_counters, observatory, memstats, cmdline) = match scrape.last_result {
        Some(Ok(vars)) => (
            None,
            vars.stats
                .iter()
                .filter(|counter| !known_names.contains(&counter.name))
                .cloned()
                .collect(),
            vars.observatory.iter().map(observatory_row_display).collect(),
            vars.memstats.as_ref().map(memstats_display),
            if vars.cmdline.is_empty() {
                None
            } else {
                Some(vars.cmdline.join(" "))
            },
        ),
        Some(Err(error)) => (Some(error.message()), Vec::new(), Vec::new(), None, None),
        None => (None, Vec::new(), Vec::new(), None, None),
    };

    MetricsPageModel {
        state,
        listen_addr,
        wiring_warnings,
        is_running: scrape.is_running,
        last_error,
        traffic,
        other_counters,
        observatory,
        memstats,
        cmdline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{
        ConfigSource, EditableXrayConfig, InboundSummary, InitSystemKind, OutboundSummary,
        RemoteCliError, RemoteCliErrorKind, XrayConfigParser, XrayInstallation,
    };

    fn succeeded(config_source: ConfigSource) -> DiscoveryState {
        DiscoveryState::Succeeded(XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: None,
            version: None,
            service_name: None,
            service_state: None,
            exec_start: None,
            config_source,
            config_readable: true,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        })
    }

    fn editable_from(path: &str, json: &str) -> EditableXrayConfig {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file(path, json);
        assert!(!outcome.has_fatal_errors(), "{:?}", outcome.errors());
        let root: serde_json::Value = serde_json::from_str(json).expect("json");
        EditableXrayConfig::from_single_file(path, root, outcome.into_sections())
    }

    fn loaded(
        editable: Option<EditableXrayConfig>,
        inbounds: Vec<InboundSummary>,
        outbounds: Vec<OutboundSummary>,
    ) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds,
            outbounds,
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable,
        }
    }

    fn inbound_summary(tag: &str) -> InboundSummary {
        InboundSummary {
            index: 0,
            tag: Some(tag.to_owned()),
            protocol: Some("vless".to_owned()),
            listen: None,
            port: None,
            clients_count: None,
            source_file: "/etc/xray/config.json".to_owned(),
        }
    }

    fn outbound_summary(tag: &str) -> OutboundSummary {
        OutboundSummary {
            index: 0,
            tag: Some(tag.to_owned()),
            protocol: Some("freedom".to_owned()),
            send_through: None,
            description: String::new(),
            source_file: "/etc/xray/config.json".to_owned(),
        }
    }

    #[test]
    fn resolves_listen_when_present() {
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{"metrics":{"tag":"Metrics","listen":"127.0.0.1:11111"}}"#,
        );
        assert_eq!(
            resolve_metrics_listen(editable.sections()),
            Some("127.0.0.1:11111".to_owned())
        );
    }

    #[test]
    fn tag_only_metrics_is_not_configured_for_this_page() {
        // Unlike `stats_wiring_warnings`' general reachability check, a `tag`-only `metrics`
        // section (reachable in the general Xray sense via routing) is still not scrapable by
        // Feldjäger — only `listen` matters here.
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{
                "metrics":{"tag":"metrics-out"},
                "routing":{"rules":[{"inboundTag":["m-in"],"outboundTag":"metrics-out"}]}
            }"#,
        );
        assert_eq!(resolve_metrics_listen(editable.sections()), None);
        let source = ConfigSource::SingleFile(
            feldjaeger_ssh::RemotePath::new("/etc/xray/config.json").unwrap(),
        );
        let model = build_metrics_page_model(
            SshStatus::Connected,
            &succeeded(source),
            &loaded(Some(editable), Vec::new(), Vec::new()),
            MetricsScrapeSnapshot {
                is_running: false,
                last_result: None,
                history: &HashMap::new(),
            },
        );
        assert_eq!(model.state, MetricsPageState::MetricsNotConfigured);
    }

    #[test]
    fn blank_listen_is_treated_as_absent() {
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{"metrics":{"listen":"   "}}"#,
        );
        assert_eq!(resolve_metrics_listen(editable.sections()), None);
    }

    #[test]
    fn build_model_groups_known_tags_and_buckets_the_rest_as_other() {
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{"metrics":{"listen":"127.0.0.1:11111"}}"#,
        );
        let source = ConfigSource::SingleFile(
            feldjaeger_ssh::RemotePath::new("/etc/xray/config.json").unwrap(),
        );
        let config = loaded(
            Some(editable),
            vec![inbound_summary("proxy-in")],
            vec![outbound_summary("direct")],
        );

        let mut history = HashMap::new();
        let now = Instant::now();
        let counters = vec![
            StatCounter {
                name: "inbound>>>proxy-in>>>traffic>>>uplink".to_owned(),
                value: 1000,
            },
            StatCounter {
                name: "user>>>someone@example.com>>>traffic>>>uplink".to_owned(),
                value: 42,
            },
        ];
        crate::app::stats_console::record_stats_sample(&mut history, &counters, now);
        let debug_vars = DebugVars {
            stats: counters,
            observatory: vec![ObservatoryOutboundStatus {
                outbound_tag: "direct".to_owned(),
                alive: true,
                delay_ms: 12,
                last_error_reason: String::new(),
                last_seen_time: 1_700_000_000,
                last_try_time: 1_700_000_005,
                health_ping: None,
            }],
            memstats: Some(MetricsMemStats {
                alloc: 2_097_152,
                ..Default::default()
            }),
            cmdline: vec!["/usr/local/bin/xray".to_owned(), "run".to_owned()],
        };
        let last_result: RemoteCliResult<DebugVars> = Ok(debug_vars);

        let model = build_metrics_page_model(
            SshStatus::Connected,
            &succeeded(source),
            &config,
            MetricsScrapeSnapshot {
                is_running: false,
                last_result: Some(&last_result),
                history: &history,
            },
        );

        assert_eq!(model.state, MetricsPageState::Ready);
        assert_eq!(model.traffic.len(), 4);
        let inbound_uplink = model
            .traffic
            .iter()
            .find(|s| s.category == TrafficCategory::Inbound && s.direction == StatDirection::Uplink)
            .unwrap();
        assert_eq!(inbound_uplink.current_display, "1000 B");
        assert_eq!(model.other_counters.len(), 1);
        assert_eq!(model.observatory.len(), 1);
        assert!(model.observatory[0].alive);
        assert_eq!(model.observatory[0].delay_display, "12 ms");
        assert_eq!(model.memstats.as_ref().unwrap().alloc, "2.0 MB");
        assert_eq!(model.cmdline.as_deref(), Some("/usr/local/bin/xray run"));
    }

    #[test]
    fn build_model_surfaces_scrape_error() {
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{"metrics":{"listen":"127.0.0.1:11111"}}"#,
        );
        let source = ConfigSource::SingleFile(
            feldjaeger_ssh::RemotePath::new("/etc/xray/config.json").unwrap(),
        );
        let config = loaded(Some(editable), Vec::new(), Vec::new());
        let history = HashMap::new();
        let error: RemoteCliResult<DebugVars> =
            Err(RemoteCliError::new(RemoteCliErrorKind::NonZeroExit, "boom".to_owned()));

        let model = build_metrics_page_model(
            SshStatus::Connected,
            &succeeded(source),
            &config,
            MetricsScrapeSnapshot {
                is_running: true,
                last_result: Some(&error),
                history: &history,
            },
        );

        assert!(model.last_error.unwrap().contains("boom"));
        assert!(model.is_running);
        assert!(model.other_counters.is_empty());
    }
}
