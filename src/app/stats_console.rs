//! Stats page view model — live `xray api statsquery`/`statssys` read + charts (Roadmap §3:129).
//!
//! Preconditions are identical to the API Console (§3:128, `app::api_console`): a resolved
//! `api.listen` address. This module reuses [`super::api_console::ApiConsolePageState`] /
//! [`super::api_console::derive_api_console_page_state`] rather than duplicating that
//! state machine — the only Stats-specific addition is checking `api.services` for
//! `StatsService` instead of `HandlerService`/`RoutingService`/`LoggerService`.
//!
//! Unlike the API Console (which shows every subcommand's output as read-only monotext because
//! the shapes are unstable / undocumented), `statsquery`/`statssys` have a stable, documented
//! JSON shape (`xray::parse_stats_query_stdout`/`parse_stats_sys_stdout`) — so this page can
//! group counters by the documented `inbound>>>{tag}>>>traffic>>>{uplink|downlink}` /
//! `outbound>>>...` naming convention and chart them, instead of dumping raw text.
//!
//! Feldjäger fetches **all** counters in one call (empty `-pattern`) and groups/filters
//! client-side — cheaper than one remote round-trip per selected tag, and it means the set of
//! chartable series is always in sync with what Xray is actually collecting. Per-user
//! (`user>>>{email}>>>...`) counters and anything else that doesn't match a known inbound/
//! outbound tag fall into [`StatsPageModel::other_counters`] as a flat read-only list — visible,
//! not hidden, per `rules.md`'s "must not hide configuration options" — but not charted; the
//! user asked for a categorized inbound/outbound picker, not a per-user or free-form regex view.
//! `-reset` is never used by this page's read path (see `super::api_ops::stats_query_all_request`
//! doc comment) — a passive dashboard must not zero counters another tool might also be polling.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use super::api_console::{
    ApiConsolePageState, derive_api_console_page_state, resolve_api_listen, resolve_api_services,
};
use super::geodata::format_size;
use super::inbounds::LoadedConfigSnapshot;
use super::status::SshStatus;
use crate::xray::{DiscoveryState, RemoteCliResult, StatCounter, SysStats, stats_wiring_warnings};

/// Traffic direction, as encoded in Xray's counter naming convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatDirection {
    /// `...>>>traffic>>>uplink`.
    Uplink,
    /// `...>>>traffic>>>downlink`.
    Downlink,
}

impl StatDirection {
    /// Label used both in the counter name and the GUI.
    pub fn label(self) -> &'static str {
        match self {
            Self::Uplink => "uplink",
            Self::Downlink => "downlink",
        }
    }
}

/// Which side of the proxy a traffic counter belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficCategory {
    /// `inbound>>>{tag}>>>...`.
    Inbound,
    /// `outbound>>>{tag}>>>...`.
    Outbound,
}

impl TrafficCategory {
    /// Sidebar/section label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Inbound => "Inbound",
            Self::Outbound => "Outbound",
        }
    }

    fn xray_prefix(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// Builds the exact Xray counter name for one tag + direction, e.g.
/// `inbound>>>proxy-in>>>traffic>>>uplink`.
pub fn traffic_counter_name(category: TrafficCategory, tag: &str, direction: StatDirection) -> String {
    format!(
        "{}>>>{}>>>traffic>>>{}",
        category.xray_prefix(),
        tag,
        direction.label()
    )
}

/// Bounds how many samples are retained per counter (manual refresh only — at one click per
/// second this is ~2 minutes of history; in practice refreshes are far less frequent, so this is
/// effectively "since the page was opened" for any realistic usage).
const STATS_HISTORY_CAP: usize = 120;

/// Appends one sample per counter to `history`, trimming each series to [`STATS_HISTORY_CAP`].
/// Pure state mutation — call once per successful `statsquery` response.
pub fn record_stats_sample(
    history: &mut HashMap<String, VecDeque<(Instant, i64)>>,
    counters: &[StatCounter],
    now: Instant,
) {
    for counter in counters {
        let series = history.entry(counter.name.clone()).or_default();
        series.push_back((now, counter.value));
        while series.len() > STATS_HISTORY_CAP {
            series.pop_front();
        }
    }
}

/// Average throughput between the last two samples of `series`, formatted (e.g. `"12.3 KB/s"`).
/// `None` when there are fewer than two samples, the gap is too short to be meaningful (< 0.5s —
/// guards against a division blow-up on back-to-back clicks), or the counter went backwards
/// (someone/something else reset it — a negative rate would be misleading, not informative).
fn rate_since_previous_sample(series: &VecDeque<(Instant, i64)>) -> Option<String> {
    let mut iter = series.iter().rev();
    let &(t_last, v_last) = iter.next()?;
    let &(t_prev, v_prev) = iter.next()?;
    let elapsed_secs = t_last.checked_duration_since(t_prev)?.as_secs_f64();
    if elapsed_secs < 0.5 {
        return None;
    }
    let delta = v_last - v_prev;
    if delta < 0 {
        return None;
    }
    let bytes_per_sec = delta as f64 / elapsed_secs;
    Some(format!("{}/s", format_size(bytes_per_sec.round() as u64)))
}

/// One inbound/outbound traffic counter, ready for display (sparkline + current + rate).
#[derive(Debug, Clone, PartialEq)]
pub struct TrafficSeriesDisplay {
    /// Inbound or Outbound.
    pub category: TrafficCategory,
    /// Inbound/outbound `tag` this counter belongs to.
    pub tag: String,
    /// Uplink or downlink.
    pub direction: StatDirection,
    /// Formatted current value (`"3.4 MB"`), or `"No data yet"` before the first successful
    /// fetch that included this counter.
    pub current_display: String,
    /// Formatted average throughput since the previous sample, when computable.
    pub rate_display: Option<String>,
    /// Raw historical values, oldest first, for the sparkline (bounded by
    /// [`STATS_HISTORY_CAP`]).
    pub points: Vec<i64>,
}

// `pub(super)`: reused by `app::metrics_console` (Roadmap §3:130), which builds the same
// `TrafficSeriesDisplay` rows from the `metrics` HTTP endpoint's counters instead of
// `xray api statsquery`'s — same grouping/charting logic, different transport.
pub(super) fn build_traffic_series(
    category: TrafficCategory,
    tag: &str,
    direction: StatDirection,
    name: &str,
    history: &HashMap<String, VecDeque<(Instant, i64)>>,
) -> TrafficSeriesDisplay {
    let series = history.get(name);
    let points: Vec<i64> = series
        .map(|s| s.iter().map(|(_, value)| *value).collect())
        .unwrap_or_default();
    let current_display = match points.last() {
        Some(value) => format_size((*value).max(0) as u64),
        None => "No data yet".to_owned(),
    };
    let rate_display = series.and_then(rate_since_previous_sample);
    TrafficSeriesDisplay {
        category,
        tag: tag.to_owned(),
        direction,
        current_display,
        rate_display,
        points,
    }
}

/// Formatted `xray api statssys` snapshot (process uptime, goroutines, memory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysStatsDisplay {
    /// Process uptime, e.g. `"2h 14m 03s"`.
    pub uptime: String,
    /// Current goroutine count.
    pub num_goroutine: String,
    /// Completed GC cycle count.
    pub num_gc: String,
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
    /// `Mallocs - Frees` — live heap object count.
    pub live_objects: String,
    /// Cumulative time spent in GC stop-the-world pauses.
    pub pause_total: String,
}

/// Formats seconds as `"1h 02m 03s"` (omitting leading zero units).
fn format_duration_seconds(total_seconds: u64) -> String {
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

/// Formats nanoseconds as milliseconds (`"12.3 ms"`) or seconds (`"1.20 s"`) above 1s.
/// `pub(super)`: reused by `app::metrics_console` for the `metrics` endpoint's GC pause field.
pub(super) fn format_duration_nanos(nanos: u64) -> String {
    let millis = nanos as f64 / 1_000_000.0;
    if millis >= 1000.0 {
        format!("{:.2} s", millis / 1000.0)
    } else {
        format!("{millis:.1} ms")
    }
}

/// Converts a raw [`SysStats`] into display-ready strings.
pub fn sys_stats_display(stats: &SysStats) -> SysStatsDisplay {
    SysStatsDisplay {
        uptime: format_duration_seconds(u64::from(stats.uptime_seconds)),
        num_goroutine: stats.num_goroutine.to_string(),
        num_gc: stats.num_gc.to_string(),
        alloc: format_size(stats.alloc),
        total_alloc: format_size(stats.total_alloc),
        sys: format_size(stats.sys),
        mallocs: stats.mallocs.to_string(),
        frees: stats.frees.to_string(),
        live_objects: stats.live_objects.to_string(),
        pause_total: format_duration_nanos(stats.pause_total_ns),
    }
}

/// Informational (non-blocking) warning when `StatsService` is missing from `api.services` —
/// mirrors `api_console::missing_services_warning`'s warn-don't-block treatment (Xray itself
/// rejects the call; Feldjäger only explains why in advance).
pub fn missing_stats_service_warning(services: &[String]) -> Option<String> {
    let has_stats_service = services
        .iter()
        .any(|service| service.eq_ignore_ascii_case("StatsService"));
    if has_stats_service {
        None
    } else {
        Some(
            "`api.services` does not list StatsService — statistics calls below will fail with \
             an Unimplemented error from Xray until it's added."
                .to_owned(),
        )
    }
}

/// Live snapshot of the `statsquery` read channel, as tracked by [`super::ApplicationService`].
pub struct StatsQuerySnapshot<'a> {
    /// `true` while a `statsquery` call is in flight.
    pub is_running: bool,
    /// Result of the last completed `statsquery` call, already parsed.
    pub last_result: Option<&'a RemoteCliResult<Vec<StatCounter>>>,
    /// Accumulated per-counter history (Roadmap §3:129 — "charts").
    pub history: &'a HashMap<String, VecDeque<(Instant, i64)>>,
}

/// Live snapshot of the `statssys` read channel.
pub struct StatsSysSnapshot<'a> {
    /// `true` while a `statssys` call is in flight.
    pub is_running: bool,
    /// Result of the last completed `statssys` call, already parsed.
    pub last_result: Option<&'a RemoteCliResult<SysStats>>,
}

/// Read-only model exposed to the Stats page.
#[derive(Debug, Clone, PartialEq)]
pub struct StatsPageModel {
    /// Coarse page state (reused from the API Console — same precondition).
    pub state: ApiConsolePageState,
    /// Resolved `api.listen` address, present only when `state == Ready`.
    pub server_addr: Option<String>,
    /// `api.services[]` as configured, verbatim.
    pub services: Vec<String>,
    /// Set when `StatsService` is missing from `api.services`.
    pub stats_service_warning: Option<String>,
    /// `stats` ↔ `policy` ↔ `api` wiring warnings (Roadmap §2.5:106) — directly relevant here:
    /// explains *why* a counter might read `0`/"No data yet" even when the call itself succeeds.
    pub wiring_warnings: Vec<String>,
    /// `true` while a `statsquery` call is in flight.
    pub is_query_running: bool,
    /// Error from the last `statsquery` call, if it failed.
    pub last_query_error: Option<String>,
    /// One row per known inbound/outbound tag × direction (Inbound tags first, then Outbound;
    /// uplink before downlink within a tag).
    pub traffic: Vec<TrafficSeriesDisplay>,
    /// Counters from the last successful `statsquery` response that don't match a known
    /// inbound/outbound tag (per-user counters, stale tags, anything else) — shown verbatim,
    /// not charted.
    pub other_counters: Vec<StatCounter>,
    /// `true` while a `statssys` call is in flight.
    pub is_sys_running: bool,
    /// Error from the last `statssys` call, if it failed.
    pub last_sys_error: Option<String>,
    /// Last successful `statssys` snapshot, formatted for display.
    pub sys: Option<SysStatsDisplay>,
}

/// Builds the Stats page model from connection/discovery/config state plus the two read
/// channels' current snapshots.
pub fn build_stats_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    query: StatsQuerySnapshot<'_>,
    sys: StatsSysSnapshot<'_>,
) -> StatsPageModel {
    let state = derive_api_console_page_state(ssh, discovery, config);
    let sections = config.editable().map(|editable| editable.sections());
    let server_addr = sections.and_then(resolve_api_listen);
    let services = sections.map(resolve_api_services).unwrap_or_default();
    let stats_service_warning = if state == ApiConsolePageState::Ready {
        missing_stats_service_warning(&services)
    } else {
        None
    };
    let wiring_warnings = sections
        .map(stats_wiring_warnings)
        .unwrap_or_default();

    let mut known_names: HashSet<String> = HashSet::new();
    let mut traffic = Vec::new();
    for (category, tags) in [
        (TrafficCategory::Inbound, config.inbounds().iter().filter_map(|i| i.tag.as_deref()).collect::<Vec<_>>()),
        (TrafficCategory::Outbound, config.outbounds().iter().filter_map(|o| o.tag.as_deref()).collect::<Vec<_>>()),
    ] {
        for tag in tags {
            for direction in [StatDirection::Uplink, StatDirection::Downlink] {
                let name = traffic_counter_name(category, tag, direction);
                known_names.insert(name.clone());
                traffic.push(build_traffic_series(category, tag, direction, &name, query.history));
            }
        }
    }

    let (last_query_error, other_counters) = match query.last_result {
        Some(Ok(counters)) => (
            None,
            counters
                .iter()
                .filter(|counter| !known_names.contains(&counter.name))
                .cloned()
                .collect(),
        ),
        Some(Err(error)) => (Some(error.message()), Vec::new()),
        None => (None, Vec::new()),
    };

    let (last_sys_error, sys_display) = match sys.last_result {
        Some(Ok(stats)) => (None, Some(sys_stats_display(stats))),
        Some(Err(error)) => (Some(error.message()), None),
        None => (None, None),
    };

    StatsPageModel {
        state,
        server_addr,
        services,
        stats_service_warning,
        wiring_warnings,
        is_query_running: query.is_running,
        last_query_error,
        traffic,
        other_counters,
        is_sys_running: sys.is_running,
        last_sys_error,
        sys: sys_display,
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
    fn traffic_counter_name_matches_xray_convention() {
        assert_eq!(
            traffic_counter_name(TrafficCategory::Inbound, "proxy-in", StatDirection::Uplink),
            "inbound>>>proxy-in>>>traffic>>>uplink"
        );
        assert_eq!(
            traffic_counter_name(TrafficCategory::Outbound, "direct", StatDirection::Downlink),
            "outbound>>>direct>>>traffic>>>downlink"
        );
    }

    #[test]
    fn record_stats_sample_appends_and_caps_history() {
        let mut history = HashMap::new();
        let base = Instant::now();
        for i in 0..(STATS_HISTORY_CAP + 10) {
            let counters = vec![StatCounter {
                name: "inbound>>>x>>>traffic>>>uplink".to_owned(),
                value: i as i64,
            }];
            record_stats_sample(&mut history, &counters, base);
        }
        let series = history.get("inbound>>>x>>>traffic>>>uplink").unwrap();
        assert_eq!(series.len(), STATS_HISTORY_CAP);
        // Oldest entries were trimmed — the first surviving value is offset by the overflow.
        assert_eq!(series.front().unwrap().1, 10);
        assert_eq!(series.back().unwrap().1, (STATS_HISTORY_CAP + 9) as i64);
    }

    #[test]
    fn rate_since_previous_sample_needs_two_points_and_positive_elapsed() {
        let mut series = VecDeque::new();
        assert_eq!(rate_since_previous_sample(&series), None);
        let t0 = Instant::now();
        series.push_back((t0, 0));
        assert_eq!(rate_since_previous_sample(&series), None);
        let t1 = t0.checked_add(std::time::Duration::from_secs(10)).unwrap();
        series.push_back((t1, 10_240));
        let rate = rate_since_previous_sample(&series).expect("rate");
        assert!(rate.ends_with("/s"), "{rate}");
    }

    #[test]
    fn rate_since_previous_sample_ignores_counter_reset() {
        let mut series = VecDeque::new();
        let t0 = Instant::now();
        let t1 = t0.checked_add(std::time::Duration::from_secs(5)).unwrap();
        series.push_back((t0, 5000));
        series.push_back((t1, 100)); // went backwards — reset elsewhere
        assert_eq!(rate_since_previous_sample(&series), None);
    }

    #[test]
    fn rate_since_previous_sample_ignores_too_short_gap() {
        let mut series = VecDeque::new();
        let t0 = Instant::now();
        let t1 = t0.checked_add(std::time::Duration::from_millis(10)).unwrap();
        series.push_back((t0, 0));
        series.push_back((t1, 500));
        assert_eq!(rate_since_previous_sample(&series), None);
    }

    #[test]
    fn missing_stats_service_warning_checks_case_insensitively() {
        assert!(missing_stats_service_warning(&[]).is_some());
        assert!(missing_stats_service_warning(&["statsservice".to_owned()]).is_none());
        assert!(missing_stats_service_warning(&["HandlerService".to_owned()]).is_some());
    }

    #[test]
    fn format_duration_seconds_omits_leading_zero_units() {
        assert_eq!(format_duration_seconds(5), "5s");
        assert_eq!(format_duration_seconds(65), "1m 05s");
        assert_eq!(format_duration_seconds(3725), "1h 02m 05s");
    }

    #[test]
    fn format_duration_nanos_switches_units_at_one_second() {
        assert_eq!(format_duration_nanos(500_000), "0.5 ms");
        assert_eq!(format_duration_nanos(2_500_000_000), "2.50 s");
    }

    #[test]
    fn sys_stats_display_formats_all_fields() {
        let stats = SysStats {
            num_goroutine: 12,
            num_gc: 3,
            alloc: 2_097_152,
            total_alloc: 4_194_304,
            sys: 8_388_608,
            mallocs: 500,
            frees: 400,
            live_objects: 100,
            pause_total_ns: 1_500_000,
            uptime_seconds: 90,
        };
        let display = sys_stats_display(&stats);
        assert_eq!(display.uptime, "1m 30s");
        assert_eq!(display.num_goroutine, "12");
        assert_eq!(display.alloc, "2.0 MB");
        assert_eq!(display.pause_total, "1.5 ms");
    }

    #[test]
    fn build_model_groups_known_tags_and_buckets_the_rest_as_other() {
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{"api":{"tag":"api","listen":"127.0.0.1:8080","services":["HandlerService"]}}"#,
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
        record_stats_sample(&mut history, &counters, now);
        let last_result: RemoteCliResult<Vec<StatCounter>> = Ok(counters);

        let model = build_stats_page_model(
            SshStatus::Connected,
            &succeeded(source),
            &config,
            StatsQuerySnapshot {
                is_running: false,
                last_result: Some(&last_result),
                history: &history,
            },
            StatsSysSnapshot {
                is_running: false,
                last_result: None,
            },
        );

        assert_eq!(model.state, ApiConsolePageState::Ready);
        // 2 tags * 2 directions = 4 rows, even though only one had data.
        assert_eq!(model.traffic.len(), 4);
        let inbound_uplink = model
            .traffic
            .iter()
            .find(|s| s.category == TrafficCategory::Inbound && s.direction == StatDirection::Uplink)
            .unwrap();
        assert_eq!(inbound_uplink.current_display, "1000 B");
        let outbound_uplink = model
            .traffic
            .iter()
            .find(|s| s.category == TrafficCategory::Outbound && s.direction == StatDirection::Uplink)
            .unwrap();
        assert_eq!(outbound_uplink.current_display, "No data yet");
        assert_eq!(model.other_counters.len(), 1);
        assert_eq!(model.other_counters[0].name, "user>>>someone@example.com>>>traffic>>>uplink");
        assert!(model.stats_service_warning.is_some()); // StatsService not in api.services
    }

    #[test]
    fn build_model_surfaces_query_error() {
        let editable = editable_from(
            "/etc/xray/config.json",
            r#"{"api":{"tag":"api","listen":"127.0.0.1:8080"}}"#,
        );
        let source = ConfigSource::SingleFile(
            feldjaeger_ssh::RemotePath::new("/etc/xray/config.json").unwrap(),
        );
        let config = loaded(Some(editable), Vec::new(), Vec::new());
        let history = HashMap::new();
        let error: RemoteCliResult<Vec<StatCounter>> =
            Err(RemoteCliError::new(RemoteCliErrorKind::NonZeroExit, "boom".to_owned()));

        let model = build_stats_page_model(
            SshStatus::Connected,
            &succeeded(source),
            &config,
            StatsQuerySnapshot {
                is_running: false,
                last_result: Some(&error),
                history: &history,
            },
            StatsSysSnapshot {
                is_running: true,
                last_result: None,
            },
        );

        assert!(model.last_query_error.unwrap().contains("boom"));
        assert!(model.is_sys_running);
        assert!(model.other_counters.is_empty());
    }
}
