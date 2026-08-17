//! Parses `xray api statsquery`/`statssys` JSON stdout (Roadmap §3:129 — Stats live read /
//! charts).
//!
//! Both subcommands go through the same generic executor as every other `xray api <subcommand>`
//! ([`super::api::run_xray_api`]) — this module only adds the typed parse step that
//! [`super::api`]'s own doc comment says most subcommands don't get, because *these* two have a
//! stable, documented wire shape (`app/stats/command/command.proto` in XTLS/Xray-core), unlike
//! `lsi`/`lso`/`bi`.
//!
//! Confirmed against the upstream source (`app/stats/command/command.go`,
//! `main/commands/all/api/stats_query.go`/`stats_sys.go`, 2026-08):
//! - `statsquery` always returns `{"stat": [{"name": "...", "value": N}, ...]}` (JSON is not
//!   opt-in via a `-json` flag — `showJSONResponse` in `shared.go` always renders JSON,
//!   `-json` is parsed but unused). A counter whose Go field is zero is omitted by
//!   `omitempty` — a missing `"value"` means `0`, not "unknown".
//! - The server matches `-pattern` with `strings.Contains`, **not** a regex, despite the flag
//!   name — irrelevant here since Feldjäger always fetches everything (empty pattern) and
//!   groups/filters client-side (`app::stats_console`).
//! - `-reset` zeroes counters on the server after reading them. Feldjäger's read path never
//!   sets it — a passive dashboard must not perturb counters another tool might also be
//!   polling.
//! - `statssys` fields keep their proto names verbatim in JSON (`NumGoroutine`, not
//!   `numGoroutine`) because the field names contain no underscores for the generator's
//!   snake_case→camelCase rewrite to act on. Same `omitempty` rule: an all-zero field is
//!   simply absent.

use serde::Deserialize;

use super::error::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult};

/// One `name`/`value` pair from `xray api statsquery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatCounter {
    /// Full counter name, e.g. `inbound>>>proxy-in>>>traffic>>>uplink`.
    pub name: String,
    /// Current cumulative value (never reset by Feldjäger's own read path).
    pub value: i64,
}

#[derive(Debug, Deserialize)]
struct RawStat {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: i64,
}

#[derive(Debug, Deserialize)]
struct RawQueryStatsResponse {
    #[serde(default)]
    stat: Vec<RawStat>,
}

/// Parses `xray api statsquery` stdout into a flat counter list (order as returned by Xray —
/// callers group/sort as needed).
pub fn parse_stats_query_stdout(stdout: &str) -> RemoteCliResult<Vec<StatCounter>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        // No counters matched (or the stats module collected nothing yet) — a bare `{}` and an
        // empty body are both valid "nothing to show" responses.
        return Ok(Vec::new());
    }
    let parsed: RawQueryStatsResponse = serde_json::from_str(trimmed).map_err(|error| {
        RemoteCliError::new(
            RemoteCliErrorKind::ParseFailed,
            format!("could not parse statsquery output as JSON: {error}"),
        )
    })?;
    Ok(parsed
        .stat
        .into_iter()
        .map(|raw| StatCounter {
            name: raw.name,
            value: raw.value,
        })
        .collect())
}

/// Process-level runtime statistics from `xray api statssys` (`runtime.MemStats` snapshot plus
/// process uptime and goroutine/GC counts).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SysStats {
    /// `runtime.NumGoroutine()` at the moment of the call.
    pub num_goroutine: u32,
    /// Number of completed garbage collection cycles.
    pub num_gc: u32,
    /// Bytes of allocated heap objects currently in use.
    pub alloc: u64,
    /// Cumulative bytes allocated for heap objects over the process lifetime.
    pub total_alloc: u64,
    /// Total bytes obtained from the OS.
    pub sys: u64,
    /// Cumulative count of heap objects allocated.
    pub mallocs: u64,
    /// Cumulative count of heap objects freed.
    pub frees: u64,
    /// `Mallocs - Frees` — live heap object count, as computed server-side.
    pub live_objects: u64,
    /// Cumulative nanoseconds spent in GC stop-the-world pauses.
    pub pause_total_ns: u64,
    /// Seconds since the Xray process's stats server started.
    pub uptime_seconds: u32,
}

#[derive(Debug, Default, Deserialize)]
struct RawSysStats {
    #[serde(default, rename = "NumGoroutine")]
    num_goroutine: u32,
    #[serde(default, rename = "NumGC")]
    num_gc: u32,
    #[serde(default, rename = "Alloc")]
    alloc: u64,
    #[serde(default, rename = "TotalAlloc")]
    total_alloc: u64,
    #[serde(default, rename = "Sys")]
    sys: u64,
    #[serde(default, rename = "Mallocs")]
    mallocs: u64,
    #[serde(default, rename = "Frees")]
    frees: u64,
    #[serde(default, rename = "LiveObjects")]
    live_objects: u64,
    #[serde(default, rename = "PauseTotalNs")]
    pause_total_ns: u64,
    #[serde(default, rename = "Uptime")]
    uptime: u32,
}

/// Parses `xray api statssys` stdout.
pub fn parse_stats_sys_stdout(stdout: &str) -> RemoteCliResult<SysStats> {
    let trimmed = stdout.trim();
    let raw: RawSysStats = if trimmed.is_empty() {
        RawSysStats::default()
    } else {
        serde_json::from_str(trimmed).map_err(|error| {
            RemoteCliError::new(
                RemoteCliErrorKind::ParseFailed,
                format!("could not parse statssys output as JSON: {error}"),
            )
        })?
    };
    Ok(SysStats {
        num_goroutine: raw.num_goroutine,
        num_gc: raw.num_gc,
        alloc: raw.alloc,
        total_alloc: raw.total_alloc,
        sys: raw.sys,
        mallocs: raw.mallocs,
        frees: raw.frees,
        live_objects: raw.live_objects,
        pause_total_ns: raw.pause_total_ns,
        uptime_seconds: raw.uptime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_stats_stat_array() {
        let stdout = r#"{
            "stat": [
                {"name": "inbound>>>proxy-in>>>traffic>>>uplink", "value": 1024},
                {"name": "inbound>>>proxy-in>>>traffic>>>downlink", "value": 2048}
            ]
        }"#;
        let counters = parse_stats_query_stdout(stdout).expect("parse");
        assert_eq!(
            counters,
            vec![
                StatCounter {
                    name: "inbound>>>proxy-in>>>traffic>>>uplink".to_owned(),
                    value: 1024
                },
                StatCounter {
                    name: "inbound>>>proxy-in>>>traffic>>>downlink".to_owned(),
                    value: 2048
                },
            ]
        );
    }

    #[test]
    fn missing_value_field_defaults_to_zero() {
        // `omitempty` drops a zero-valued counter's "value" key entirely.
        let stdout = r#"{"stat": [{"name": "inbound>>>idle-in>>>traffic>>>uplink"}]}"#;
        let counters = parse_stats_query_stdout(stdout).expect("parse");
        assert_eq!(counters, vec![StatCounter {
            name: "inbound>>>idle-in>>>traffic>>>uplink".to_owned(),
            value: 0
        }]);
    }

    #[test]
    fn empty_stat_array_and_empty_body_both_yield_no_counters() {
        assert_eq!(parse_stats_query_stdout(r#"{"stat": []}"#).unwrap(), Vec::new());
        assert_eq!(parse_stats_query_stdout("").unwrap(), Vec::new());
        assert_eq!(parse_stats_query_stdout("   ").unwrap(), Vec::new());
    }

    #[test]
    fn missing_stat_key_is_not_an_error() {
        assert_eq!(parse_stats_query_stdout("{}").unwrap(), Vec::new());
    }

    #[test]
    fn rejects_malformed_json() {
        let err = parse_stats_query_stdout("not json").unwrap_err();
        assert_eq!(err.kind(), RemoteCliErrorKind::ParseFailed);
    }

    #[test]
    fn parses_sys_stats_with_capitalized_keys() {
        let stdout = r#"{
            "NumGoroutine": 42,
            "NumGC": 3,
            "Alloc": 1048576,
            "TotalAlloc": 5242880,
            "Sys": 8388608,
            "Mallocs": 10000,
            "Frees": 9000,
            "LiveObjects": 1000,
            "PauseTotalNs": 123456,
            "Uptime": 3600
        }"#;
        let stats = parse_stats_sys_stdout(stdout).expect("parse");
        assert_eq!(
            stats,
            SysStats {
                num_goroutine: 42,
                num_gc: 3,
                alloc: 1_048_576,
                total_alloc: 5_242_880,
                sys: 8_388_608,
                mallocs: 10_000,
                frees: 9_000,
                live_objects: 1_000,
                pause_total_ns: 123_456,
                uptime_seconds: 3_600,
            }
        );
    }

    #[test]
    fn sys_stats_omitted_zero_fields_default_to_zero() {
        // A freshly started process can plausibly have NumGC == 0, which `omitempty` drops.
        let stats = parse_stats_sys_stdout(r#"{"NumGoroutine": 5, "Uptime": 1}"#).expect("parse");
        assert_eq!(stats.num_gc, 0);
        assert_eq!(stats.alloc, 0);
        assert_eq!(stats.num_goroutine, 5);
        assert_eq!(stats.uptime_seconds, 1);
    }

    #[test]
    fn empty_sys_stats_body_defaults_to_all_zero() {
        assert_eq!(parse_stats_sys_stdout("").unwrap(), SysStats::default());
    }

    #[test]
    fn rejects_malformed_sys_stats_json() {
        let err = parse_stats_sys_stdout("not json").unwrap_err();
        assert_eq!(err.kind(), RemoteCliErrorKind::ParseFailed);
    }
}
