//! `metrics` HTTP endpoint scrape + `/debug/vars` parsing (Roadmap §3:130 — Metrics scrape /
//! dashboard integration).
//!
//! Xray's `metrics` config section (`config/metrics.html`) is **not** a Prometheus scrape target
//! despite the roadmap wording — confirmed against the upstream Go source
//! (`app/metrics/metrics.go`, 2026-08): it serves two plain HTTP endpoints, `/debug/pprof/*` (Go
//! profiling, out of scope — a debugging tool, not administration) and `/debug/vars`, which is
//! the Go standard library's `expvar` package: a single JSON object combining every registered
//! expvar (`cmdline`, `memstats`, …) with two Xray-specific keys, `stats` (the same inbound/
//! outbound/user traffic counters `xray api statsquery` exposes, Roadmap §3:129, just nested
//! instead of flat) and `observatory` (live outbound health-check results — data unavailable
//! anywhere else in Feldjäger; the read-only Observatory page, Roadmap §23, only shows the static
//! `subjectSelector`/`probeUrl` configuration, never live probe results).
//!
//! `metrics.listen` is normally bound to loopback on the remote host (same operational pattern as
//! `api.listen`), unreachable from Feldjäger's desktop client directly. Per the transport decision
//! confirmed with the user, this module reaches it the same way `xray::run_xray_api` reaches
//! `api.listen`: by SSH-execing a fetch tool *on the remote host* — `curl`, falling back to `wget`
//! only when curl itself is absent (exit code 127, the POSIX "command not found" convention shared
//! by dash/bash/ash) — rather than adding SSH port-forwarding and a local HTTP client dependency.

use serde::Deserialize;
use serde_json::Value;
use tracing::debug;

use feldjaeger_ssh::{RemoteCommand, SshSession};

use super::error::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult};
use super::exec::classify_exec_error;
use super::stats::StatCounter;

const SCRAPE_TIMEOUT_SECONDS: &str = "10";
/// POSIX shell convention for "command not found" (dash/bash/ash all agree).
const COMMAND_NOT_FOUND_EXIT_CODE: i32 = 127;

/// Fetches `http://{listen_addr}{path}` by SSH-execing `curl` (or `wget` when curl is absent) on
/// the remote host and returns the raw response body.
pub async fn run_metrics_scrape<S: SshSession + Sync>(
    session: &S,
    listen_addr: &str,
    path: &str,
) -> RemoteCliResult<String> {
    let listen_addr = listen_addr.trim();
    if listen_addr.is_empty() {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::CommandFailed,
            "Metrics server address is empty (configure `metrics.listen`)".to_owned(),
        ));
    }
    let url = format!("http://{listen_addr}{path}");

    match run_curl(session, &url).await {
        ToolOutcome::Ok(body) => return Ok(body),
        ToolOutcome::NotFound => {}
        ToolOutcome::Err(error) => return Err(error),
    }

    match run_wget(session, &url).await {
        ToolOutcome::Ok(body) => Ok(body),
        ToolOutcome::NotFound => Err(RemoteCliError::new(
            RemoteCliErrorKind::CommandFailed,
            "Neither curl nor wget is available on the remote host — install one to use the \
             Metrics page."
                .to_owned(),
        )),
        ToolOutcome::Err(error) => Err(error),
    }
}

enum ToolOutcome {
    Ok(String),
    /// The tool itself is not installed on the remote host (exit 127) — caller may fall back.
    NotFound,
    Err(RemoteCliError),
}

async fn run_curl<S: SshSession + Sync>(session: &S, url: &str) -> ToolOutcome {
    let args = vec![
        "-sS".to_owned(),
        "-m".to_owned(),
        SCRAPE_TIMEOUT_SECONDS.to_owned(),
        url.to_owned(),
    ];
    run_tool(session, "curl", args).await
}

async fn run_wget<S: SshSession + Sync>(session: &S, url: &str) -> ToolOutcome {
    let args = vec![
        "-q".to_owned(),
        "-T".to_owned(),
        SCRAPE_TIMEOUT_SECONDS.to_owned(),
        "-O".to_owned(),
        "-".to_owned(),
        url.to_owned(),
    ];
    run_tool(session, "wget", args).await
}

async fn run_tool<S: SshSession + Sync>(session: &S, program: &str, args: Vec<String>) -> ToolOutcome {
    let command = match RemoteCommand::new(program, args) {
        Ok(command) => command,
        Err(error) => {
            return ToolOutcome::Err(RemoteCliError::new(
                RemoteCliErrorKind::CommandFailed,
                error.message().to_owned(),
            ));
        }
    };

    let result = match session.exec(&command).await {
        Ok(result) => result,
        Err(error) => return ToolOutcome::Err(classify_exec_error(error)),
    };

    if result.exit_code == COMMAND_NOT_FOUND_EXIT_CODE {
        debug!(target: "xray", tool = program, "remote fetch tool not found, trying fallback");
        return ToolOutcome::NotFound;
    }
    if result.exit_code != 0 {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let stdout = String::from_utf8_lossy(&result.stdout);
        let detail_source = if !stderr.trim().is_empty() {
            stderr.as_ref()
        } else {
            stdout.as_ref()
        };
        let detail = crate::logging::redact::sanitize_detail(&truncate(detail_source, 300));
        return ToolOutcome::Err(RemoteCliError::new(
            RemoteCliErrorKind::NonZeroExit,
            if detail.is_empty() {
                format!("{program} exited with code {}", result.exit_code)
            } else {
                format!("{program}: {detail}")
            },
        ));
    }

    ToolOutcome::Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

fn truncate(input: &str, max_chars: usize) -> String {
    let trimmed = input.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_owned()
    } else {
        let mut out: String = trimmed.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

// ─── `/debug/vars` parsing ─────────────────────────────────────────────────────

/// Parsed `/debug/vars` payload.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DebugVars {
    /// Traffic counters, reconstructed into the same `type>>>tag>>>traffic>>>direction` naming
    /// convention `xray api statsquery` uses (Roadmap §3:129), so both transports can share the
    /// same grouping/charting logic (`app::stats_console`).
    pub stats: Vec<StatCounter>,
    /// Live Observatory health-check results, one per outbound under observation.
    pub observatory: Vec<ObservatoryOutboundStatus>,
    /// A useful subset of Go's default `memstats` expvar (`runtime.MemStats`), when published.
    pub memstats: Option<MetricsMemStats>,
    /// Process argv, from Go's default `cmdline` expvar.
    pub cmdline: Vec<String>,
}

/// One outbound's live Observatory status (`observatory.OutboundStatus` upstream proto,
/// confirmed against `app/observatory/config.proto`/`config.pb.go`, 2026-08).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObservatoryOutboundStatus {
    /// The outbound tag this status is for.
    pub outbound_tag: String,
    /// Whether the outbound currently passes its health check.
    pub alive: bool,
    /// Probe round-trip time in milliseconds.
    pub delay_ms: i64,
    /// The last error that made a probe fail, if any.
    pub last_error_reason: String,
    /// Unix seconds — the last time this outbound was seen alive.
    pub last_seen_time: i64,
    /// Unix seconds — the last time this outbound was probed at all.
    pub last_try_time: i64,
    /// Aggregate ping measurements, present only under `burstObservatory`/HealthPing strategies.
    pub health_ping: Option<HealthPingMeasurement>,
}

/// `observatory.HealthPingMeasurementResult` upstream — counts and millisecond measurements.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HealthPingMeasurement {
    /// Total probes performed.
    pub all: i64,
    /// Failed probes.
    pub fail: i64,
    /// Deviation, in milliseconds.
    pub deviation: i64,
    /// Average delay, in milliseconds.
    pub average: i64,
    /// Maximum delay, in milliseconds.
    pub max: i64,
    /// Minimum delay, in milliseconds.
    pub min: i64,
}

/// Subset of Go's `runtime.MemStats`, as published under the default `memstats` expvar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsMemStats {
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
    /// Live heap object count (`Mallocs - Frees`, published directly by Go).
    pub heap_objects: u64,
    /// Completed garbage collection cycles.
    pub num_gc: u32,
    /// Cumulative nanoseconds spent in GC stop-the-world pauses.
    pub pause_total_ns: u64,
}

#[derive(Debug, Default, Deserialize)]
struct RawHealthPing {
    #[serde(default)]
    all: i64,
    #[serde(default)]
    fail: i64,
    #[serde(default)]
    deviation: i64,
    #[serde(default)]
    average: i64,
    #[serde(default)]
    max: i64,
    #[serde(default)]
    min: i64,
}

#[derive(Debug, Default, Deserialize)]
struct RawOutboundStatus {
    #[serde(default)]
    alive: bool,
    #[serde(default)]
    delay: i64,
    #[serde(default)]
    last_error_reason: String,
    #[serde(default)]
    outbound_tag: String,
    #[serde(default)]
    last_seen_time: i64,
    #[serde(default)]
    last_try_time: i64,
    #[serde(default)]
    health_ping: Option<RawHealthPing>,
}

#[derive(Debug, Default, Deserialize)]
struct RawMemStats {
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
    #[serde(default, rename = "HeapObjects")]
    heap_objects: u64,
    #[serde(default, rename = "NumGC")]
    num_gc: u32,
    #[serde(default, rename = "PauseTotalNs")]
    pause_total_ns: u64,
}

/// Parses `/debug/vars` JSON into [`DebugVars`]. An empty body is treated as an empty snapshot,
/// not an error (mirrors [`super::stats::parse_stats_query_stdout`]'s convention).
pub fn parse_debug_vars_stdout(body: &str) -> RemoteCliResult<DebugVars> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(DebugVars::default());
    }
    let root: Value = serde_json::from_str(trimmed).map_err(|error| {
        RemoteCliError::new(
            RemoteCliErrorKind::ParseFailed,
            format!("could not parse /debug/vars output as JSON: {error}"),
        )
    })?;

    let stats = root.get("stats").map(parse_stats_value).unwrap_or_default();
    let observatory = root
        .get("observatory")
        .map(parse_observatory_value)
        .unwrap_or_default();
    let memstats = root
        .get("memstats")
        .and_then(|value| serde_json::from_value::<RawMemStats>(value.clone()).ok())
        .map(|raw| MetricsMemStats {
            alloc: raw.alloc,
            total_alloc: raw.total_alloc,
            sys: raw.sys,
            mallocs: raw.mallocs,
            frees: raw.frees,
            heap_objects: raw.heap_objects,
            num_gc: raw.num_gc,
            pause_total_ns: raw.pause_total_ns,
        });
    let cmdline = root
        .get("cmdline")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    Ok(DebugVars {
        stats,
        observatory,
        memstats,
        cmdline,
    })
}

/// Reconstructs `type>>>tagOrUser>>>traffic>>>direction` counters from the nested
/// `{"inbound": {tag: {direction: n}}, "outbound": {...}, "user": {...}}` shape
/// (`MetricsHandler.stats()` upstream, `app/metrics/metrics.go`) — the middle segment is always
/// the literal `"traffic"`, the only stat name shape with enough `>>>`-separated segments to
/// survive that function's `strings.Split` in current Xray-core.
fn parse_stats_value(value: &Value) -> Vec<StatCounter> {
    let Some(by_type) = value.as_object() else {
        return Vec::new();
    };
    let mut counters = Vec::new();
    for (type_name, by_tag) in by_type {
        let Some(by_tag) = by_tag.as_object() else {
            continue;
        };
        for (tag, by_direction) in by_tag {
            let Some(by_direction) = by_direction.as_object() else {
                continue;
            };
            for (direction, raw_value) in by_direction {
                let Some(value) = raw_value.as_i64() else {
                    continue;
                };
                counters.push(StatCounter {
                    name: format!("{type_name}>>>{tag}>>>traffic>>>{direction}"),
                    value,
                });
            }
        }
    }
    counters
}

fn parse_observatory_value(value: &Value) -> Vec<ObservatoryOutboundStatus> {
    let Some(by_tag) = value.as_object() else {
        return Vec::new();
    };
    let mut statuses: Vec<ObservatoryOutboundStatus> = by_tag
        .iter()
        .filter_map(|(tag, raw)| {
            let raw: RawOutboundStatus = serde_json::from_value(raw.clone()).ok()?;
            let outbound_tag = if raw.outbound_tag.is_empty() {
                tag.clone()
            } else {
                raw.outbound_tag
            };
            Some(ObservatoryOutboundStatus {
                outbound_tag,
                alive: raw.alive,
                delay_ms: raw.delay,
                last_error_reason: raw.last_error_reason,
                last_seen_time: raw.last_seen_time,
                last_try_time: raw.last_try_time,
                health_ping: raw.health_ping.map(|hp| HealthPingMeasurement {
                    all: hp.all,
                    fail: hp.fail,
                    deviation: hp.deviation,
                    average: hp.average,
                    max: hp.max,
                    min: hp.min,
                }),
            })
        })
        .collect();
    statuses.sort_by(|a, b| a.outbound_tag.cmp(&b.outbound_tag));
    statuses
}

#[cfg(test)]
mod tests {
    use super::*;
    use feldjaeger_ssh::{ConnectionProfile, ExecResult, RemotePath, SshError, SshResult};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // ─── scrape transport ───────────────────────────────────────────────────

    // `Mutex`, not `RefCell`: `SshSession` methods are called through `&S` across `.await`
    // points, which requires `S: Sync` — `RefCell` is `!Sync` and would fail to compile there.
    struct MockSession {
        profile: ConnectionProfile,
        // Queued (program, ExecResult) pairs, consumed in order.
        responses: Mutex<VecDeque<(&'static str, SshResult<ExecResult>)>>,
        calls: Mutex<Vec<String>>,
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        async fn read_file(&self, _path: &RemotePath) -> SshResult<Vec<u8>> {
            Err(SshError::new("not used"))
        }

        async fn write_file(&self, _path: &RemotePath, _contents: &[u8]) -> SshResult<()> {
            Err(SshError::new("not used"))
        }

        async fn write_file_atomic(&self, _path: &RemotePath, _contents: &[u8]) -> SshResult<()> {
            Err(SshError::new("not used"))
        }

        async fn rename_file(&self, _from: &RemotePath, _to: &RemotePath) -> SshResult<()> {
            Err(SshError::new("not used"))
        }

        async fn remove_file(&self, _path: &RemotePath) -> SshResult<()> {
            Err(SshError::new("not used"))
        }

        async fn path_is_file(&self, _path: &RemotePath) -> SshResult<bool> {
            Ok(false)
        }

        async fn exec(&self, command: &RemoteCommand) -> SshResult<ExecResult> {
            self.calls.lock().unwrap().push(command.program().to_owned());
            let mut responses = self.responses.lock().unwrap();
            let (expected_program, result) = responses
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected exec call: {}", command.program()));
            assert_eq!(expected_program, command.program());
            result
        }

        async fn exec_with_stdin(
            &self,
            command: &RemoteCommand,
            _stdin: &[u8],
        ) -> SshResult<ExecResult> {
            self.exec(command).await
        }

        async fn disconnect(self) -> SshResult<()> {
            Ok(())
        }
    }

    fn session(responses: Vec<(&'static str, SshResult<ExecResult>)>) -> MockSession {
        MockSession {
            profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn ok_result(body: &str) -> SshResult<ExecResult> {
        Ok(ExecResult::new(body.as_bytes().to_vec(), Vec::new(), 0))
    }

    fn not_found_result() -> SshResult<ExecResult> {
        Ok(ExecResult::new(
            Vec::new(),
            b"sh: 1: curl: not found".to_vec(),
            127,
        ))
    }

    #[tokio::test]
    async fn curl_success_returns_body() {
        let session = session(vec![("curl", ok_result(r#"{"stats":{}}"#))]);
        let body = run_metrics_scrape(&session, "127.0.0.1:11111", "/debug/vars")
            .await
            .expect("scrape");
        assert_eq!(body, r#"{"stats":{}}"#);
        assert_eq!(session.calls.lock().unwrap().as_slice(), ["curl"]);
    }

    #[tokio::test]
    async fn falls_back_to_wget_when_curl_missing() {
        let session = session(vec![
            ("curl", not_found_result()),
            ("wget", ok_result(r#"{"stats":{}}"#)),
        ]);
        let body = run_metrics_scrape(&session, "127.0.0.1:11111", "/debug/vars")
            .await
            .expect("scrape");
        assert_eq!(body, r#"{"stats":{}}"#);
        assert_eq!(session.calls.lock().unwrap().as_slice(), ["curl", "wget"]);
    }

    #[tokio::test]
    async fn neither_tool_available_is_a_clear_error() {
        let session = session(vec![("curl", not_found_result()), ("wget", not_found_result())]);
        let error = run_metrics_scrape(&session, "127.0.0.1:11111", "/debug/vars")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), RemoteCliErrorKind::CommandFailed);
        assert!(error.message().contains("Neither curl nor wget"));
    }

    #[tokio::test]
    async fn curl_connection_refused_does_not_fall_back_to_wget() {
        let session = session(vec![(
            "curl",
            Ok(ExecResult::new(
                Vec::new(),
                b"curl: (7) Failed to connect".to_vec(),
                7,
            )),
        )]);
        let error = run_metrics_scrape(&session, "127.0.0.1:11111", "/debug/vars")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), RemoteCliErrorKind::NonZeroExit);
        assert!(error.message().contains("Failed to connect"));
        assert_eq!(session.calls.lock().unwrap().as_slice(), ["curl"]);
    }

    #[tokio::test]
    async fn empty_listen_address_is_rejected_before_exec() {
        let session = session(Vec::new());
        let error = run_metrics_scrape(&session, "  ", "/debug/vars")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), RemoteCliErrorKind::CommandFailed);
        assert!(session.calls.lock().unwrap().is_empty());
    }

    // ─── /debug/vars parsing ────────────────────────────────────────────────

    #[test]
    fn empty_body_yields_default_snapshot() {
        assert_eq!(parse_debug_vars_stdout("").unwrap(), DebugVars::default());
        assert_eq!(parse_debug_vars_stdout("   ").unwrap(), DebugVars::default());
    }

    #[test]
    fn rejects_malformed_json() {
        let error = parse_debug_vars_stdout("not json").unwrap_err();
        assert_eq!(error.kind(), RemoteCliErrorKind::ParseFailed);
    }

    #[test]
    fn reconstructs_traffic_counter_names_from_nested_stats() {
        let body = r#"{
            "stats": {
                "inbound": {"proxy-in": {"uplink": 100, "downlink": 200}},
                "outbound": {"direct": {"uplink": 5}},
                "user": {"a@example.com": {"uplink": 1}}
            }
        }"#;
        let vars = parse_debug_vars_stdout(body).expect("parse");
        let mut names: Vec<&str> = vars.stats.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "inbound>>>proxy-in>>>traffic>>>downlink",
                "inbound>>>proxy-in>>>traffic>>>uplink",
                "outbound>>>direct>>>traffic>>>uplink",
                "user>>>a@example.com>>>traffic>>>uplink",
            ]
        );
        let uplink = vars
            .stats
            .iter()
            .find(|c| c.name == "inbound>>>proxy-in>>>traffic>>>uplink")
            .unwrap();
        assert_eq!(uplink.value, 100);
    }

    #[test]
    fn missing_stats_key_is_empty_not_an_error() {
        let vars = parse_debug_vars_stdout("{}").expect("parse");
        assert!(vars.stats.is_empty());
        assert!(vars.observatory.is_empty());
        assert!(vars.memstats.is_none());
        assert!(vars.cmdline.is_empty());
    }

    #[test]
    fn null_observatory_is_empty() {
        let vars = parse_debug_vars_stdout(r#"{"observatory": null}"#).expect("parse");
        assert!(vars.observatory.is_empty());
    }

    #[test]
    fn parses_observatory_statuses_sorted_by_tag() {
        let body = r#"{
            "observatory": {
                "warp": {"alive": true, "delay": 42, "outbound_tag": "warp", "last_seen_time": 1000, "last_try_time": 1005},
                "direct": {"outbound_tag": "direct", "last_try_time": 999}
            }
        }"#;
        let vars = parse_debug_vars_stdout(body).expect("parse");
        assert_eq!(vars.observatory.len(), 2);
        assert_eq!(vars.observatory[0].outbound_tag, "direct");
        assert!(!vars.observatory[0].alive);
        assert_eq!(vars.observatory[1].outbound_tag, "warp");
        assert!(vars.observatory[1].alive);
        assert_eq!(vars.observatory[1].delay_ms, 42);
    }

    #[test]
    fn observatory_tag_falls_back_to_map_key_when_field_absent() {
        let body = r#"{"observatory": {"warp": {"alive": true}}}"#;
        let vars = parse_debug_vars_stdout(body).expect("parse");
        assert_eq!(vars.observatory[0].outbound_tag, "warp");
    }

    #[test]
    fn parses_health_ping_measurement() {
        let body = r#"{
            "observatory": {
                "warp": {
                    "outbound_tag": "warp",
                    "health_ping": {"all": 10, "fail": 2, "deviation": 3, "average": 45, "max": 120, "min": 20}
                }
            }
        }"#;
        let vars = parse_debug_vars_stdout(body).expect("parse");
        let ping = vars.observatory[0].health_ping.expect("health_ping");
        assert_eq!(ping.all, 10);
        assert_eq!(ping.fail, 2);
        assert_eq!(ping.average, 45);
    }

    #[test]
    fn parses_memstats_subset_with_capitalized_keys() {
        let body = r#"{
            "memstats": {
                "Alloc": 1048576,
                "TotalAlloc": 5242880,
                "Sys": 8388608,
                "Mallocs": 10000,
                "Frees": 9000,
                "HeapObjects": 1000,
                "NumGC": 3,
                "PauseTotalNs": 123456,
                "SomeFutureField": "ignored"
            }
        }"#;
        let vars = parse_debug_vars_stdout(body).expect("parse");
        let mem = vars.memstats.expect("memstats");
        assert_eq!(mem.alloc, 1_048_576);
        assert_eq!(mem.num_gc, 3);
        assert_eq!(mem.pause_total_ns, 123_456);
    }

    #[test]
    fn parses_cmdline_array() {
        let body = r#"{"cmdline": ["/usr/local/bin/xray", "run", "-c", "/etc/xray/config.json"]}"#;
        let vars = parse_debug_vars_stdout(body).expect("parse");
        assert_eq!(
            vars.cmdline,
            vec![
                "/usr/local/bin/xray".to_owned(),
                "run".to_owned(),
                "-c".to_owned(),
                "/etc/xray/config.json".to_owned(),
            ]
        );
    }
}
