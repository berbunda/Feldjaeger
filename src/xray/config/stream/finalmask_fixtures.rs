//! Fixture corpus for FinalMask validation (Roadmap §2.6 stage 1.5).
//!
//! Each file under `fixtures/finalmask/` is a `streamSettings.finalmask` object exactly as it
//! would sit on disk — pure Xray JSON, so it can also be pasted into a config by hand. What a
//! fixture is expected to do (side, outcome, error text, whether `xray run -test` sees it) lives
//! in [`CASES`], so one file can be valid on one side and invalid on the other.
//!
//! Fixtures are embedded with `include_str!`: a missing file is a compile error, not a test that
//! fails only on a clean clone.
//!
//! The parity test runs every case through a local `xray run -test` when `XRAY_BIN` points to an
//! Xray executable (or `xray-bin/xray` exists, see [`crate::xray::local_xray`]), and is a no-op
//! otherwise.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::xray::local_xray::local_xray_bin;
use super::{FinalMaskChain, StreamDirection, parse_finalmask_layers, validate_finalmask_layers};
use crate::xray::config::compatibility::{CoreFeature, XrayCoreVersion};

/// Where the core reports a problem that Feldjäger refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreCheck {
    /// `Build()` — `xray run -test` fails.
    Build,
    /// Only when the core listens or dials (mask constructors, runtime) — `xray run -test`
    /// passes, which is why Feldjäger checks it.
    Runtime,
}

#[derive(Debug, Clone, Copy)]
enum Expect {
    Valid,
    /// The validation error contains `needle`.
    Invalid { needle: &'static str, core: CoreCheck },
}

struct Case {
    /// Path under `fixtures/finalmask/` without `.json`.
    file: &'static str,
    json: &'static str,
    direction: StreamDirection,
    expect: Expect,
    /// The first core release that understands the fixture; older cores are skipped in parity.
    feature: Option<CoreFeature>,
}

macro_rules! case {
    ($file:literal, $direction:ident, $expect:expr) => {
        case!(@ $file, $direction, $expect, None)
    };
    ($file:literal, $direction:ident, $expect:expr, $feature:ident) => {
        case!(@ $file, $direction, $expect, Some(CoreFeature::$feature))
    };
    (@ $file:literal, $direction:ident, $expect:expr, $feature:expr) => {
        Case {
            file: $file,
            json: include_str!(concat!("fixtures/finalmask/", $file, ".json")),
            direction: StreamDirection::$direction,
            expect: $expect,
            feature: $feature,
        }
    };
}

const fn build(needle: &'static str) -> Expect {
    Expect::Invalid { needle, core: CoreCheck::Build }
}

const fn runtime(needle: &'static str) -> Expect {
    Expect::Invalid { needle, core: CoreCheck::Runtime }
}

use Expect::Valid;

/// Every documented layer type has a valid case; every type with a core check has an invalid
/// one.
const CASES: &[Case] = &[
    // ── finalmask.tcp ──
    case!("valid/fragment_tcp", Inbound, Valid),
    case!("valid/header_custom_tcp", Inbound, Valid),
    case!("valid/header_custom_tcp_http", Inbound, Valid),
    case!("valid/header_custom_tcp_http", Outbound, Valid),
    case!("valid/sudoku_tcp", Inbound, Valid),
    case!("valid/sudoku_custom_tables", Inbound, Valid),
    case!("valid/sudoku_custom_tables", Outbound, Valid),
    // `Sudoku.Build()` checks nothing; the tables are built per connection (`getTables`).
    case!("invalid/sudoku_custom_table", Inbound, runtime("customTables[1]: \"xxpvvvv\" must be 8 characters, got 7")),
    case!("valid/xmc_tcp", Inbound, Valid, XmcProfilesSchema),
    case!("valid/xmc_tcp", Outbound, Valid, XmcProfilesSchema),
    case!("invalid/empty_type", Inbound, build("non-empty type (finalmask.tcp[0])")),
    case!("invalid/fragment_packets_from_zero", Inbound, build("packets: a range must not start at 0")),
    case!("invalid/fragment_last_length_zero", Outbound, build("lengths: the last entry must not start at 0")),
    case!("invalid/header_custom_tcp_two_kinds", Inbound, build("clients[0][0]: exactly one of packet, rand")),
    // Before v26.7.28 (#6487) the core ignored `profiles`, so these need the profiles schema.
    case!("invalid/xmc_bad_username", Inbound, build("profiles[0]: invalid Minecraft username"), XmcProfilesSchema),
    case!("invalid/xmc_no_profiles", Inbound, build("profiles: at least one"), XmcProfilesSchema),
    // The RSA block and the Minecraft string limit only bite in the login handshake.
    case!("invalid/xmc_long_password", Inbound, runtime("password is 114 bytes"), XmcProfilesSchema),
    case!("invalid/xmc_long_password", Outbound, runtime("password is 114 bytes"), XmcProfilesSchema),
    case!("invalid/xmc_long_hostname", Outbound, runtime("hostname is 4097 bytes"), XmcProfilesSchema),
    // Only the client sends `hostname`; the server ignores it.
    case!("invalid/xmc_long_hostname", Inbound, Valid, XmcProfilesSchema),
    // ── finalmask.udp ──
    case!("valid/header_custom_udp", Inbound, Valid),
    case!("valid/header_custom_udp_prefix", Inbound, Valid),
    case!("valid/header_custom_udp_prefix", Outbound, Valid),
    case!("valid/mkcp_legacy_udp", Inbound, Valid),
    case!("valid/mkcp_legacy_dns", Inbound, Valid),
    case!("valid/mkcp_legacy_aes", Outbound, Valid),
    case!("valid/noise_udp", Outbound, Valid),
    case!("valid/noise_exp_udp", Outbound, Valid, NoiseExpPacket),
    case!("valid/salamander_udp", Inbound, Valid),
    case!("valid/sudoku_udp", Inbound, Valid),
    case!("valid/xdns_server", Inbound, Valid, XdnsObjectSchema),
    case!("valid/xdns_client", Outbound, Valid, XdnsObjectSchema),
    case!("valid/xicmp_udp", Outbound, Valid),
    case!("valid/realm_udp", Inbound, Valid),
    case!("valid/realm_udp", Outbound, Valid),
    case!("valid/udphop_client", Outbound, Valid, UdpHopUdpMask),
    case!("valid/both_chains", Outbound, Valid),
    case!("invalid/fragment_in_udp", Inbound, build("finalmask.udp[0] (fragment): `fragment` is a finalmask.tcp mask")),
    case!("invalid/header_custom_udp_mode_case", Inbound, build("unknown mode \"PREFIX\"")),
    // The header is sized when the listener is created (`measureUDPItems`), not by `Build()`.
    case!("invalid/header_custom_udp_unknown_reuse", Inbound, runtime("client[0]: unknown variable \"nonce\"")),
    case!("invalid/mkcp_legacy_header", Inbound, build("invalid header \"none\"")),
    // The DNS name is packed by `NewHeaderDNS` when the listener starts, not by `Build()`.
    case!("invalid/mkcp_legacy_dns_label", Inbound, runtime("value: domain label")),
    case!("invalid/noise_packet_and_rand", Outbound, build("noise[0]: set either packet or rand")),
    case!("invalid/noise_exp_unknown_segment", Outbound, build("unknown <q> in noise exp"), NoiseExpPacket),
    case!("invalid/salamander_packet_size", Inbound, build("packetSize must lie within 1–2048")),
    // The key length is checked by `NewSalamanderObfuscator` when the listener / dialer starts.
    case!("invalid/salamander_short_password", Inbound, runtime("password is 3 bytes, Xray-core needs at least 4")),
    case!("invalid/salamander_short_password", Outbound, runtime("password is 3 bytes")),
    // On `udp[]` the tables are built when the listener / dialer is created (`NewUDPConn`).
    case!("invalid/sudoku_ascii_mode", Inbound, runtime("ascii: unknown mode \"binary\"")),
    case!("invalid/xdns_extra_poll", Inbound, build("extraPoll must lie within 0–3"), XdnsObjectSchema),
    // The server fixture on the client side: resolvers are checked by `NewClient`, not `Build()`.
    case!("valid/xdns_server", Outbound, runtime("resolvers: the client side needs at least one resolver"), XdnsObjectSchema),
    case!("invalid/xicmp_cidr", Outbound, build("ips: invalid IP address \"10.0.0.0/8\"")),
    case!("invalid/realm_no_stun", Inbound, build("stunServers: at least one host:port is required")),
    case!("invalid/realm_stun_port_name", Outbound, runtime("port must be a number 1–65535")),
    case!("invalid/udphop_short_interval", Outbound, build("interval must be at least 5"), UdpHopUdpMask),
    case!("invalid/udphop_on_inbound", Inbound, runtime("client only"), UdpHopUdpMask),
];

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/xray/config/stream/fixtures/finalmask")
}

fn finalmask_of(case: &Case) -> Value {
    serde_json::from_str(case.json).unwrap_or_else(|error| panic!("{}: not JSON: {error}", case.file))
}

/// Runs both chains of a fixture through the save-time validation, like `apply_inbound_stream`.
fn validate(case: &Case) -> Result<(), String> {
    let finalmask = finalmask_of(case);
    for chain in [FinalMaskChain::Tcp, FinalMaskChain::Udp] {
        let Some(array) = finalmask.get(chain.key()) else { continue };
        let array = array.as_array().unwrap_or_else(|| panic!("{}: {} is not an array", case.file, chain.key()));
        let layers = parse_finalmask_layers(array)
            .unwrap_or_else(|| panic!("{}: {} is not a list of {{type, settings}}", case.file, chain.key()));
        validate_finalmask_layers(&layers, chain, case.direction).map_err(|error| error.message().to_owned())?;
    }
    Ok(())
}

#[test]
fn every_fixture_matches_its_expectation() {
    for case in CASES {
        let label = format!("{} ({})", case.file, case.direction.as_str());
        match (case.expect, validate(case)) {
            (Expect::Valid, Ok(())) => {}
            (Expect::Valid, Err(error)) => panic!("{label}: expected valid, got: {error}"),
            (Expect::Invalid { .. }, Ok(())) => panic!("{label}: expected an error, validation passed"),
            (Expect::Invalid { needle, .. }, Err(error)) => {
                assert!(error.contains(needle), "{label}: error lacks `{needle}`: {error}");
            }
        }
    }
}

/// Every documented type has a valid fixture in each of its chains, so a new type cannot be added
/// to `TCP_FINALMASK_TYPES` / `UDP_FINALMASK_TYPES` without one.
#[test]
fn every_documented_type_has_a_valid_fixture() {
    for chain in [FinalMaskChain::Tcp, FinalMaskChain::Udp] {
        for kind in chain.types() {
            let covered = CASES.iter().filter(|case| matches!(case.expect, Expect::Valid)).any(|case| {
                finalmask_of(case)
                    .get(chain.key())
                    .and_then(Value::as_array)
                    .is_some_and(|layers| layers.iter().any(|layer| layer["type"] == *kind))
            });
            assert!(covered, "no valid fixture for finalmask.{} `{kind}`", chain.key());
        }
    }
}

/// A file on disk that no case uses is dead weight that looks like coverage.
#[test]
fn every_fixture_file_is_used() {
    for group in ["valid", "invalid"] {
        let dir = fixture_dir().join(group);
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
        for entry in entries {
            let path = entry.expect("fixture dir entry").path();
            let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap_or_default();
            let file = format!("{group}/{stem}");
            assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("json"), "{}", path.display());
            assert!(CASES.iter().any(|case| case.file == file), "{file}.json is not listed in CASES");
        }
    }
}

// ── parity with `xray run -test` ──

/// A minimal config around the fixture: one inbound (VLESS) or outbound (Freedom) carrying it.
/// The network follows the chain so a UDP mask sits on a UDP transport.
fn parity_config(case: &Case) -> Value {
    let finalmask = finalmask_of(case);
    let network = if finalmask.get("tcp").is_none() { "kcp" } else { "raw" };
    let stream = json!({"network": network, "finalmask": finalmask});
    let freedom = json!({"protocol": "freedom", "tag": "direct"});
    match case.direction {
        StreamDirection::Inbound => json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": 10443,
                "protocol": "vless",
                "settings": {"clients": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b"}], "decryption": "none"},
                "streamSettings": stream
            }],
            "outbounds": [freedom]
        }),
        StreamDirection::Outbound => {
            let mut outbound = freedom;
            outbound["streamSettings"] = stream;
            json!({"outbounds": [outbound]})
        }
    }
}

fn xray_version(xray: &Path) -> Option<XrayCoreVersion> {
    let output = Command::new(xray).arg("version").output().ok()?;
    XrayCoreVersion::parse(&String::from_utf8_lossy(&output.stdout))
}

/// `XRAY_BIN=/path/to/xray cargo test finalmask_fixtures` (or `xray-bin/xray` in the crate root):
/// Feldjäger and the core agree on every case `xray run -test` can judge. A `Runtime` case is
/// expected to **pass** `-test` — if the core starts refusing it at build time, the case should
/// move to `Build`.
#[test]
fn parity_with_xray_run_test() {
    let Some(xray) = local_xray_bin() else {
        eprintln!("no local Xray (XRAY_BIN / xray-bin) — skipping the `xray run -test` parity check");
        return;
    };
    let xray = xray.as_path();
    let version = xray_version(xray);
    let dir = std::env::temp_dir().join(format!("feldjaeger-finalmask-parity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("parity temp dir");
    let mut failures = Vec::new();
    for (index, case) in CASES.iter().enumerate() {
        let label = format!("{} ({})", case.file, case.direction.as_str());
        if let Some(feature) = case.feature
            && !feature.available_in(version)
        {
            eprintln!("{label}: skipped — needs Xray-core {}", feature.min_version());
            continue;
        }
        let path = dir.join(format!("case-{index}.json"));
        let config = serde_json::to_string_pretty(&parity_config(case)).expect("serialize parity config");
        std::fs::write(&path, config).expect("write parity config");
        let output = Command::new(xray).arg("run").arg("-test").arg("-c").arg(&path).output();
        let output = output.unwrap_or_else(|error| panic!("cannot run {}: {error}", xray.display()));
        let core_accepts = output.status.success();
        let core_should_accept = !matches!(case.expect, Expect::Invalid { core: CoreCheck::Build, .. });
        if core_accepts != core_should_accept {
            let verdict = if core_accepts { "accepted" } else { "rejected" };
            let stdout = String::from_utf8_lossy(&output.stdout);
            failures.push(format!("{label}: xray run -test {verdict} it\n{}", stdout.trim()));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "parity mismatches:\n{}", failures.join("\n\n"));
}
