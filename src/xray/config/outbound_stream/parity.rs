//! Parity of the outbound Stream / Security / FinalMask validation with a local
//! `xray run -test` (Roadmap §4.2, §2.6 stage 7.1; also `sendThrough`). Runs when `XRAY_BIN` points to an Xray
//! executable or `xray-bin/xray` exists ([`crate::xray::local_xray`]); a no-op otherwise.

use std::process::Command;

use serde_json::{Value, json};

use super::{SockoptDraft, apply_outbound_stream, parse_outbound_stream};
use crate::xray::config::compatibility::{CompatibilityWarningId, outbound_warnings};
use crate::xray::config::outbound_edit::validate_send_through;
use crate::xray::local_xray::local_xray_bin;

/// What the core does with a case Feldjäger is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Both accept.
    Valid,
    /// Both refuse: `Build()` fails, so `xray run -test` does.
    Build,
    /// Feldjäger refuses what `xray run -test` passes, because the core only fails once it dials.
    Runtime,
}

const UUID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";
const PUBLIC_KEY: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

/// A VLESS outbound around `stream`. Without TLS / REALITY the server is a private IP, so the
/// core's plaintext rule (XTLS/Xray-core#6303, checked separately below) does not decide the case.
fn vless(stream: Value) -> Value {
    let secured = stream
        .get("security")
        .and_then(Value::as_str)
        .is_some_and(|security| security != "none");
    let address = if secured { "example.com" } else { "10.0.0.1" };
    vless_to(address, stream)
}

fn vless_to(address: &str, stream: Value) -> Value {
    json!({"tag": "out", "protocol": "vless",
           "settings": {"address": address, "port": 443, "id": UUID, "encryption": "none"},
           "streamSettings": stream})
}

/// Plaintext rule cases: (label, outbound, whether the core refuses it).
fn plaintext_cases() -> Vec<(&'static str, Value, bool)> {
    let raw = || json!({"network": "raw"});
    vec![
        ("public domain", vless_to("example.com", raw()), true),
        ("public IP, security none", vless_to("1.1.1.1", json!({"network": "raw", "security": "none"})), true),
        ("private IP", vless_to("192.168.1.10", raw()), false),
        ("*.lan", vless_to("router.lan", raw()), false),
        ("dotless name", vless_to("backend", raw()), false),
        ("under example", vless_to("srv.example", raw()), false),
        ("tls", vless_to("example.com", json!({"network": "raw", "security": "tls"})), false),
        ("trojan public", json!({"tag": "out", "protocol": "trojan",
            "settings": {"servers": [{"address": "1.1.1.1", "port": 443, "password": "p"}]}}), true),
    ]
}

fn hysteria(stream: Value) -> Value {
    json!({"tag": "out", "protocol": "hysteria",
           "settings": {"version": 2, "address": "example.com", "port": 443},
           "streamSettings": stream})
}

fn reality(extra: Value) -> Value {
    let mut settings = json!({"serverName": "example.com", "publicKey": PUBLIC_KEY, "shortId": "6ba85179e30d4fc2"});
    if let (Some(object), Some(extra)) = (settings.as_object_mut(), extra.as_object()) {
        object.extend(extra.clone());
    }
    settings
}

fn cases() -> Vec<(&'static str, Value, Expect)> {
    vec![
        ("raw + reality", vless(json!({"network": "raw", "security": "reality", "realitySettings": reality(json!({}))})), Expect::Valid),
        ("grpc + reality", vless(json!({"network": "grpc", "security": "reality", "grpcSettings": {"serviceName": "s", "authority": "a.example"},
            "realitySettings": reality(json!({}))})), Expect::Valid),
        ("ws + reality", vless(json!({"network": "ws", "security": "reality", "realitySettings": reality(json!({}))})), Expect::Build),
        ("reality bad publicKey", vless(json!({"network": "raw", "security": "reality",
            "realitySettings": reality(json!({"publicKey": "short"}))})), Expect::Build),
        ("reality odd shortId", vless(json!({"network": "raw", "security": "reality",
            "realitySettings": reality(json!({"shortId": "abc"}))})), Expect::Build),
        ("reality fingerprint unsafe", vless(json!({"network": "raw", "security": "reality",
            "realitySettings": reality(json!({"fingerprint": "unsafe"}))})), Expect::Build),
        ("reality spiderX", vless(json!({"network": "raw", "security": "reality",
            "realitySettings": reality(json!({"spiderX": "x"}))})), Expect::Build),
        ("reality server shortIds", vless(json!({"network": "raw", "security": "reality",
            "realitySettings": reality(json!({"shortIds": ["aa"]}))})), Expect::Build),
        ("tls client", vless(json!({"network": "ws", "security": "tls", "wsSettings": {"path": "/ws?ed=2048", "host": "cdn.example"},
            "tlsSettings": {"serverName": "example.com", "alpn": "h2,http/1.1", "fingerprint": "Firefox",
                            "pinnedPeerCertSha256": "0A:".repeat(31) + "0A"}})), Expect::Valid),
        ("tls bad pin", vless(json!({"network": "raw", "security": "tls", "tlsSettings": {"pinnedPeerCertSha256": "abcd"}})), Expect::Build),
        ("tls unknown fingerprint", vless(json!({"network": "raw", "security": "tls", "tlsSettings": {"fingerprint": "netscape"}})), Expect::Build),
        ("httpupgrade host header", vless(json!({"network": "httpupgrade", "httpupgradeSettings": {"path": "/", "headers": {"Host": "x"}}})), Expect::Build),
        ("httpupgrade", vless(json!({"network": "httpupgrade", "security": "tls",
            "httpupgradeSettings": {"path": "/up", "headers": {"User-Agent": "x"}}})), Expect::Valid),
        ("grpc int32 overflow", vless(json!({"network": "grpc", "grpcSettings": {"idle_timeout": 3_000_000_000_i64}})), Expect::Build),
        ("mkcp mtu", vless(json!({"network": "kcp", "kcpSettings": {"mtu": 10}})), Expect::Build),
        ("mkcp + udphop", vless(json!({"network": "kcp", "finalmask": {"udp": [
            {"type": "udphop", "settings": {"mode": "intervalRemote", "remotePorts": "20000-30000"}}]}})), Expect::Valid),
        ("hysteria", hysteria(json!({"network": "hysteria", "security": "tls", "tlsSettings": {"serverName": "example.com"},
            "hysteriaSettings": {"version": 2, "auth": "pw", "udpIdleTimeout": 60},
            "finalmask": {"quicParams": {"congestion": "brutal", "brutalUp": "50 mbps"}}})), Expect::Valid),
        ("hysteria version 1", hysteria(json!({"network": "hysteria", "security": "tls",
            "hysteriaSettings": {"version": 1, "auth": "pw"}})), Expect::Build),
        ("hysteria udpIdleTimeout", hysteria(json!({"network": "hysteria", "security": "tls",
            "hysteriaSettings": {"version": 2, "udpIdleTimeout": 1}})), Expect::Build),
        ("xhttp/3 brutal", vless(json!({"network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h3"]},
            "xhttpSettings": {"path": "/x"}, "finalmask": {"quicParams": {"congestion": "brutal"}}})), Expect::Runtime),
        // Outbound `sockopt` editor (Roadmap §4.2): `SocketConfig` decode + `Build()`.
        ("sockopt outbound fields", vless(sockopt(json!({"mark": 255, "domainStrategy": "useipv4v6",
            "interface": "eth0", "tcpCongestion": "bbr", "tcpMptcp": true, "addressPortStrategy": "SrvPortOnly",
            "dialerProxy": "nowhere", "tcpKeepAliveIdle": -1,
            "happyEyeballs": {"tryDelayMs": 250, "prioritizeIPv6": true, "interleave": 2, "maxConcurrentTry": 4}}))), Expect::Valid),
        ("sockopt tcpcongestion spelling", vless(sockopt(json!({"tcpcongestion": "bbr"}))), Expect::Valid),
        ("sockopt domainStrategy", vless(sockopt(json!({"domainStrategy": "UseIPv5"}))), Expect::Build),
        ("sockopt addressPortStrategy", vless(sockopt(json!({"addressPortStrategy": "SrvOnly"}))), Expect::Build),
        ("sockopt mark int32", vless(sockopt(json!({"mark": 2_147_483_648_i64}))), Expect::Build),
        ("sockopt tcpUserTimeout int32", vless(sockopt(json!({"tcpUserTimeout": 3_000_000_000_i64}))), Expect::Build),
        ("sockopt happyEyeballs uint32", vless(sockopt(json!({"happyEyeballs": {"interleave": 4_294_967_296_i64}}))), Expect::Build),
        ("sockopt dialerProxy self", vless(sockopt(json!({"dialerProxy": "out"}))), Expect::Runtime),
    ]
}

/// RAW stream with the given `sockopt`.
fn sockopt(sockopt: Value) -> Value {
    json!({"network": "raw", "sockopt": sockopt})
}

/// Feldjäger's verdict: every part of the draft written, as an edit in the GUI would.
fn feldjaeger_accepts(outbound: &Value) -> Result<(), String> {
    let mut draft = parse_outbound_stream(outbound);
    draft.write = true;
    let finalmask = outbound.pointer("/streamSettings/finalmask");
    draft.write_finalmask_tcp = finalmask.and_then(|f| f.get("tcp")).is_some();
    draft.write_finalmask_udp = finalmask.and_then(|f| f.get("udp")).is_some();
    draft.write_quic_params = finalmask.and_then(|f| f.get("quicParams")).is_some();
    // Every sockopt key counts as typed in the editor, so all of them are validated.
    draft.disk_sockopt = SockoptDraft::default();
    apply_outbound_stream(&mut outbound.clone(), &draft).map_err(|error| error.message())
}

/// `sendThrough` forms (Roadmap §4.2): Feldjäger's [`validate_send_through`] against
/// `OutboundDetourConfig.Build()`.
fn send_through_cases() -> Vec<(&'static str, Expect)> {
    vec![
        ("0.0.0.0", Expect::Valid),
        ("[2001:db8::1]", Expect::Valid),
        ("2001:db8::/64", Expect::Valid),
        ("10.0.0.0/8", Expect::Valid),
        ("origin", Expect::Valid),
        ("srcip", Expect::Valid),
        ("", Expect::Build),
        ("Origin", Expect::Build),
        ("example.com", Expect::Build),
        ("env:BIND", Expect::Build),
        ("fe80::1%eth0", Expect::Build),
        ("origin/24", Expect::Runtime),
        ("example.com/24", Expect::Runtime),
        ("1.2.3.4/abc", Expect::Runtime),
        ("1.2.3.4/33", Expect::Runtime),
    ]
}

#[test]
fn send_through_parity_with_xray_run_test() {
    let mut failures = Vec::new();
    for (value, expect) in send_through_cases() {
        // An empty field omits the key in Feldjäger; the case is about `"sendThrough": ""` on disk.
        let ours = if value.is_empty() { Err(String::new()) } else { validate_send_through(value) };
        if ours.is_ok() != (expect == Expect::Valid) {
            failures.push(format!("sendThrough {value:?}: Feldjäger {ours:?}, expected {expect:?}"));
        }
    }
    let Some(xray) = local_xray_bin() else {
        eprintln!("no local Xray (XRAY_BIN / xray-bin) — skipping the sendThrough `xray run -test` parity check");
        assert!(failures.is_empty(), "mismatches:\n{}", failures.join("\n"));
        return;
    };
    let dir = std::env::temp_dir().join(format!("feldjaeger-send-through-parity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("parity temp dir");
    for (index, (value, expect)) in send_through_cases().into_iter().enumerate() {
        let path = dir.join(format!("case-{index}.json"));
        let config = json!({"outbounds": [{"tag": "out", "protocol": "freedom", "sendThrough": value}]});
        std::fs::write(&path, serde_json::to_string_pretty(&config).expect("serialize")).expect("write config");
        let output = Command::new(&xray).args(["run", "-test", "-c"]).arg(&path).output();
        let output = output.unwrap_or_else(|error| panic!("cannot run {}: {error}", xray.display()));
        if output.status.success() != (expect != Expect::Build) {
            failures.push(format!(
                "sendThrough {value:?}: xray run -test {}\n{}",
                if output.status.success() { "accepted it" } else { "rejected it" },
                String::from_utf8_lossy(&output.stdout).trim()
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "parity mismatches:\n{}", failures.join("\n\n"));
}

/// `cargo test outbound_stream` with a local Xray: Feldjäger and `xray run -test` agree on
/// every case the core judges at build time.
#[test]
fn parity_with_xray_run_test() {
    let mut failures = Vec::new();
    // Feldjäger's side runs everywhere.
    for (label, outbound, expect) in cases() {
        let ours = feldjaeger_accepts(&outbound);
        if ours.is_ok() != (expect == Expect::Valid) {
            failures.push(format!("{label}: Feldjäger {ours:?}, expected {expect:?}"));
        }
    }
    for (label, outbound, refused) in plaintext_cases() {
        let warned = outbound_warnings(&outbound, None)
            .iter()
            .any(|warning| warning.id == CompatibilityWarningId::PlaintextOutboundForbidden);
        if warned != refused {
            failures.push(format!("plaintext {label}: Feldjäger warning {warned}, core refuses {refused}"));
        }
    }
    let Some(xray) = local_xray_bin() else {
        eprintln!("no local Xray (XRAY_BIN / xray-bin) — skipping the outbound `xray run -test` parity check");
        assert!(failures.is_empty(), "mismatches:\n{}", failures.join("\n"));
        return;
    };
    let dir = std::env::temp_dir().join(format!("feldjaeger-outbound-parity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("parity temp dir");
    for (index, (label, outbound, expect)) in cases().into_iter().enumerate() {
        let path = dir.join(format!("case-{index}.json"));
        let config = json!({"outbounds": [outbound]});
        std::fs::write(&path, serde_json::to_string_pretty(&config).expect("serialize")).expect("write config");
        let output = Command::new(&xray).args(["run", "-test", "-c"]).arg(&path).output();
        let output = output.unwrap_or_else(|error| panic!("cannot run {}: {error}", xray.display()));
        let core_accepts = output.status.success();
        if core_accepts != (expect != Expect::Build) {
            let verdict = if core_accepts { "accepted" } else { "rejected" };
            failures.push(format!(
                "{label}: xray run -test {verdict} it\n{}",
                String::from_utf8_lossy(&output.stdout).trim()
            ));
        }
    }
    let offset = cases().len();
    for (index, (label, outbound, refused)) in plaintext_cases().into_iter().enumerate() {
        let path = dir.join(format!("case-{}.json", offset + index));
        let config = json!({"outbounds": [outbound]});
        std::fs::write(&path, serde_json::to_string_pretty(&config).expect("serialize")).expect("write config");
        let output = Command::new(&xray).args(["run", "-test", "-c"]).arg(&path).output();
        let output = output.unwrap_or_else(|error| panic!("cannot run {}: {error}", xray.display()));
        if output.status.success() == refused {
            failures.push(format!(
                "plaintext {label}: xray run -test {} it\n{}",
                if refused { "accepted" } else { "rejected" },
                String::from_utf8_lossy(&output.stdout).trim()
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "parity mismatches:\n{}", failures.join("\n\n"));
}
