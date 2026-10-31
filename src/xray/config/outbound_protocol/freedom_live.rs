//! Freedom "Fix config" against the real core (Xray-core v26.10.29 deprecation, XTLS/Xray-core#7242).
//!
//! [`super::FreedomSettingsDraft::migrate_legacy_obfuscation`] claims the FinalMask layers it
//! writes do what the deprecated Freedom `fragment` / `noises` did. Checked end to end: a
//! `tunnel` inbound in front of the Freedom outbound and TCP / UDP sinks behind it that record what
//! arrives —
//! - `fragment`: the payload arrives intact but in many TCP segments (one without the mask);
//! - `noises`: the noise datagrams arrive before the payload datagram, in the same order;
//! - the migrated config loads without the deprecation warning.
//!
//! Runs only with a local Xray ([`crate::xray::local_xray`]).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use super::freedom::{apply_freedom_settings, parse_freedom_settings};
use crate::xray::config::outbound_stream::{apply_outbound_stream, parse_outbound_stream};
use crate::xray::local_xray::local_xray_bin;

const PAYLOAD: &[u8] = b"feldjaeger-freedom-fix-config-payload-0123456789";

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port()
}

/// The outbound after "Fix config" + Save.
fn fixed(outbound: &Value) -> Value {
    let mut draft = parse_freedom_settings(outbound);
    let mut stream = parse_outbound_stream(outbound);
    draft.migrate_legacy_obfuscation(&mut stream).expect("fix config");
    let mut result = outbound.clone();
    apply_freedom_settings(&mut result, &draft).expect("apply settings");
    apply_outbound_stream(&mut result, &stream).expect("apply stream");
    result
}

/// What the TCP and UDP sinks received through `outbound`: the TCP reads, the UDP datagrams.
fn observe(xray: &Path, dir: &Path, label: &str, outbound: &Value) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (tcp_in, udp_in) = (free_tcp_port(), free_udp_port());
    let tcp_sink = TcpListener::bind("127.0.0.1:0").expect("tcp sink");
    let udp_sink = UdpSocket::bind("127.0.0.1:0").expect("udp sink");
    let (tcp_target, udp_target) = (
        tcp_sink.local_addr().expect("addr").port(),
        udp_sink.local_addr().expect("addr").port(),
    );
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": tcp_in, "protocol": "tunnel",
             "settings": {"address": "127.0.0.1", "port": tcp_target, "network": "tcp"}},
            {"listen": "127.0.0.1", "port": udp_in, "protocol": "tunnel",
             "settings": {"address": "127.0.0.1", "port": udp_target, "network": "udp"}}
        ],
        "outbounds": [outbound]
    });
    let path = dir.join(format!("{label}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&config).expect("serialize")).expect("write config");
    let mut child = Command::new(xray)
        .args(["run", "-c"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("cannot start {}: {error}", xray.display()));
    // Ready when the core logs "Xray … started" (warning level). No probe connection: the core
    // fragments only the first connection of the process, legacy Freedom and FinalMask alike
    // (live check 2026-10-31), so the payload has to be that first one.
    let stdout = child.stdout.take().expect("stdout");
    let _xray = Running(child);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains(" started") {
                let _ = started_tx.send(());
            }
        }
    });
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| panic!("{label}: xray did not start"));

    let tcp_reader = thread::spawn(move || {
        tcp_sink.set_nonblocking(false).expect("blocking");
        let (mut conn, _) = tcp_sink.accept().expect("accept");
        conn.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
        let mut reads = Vec::new();
        let mut buffer = [0_u8; 4096];
        while let Ok(n) = conn.read(&mut buffer) {
            if n == 0 {
                break;
            }
            reads.push(buffer[..n].to_vec());
        }
        reads
    });
    let mut client = TcpStream::connect(("127.0.0.1", tcp_in)).expect("connect tunnel");
    client.write_all(PAYLOAD).expect("send tcp");
    thread::sleep(Duration::from_millis(800));
    drop(client);
    let tcp_reads = tcp_reader.join().expect("tcp sink thread");

    udp_sink.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    UdpSocket::bind("127.0.0.1:0").expect("udp client").send_to(PAYLOAD, ("127.0.0.1", udp_in)).expect("send udp");
    let mut datagrams = Vec::new();
    let mut buffer = [0_u8; 2048];
    while let Ok((n, _)) = udp_sink.recv_from(&mut buffer) {
        datagrams.push(buffer[..n].to_vec());
    }
    (tcp_reads, datagrams)
}

#[test]
fn fix_config_layers_behave_like_freedom_fragment_and_noises() {
    let Some(xray) = local_xray_bin() else {
        eprintln!("no local Xray (XRAY_BIN / xray-bin) — skipping the Freedom Fix config live check");
        return;
    };
    let dir = std::env::temp_dir().join(format!("feldjaeger-freedom-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let legacy = json!({"protocol": "freedom", "settings": {
        "fragment": {"packets": "1-1", "length": "3-5", "interval": "5"},
        "noises": [{"type": "str", "packet": "NOISE1", "delay": "5"}, {"type": "base64", "packet": "Tk9JU0Uy"}]
    }});
    let migrated = fixed(&legacy);
    assert!(migrated["settings"].get("fragment").is_none() && migrated["settings"].get("noises").is_none());

    let (plain_tcp, plain_udp) = observe(&xray, &dir, "plain", &json!({"protocol": "freedom"}));
    assert_eq!(plain_udp, vec![PAYLOAD.to_vec()], "no noise without a mask");
    assert!(plain_tcp.len() <= 2, "unmasked payload arrives in one piece: {} reads", plain_tcp.len());

    for (label, outbound) in [("legacy", &legacy), ("migrated", &migrated)] {
        let (tcp, udp) = observe(&xray, &dir, label, outbound);
        assert_eq!(tcp.concat(), PAYLOAD, "{label}: TCP payload intact");
        assert!(tcp.len() >= 8, "{label}: fragmented into {} reads", tcp.len());
        assert_eq!(
            udp,
            vec![b"NOISE1".to_vec(), b"NOISE2".to_vec(), PAYLOAD.to_vec()],
            "{label}: noise datagrams before the payload"
        );
    }

    // The migrated config loads without the deprecation warning.
    let path = dir.join("migrated-test.json");
    let config = json!({"outbounds": [migrated]});
    std::fs::write(&path, serde_json::to_string(&config).expect("serialize")).expect("write");
    let output = Command::new(&xray).args(["run", "-test", "-c"]).arg(&path).output().expect("run -test");
    let log = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "migrated config refused:\n{log}");
    assert!(!log.contains("deprecated"), "migrated config still warns:\n{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
