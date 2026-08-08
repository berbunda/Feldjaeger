//! CompatibilityGate for inbound Shell Save / Add / client mutate.
//!
//! Wave A Save order: **G9→G10→G6→G5→G1→G2→G8→G12→G4→G3** (G7 retired;
//! G11 predicate+tests only until Wave B).

mod matrix;

pub use matrix::{
    allowed_security_modes, allowed_stream_methods, coerce_display_stream_method,
    coerce_security_mode_for_transport, g10_hysteria_requires_tls, g11_shadowsocks_tcp_only,
    g9_hysteria_protocol_transport_ok, matrix_transport, selectable_stream_methods,
    transport_security_allowed, vision_active_from_inbound,
};

use serde_json::Value;

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Stable gate identifiers (design G1–G12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompatibilityGateId {
    /// Reality + method not in {raw,tcp,xhttp,grpc}.
    G1,
    /// Reality destination empty / not host:port.
    G2,
    /// Vision flow with non-tcp/raw method.
    G3,
    /// Reality + non-empty finalmask.tcp.
    G4,
    /// VLESS missing/empty decryption.
    G5,
    /// Trojan + effective security=none.
    G6,
    /// Hysteria in Add/Shell before TLS lake (retired Wave A — kept for message stability).
    G7,
    /// Reality missing privateKey / shortIds / serverNames.
    G8,
    /// Hysteria protocol ⇒ transport hysteria (wired Wave A).
    G9,
    /// Hysteria protocol/transport ⇒ security tls (wired Wave A).
    G10,
    /// Shadowsocks ⇒ editable transport raw/tcp only (gate kept; SS editor deferred to Tier 4).
    G11,
    /// TLS mode ⇒ every certificates[] entry has file paths or PEM (verify: key optional).
    G12,
}

impl CompatibilityGateId {
    /// Short user-facing reason (no secrets).
    pub fn message(self) -> &'static str {
        match self {
            Self::G1 => "Reality requires transport raw/tcp, xhttp, or grpc",
            Self::G2 => "Reality destination must be host:port (target or dest)",
            Self::G3 => "xtls-rprx-vision requires transport raw/tcp",
            Self::G4 => "Reality is incompatible with non-empty finalmask.tcp",
            Self::G5 => "VLESS requires non-empty settings.decryption",
            Self::G6 => "Trojan requires transport security (none is not allowed)",
            Self::G7 => "Hysteria inbound editing is not available yet (retired)",
            Self::G8 => "Reality requires privateKey, serverNames, and shortIds",
            Self::G9 => "Hysteria protocol requires transport hysteria",
            Self::G10 => "Hysteria requires security tls",
            Self::G11 => "Shadowsocks editable transport is raw/tcp only",
            Self::G12 => {
                "TLS requires each certificate entry to have file paths or PEM (key optional for usage verify)"
            }
        }
    }
}

/// Runs all applicable gates against one inbound JSON object.
pub fn check_inbound_compatibility(inbound: &Value) -> ConfigModifyResult<()> {
    if let Some(id) = first_failing_gate(inbound) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            id.message().to_owned(),
        ));
    }
    Ok(())
}

/// Returns the first failing gate id, if any.
///
/// Wave A order: **G9→G10→G11→G6→G5→G1→G2→G8→G12→G4→G3**.
pub fn first_failing_gate(inbound: &Value) -> Option<CompatibilityGateId> {
    let protocol = inbound
        .get("protocol")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase());
    let protocol_str = protocol.as_deref().unwrap_or("");
    let security = effective_security(inbound);
    let method = normalized_method(inbound);

    // G9: Hysteria protocol ⇒ transport hysteria
    if !matrix::g9_hysteria_protocol_transport_ok(protocol_str, &method) {
        return Some(CompatibilityGateId::G9);
    }

    // G10: Hysteria protocol/transport ⇒ security tls
    if !matrix::g10_hysteria_requires_tls(protocol_str, &method, &security) {
        return Some(CompatibilityGateId::G10);
    }

    // G11: Shadowsocks ⇒ transport raw/tcp only (product UI deferred to Tier 4).
    if !matrix::g11_shadowsocks_tcp_only(protocol_str, &method) {
        return Some(CompatibilityGateId::G11);
    }

    if protocol.as_deref() == Some("trojan") && security == "none" {
        return Some(CompatibilityGateId::G6);
    }

    if protocol.as_deref() == Some("vless") && !has_non_empty_decryption(inbound) {
        return Some(CompatibilityGateId::G5);
    }

    if security == "reality" {
        if !matches!(method.as_str(), "raw" | "tcp" | "xhttp" | "grpc") {
            return Some(CompatibilityGateId::G1);
        }
        if !reality_destination_ok(inbound) {
            return Some(CompatibilityGateId::G2);
        }
        if !reality_required_fields_ok(inbound) {
            return Some(CompatibilityGateId::G8);
        }
    }

    // G12: TLS ⇒ every certificates[] entry complete (file or PEM; verify key optional)
    if security == "tls" && !tls_certificates_ok(inbound) {
        return Some(CompatibilityGateId::G12);
    }

    if security == "reality" && reality_finalmask_tcp_nonempty(inbound) {
        return Some(CompatibilityGateId::G4);
    }

    if inbound_has_vision_flow(inbound) && !matches!(method.as_str(), "raw" | "tcp") {
        return Some(CompatibilityGateId::G3);
    }

    None
}

fn tls_certificates_ok(inbound: &Value) -> bool {
    let Some(certs) = inbound
        .get("streamSettings")
        .and_then(|s| s.get("tlsSettings"))
        .and_then(|t| t.get("certificates"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    if certs.is_empty() {
        return false;
    }
    certs.iter().all(tls_certificate_entry_ok)
}

fn tls_certificate_entry_ok(entry: &Value) -> bool {
    let Some(cert) = entry.as_object() else {
        return false;
    };
    let usage = cert
        .get("usage")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("encipherment")
        .to_ascii_lowercase();
    let need_key = usage != "verify";

    let cert_file = cert
        .get("certificateFile")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let key_file = cert
        .get("keyFile")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let file_mode = !cert_file.is_empty() && (!need_key || !key_file.is_empty());

    let has_cert_pem = non_empty_string_array(cert.get("certificate"));
    let has_key_pem = non_empty_string_array(cert.get("key"));
    let pem_mode = has_cert_pem && (!need_key || has_key_pem);

    file_mode || pem_mode
}

fn non_empty_string_array(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.as_str()
                    .map(str::trim)
                    .is_some_and(|s| !s.is_empty())
            })
        })
}

/// Missing/null streamSettings or missing/empty security → `none`.
pub fn effective_security(inbound: &Value) -> String {
    let Some(stream) = inbound.get("streamSettings").filter(|v| !v.is_null()) else {
        return "none".to_owned();
    };
    stream
        .get("security")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("none")
        .to_ascii_lowercase()
}

/// Missing method/network → `tcp` (≡ raw for gates).
pub fn normalized_method(inbound: &Value) -> String {
    let Some(stream) = inbound.get("streamSettings").filter(|v| !v.is_null()) else {
        return "tcp".to_owned();
    };
    let raw = stream
        .get("network")
        .or_else(|| stream.get("method"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    if raw == "raw" {
        "tcp".to_owned()
    } else {
        raw
    }
}

/// Whether any client uses Vision flow (`xtls-rprx-vision` / contains `vision`).
pub fn inbound_has_vision_flow(inbound: &Value) -> bool {
    let Some(settings) = inbound.get("settings") else {
        return false;
    };
    for key in ["clients", "users"] {
        if let Some(array) = settings.get(key).and_then(Value::as_array) {
            for client in array {
                if client
                    .get("flow")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .is_some_and(|flow| {
                        !flow.is_empty()
                            && (flow.eq_ignore_ascii_case("xtls-rprx-vision")
                                || flow.to_ascii_lowercase().contains("vision"))
                    })
                {
                    return true;
                }
            }
        }
    }
    false
}

fn has_non_empty_decryption(inbound: &Value) -> bool {
    inbound
        .get("settings")
        .and_then(|s| s.get("decryption"))
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
}

fn reality_settings(inbound: &Value) -> Option<&Value> {
    inbound
        .get("streamSettings")?
        .get("realitySettings")
        .filter(|v| v.is_object())
}

fn reality_destination_ok(inbound: &Value) -> bool {
    let Some(reality) = reality_settings(inbound) else {
        return false;
    };
    let dest = reality
        .get("target")
        .or_else(|| reality.get("dest"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    is_host_port(dest)
}

fn is_host_port(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    // Accept host:port or [ipv6]:port — require a trailing :port with digits.
    match value.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            true
        }
        _ => false,
    }
}

fn reality_required_fields_ok(inbound: &Value) -> bool {
    let Some(reality) = reality_settings(inbound) else {
        return false;
    };
    let private_key = reality
        .get("privateKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if private_key.is_empty() {
        return false;
    }
    let server_names = reality
        .get("serverNames")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().any(|v| {
                v.as_str()
                    .map(str::trim)
                    .is_some_and(|s| !s.is_empty())
            })
        })
        .unwrap_or(false);
    let short_ids = reality
        .get("shortIds")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().any(|v| {
                v.as_str()
                    .map(str::trim)
                    .is_some_and(|s| !s.is_empty())
            })
        })
        .unwrap_or(false);
    server_names && short_ids
}

fn reality_finalmask_tcp_nonempty(inbound: &Value) -> bool {
    // `finalmask` is a sibling of `realitySettings` under `streamSettings`, not nested inside
    // it — see https://xtls.github.io/ru/config/transports/finalmask.html.
    inbound
        .get("streamSettings")
        .and_then(|s| s.get("finalmask"))
        .and_then(|f| f.get("tcp"))
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn g6_rejects_trojan_without_stream_settings() {
        let inbound = json!({"protocol":"trojan","settings":{"clients":[]}});
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G6));
    }

    #[test]
    fn g6_rejects_trojan_security_none() {
        let inbound = json!({
            "protocol":"trojan",
            "streamSettings":{"security":"none","network":"tcp"}
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G6));
    }

    #[test]
    fn trojan_reality_passes_when_fields_ok() {
        let inbound = json!({
            "protocol":"trojan",
            "settings":{"clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"reality",
                "realitySettings":{
                    "target":"www.example.com:443",
                    "privateKey":"abc",
                    "serverNames":["www.example.com"],
                    "shortIds":["abcd"]
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), None);
    }

    #[test]
    fn g5_rejects_vless_without_decryption() {
        let inbound = json!({"protocol":"vless","settings":{"clients":[]}});
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G5));
    }

    #[test]
    fn g5_accepts_vless_decryption_none() {
        let inbound = json!({
            "protocol":"vless",
            "settings":{"clients":[],"decryption":"none"}
        });
        assert_eq!(first_failing_gate(&inbound), None);
    }

    #[test]
    fn g8_rejects_missing_private_key() {
        let inbound = json!({
            "protocol":"trojan",
            "streamSettings":{
                "security":"reality",
                "realitySettings":{
                    "target":"a:443",
                    "serverNames":["a"],
                    "shortIds":["01"]
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G8));
    }

    #[test]
    fn g2_rejects_bad_destination() {
        let inbound = json!({
            "protocol":"trojan",
            "streamSettings":{
                "security":"reality",
                "realitySettings":{
                    "target":"no-port",
                    "privateKey":"k",
                    "serverNames":["a"],
                    "shortIds":["01"]
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G2));
    }

    #[test]
    fn g3_scans_both_client_arrays() {
        let inbound = json!({
            "protocol":"vless",
            "settings":{
                "decryption":"none",
                "clients":[{"id":"a","flow":"xtls-rprx-vision"}],
                "users":[{"id":"b"}]
            },
            "streamSettings":{"network":"xhttp","security":"none"}
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G3));
    }

    #[test]
    fn g9_rejects_hysteria_with_tcp() {
        let inbound = json!({
            "protocol":"hysteria",
            "settings":{"version":2,"users":[]},
            "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{
                "certificates":[{"certificateFile":"/c","keyFile":"/k"}]
            }}
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G9));
    }

    #[test]
    fn g10_rejects_hysteria_without_tls() {
        let inbound = json!({
            "protocol":"hysteria",
            "settings":{"version":2,"users":[]},
            "streamSettings":{"network":"hysteria","security":"none"}
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G10));
    }

    #[test]
    fn hysteria_tls_hysteria_transport_passes() {
        let inbound = json!({
            "protocol":"hysteria",
            "settings":{"version":2,"users":[]},
            "streamSettings":{
                "network":"hysteria",
                "security":"tls",
                "tlsSettings":{
                    "certificates":[{"certificateFile":"/c.pem","keyFile":"/k.pem"}]
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), None);
    }

    #[test]
    fn g12_rejects_empty_tls_paths() {
        let inbound = json!({
            "protocol":"vless",
            "settings":{"decryption":"none","clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"tls",
                "tlsSettings":{"certificates":[{"certificateFile":"","keyFile":"/k"}]}
            }
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G12));
    }

    #[test]
    fn g12_rejects_empty_certificates_array() {
        let inbound = json!({
            "protocol":"vless",
            "settings":{"decryption":"none","clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"tls",
                "tlsSettings":{"certificates":[]}
            }
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G12));
    }

    #[test]
    fn g12_accepts_pem_only_certificate() {
        let inbound = json!({
            "protocol":"vless",
            "settings":{"decryption":"none","clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"tls",
                "tlsSettings":{
                    "certificates":[{
                        "certificate":["-----BEGIN CERTIFICATE-----","abc","-----END CERTIFICATE-----"],
                        "key":["-----BEGIN PRIVATE KEY-----","xyz","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), None);
    }

    #[test]
    fn g12_accepts_verify_without_key() {
        let inbound = json!({
            "protocol":"vless",
            "settings":{"decryption":"none","clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"tls",
                "tlsSettings":{
                    "certificates":[{
                        "certificateFile":"/ca.pem",
                        "usage":"verify"
                    }]
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), None);
    }

    #[test]
    fn g12_accepts_multi_entry_when_all_complete() {
        let inbound = json!({
            "protocol":"vless",
            "settings":{"decryption":"none","clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"tls",
                "tlsSettings":{
                    "certificates":[
                        {"certificateFile":"/a.pem","keyFile":"/a.key"},
                        {"certificateFile":"/b.pem","keyFile":"/b.key","usage":"issue"}
                    ]
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), None);
    }

    #[test]
    fn g12_rejects_incomplete_second_entry() {
        let inbound = json!({
            "protocol":"vless",
            "settings":{"decryption":"none","clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"tls",
                "tlsSettings":{
                    "certificates":[
                        {"certificateFile":"/a.pem","keyFile":"/a.key"},
                        {"certificateFile":"/b.pem","keyFile":""}
                    ]
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G12));
    }

    #[test]
    fn g12_message_exists() {
        assert!(
            CompatibilityGateId::G12
                .message()
                .contains("certificate")
        );
    }

    #[test]
    fn g11_blocks_shadowsocks_non_tcp_transport() {
        let inbound = json!({
            "protocol":"shadowsocks",
            "settings":{"clients":[],"network":"tcp,udp"},
            "streamSettings":{"network":"xhttp","security":"none"}
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G11));
        assert!(!g11_shadowsocks_tcp_only("shadowsocks", "xhttp"));
    }

    #[test]
    fn g4_blocks_reality_with_top_level_finalmask_tcp() {
        let inbound = json!({
            "protocol":"trojan",
            "settings":{"clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"reality",
                "realitySettings":{
                    "target":"www.example.com:443",
                    "privateKey":"abc",
                    "serverNames":["www.example.com"],
                    "shortIds":["abcd"]
                },
                "finalmask":{"tcp":[{"type":"fragment","settings":{}}]}
            }
        });
        assert_eq!(first_failing_gate(&inbound), Some(CompatibilityGateId::G4));
    }

    #[test]
    fn g4_ignores_finalmask_tcp_nested_inside_reality_settings() {
        // Historical (buggy) shape: `finalmask` nested inside `realitySettings` is not the
        // official wire location (finalmask is a sibling of realitySettings), so it must not
        // false-positive block an otherwise-valid Reality inbound.
        let inbound = json!({
            "protocol":"trojan",
            "settings":{"clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"reality",
                "realitySettings":{
                    "target":"www.example.com:443",
                    "privateKey":"abc",
                    "serverNames":["www.example.com"],
                    "shortIds":["abcd"],
                    "finalmask":{"tcp":[{"type":"fragment","settings":{}}]}
                }
            }
        });
        assert_eq!(first_failing_gate(&inbound), None);
    }

    #[test]
    fn g4_passes_when_finalmask_tcp_empty_or_absent() {
        let base = json!({
            "protocol":"trojan",
            "settings":{"clients":[]},
            "streamSettings":{
                "network":"tcp",
                "security":"reality",
                "realitySettings":{
                    "target":"www.example.com:443",
                    "privateKey":"abc",
                    "serverNames":["www.example.com"],
                    "shortIds":["abcd"]
                }
            }
        });
        assert_eq!(first_failing_gate(&base), None);

        let mut with_empty = base;
        with_empty["streamSettings"]["finalmask"] = json!({"tcp": []});
        assert_eq!(first_failing_gate(&with_empty), None);
    }
}
