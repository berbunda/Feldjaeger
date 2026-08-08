//! Static CompatibilityMatrix: wire-string cells + typed GUI filter helpers.
//!
//! Matrix keys are Xray wire strings (`tcp`/`raw`, `xhttp`, `reality`, …).
//! Typed [`allowed_stream_methods`] / [`allowed_security_modes`] intersect the
//! matrix with currently editable enums ([`StreamMethod`], [`InboundSecurityMode`]).

use super::inbound_has_vision_flow;
use crate::xray::config::inbound_security::InboundSecurityMode;
use crate::xray::config::inbound_stream::StreamMethod;
use serde_json::Value;

/// Canonical transport key for matrix lookups (`raw` → `tcp`, `ws` → `websocket`).
pub fn matrix_transport(wire: &str) -> String {
    let t = wire.trim().to_ascii_lowercase();
    match t.as_str() {
        "raw" => "tcp".to_owned(),
        "ws" => "websocket".to_owned(),
        "kcp" => "mkcp".to_owned(),
        other => other.to_owned(),
    }
}

/// Official transport × security cell (Wave 0 static table).
///
/// Returns `true` when the combination is allowed by Xray docs / Core design.
pub fn transport_security_allowed(transport: &str, security: &str) -> bool {
    let t = matrix_transport(transport);
    let s = security.trim().to_ascii_lowercase();
    match t.as_str() {
        "tcp" | "xhttp" | "grpc" => matches!(s.as_str(), "none" | "tls" | "reality"),
        "websocket" | "httpupgrade" | "http" | "mkcp" => {
            matches!(s.as_str(), "none" | "tls")
        }
        "hysteria" => s == "tls",
        // Unknown / exotic: do not grey in GUI (preserve path); Save uses G1+.
        _ => true,
    }
}

/// G9 predicate: Hysteria **protocol** requires network/method = hysteria.
pub fn g9_hysteria_protocol_transport_ok(protocol: &str, transport: &str) -> bool {
    if protocol.trim().eq_ignore_ascii_case("hysteria") {
        matrix_transport(transport) == "hysteria"
    } else {
        true
    }
}

/// G10 predicate: Hysteria protocol or hysteria transport requires security = tls.
pub fn g10_hysteria_requires_tls(protocol: &str, transport: &str, security: &str) -> bool {
    let hy_proto = protocol.trim().eq_ignore_ascii_case("hysteria");
    let hy_transport = matrix_transport(transport) == "hysteria";
    if hy_proto || hy_transport {
        security.trim().eq_ignore_ascii_case("tls")
    } else {
        true
    }
}

/// G11 predicate: Shadowsocks editable transport is raw/tcp only.
pub fn g11_shadowsocks_tcp_only(protocol: &str, transport: &str) -> bool {
    if protocol.trim().eq_ignore_ascii_case("shadowsocks") {
        matrix_transport(transport) == "tcp"
    } else {
        true
    }
}

fn protocol_allows_editable_transport(protocol: &str, method: StreamMethod) -> bool {
    match protocol.trim().to_ascii_lowercase().as_str() {
        "shadowsocks" | "tunnel" => method == StreamMethod::Tcp,
        "hysteria" => method == StreamMethod::Hysteria,
        _ => method != StreamMethod::Hysteria,
    }
}

/// Editable stream methods allowed for the current protocol × security × Vision.
pub fn allowed_stream_methods(
    protocol: &str,
    security: &str,
    vision_active: bool,
) -> Vec<StreamMethod> {
    selectable_stream_methods(protocol, vision_active)
        .into_iter()
        .filter(|m| transport_security_allowed(m.as_wire(), security))
        .collect()
}

/// Stream methods the GUI may offer for a protocol (Vision-narrowed).
///
/// Does **not** filter by current security — selecting an incompatible transport
/// should coerce security (Wave C1: Reality → WebSocket).
pub fn selectable_stream_methods(protocol: &str, vision_active: bool) -> Vec<StreamMethod> {
    [
        StreamMethod::Tcp,
        StreamMethod::Xhttp,
        StreamMethod::Grpc,
        StreamMethod::Ws,
        StreamMethod::Mkcp,
        StreamMethod::Hysteria,
    ]
    .into_iter()
    .filter(|m| protocol_allows_editable_transport(protocol, *m))
    .filter(|m| !vision_active || *m == StreamMethod::Tcp)
    .collect()
}

/// When `current` is illegal for `method_wire`, pick a legal replacement.
///
/// Wave C1: WebSocket drops Reality — Trojan → `tls`, VLESS → keep `tls` else `none`.
pub fn coerce_security_mode_for_transport(
    protocol: &str,
    method_wire: &str,
    current: InboundSecurityMode,
) -> InboundSecurityMode {
    let allowed = allowed_security_modes(protocol, method_wire);
    if allowed.contains(&current) {
        return current;
    }
    let proto = protocol.trim().to_ascii_lowercase();
    if proto == "trojan" {
        if allowed.contains(&InboundSecurityMode::Tls) {
            return InboundSecurityMode::Tls;
        }
    } else if current == InboundSecurityMode::Tls && allowed.contains(&InboundSecurityMode::Tls) {
        return InboundSecurityMode::Tls;
    } else if allowed.contains(&InboundSecurityMode::None) {
        return InboundSecurityMode::None;
    } else if allowed.contains(&InboundSecurityMode::Tls) {
        return InboundSecurityMode::Tls;
    }
    allowed.first().copied().unwrap_or(current)
}

/// Editable security modes allowed for the current protocol × transport.
///
/// Wave A: VLESS `none|tls|reality`; Trojan `tls|reality`.
pub fn allowed_security_modes(protocol: &str, method_wire: &str) -> Vec<InboundSecurityMode> {
    let candidates: &[InboundSecurityMode] = match protocol.trim().to_ascii_lowercase().as_str() {
        "shadowsocks" | "tunnel" => &[InboundSecurityMode::None],
        "trojan" => &[InboundSecurityMode::Tls, InboundSecurityMode::Reality],
        "hysteria" => &[InboundSecurityMode::Tls],
        _ => &[
            InboundSecurityMode::None,
            InboundSecurityMode::Tls,
            InboundSecurityMode::Reality,
        ],
    };
    candidates
        .iter()
        .copied()
        .filter(|mode| transport_security_allowed(method_wire, mode.as_wire()))
        .collect()
}

/// Combo display method when the draft editable method is illegal under filters.
///
/// Does **not** mutate the draft. `None` means exotic (`other_method`) — no coerce.
pub fn coerce_display_stream_method(
    draft_method: Option<StreamMethod>,
    allowed: &[StreamMethod],
) -> Option<StreamMethod> {
    let Some(current) = draft_method else {
        return None;
    };
    if allowed.contains(&current) {
        return Some(current);
    }
    allowed.first().copied()
}

/// Whether any client on the inbound uses Vision flow (same scan as G3).
pub fn vision_active_from_inbound(inbound: &Value) -> bool {
    inbound_has_vision_flow(inbound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reality_blocks_websocket() {
        assert!(!transport_security_allowed("ws", "reality"));
        assert!(!transport_security_allowed("websocket", "reality"));
        assert!(!transport_security_allowed("httpupgrade", "reality"));
        assert!(!transport_security_allowed("mkcp", "reality"));
    }

    #[test]
    fn reality_allows_tcp_xhttp_grpc() {
        for t in ["tcp", "raw", "xhttp", "grpc"] {
            assert!(transport_security_allowed(t, "reality"), "{t}");
        }
    }

    #[test]
    fn hysteria_transport_requires_tls() {
        assert!(transport_security_allowed("hysteria", "tls"));
        assert!(!transport_security_allowed("hysteria", "none"));
        assert!(!transport_security_allowed("hysteria", "reality"));
    }

    #[test]
    fn table_driven_transport_security_cells() {
        let cases: &[(&str, &str, bool)] = &[
            ("tcp", "none", true),
            ("tcp", "tls", true),
            ("tcp", "reality", true),
            ("xhttp", "none", true),
            ("xhttp", "tls", true),
            ("xhttp", "reality", true),
            ("grpc", "none", true),
            ("grpc", "tls", true),
            ("grpc", "reality", true),
            ("ws", "none", true),
            ("ws", "tls", true),
            ("ws", "reality", false),
            ("httpupgrade", "none", true),
            ("httpupgrade", "tls", true),
            ("httpupgrade", "reality", false),
            ("mkcp", "none", true),
            ("mkcp", "tls", true),
            ("mkcp", "reality", false),
            ("hysteria", "none", false),
            ("hysteria", "tls", true),
            ("hysteria", "reality", false),
        ];
        for &(transport, security, ok) in cases {
            assert_eq!(
                transport_security_allowed(transport, security),
                ok,
                "{transport} × {security}"
            );
        }
    }

    #[test]
    fn g9_g10_g11_predicates() {
        assert!(!g9_hysteria_protocol_transport_ok("hysteria", "tcp"));
        assert!(g9_hysteria_protocol_transport_ok("hysteria", "hysteria"));
        assert!(g9_hysteria_protocol_transport_ok("vless", "xhttp"));

        assert!(!g10_hysteria_requires_tls("hysteria", "hysteria", "none"));
        assert!(g10_hysteria_requires_tls("hysteria", "hysteria", "tls"));
        assert!(!g10_hysteria_requires_tls("vless", "hysteria", "reality"));
        assert!(g10_hysteria_requires_tls("vless", "tcp", "none"));

        assert!(!g11_shadowsocks_tcp_only("shadowsocks", "xhttp"));
        assert!(g11_shadowsocks_tcp_only("shadowsocks", "tcp"));
        assert!(g11_shadowsocks_tcp_only("vless", "xhttp"));
    }

    #[test]
    fn vision_narrows_stream_methods() {
        let open = allowed_stream_methods("vless", "none", false);
        assert_eq!(
            open,
            vec![
                StreamMethod::Tcp,
                StreamMethod::Xhttp,
                StreamMethod::Grpc,
                StreamMethod::Ws,
                StreamMethod::Mkcp
            ]
        );
        let vision = allowed_stream_methods("vless", "none", true);
        assert_eq!(vision, vec![StreamMethod::Tcp]);
        let under_reality = allowed_stream_methods("vless", "reality", false);
        assert_eq!(
            under_reality,
            vec![StreamMethod::Tcp, StreamMethod::Xhttp, StreamMethod::Grpc]
        );
        assert_eq!(
            selectable_stream_methods("vless", false),
            vec![
                StreamMethod::Tcp,
                StreamMethod::Xhttp,
                StreamMethod::Grpc,
                StreamMethod::Ws,
                StreamMethod::Mkcp
            ]
        );
    }

    #[test]
    fn coerce_security_for_websocket() {
        assert_eq!(
            coerce_security_mode_for_transport("trojan", "websocket", InboundSecurityMode::Reality),
            InboundSecurityMode::Tls
        );
        assert_eq!(
            coerce_security_mode_for_transport("vless", "websocket", InboundSecurityMode::Reality),
            InboundSecurityMode::None
        );
        assert_eq!(
            coerce_security_mode_for_transport("vless", "websocket", InboundSecurityMode::Tls),
            InboundSecurityMode::Tls
        );
    }

    #[test]
    fn coerce_security_for_mkcp() {
        assert_eq!(
            coerce_security_mode_for_transport("trojan", "mkcp", InboundSecurityMode::Reality),
            InboundSecurityMode::Tls
        );
        assert_eq!(
            coerce_security_mode_for_transport("vless", "mkcp", InboundSecurityMode::Reality),
            InboundSecurityMode::None
        );
        assert_eq!(
            coerce_security_mode_for_transport("vless", "kcp", InboundSecurityMode::Tls),
            InboundSecurityMode::Tls
        );
        assert_eq!(
            allowed_security_modes("trojan", "mkcp"),
            vec![InboundSecurityMode::Tls]
        );
        assert_eq!(
            allowed_security_modes("vless", "mkcp"),
            vec![InboundSecurityMode::None, InboundSecurityMode::Tls]
        );
    }

    #[test]
    fn trojan_security_modes_tls_and_reality() {
        assert_eq!(
            allowed_security_modes("trojan", "tcp"),
            vec![InboundSecurityMode::Tls, InboundSecurityMode::Reality]
        );
        assert_eq!(
            allowed_security_modes("trojan", "websocket"),
            vec![InboundSecurityMode::Tls]
        );
        assert_eq!(
            allowed_security_modes("vless", "tcp"),
            vec![
                InboundSecurityMode::None,
                InboundSecurityMode::Tls,
                InboundSecurityMode::Reality
            ]
        );
        assert_eq!(
            allowed_security_modes("vless", "websocket"),
            vec![InboundSecurityMode::None, InboundSecurityMode::Tls]
        );
        assert_eq!(
            allowed_security_modes("hysteria", "hysteria"),
            vec![InboundSecurityMode::Tls]
        );
    }

    #[test]
    fn coerce_display_only_when_editable_illegal() {
        let allowed = [StreamMethod::Tcp];
        assert_eq!(
            coerce_display_stream_method(Some(StreamMethod::Xhttp), &allowed),
            Some(StreamMethod::Tcp)
        );
        assert_eq!(
            coerce_display_stream_method(Some(StreamMethod::Tcp), &allowed),
            Some(StreamMethod::Tcp)
        );
        // Exotic: no coerce.
        assert_eq!(coerce_display_stream_method(None, &allowed), None);
    }

    #[test]
    fn vision_active_from_inbound_scans_clients() {
        let inbound = json!({
            "settings": {
                "clients": [{"id":"a","flow":"xtls-rprx-vision"}]
            }
        });
        assert!(vision_active_from_inbound(&inbound));
        let plain = json!({"settings":{"clients":[{"id":"a"}]}});
        assert!(!vision_active_from_inbound(&plain));
    }

    #[test]
    fn ss_allowed_methods_tcp_only() {
        assert_eq!(
            allowed_stream_methods("shadowsocks", "none", false),
            vec![StreamMethod::Tcp]
        );
    }

    #[test]
    fn tunnel_allows_tcp_none_only() {
        assert_eq!(
            allowed_stream_methods("tunnel", "none", false),
            vec![StreamMethod::Tcp]
        );
        assert_eq!(
            allowed_security_modes("tunnel", "tcp"),
            vec![InboundSecurityMode::None]
        );
        assert!(transport_security_allowed("tcp", "none"));
    }
}
