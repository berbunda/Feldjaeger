//! Static CompatibilityMatrix: wire-string cells + typed GUI filter helpers.
//!
//! Matrix keys are Xray wire strings (`tcp`/`raw`, `xhttp`, `reality`, …).
//! Typed [`allowed_stream_methods`] / [`allowed_security_modes`] intersect the
//! matrix with currently editable enums ([`StreamMethod`], [`InboundSecurityMode`]).

use super::{inbound_has_vision_flow, normalized_method};
use crate::xray::config::inbound_security::InboundSecurityMode;
use crate::xray::config::inbound_stream::StreamMethod;
use crate::xray::config::stream::{FinalMaskChain, QuicTransport, quic_transport_of};
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

/// Which FinalMask chains an inbound's listeners wrap (Roadmap §2.6 stage 4.3).
///
/// Verified against `XTLS/Xray-core@main` (`transport/internet/finalmask/finalmask.go`):
/// `FinalMask.Listen` (a TCP listener) applies only the `tcp[]` masks, `FinalMask.ListenPacket`
/// (a UDP socket) only the `udp[]` masks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FinalMaskChainUse {
    /// Some listener wraps its socket with `finalmask.tcp[]`.
    pub tcp: bool,
    /// Some listener wraps its socket with `finalmask.udp[]`.
    pub udp: bool,
}

impl FinalMaskChainUse {
    /// Whether some listener applies `chain`.
    pub fn uses(self, chain: FinalMaskChain) -> bool {
        match chain {
            FinalMaskChain::Tcp => self.tcp,
            FinalMaskChain::Udp => self.udp,
        }
    }

    fn mark(&mut self, chain: FinalMaskChain) {
        match chain {
            FinalMaskChain::Tcp => self.tcp = true,
            FinalMaskChain::Udp => self.udp = true,
        }
    }
}

/// Which FinalMask chain an outbound's dialer applies (Roadmap §2.6 stage 7.1), or `None` when
/// that cannot be told for sure.
///
/// Verified against `XTLS/Xray-core@main` (`transport/internet/dialer.go`,
/// `memory_settings.go`): a TCP dial goes through the transport's dialer — RAW, WebSocket, gRPC,
/// HTTPUpgrade and XHTTP over TCP wrap it with `tcp[]`; mKCP, Hysteria and XHTTP/3 dial UDP and
/// wrap it with `udp[]` — while a UDP dial goes through the UDP dialer (`udp[]`). VLESS, VMess,
/// Trojan and Hysteria carry their UDP traffic inside the transport, so only the transport's
/// chain is used. Other protocols (Freedom, Shadowsocks, WireGuard, …) may dial UDP directly;
/// no claim is made for them.
pub fn outbound_finalmask_chain_use(outbound: &Value) -> Option<FinalMaskChainUse> {
    let protocol = outbound.get("protocol")?.as_str()?.to_ascii_lowercase();
    if !matches!(protocol.as_str(), "vless" | "vmess" | "trojan" | "hysteria") {
        return None;
    }
    let mut used = FinalMaskChainUse::default();
    used.mark(transport_finalmask_chain(outbound)?);
    Some(used)
}

/// The networks a proxy's `Network()` returns — they decide which workers
/// `AlwaysOnInboundHandler` creates.
#[derive(Debug, Default)]
struct ProxyNetworks {
    tcp: bool,
    udp: bool,
    unix: bool,
}

/// The FinalMask chains the inbound's listeners actually wrap, or `None` when that cannot be told
/// for sure (a protocol or transport this table does not know, or a value the core refuses to
/// load) — callers then stay silent rather than guess.
///
/// How the core decides (`app/proxyman/inbound/always.go`): an IP `listen` gets, per port, a
/// stream worker when the proxy's networks include TCP — it listens through the transport, so
/// the transport picks the chain — and a UDP worker when they include UDP (`udp.ListenUDP`,
/// always `udp[]`, whatever the transport). A Unix-socket `listen` (absolute path or `@…`) gets
/// only the domain-socket worker (through the transport), and only when the networks include
/// UNIX.
pub fn inbound_finalmask_chain_use(inbound: &Value) -> Option<FinalMaskChainUse> {
    let networks = proxy_networks(inbound)?;
    let unix_listen = inbound
        .get("listen")
        .and_then(Value::as_str)
        .is_some_and(|listen| listen.starts_with('/') || listen.starts_with('@'));
    let mut used = FinalMaskChainUse::default();
    let stream_worker = if unix_listen { networks.unix } else { networks.tcp };
    if stream_worker {
        used.mark(transport_finalmask_chain(inbound)?);
    }
    if networks.udp && !unix_listen {
        used.mark(FinalMaskChain::Udp);
    }
    Some(used)
}

/// `Network()` of the inbound's proxy; the protocol name is case-insensitive in the core
/// (`JSONConfigLoader.LoadWithID`). `None` for protocols this table does not cover.
fn proxy_networks(inbound: &Value) -> Option<ProxyNetworks> {
    let protocol = inbound.get("protocol")?.as_str()?.to_ascii_lowercase();
    match protocol.as_str() {
        // `proxy/vless/inbound`, `proxy/trojan`.
        "vless" | "trojan" => Some(ProxyNetworks {
            tcp: true,
            udp: false,
            unix: true,
        }),
        // `proxy/hysteria`: QUIC is the hysteria transport's own UDP socket, behind the stream
        // worker.
        "hysteria" => Some(ProxyNetworks {
            tcp: true,
            ..ProxyNetworks::default()
        }),
        "tunnel" | "dokodemo-door" => tunnel_networks(inbound.get("settings")),
        _ => None,
    }
}

/// `DokodemoConfig.Build()`: a legacy `network` replaces `allowedNetwork`; neither (or `null`)
/// means TCP. `NetworkList` is an array of strings or one string split at `,` — not trimmed, each
/// name compared case-insensitively, anything else ignored (`"tcp, udp"` is TCP only). The
/// proxy's `Network()` adds UNIX whenever TCP is allowed.
fn tunnel_networks(settings: Option<&Value>) -> Option<ProxyNetworks> {
    let present = |key: &str| {
        settings
            .and_then(|settings| settings.get(key))
            .filter(|value| !value.is_null())
    };
    let names: Vec<String> = match present("network").or_else(|| present("allowedNetwork")) {
        None => vec!["tcp".to_owned()],
        Some(Value::String(text)) => text.split(',').map(str::to_owned).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<_>>()?,
        // The core refuses to load it.
        Some(_) => return None,
    };
    let mut networks = ProxyNetworks::default();
    for name in names {
        match name.to_ascii_lowercase().as_str() {
            "tcp" => networks.tcp = true,
            "udp" => networks.udp = true,
            "unix" => networks.unix = true,
            _ => {}
        }
    }
    networks.unix |= networks.tcp;
    Some(networks)
}

/// The chain the inbound's transport listener applies: TCP listeners — RAW, WebSocket, gRPC,
/// HTTPUpgrade, XHTTP over TCP (`FinalMask.Listen`); UDP sockets — mKCP (`udp.ListenUDP`),
/// Hysteria and XHTTP/3 (`FinalMask.ListenPacket`). `None` for any other transport.
fn transport_finalmask_chain(inbound: &Value) -> Option<FinalMaskChain> {
    match matrix_transport(&normalized_method(inbound)).as_str() {
        "tcp" | "websocket" | "grpc" | "httpupgrade" => Some(FinalMaskChain::Tcp),
        "xhttp" | "splithttp" => {
            let h3 = inbound.get("streamSettings").and_then(quic_transport_of)
                == Some(QuicTransport::XhttpH3);
            Some(if h3 { FinalMaskChain::Udp } else { FinalMaskChain::Tcp })
        }
        "mkcp" | "hysteria" => Some(FinalMaskChain::Udp),
        _ => None,
    }
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

    const TCP: Option<FinalMaskChainUse> = Some(FinalMaskChainUse { tcp: true, udp: false });
    const UDP: Option<FinalMaskChainUse> = Some(FinalMaskChainUse { tcp: false, udp: true });
    const BOTH: Option<FinalMaskChainUse> = Some(FinalMaskChainUse { tcp: true, udp: true });
    const NONE: Option<FinalMaskChainUse> = Some(FinalMaskChainUse { tcp: false, udp: false });

    /// Roadmap §2.6 stage 4.3: the transport picks the chain of a TCP-only proxy.
    #[test]
    fn finalmask_chain_use_follows_the_transport() {
        let vless = |stream: Value| json!({"protocol": "VLESS", "streamSettings": stream});
        for (stream, expected) in [
            (json!({}), TCP),
            (json!({"network": "raw"}), TCP),
            (json!({"network": "ws"}), TCP),
            (json!({"network": "grpc"}), TCP),
            (json!({"network": "httpupgrade"}), TCP),
            (json!({"network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h3", "h2"]}}), TCP),
            (json!({"network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h3"]}}), UDP),
            (json!({"method": "splithttp", "security": "tls", "tlsSettings": {"alpn": "h3"}}), UDP),
            (json!({"network": "kcp"}), UDP),
            (json!({"network": "masque"}), None),
        ] {
            assert_eq!(inbound_finalmask_chain_use(&vless(stream.clone())), expected, "{stream}");
        }
        let hysteria = json!({"protocol": "hysteria", "streamSettings": {"network": "hysteria"}});
        assert_eq!(inbound_finalmask_chain_use(&hysteria), UDP);
        // Protocols outside the table: no claim.
        assert_eq!(inbound_finalmask_chain_use(&json!({"protocol": "vmess"})), None);
        assert_eq!(inbound_finalmask_chain_use(&json!({})), None);
    }

    /// A Tunnel adds a UDP worker (`udp.ListenUDP`, always `udp[]`) for `allowedNetwork` udp;
    /// `NetworkList` is split at `,` without trimming, and a legacy `network` wins.
    #[test]
    fn finalmask_chain_use_of_a_tunnel_follows_its_networks() {
        let tunnel = |settings: Value| json!({"protocol": "tunnel", "settings": settings});
        for (settings, expected) in [
            (json!({}), TCP),
            (json!({"allowedNetwork": null}), TCP),
            (json!({"allowedNetwork": "udp"}), UDP),
            (json!({"allowedNetwork": "TCP,UDP"}), BOTH),
            (json!({"allowedNetwork": "tcp, udp"}), TCP),
            (json!({"allowedNetwork": ["udp", "tcp"]}), BOTH),
            (json!({"allowedNetwork": ""}), NONE),
            (json!({"allowedNetwork": "tcp", "network": "udp"}), UDP),
            (json!({"allowedNetwork": "udp", "network": null}), UDP),
            (json!({"allowedNetwork": 5}), None),
            (json!({"allowedNetwork": ["tcp", 5]}), None),
        ] {
            assert_eq!(inbound_finalmask_chain_use(&tunnel(settings.clone())), expected, "{settings}");
        }
        // The UDP worker does not depend on the transport; the stream worker does.
        let udp_only = json!({"protocol": "dokodemo-door", "settings": {"allowedNetwork": "udp"},
                              "streamSettings": {"network": "masque"}});
        assert_eq!(inbound_finalmask_chain_use(&udp_only), UDP);
    }

    /// A Unix-socket `listen` gets only the domain-socket worker, and only with UNIX networks.
    #[test]
    fn finalmask_chain_use_on_a_unix_socket() {
        for listen in ["/run/xray/vless.sock", "@vless"] {
            let vless = json!({"protocol": "vless", "listen": listen});
            assert_eq!(inbound_finalmask_chain_use(&vless), TCP, "{listen}");
        }
        let tunnel = json!({"protocol": "tunnel", "listen": "/run/t.sock",
                            "settings": {"allowedNetwork": "tcp,udp"}});
        assert_eq!(inbound_finalmask_chain_use(&tunnel), TCP);
        let udp_tunnel = json!({"protocol": "tunnel", "listen": "@t", "settings": {"allowedNetwork": "udp"}});
        assert_eq!(inbound_finalmask_chain_use(&udp_tunnel), NONE);
        let hysteria = json!({"protocol": "hysteria", "listen": "/run/hy.sock",
                              "streamSettings": {"network": "hysteria"}});
        assert_eq!(inbound_finalmask_chain_use(&hysteria), NONE);
    }
}
