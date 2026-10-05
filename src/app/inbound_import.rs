//! Inbound import from a pasted share URI (Roadmap §3:133 — "Inbound import from Share URI /
//! client link").
//!
//! Scope confirmed with the user before implementation (two disputed points):
//! - **What import produces**: both — either a brand-new inbound (port/transport/security
//!   prefilled from the link) or a new user added to an already-existing inbound of the matching
//!   protocol (UUID/password/auth/flow/email prefilled) — the caller picks per import.
//! - **REALITY links**: imported anyway, with a brand-new key pair generated remotely (same
//!   "Generate x25519" flow as the Add Inbound presets, Roadmap §3:123) — the link's own public
//!   key can never be reused (see `xray::share_uri` module doc for why), so the original link
//!   becomes invalid and a fresh one must be shared afterward. Surfaced as an explicit warning,
//!   never silently dropped or silently substituted.
//!
//! This module only builds the read-only preview (parsed data + human-readable summaries +
//! warnings about what can't round-trip). Applying a preview to a new inbound's editor session,
//! or to an existing inbound's Add User dialog, happens in the GUI layer
//! (`gui::pages::inbounds`) — the same layer that already owns `apply_inbound_preset`
//! (Roadmap §3:123), which this mirrors.

use crate::xray::{
    FinalMaskLayerDraft, InboundClientProtocol, ParsedShareUri, ShareProtocol, ShareSecurity, ShareTransport,
    server_finalmask_from_client,
};

/// A parsed share URI, summarized for display, plus every warning about what this import can't
/// fully reproduce.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportPreview {
    /// Which protocol this inbound/user would use.
    pub protocol: InboundClientProtocol,
    /// Port from the link, when parseable (scalar only — see the hy2 port-hop warning).
    pub port: Option<u16>,
    /// Human-readable transport summary, e.g. `"xhttp path=/api host=cdn.example"`.
    pub transport_summary: String,
    /// Human-readable security summary, e.g. `"reality sni=example.com"`.
    pub security_summary: String,
    /// Client credential from the link (UUID / password / auth) — needed to prefill Add User.
    pub user_id: String,
    /// Suggested client email (from the link's remark/fragment) — editable afterward, may be
    /// empty when the link had no fragment.
    pub email_hint: String,
    /// VLESS flow, when present.
    pub flow: Option<String>,
    /// `finalmask.tcp` layers for a new inbound, from the link's `fm` (Roadmap §2.6 stage 6.2);
    /// `None` = nothing to write.
    pub finalmask_tcp: Option<Vec<FinalMaskLayerDraft>>,
    /// `finalmask.udp` layers for a new inbound, from `fm` or a hy2 salamander `obfs`.
    pub finalmask_udp: Option<Vec<FinalMaskLayerDraft>>,
    /// Human-readable FinalMask summary, e.g. `"tcp: sudoku · udp: salamander"`; `None` when the
    /// link carries no masks.
    pub finalmask_summary: Option<String>,
    /// Everything this import can't fully reproduce, in a fixed, deterministic order — never
    /// hidden (`rules.md`: "must not hide configuration options").
    pub warnings: Vec<String>,
    /// The full parsed data, for applying to a new inbound's editor session drafts.
    pub parsed: ParsedShareUri,
}

/// Builds the import preview from a successfully parsed share URI.
pub fn build_import_preview(parsed: ParsedShareUri) -> ImportPreview {
    let protocol = match parsed.protocol {
        ShareProtocol::Vless => InboundClientProtocol::Vless,
        ShareProtocol::Trojan => InboundClientProtocol::Trojan,
        ShareProtocol::Hysteria => InboundClientProtocol::Hysteria,
    };

    let mut warnings = Vec::new();
    let security_summary = describe_security(&parsed, &mut warnings);
    let transport_summary = describe_transport(&parsed, &mut warnings);

    if parsed.protocol == ShareProtocol::Hysteria {
        if let Some(hop) = &parsed.port_hop {
            warnings.push(format!(
                "Port-hopping range `{hop}` detected — only the first port ({}) is imported; \
                 configure the full range via the Raw JSON editor if needed.",
                parsed.port.map(|p| p.to_string()).unwrap_or_default()
            ));
        }
        if parsed.pin_sha256.is_some() {
            warnings.push(
                "Certificate pin (`pinSHA256`) is a client-side value with no server \
                 configuration field — not imported."
                    .to_owned(),
            );
        }
    }

    if parsed.protocol == ShareProtocol::Vless
        && parsed.encryption.as_deref().is_some_and(|e| e != "none")
    {
        warnings.push(
            "Post-quantum client encryption (`encryption=`) can't be imported — the server-side \
             decryption secret is never present in a client link. Configure separately \
             (Protocol tab → Generate) if needed."
                .to_owned(),
        );
    }

    let (finalmask_tcp, finalmask_udp) = import_finalmask(&parsed, &mut warnings);
    let finalmask_summary = summarize_finalmask(finalmask_tcp.as_deref(), finalmask_udp.as_deref());

    ImportPreview {
        protocol,
        port: parsed.port,
        transport_summary,
        security_summary,
        user_id: parsed.user_id.clone(),
        email_hint: parsed.remark.clone().unwrap_or_default(),
        flow: parsed.flow.clone(),
        finalmask_tcp,
        finalmask_udp,
        finalmask_summary,
        warnings,
        parsed,
    }
}

type Layers = Option<Vec<FinalMaskLayerDraft>>;

/// The new inbound's FinalMask chains (Roadmap §2.6 stage 6.2): `fm` turned into server chains;
/// for hy2 without `fm`, a salamander `obfs` as one `udp` layer (stage 4.1 import). A hy2 inbound
/// listens only through `udp[]`, so an `fm.tcp` chain is reported instead of imported; when a hy2
/// link has both, `fm` wins — clients do the same (v2rayN replaces its own finalmask with `fm`).
fn import_finalmask(parsed: &ParsedShareUri, warnings: &mut Vec<String>) -> (Layers, Layers) {
    let hysteria = parsed.protocol == ShareProtocol::Hysteria;
    if hysteria
        && let Some(obfs) = parsed.obfs.as_deref()
        && !obfs.trim().eq_ignore_ascii_case("salamander")
    {
        warnings.push(format!(
            "hy2 `obfs={obfs}` isn't a standard hy2 obfs (only salamander is) — not imported; add the \
             layer on the Stream tab if the server needs it."
        ));
    }
    let Some(fm) = parsed.finalmask.as_deref() else {
        let udp = hysteria
            .then_some(parsed.obfs_salamander_password.as_ref())
            .flatten()
            .map(|password| {
                vec![FinalMaskLayerDraft {
                    layer_type: "salamander".to_owned(),
                    settings: serde_json::json!({ "password": password }),
                }]
            });
        return (None, udp);
    };
    let import = server_finalmask_from_client(fm);
    warnings.extend(import.warnings);
    if !hysteria {
        return (import.tcp, import.udp);
    }
    if import.tcp.is_some() {
        warnings.push(
            "fm.tcp is not imported — a Hysteria inbound listens only through finalmask.udp.".to_owned(),
        );
    }
    if parsed.obfs_salamander_password.is_some() {
        warnings.push("hy2 `obfs` is ignored — the link's `fm` replaces it.".to_owned());
    }
    (None, import.udp)
}

fn summarize_finalmask(tcp: Option<&[FinalMaskLayerDraft]>, udp: Option<&[FinalMaskLayerDraft]>) -> Option<String> {
    let chain = |key: &str, layers: Option<&[FinalMaskLayerDraft]>| {
        layers.map(|layers| {
            let types: Vec<&str> = layers.iter().map(|layer| layer.layer_type.as_str()).collect();
            format!("{key}: {}", types.join(", "))
        })
    };
    let parts: Vec<String> = [chain("tcp", tcp), chain("udp", udp)].into_iter().flatten().collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

fn describe_security(parsed: &ParsedShareUri, warnings: &mut Vec<String>) -> String {
    match &parsed.security {
        ShareSecurity::None => "none".to_owned(),
        ShareSecurity::Tls {
            server_name,
            insecure,
            alpn,
        } => {
            warnings.push(
                "TLS certificate files aren't part of a share link — set \
                 certificateFile/keyFile on the Security tab after creating this inbound."
                    .to_owned(),
            );
            let mut parts = vec!["tls".to_owned()];
            if let Some(sni) = server_name.as_deref().filter(|s| !s.is_empty()) {
                parts.push(format!("sni={sni}"));
            }
            if *insecure {
                parts.push("allowInsecure".to_owned());
            }
            if !alpn.is_empty() {
                parts.push(format!("alpn={}", alpn.join(",")));
            }
            parts.join(" ")
        }
        ShareSecurity::Reality {
            server_name,
            short_id,
            public_key,
            ..
        } => {
            warnings.push(format!(
                "REALITY's private key is never present in a share link — the link's public key \
                 (`{public_key}`) can't be reused on this server. A brand-new key pair will be \
                 generated, which makes the original link invalid — share a new link \
                 afterward."
            ));
            let mut parts = vec!["reality".to_owned()];
            if !server_name.is_empty() {
                parts.push(format!("sni={server_name}"));
            }
            if !short_id.is_empty() {
                parts.push(format!("sid={short_id}"));
            }
            parts.join(" ")
        }
    }
}

fn describe_transport(parsed: &ParsedShareUri, warnings: &mut Vec<String>) -> String {
    if parsed.protocol == ShareProtocol::Hysteria {
        return "hysteria (QUIC)".to_owned();
    }
    match &parsed.transport {
        ShareTransport::Tcp => "tcp".to_owned(),
        ShareTransport::Xhttp {
            path,
            host,
            mode,
            extra,
        } => {
            if extra.is_some() {
                warnings.push(
                    "Advanced XHTTP parameters (`extra=`) aren't imported — only path/host/mode."
                        .to_owned(),
                );
            }
            let mut parts = vec![format!("xhttp path={path}")];
            if let Some(host) = host.as_deref().filter(|s| !s.is_empty()) {
                parts.push(format!("host={host}"));
            }
            if let Some(mode) = mode.as_deref().filter(|s| !s.is_empty()) {
                parts.push(format!("mode={mode}"));
            }
            parts.join(" ")
        }
        ShareTransport::Grpc { service_name } => format!("grpc serviceName={service_name}"),
        ShareTransport::Ws { path, host } => {
            let mut parts = vec![format!("websocket path={path}")];
            if let Some(host) = host.as_deref().filter(|s| !s.is_empty()) {
                parts.push(format!("host={host}"));
            }
            parts.join(" ")
        }
        ShareTransport::Kcp => "mkcp".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::parse_share_uri;

    #[test]
    fn reality_import_warns_about_new_key_pair() {
        let parsed = parse_share_uri(
            "vless://11111111-1111-1111-1111-111111111111@host:443?security=reality&pbk=PUB&sid=abcd&sni=example.com&fp=chrome&flow=xtls-rprx-vision#label",
        )
        .expect("parse");
        let preview = build_import_preview(parsed);
        assert_eq!(preview.protocol, InboundClientProtocol::Vless);
        assert_eq!(preview.port, Some(443));
        assert_eq!(preview.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(preview.email_hint, "label");
        assert!(preview.security_summary.contains("reality"));
        assert!(preview.security_summary.contains("sni=example.com"));
        assert!(preview.warnings.iter().any(|w| w.contains("private key") && w.contains("PUB")));
    }

    #[test]
    fn tls_import_always_warns_about_missing_certificate() {
        let parsed = parse_share_uri("trojan://pw@host:443?security=tls&sni=example.com").expect("parse");
        let preview = build_import_preview(parsed);
        assert!(preview.warnings.iter().any(|w| w.contains("certificateFile")));
    }

    #[test]
    fn none_security_and_tcp_transport_has_no_warnings() {
        let parsed = parse_share_uri("trojan://pw@host:443?security=none&type=tcp").expect("parse");
        let preview = build_import_preview(parsed);
        assert!(preview.warnings.is_empty(), "{:?}", preview.warnings);
        assert_eq!(preview.security_summary, "none");
        assert_eq!(preview.transport_summary, "tcp");
    }

    #[test]
    fn vless_non_none_encryption_warns_and_is_not_applied_anywhere() {
        let parsed = parse_share_uri(
            "vless://u@host:443?security=none&encryption=mlkem768x25519plus.native.600s.BASE64",
        )
        .expect("parse");
        let preview = build_import_preview(parsed);
        assert!(preview.warnings.iter().any(|w| w.contains("Post-quantum")));
    }

    #[test]
    fn xhttp_extra_param_warns_but_basic_fields_still_summarized() {
        let parsed = parse_share_uri(
            "vless://u@host:443?security=none&type=xhttp&path=%2Fapi&host=cdn.example&mode=auto&extra=%7B%7D",
        )
        .expect("parse");
        let preview = build_import_preview(parsed);
        assert!(preview.transport_summary.contains("path=/api"));
        assert!(preview.transport_summary.contains("host=cdn.example"));
        assert!(preview.warnings.iter().any(|w| w.contains("extra=")));
    }

    #[test]
    fn hysteria_port_hop_and_pin_warn() {
        let parsed = parse_share_uri(
            "hy2://auth@host:443,5000-6000?sni=example.com&pinSHA256=deadbeef",
        )
        .expect("parse");
        let preview = build_import_preview(parsed);
        assert_eq!(preview.protocol, InboundClientProtocol::Hysteria);
        assert_eq!(preview.transport_summary, "hysteria (QUIC)");
        assert!(preview.warnings.iter().any(|w| w.contains("Port-hopping")));
        assert!(preview.warnings.iter().any(|w| w.contains("pinSHA256")));
    }

    /// Roadmap §2.6 stage 6.2: a link's `fm` becomes the new inbound's chains, minus what only the
    /// client uses — each omission is a warning.
    #[test]
    fn vless_fm_becomes_server_chains() {
        let fm = r#"{"tcp":[{"type":"fragment","settings":{}},{"type":"sudoku","settings":{"password":"p"}}],"udp":[{"type":"mkcp-legacy","settings":{"value":"s"}}]}"#;
        let uri = format!(
            "vless://11111111-1111-1111-1111-111111111111@host:443?security=tls&type=kcp&fm={}",
            crate::xray::pct_encode(fm)
        );
        let preview = build_import_preview(parse_share_uri(&uri).expect("parse"));
        let layer = |kind: &str, settings: serde_json::Value| FinalMaskLayerDraft {
            layer_type: kind.to_owned(),
            settings,
        };
        assert_eq!(preview.finalmask_tcp, Some(vec![layer("sudoku", serde_json::json!({"password": "p"}))]));
        assert_eq!(preview.finalmask_udp, Some(vec![layer("mkcp-legacy", serde_json::json!({"value": "s"}))]));
        assert_eq!(preview.finalmask_summary.as_deref(), Some("tcp: sudoku · udp: mkcp-legacy"));
        assert!(preview.warnings.iter().any(|w| w.contains("`fragment`")), "{:?}", preview.warnings);

        let plain = build_import_preview(parse_share_uri("trojan://pw@host:443?security=tls").expect("parse"));
        assert_eq!((plain.finalmask_tcp, plain.finalmask_udp, plain.finalmask_summary), (None, None, None));
    }

    #[test]
    fn hysteria_fm_replaces_obfs_and_drops_tcp() {
        let fm = r#"{"tcp":[{"type":"sudoku","settings":{}}],"udp":[{"type":"salamander","settings":{"password":"fm"}}]}"#;
        let uri = format!(
            "hy2://auth@host:443?obfs=salamander&obfs-password=cat&fm={}",
            crate::xray::pct_encode(fm)
        );
        let preview = build_import_preview(parse_share_uri(&uri).expect("parse"));
        assert_eq!(preview.finalmask_tcp, None);
        let udp = preview.finalmask_udp.expect("udp");
        assert_eq!(udp[0].settings, serde_json::json!({"password": "fm"}));
        assert!(preview.warnings.iter().any(|w| w.contains("fm.tcp is not imported")));
        assert!(preview.warnings.iter().any(|w| w.contains("`obfs` is ignored")));

        let gecko = build_import_preview(parse_share_uri("hy2://a@host:443?obfs=gecko&obfs-password=x").expect("parse"));
        assert_eq!(gecko.finalmask_udp, None);
        assert!(gecko.warnings.iter().any(|w| w.contains("obfs=gecko")), "{:?}", gecko.warnings);
    }

    #[test]
    fn hysteria_obfs_password_produces_no_warning_itself() {
        let parsed = parse_share_uri("hy2://auth@host:443?obfs=salamander&obfs-password=cat").expect("parse");
        let preview = build_import_preview(parsed);
        assert!(!preview.warnings.iter().any(|w| w.contains("obfs")));
        assert_eq!(preview.parsed.obfs_salamander_password.as_deref(), Some("cat"));
        let udp = preview.finalmask_udp.expect("salamander layer");
        assert_eq!(udp[0].layer_type, "salamander");
        assert_eq!(udp[0].settings, serde_json::json!({"password": "cat"}));
        assert_eq!(preview.finalmask_summary.as_deref(), Some("udp: salamander"));
    }
}
