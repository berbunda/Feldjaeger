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

use crate::xray::{InboundClientProtocol, ParsedShareUri, ShareProtocol, ShareSecurity, ShareTransport};

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

    ImportPreview {
        protocol,
        port: parsed.port,
        transport_summary,
        security_summary,
        user_id: parsed.user_id.clone(),
        email_hint: parsed.remark.clone().unwrap_or_default(),
        flow: parsed.flow.clone(),
        warnings,
        parsed,
    }
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

    #[test]
    fn hysteria_obfs_password_produces_no_warning_itself() {
        let parsed = parse_share_uri("hy2://auth@host:443?obfs=salamander&obfs-password=cat").expect("parse");
        let preview = build_import_preview(parsed);
        assert!(!preview.warnings.iter().any(|w| w.contains("obfs")));
        assert_eq!(preview.parsed.obfs_salamander_password.as_deref(), Some("cat"));
    }
}
