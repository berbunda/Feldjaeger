//! Client share URI builders (`vless://` / `trojan://` / `hy2://`) for IB Share lake.
//!
//! Reality `publicKey` and VLESS client `encryption` are **never** read from
//! server inbound JSON — callers must supply them from Generate ephemerals.

use std::fmt;

/// Transport encoded into share query `type=` (+ nested params).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareTransport {
    /// `type=tcp` (also used for raw).
    Tcp,
    /// `type=xhttp` with path (+ optional host/mode/`extra` JSON).
    Xhttp {
        /// Request path.
        path: String,
        /// Optional Host header value.
        host: Option<String>,
        /// Optional mode.
        mode: Option<String>,
        /// Optional URL-decoded `extra` JSON body (all advanced fields).
        extra: Option<String>,
    },
    /// `type=grpc` with serviceName.
    Grpc {
        /// gRPC service name.
        service_name: String,
    },
    /// `type=ws` with path (+ optional host). Wave C1: TLS-only shares.
    Ws {
        /// WebSocket path (may include `?ed=`).
        path: String,
        /// Optional Host header value.
        host: Option<String>,
    },
    /// `type=kcp` (mKCP). Wave C1: TLS-only shares; no seed/header query.
    Kcp,
}

/// Transport security for the share link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareSecurity {
    /// `security=none`.
    None,
    /// `security=tls` (+ optional SNI / allowInsecure / ALPN).
    Tls {
        /// Optional SNI (`sni`).
        server_name: Option<String>,
        /// Optional `allowInsecure` / `insecure`.
        insecure: bool,
        /// ALPN protocol list from `tlsSettings.alpn` (e.g. `h2`, `http/1.1`); empty omits the
        /// query (Roadmap §3:121: richer VLESS/Trojan query parity).
        alpn: Vec<String>,
    },
    /// `security=reality` (+ Reality client params).
    Reality {
        /// Client public key (`pbk`) from `xray x25519` Password (PublicKey).
        public_key: String,
        /// One short id from server `shortIds` (may be empty string).
        short_id: String,
        /// SNI from server `serverNames`.
        server_name: String,
        /// Client TLS fingerprint (`fp`); default callers often use `chrome`.
        fingerprint: String,
        /// SpiderX path (`spx`); default `/`.
        spider_x: String,
        /// Optional post-quantum verify (`pqv` / mldsa65Verify).
        mldsa65_verify: Option<String>,
    },
}

/// Protocol for the share URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareProtocol {
    /// `vless://uuid@…`
    Vless,
    /// `trojan://password@…`
    Trojan,
    /// `hy2://auth@…`
    Hysteria,
}

/// Inputs for [`build_share_uri`].
///
/// Trojan password / VLESS uuid sit in `user_id` — never log this struct via
/// [`Debug`] (custom impl redacts `user_id`).
#[derive(Clone, PartialEq, Eq)]
pub struct ShareUriRequest {
    /// VLESS, Trojan, or Hysteria.
    pub protocol: ShareProtocol,
    /// UUID (VLESS) or password (Trojan) or auth (Hysteria).
    pub user_id: String,
    /// Server address shown to clients (usually SSH host, not `0.0.0.0`).
    pub address: String,
    /// Listen port.
    pub port: u64,
    /// Optional fragment / remark (`#…`).
    pub remark: Option<String>,
    /// VLESS `flow` query when present.
    pub flow: Option<String>,
    /// VLESS `encryption` query (`none` or client half from `vlessenc`).
    pub encryption: String,
    /// none | tls | reality.
    pub security: ShareSecurity,
    /// Stream type.
    pub transport: ShareTransport,
    /// Hysteria2 "port hopping" syntax (`123,5000-6000`) when the inbound `port` is a
    /// range/array; overrides `port` in the host:port segment of `hy2://` links only (Roadmap
    /// §3:121). Ignored for VLESS/Trojan.
    pub port_hop: Option<String>,
    /// `salamander` FinalMask UDP layer password, surfaced as hy2 `obfs`/`obfs-password`
    /// (Roadmap §3:121). Ignored for VLESS/Trojan.
    pub obfs_salamander_password: Option<String>,
    /// SHA-256 pin of the leaf TLS certificate, surfaced as hy2 `pinSHA256` (Roadmap §3:121).
    /// Ignored for VLESS/Trojan.
    pub pin_sha256: Option<String>,
}

impl fmt::Debug for ShareUriRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareUriRequest")
            .field("protocol", &self.protocol)
            .field("user_id", &"[REDACTED]")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("remark", &self.remark)
            .field("flow", &self.flow)
            .field("encryption", &redact_encryption(&self.encryption))
            .field("security", &self.security)
            .field("transport", &self.transport)
            .finish()
    }
}

fn redact_encryption(value: &str) -> &str {
    if value.trim().is_empty() || value == "none" {
        value
    } else {
        "[REDACTED]"
    }
}

/// Error building a share URI (safe for Status Bar).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareUriError {
    detail: String,
}

impl ShareUriError {
    /// Creates an error with a user-facing detail (no secrets).
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// Safe detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ShareUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

/// Builds a single-line share URI. Never logs secrets.
pub fn build_share_uri(request: &ShareUriRequest) -> Result<String, ShareUriError> {
    let address = request.address.trim();
    if address.is_empty() {
        return Err(ShareUriError::new("Share host is empty (set Connection host)."));
    }
    if request.port == 0 {
        return Err(ShareUriError::new("Inbound port is missing or zero."));
    }
    let user_id = request.user_id.trim();
    if user_id.is_empty() {
        return Err(ShareUriError::new(match request.protocol {
            ShareProtocol::Vless => "Client UUID is empty.",
            ShareProtocol::Trojan => "Client password is empty.",
            ShareProtocol::Hysteria => "Hysteria auth is empty.",
        }));
    }

    if request.protocol == ShareProtocol::Hysteria {
        return build_hy2_uri(request, user_id);
    }

    if let ShareSecurity::Reality {
        public_key,
        server_name,
        ..
    } = &request.security
    {
        if public_key.trim().is_empty() {
            return Err(ShareUriError::new(
                "Reality PublicKey is missing. Generate x25519 on the Security tab first.",
            ));
        }
        if server_name.trim().is_empty() {
            return Err(ShareUriError::new("Reality serverName / SNI is empty."));
        }
    }

    if matches!(
        &request.transport,
        ShareTransport::Ws { .. } | ShareTransport::Kcp
    ) && !matches!(&request.security, ShareSecurity::Tls { .. })
    {
        return Err(ShareUriError::new(match &request.transport {
            ShareTransport::Kcp => "mKCP share requires TLS. Configure Security → tls first.",
            _ => "WebSocket share requires TLS. Configure Security → tls first.",
        }));
    }

    let encryption = request.encryption.trim();
    if encryption.is_empty() {
        return Err(ShareUriError::new("VLESS encryption must not be empty."));
    }

    let host = format_host(address);
    let scheme = match request.protocol {
        ShareProtocol::Vless => "vless",
        ShareProtocol::Trojan => "trojan",
        ShareProtocol::Hysteria => unreachable!("handled above"),
    };
    let mut uri = format!(
        "{scheme}://{user}@{host}:{port}",
        user = pct_encode(user_id),
        port = request.port
    );

    let mut query: Vec<(String, String)> = Vec::new();
    match &request.security {
        ShareSecurity::None => {
            query.push(("security".to_owned(), "none".to_owned()));
        }
        ShareSecurity::Tls {
            server_name,
            insecure,
            alpn,
        } => {
            query.push(("security".to_owned(), "tls".to_owned()));
            if let Some(sni) = server_name {
                let sni = sni.trim();
                if !sni.is_empty() {
                    query.push(("sni".to_owned(), sni.to_owned()));
                }
            }
            if *insecure {
                query.push(("allowInsecure".to_owned(), "1".to_owned()));
            }
            let alpn_list = joined_alpn(alpn);
            if let Some(alpn_list) = alpn_list {
                query.push(("alpn".to_owned(), alpn_list));
            }
        }
        ShareSecurity::Reality {
            public_key,
            short_id,
            server_name,
            fingerprint,
            spider_x,
            mldsa65_verify,
        } => {
            query.push(("security".to_owned(), "reality".to_owned()));
            query.push(("pbk".to_owned(), public_key.trim().to_owned()));
            query.push(("sid".to_owned(), short_id.trim().to_owned()));
            query.push(("sni".to_owned(), server_name.trim().to_owned()));
            let fp = fingerprint.trim();
            if !fp.is_empty() {
                query.push(("fp".to_owned(), fp.to_owned()));
            }
            let spx = spider_x.trim();
            if !spx.is_empty() {
                query.push(("spx".to_owned(), spx.to_owned()));
            }
            if let Some(pqv) = mldsa65_verify {
                let pqv = pqv.trim();
                if !pqv.is_empty() {
                    query.push(("pqv".to_owned(), pqv.to_owned()));
                }
            }
        }
    }

    match &request.transport {
        ShareTransport::Tcp => {
            query.push(("type".to_owned(), "tcp".to_owned()));
        }
        ShareTransport::Xhttp {
            path,
            host,
            mode,
            extra,
        } => {
            query.push(("type".to_owned(), "xhttp".to_owned()));
            let path = path.trim();
            if path.is_empty() {
                return Err(ShareUriError::new("xhttp path is empty."));
            }
            query.push(("path".to_owned(), path.to_owned()));
            if let Some(host) = host {
                let host = host.trim();
                if !host.is_empty() {
                    query.push(("host".to_owned(), host.to_owned()));
                }
            }
            if let Some(mode) = mode {
                let mode = mode.trim();
                if !mode.is_empty() {
                    query.push(("mode".to_owned(), mode.to_owned()));
                }
            }
            if let Some(extra) = extra {
                let extra = extra.trim();
                if !extra.is_empty() && extra != "{}" {
                    query.push(("extra".to_owned(), extra.to_owned()));
                }
            }
        }
        ShareTransport::Grpc { service_name } => {
            query.push(("type".to_owned(), "grpc".to_owned()));
            let name = service_name.trim();
            if name.is_empty() {
                return Err(ShareUriError::new("gRPC serviceName is empty."));
            }
            query.push(("serviceName".to_owned(), name.to_owned()));
        }
        ShareTransport::Ws { path, host } => {
            query.push(("type".to_owned(), "ws".to_owned()));
            let path = path.trim();
            if path.is_empty() {
                return Err(ShareUriError::new("WebSocket path is empty."));
            }
            query.push(("path".to_owned(), path.to_owned()));
            if let Some(host) = host {
                let host = host.trim();
                if !host.is_empty() {
                    query.push(("host".to_owned(), host.to_owned()));
                }
            }
        }
        ShareTransport::Kcp => {
            query.push(("type".to_owned(), "kcp".to_owned()));
        }
    }

    if request.protocol == ShareProtocol::Vless {
        query.push(("encryption".to_owned(), encryption.to_owned()));
        if let Some(flow) = &request.flow {
            let flow = flow.trim();
            if !flow.is_empty() {
                query.push(("flow".to_owned(), flow.to_owned()));
            }
        }
    }

    uri.push('?');
    for (i, (key, value)) in query.iter().enumerate() {
        if i > 0 {
            uri.push('&');
        }
        uri.push_str(key);
        uri.push('=');
        uri.push_str(&pct_encode(value));
    }

    if let Some(remark) = &request.remark {
        let remark = remark.trim();
        if !remark.is_empty() {
            uri.push('#');
            uri.push_str(&pct_encode(remark));
        }
    }

    Ok(uri)
}

fn build_hy2_uri(request: &ShareUriRequest, auth: &str) -> Result<String, ShareUriError> {
    let address = request.address.trim();
    let host = format_host(address);
    let port_segment = request
        .port_hop
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| request.port.to_string());
    let mut uri = format!(
        "hy2://{user}@{host}:{port_segment}",
        user = pct_encode(auth),
    );

    let mut query: Vec<(String, String)> = Vec::new();
    if let Some(password) = request
        .obfs_salamander_password
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        query.push(("obfs".to_owned(), "salamander".to_owned()));
        query.push(("obfs-password".to_owned(), password.to_owned()));
    }
    match &request.security {
        ShareSecurity::Tls {
            server_name,
            insecure,
            ..
        } => {
            if let Some(sni) = server_name {
                let sni = sni.trim();
                if !sni.is_empty() {
                    query.push(("sni".to_owned(), sni.to_owned()));
                }
            }
            if *insecure {
                query.push(("insecure".to_owned(), "1".to_owned()));
            }
        }
        ShareSecurity::None | ShareSecurity::Reality { .. } => {
            // Minimal hy2 assumes TLS; Reality is invalid for Hy.
        }
    }
    if let Some(pin) = request
        .pin_sha256
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        query.push(("pinSHA256".to_owned(), pin.to_owned()));
    }

    if !query.is_empty() {
        uri.push('?');
        for (i, (key, value)) in query.iter().enumerate() {
            if i > 0 {
                uri.push('&');
            }
            uri.push_str(key);
            uri.push('=');
            uri.push_str(&pct_encode(value));
        }
    }

    if let Some(remark) = &request.remark {
        let remark = remark.trim();
        if !remark.is_empty() {
            uri.push('#');
            uri.push_str(&pct_encode(remark));
        }
    }

    Ok(uri)
}

/// Joins non-empty, trimmed ALPN entries with `,` for the share query `alpn=` value.
fn joined_alpn(alpn: &[String]) -> Option<String> {
    let entries: Vec<&str> = alpn
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if entries.is_empty() {
        None
    } else {
        Some(entries.join(","))
    }
}

fn format_host(address: &str) -> String {
    if address.contains(':') && !address.starts_with('[') {
        // Likely IPv6 literal.
        format!("[{address}]")
    } else {
        address.to_owned()
    }
}

/// Percent-encode for URI userinfo / query / fragment (RFC 3986 unreserved passthrough).
pub fn pct_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(byte >> 4));
                out.push(hex_digit(byte & 0xf));
            }
        }
    }
    out
}

fn hex_digit(n: u8) -> char {
    char::from(match n {
        0..=9 => b'0' + n,
        10..=15 => b'A' + (n - 10),
        _ => b'0',
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reality_tcp_vless() -> ShareUriRequest {
        ShareUriRequest {
            protocol: ShareProtocol::Vless,
            user_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            address: "203.0.113.10".to_owned(),
            port: 443,
            remark: Some("demo".to_owned()),
            flow: Some("xtls-rprx-vision".to_owned()),
            encryption: "none".to_owned(),
            security: ShareSecurity::Reality {
                public_key: "RGhjWSrEM-rYV-nrfeDNswssqctjn8GFalDEuEcII1c".to_owned(),
                short_id: "abcd".to_owned(),
                server_name: "www.example.com".to_owned(),
                fingerprint: "chrome".to_owned(),
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            },
            transport: ShareTransport::Tcp,
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        }
    }

    fn hy2_base() -> ShareUriRequest {
        ShareUriRequest {
            protocol: ShareProtocol::Hysteria,
            user_id: "secret-auth".to_owned(),
            address: "203.0.113.10".to_owned(),
            port: 443,
            remark: Some("hy".to_owned()),
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::Tls {
                server_name: Some("www.example.com".to_owned()),
                insecure: true,
                alpn: Vec::new(),
            },
            transport: ShareTransport::Tcp,
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        }
    }

    #[test]
    fn builds_vless_reality_tcp() {
        let uri = build_share_uri(&reality_tcp_vless()).expect("uri");
        assert!(uri.starts_with("vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?"));
        assert!(uri.contains("security=reality"));
        assert!(uri.contains("pbk=RGhjWSrEM-rYV-nrfeDNswssqctjn8GFalDEuEcII1c"));
        assert!(uri.contains("sid=abcd"));
        assert!(uri.contains("sni=www.example.com"));
        assert!(uri.contains("fp=chrome"));
        assert!(uri.contains("spx=%2F") || uri.contains("spx=/"));
        assert!(uri.contains("type=tcp"));
        assert!(uri.contains("encryption=none"));
        assert!(uri.contains("flow=xtls-rprx-vision"));
        assert!(uri.ends_with("#demo"));
    }

    #[test]
    fn builds_vless_reality_with_pqv_and_empty_sid() {
        let mut req = reality_tcp_vless();
        if let ShareSecurity::Reality {
            short_id,
            mldsa65_verify,
            ..
        } = &mut req.security
        {
            *short_id = String::new();
            *mldsa65_verify = Some("verify-token".to_owned());
        }
        let uri = build_share_uri(&req).expect("uri");
        assert!(uri.contains("sid="));
        assert!(uri.contains("pqv=verify-token"));
    }

    #[test]
    fn builds_trojan_reality() {
        let req = ShareUriRequest {
            protocol: ShareProtocol::Trojan,
            user_id: "p@ss word".to_owned(),
            address: "example.com".to_owned(),
            port: 8443,
            remark: None,
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::Reality {
                public_key: "pub".to_owned(),
                short_id: "01".to_owned(),
                server_name: "sni.example".to_owned(),
                fingerprint: "chrome".to_owned(),
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            },
            transport: ShareTransport::Tcp,
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        };
        let uri = build_share_uri(&req).expect("uri");
        assert!(uri.starts_with("trojan://p%40ss%20word@example.com:8443?"));
        assert!(uri.contains("security=reality"));
        assert!(!uri.contains("encryption="));
    }

    #[test]
    fn builds_vless_none_xhttp() {
        let req = ShareUriRequest {
            protocol: ShareProtocol::Vless,
            user_id: "u".to_owned(),
            address: "h".to_owned(),
            port: 80,
            remark: None,
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::None,
            transport: ShareTransport::Xhttp {
                path: "/api".to_owned(),
                host: Some("cdn.example".to_owned()),
                mode: Some("auto".to_owned()),
                extra: Some(r#"{"xPaddingBytes":"100-1000","noSSEHeader":false}"#.to_owned()),
            },
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        };
        let uri = build_share_uri(&req).expect("uri");
        assert!(uri.contains("security=none"));
        assert!(uri.contains("type=xhttp"));
        assert!(uri.contains("path=%2Fapi") || uri.contains("path=/api"));
        assert!(uri.contains("host=cdn.example"));
        assert!(uri.contains("mode=auto"));
        assert!(uri.contains("extra="));
        assert!(uri.contains("%22xPaddingBytes%22") || uri.contains("xPaddingBytes"));
    }

    #[test]
    fn builds_vless_tls_ws() {
        let req = ShareUriRequest {
            protocol: ShareProtocol::Vless,
            user_id: "u".to_owned(),
            address: "h".to_owned(),
            port: 443,
            remark: None,
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::Tls {
                server_name: Some("sni.example".to_owned()),
                insecure: false,
                alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            },
            transport: ShareTransport::Ws {
                path: "/ray?ed=2048".to_owned(),
                host: Some("example.com".to_owned()),
            },
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        };
        let uri = build_share_uri(&req).expect("uri");
        assert!(uri.contains("security=tls"));
        assert!(uri.contains("type=ws"));
        assert!(uri.contains("path=%2Fray%3Fed%3D2048") || uri.contains("path=/ray?ed=2048"));
        assert!(uri.contains("host=example.com"));
        assert!(uri.contains("alpn=h2%2Chttp%2F1.1") || uri.contains("alpn=h2,http/1.1"));
    }

    #[test]
    fn rejects_ws_without_tls() {
        let req = ShareUriRequest {
            protocol: ShareProtocol::Vless,
            user_id: "u".to_owned(),
            address: "h".to_owned(),
            port: 80,
            remark: None,
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::None,
            transport: ShareTransport::Ws {
                path: "/".to_owned(),
                host: None,
            },
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        };
        let err = build_share_uri(&req).unwrap_err();
        assert!(err.detail().contains("TLS"));
    }

    #[test]
    fn builds_vless_tls_kcp() {
        let req = ShareUriRequest {
            protocol: ShareProtocol::Vless,
            user_id: "u".to_owned(),
            address: "h".to_owned(),
            port: 443,
            remark: None,
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::Tls {
                server_name: Some("sni.example".to_owned()),
                insecure: false,
                alpn: Vec::new(),
            },
            transport: ShareTransport::Kcp,
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        };
        let uri = build_share_uri(&req).expect("uri");
        assert!(uri.contains("security=tls"));
        assert!(uri.contains("type=kcp"));
    }

    #[test]
    fn rejects_kcp_without_tls() {
        let req = ShareUriRequest {
            protocol: ShareProtocol::Vless,
            user_id: "u".to_owned(),
            address: "h".to_owned(),
            port: 80,
            remark: None,
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::None,
            transport: ShareTransport::Kcp,
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        };
        let err = build_share_uri(&req).unwrap_err();
        assert!(err.detail().contains("mKCP"));
        assert!(err.detail().contains("TLS"));
    }

    #[test]
    fn rejects_missing_reality_public() {
        let mut req = reality_tcp_vless();
        if let ShareSecurity::Reality { public_key, .. } = &mut req.security {
            public_key.clear();
        }
        let err = build_share_uri(&req).unwrap_err();
        assert!(err.detail().contains("PublicKey"));
    }

    #[test]
    fn debug_redacts_user_id() {
        let dbg = format!("{:?}", reality_tcp_vless());
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("11111111"));
    }

    #[test]
    fn ipv6_host_bracketed() {
        let mut req = reality_tcp_vless();
        req.address = "2001:db8::1".to_owned();
        let uri = build_share_uri(&req).expect("uri");
        assert!(uri.contains("@[2001:db8::1]:443?"));
    }

    #[test]
    fn builds_hy2_minimal() {
        let uri = build_share_uri(&hy2_base()).expect("hy2");
        assert!(uri.starts_with("hy2://secret-auth@203.0.113.10:443?"));
        assert!(uri.contains("sni=www.example.com"));
        assert!(uri.contains("insecure=1"));
        assert!(uri.ends_with("#hy"));
    }

    #[test]
    fn builds_hy2_with_port_hop() {
        let mut req = hy2_base();
        req.port_hop = Some("443,5000-6000".to_owned());
        let uri = build_share_uri(&req).expect("hy2 hop");
        assert!(uri.starts_with("hy2://secret-auth@203.0.113.10:443,5000-6000?"));
    }

    #[test]
    fn builds_hy2_with_salamander_obfs() {
        let mut req = hy2_base();
        req.obfs_salamander_password = Some("cat".to_owned());
        let uri = build_share_uri(&req).expect("hy2 obfs");
        assert!(uri.contains("obfs=salamander"));
        assert!(uri.contains("obfs-password=cat"));
    }

    #[test]
    fn builds_hy2_with_pin_sha256() {
        let mut req = hy2_base();
        req.pin_sha256 = Some("deadbeef".to_owned());
        let uri = build_share_uri(&req).expect("hy2 pin");
        assert!(uri.contains("pinSHA256=deadbeef"));
    }

    #[test]
    fn builds_hy2_ignores_blank_optional_fields() {
        let mut req = hy2_base();
        req.port_hop = Some("   ".to_owned());
        req.obfs_salamander_password = Some(String::new());
        req.pin_sha256 = Some("  ".to_owned());
        let uri = build_share_uri(&req).expect("hy2");
        assert!(uri.starts_with("hy2://secret-auth@203.0.113.10:443?"));
        assert!(!uri.contains("obfs="));
        assert!(!uri.contains("pinSHA256="));
    }

    #[test]
    fn builds_vless_tls() {
        let uri = build_share_uri(&ShareUriRequest {
            protocol: ShareProtocol::Vless,
            user_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            address: "203.0.113.10".to_owned(),
            port: 443,
            remark: None,
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::Tls {
                server_name: Some("sni.example".to_owned()),
                insecure: false,
                alpn: Vec::new(),
            },
            transport: ShareTransport::Tcp,
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        })
        .expect("tls");
        assert!(uri.contains("security=tls"));
        assert!(uri.contains("sni=sni.example"));
        assert!(!uri.contains("allowInsecure"));
        assert!(!uri.contains("alpn="));
    }
}
