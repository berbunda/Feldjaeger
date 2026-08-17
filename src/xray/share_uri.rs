//! Client share URI builders (`vless://` / `trojan://` / `hy2://`) for IB Share lake, plus the
//! reverse direction — parsing a pasted share URI for Inbound import (Roadmap §3:133).
//!
//! Reality `publicKey` and VLESS client `encryption` are **never** read from
//! server inbound JSON — callers must supply them from Generate ephemerals.
//!
//! **Import direction — what can and cannot round-trip.** A share URI is inherently a partial,
//! one-way view of a server config: it was built from server data (see [`build_share_uri`]) that
//! deliberately excludes anything secret, so parsing one back can only ever recover a subset of
//! what a working inbound needs:
//! - REALITY `pbk` (public key) is present, but the matching `privateKey` never is (see module
//!   doc above) — an imported Reality link can prefill `sni`/`sid`/`fp`/`spx`, but the inbound
//!   still needs a **freshly generated** keypair, which makes the original link's `pbk` unusable
//!   afterward. Confirmed with the user as the intended behavior (Roadmap §3:133).
//! - TLS certificate files are never encoded in a link (only `sni`/`alpn`/`allowInsecure`) — an
//!   imported TLS inbound still needs `certificateFile`/`keyFile` configured separately.
//! - VLESS `encryption` (post-quantum ML-KEM client encryption), when present and not `"none"`,
//!   is parsed but intentionally **not** applied to the new inbound's `decryption` — same
//!   category of problem as the Reality private key (the server-side secret half is never in the
//!   client's link) — surfaced as an import warning instead.
//! - hy2 `pinSHA256` is a pure client-side pinning value with no corresponding server config
//!   field at all — parsed only to warn that it exists, never written anywhere.
//! - hy2 `obfs=salamander`/`obfs-password` *is* a plain shared secret (both sides must already
//!   agree on it) and *is* fully reusable — imported into `streamSettings.finalmask.udp[]`.

use std::collections::HashMap;
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

/// Percent-decodes a URI component. Malformed `%` escapes (not followed by two hex digits) are
/// passed through literally rather than rejected — links pasted from other tools are trusted
/// input the user typed/pasted themselves, not attacker-controlled wire data; being lenient here
/// matches this project's general "prefer compatibility over convenience" stance (`rules.md`).
pub fn pct_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ─── Import: parsing a pasted share URI ────────────────────────────────────────

/// Everything recoverable from parsing a client share URI (see module doc for what's
/// deliberately *not* recoverable). Reuses [`ShareSecurity`]/[`ShareTransport`] directly — the
/// same types [`build_share_uri`] consumes — so downstream import code interprets exactly the
/// same shapes it already knows how to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedShareUri {
    /// VLESS, Trojan, or Hysteria.
    pub protocol: ShareProtocol,
    /// UUID (VLESS) / password (Trojan) / auth (Hysteria) — percent-decoded userinfo.
    pub user_id: String,
    /// Host from the authority section — informational only; import never writes this anywhere
    /// (it's the address *clients* use to reach the server, not something to set as `listen`).
    pub host: String,
    /// First/primary port, when parseable.
    pub port: Option<u16>,
    /// Raw hy2 "port hopping" segment (`"443,5000-6000"`) when the port section contained a
    /// comma. `None` for VLESS/Trojan (never has hop syntax) and for a plain hy2 port.
    pub port_hop: Option<String>,
    /// Fragment (`#…`), percent-decoded.
    pub remark: Option<String>,
    /// VLESS `flow` query, when non-empty.
    pub flow: Option<String>,
    /// VLESS `encryption` query, when present — kept only so callers can warn that it isn't
    /// imported (see module doc), never applied to a new inbound's `decryption`.
    pub encryption: Option<String>,
    /// none | tls | reality.
    pub security: ShareSecurity,
    /// Stream type. For Hysteria this is always [`ShareTransport::Tcp`] as a placeholder — hy2
    /// links carry no `type=` query at all, so this field is meaningless for that protocol and
    /// import code must not read it there.
    pub transport: ShareTransport,
    /// hy2 `obfs-password`, only when `obfs=salamander` was present — the one Hysteria security
    /// param that *is* fully reusable (see module doc).
    pub obfs_salamander_password: Option<String>,
    /// hy2 `pinSHA256`, kept only to warn it exists — no server-side field to import it into.
    pub pin_sha256: Option<String>,
}

/// Parses a `vless://`, `trojan://`, or `hy2://`/`hysteria2://` share URI.
///
/// Accepts `hysteria2://` as an alias for `hy2://` on import (but never emits it) since that's
/// the scheme name many other Hysteria2 panels/tools use.
pub fn parse_share_uri(input: &str) -> Result<ParsedShareUri, ShareUriError> {
    let input = input.trim();
    let (scheme, rest) = input
        .split_once("://")
        .ok_or_else(|| ShareUriError::new("Not a share URI (missing `scheme://`)."))?;
    let protocol = match scheme.to_ascii_lowercase().as_str() {
        "vless" => ShareProtocol::Vless,
        "trojan" => ShareProtocol::Trojan,
        "hy2" | "hysteria2" | "hysteria" => ShareProtocol::Hysteria,
        other => {
            return Err(ShareUriError::new(format!(
                "Unsupported scheme `{other}://` (expected vless / trojan / hy2)."
            )));
        }
    };

    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((a, b)) => (a, Some(pct_decode(b))),
        None => (rest, None),
    };
    let (authority_and_userinfo, query_str) = match before_fragment.split_once('?') {
        Some((a, b)) => (a, b),
        None => (before_fragment, ""),
    };
    let (userinfo, authority) = authority_and_userinfo
        .rsplit_once('@')
        .ok_or_else(|| ShareUriError::new("Missing credential before `@` in share URI."))?;
    let user_id = pct_decode(userinfo);
    if user_id.trim().is_empty() {
        return Err(ShareUriError::new("Empty credential in share URI."));
    }

    let (host, port_section) = split_host_port(authority)?;

    let mut port: Option<u16> = None;
    let mut port_hop: Option<String> = None;
    if let Some(section) = port_section {
        let section = section.trim();
        if section.contains(',') {
            port_hop = Some(section.to_owned());
            port = section
                .split([',', '-'])
                .next()
                .and_then(|first| first.trim().parse().ok());
        } else {
            port = section.parse().ok();
        }
    }

    let query = parse_query(query_str);

    Ok(match protocol {
        ShareProtocol::Hysteria => parse_hy2_fields(user_id, host, port, port_hop, fragment, &query),
        _ => parse_vless_trojan_fields(protocol, user_id, host, port, fragment, &query),
    })
}

fn split_host_port(authority: &str) -> Result<(String, Option<&str>), ShareUriError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| ShareUriError::new("Unterminated IPv6 literal in share URI host."))?;
        return Ok((host.to_owned(), after.strip_prefix(':')));
    }
    match authority.split_once(':') {
        Some((host, port)) => Ok((host.to_owned(), Some(port))),
        None => Ok((authority.to_owned(), None)),
    }
}

fn parse_query(query_str: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query_str.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(pct_decode(key), pct_decode(value));
    }
    map
}

fn parse_vless_trojan_fields(
    protocol: ShareProtocol,
    user_id: String,
    host: String,
    port: Option<u16>,
    remark: Option<String>,
    query: &HashMap<String, String>,
) -> ParsedShareUri {
    let security = match query.get("security").map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("reality") => ShareSecurity::Reality {
            public_key: query.get("pbk").cloned().unwrap_or_default(),
            short_id: query.get("sid").cloned().unwrap_or_default(),
            server_name: query.get("sni").cloned().unwrap_or_default(),
            fingerprint: query.get("fp").cloned().unwrap_or_default(),
            spider_x: query.get("spx").cloned().unwrap_or_default(),
            mldsa65_verify: query.get("pqv").cloned(),
        },
        Some("tls") => ShareSecurity::Tls {
            server_name: query.get("sni").cloned(),
            insecure: query_flag(query, "allowInsecure") || query_flag(query, "insecure"),
            alpn: split_alpn(query.get("alpn")),
        },
        _ => ShareSecurity::None,
    };

    let transport = match query.get("type").map(String::as_str) {
        Some("xhttp") | Some("splithttp") => ShareTransport::Xhttp {
            path: query.get("path").cloned().unwrap_or_default(),
            host: query.get("host").cloned(),
            mode: query.get("mode").cloned(),
            extra: query.get("extra").cloned(),
        },
        Some("grpc") => ShareTransport::Grpc {
            service_name: query.get("serviceName").cloned().unwrap_or_default(),
        },
        Some("ws") | Some("websocket") => ShareTransport::Ws {
            path: query.get("path").cloned().unwrap_or_default(),
            host: query.get("host").cloned(),
        },
        Some("kcp") | Some("mkcp") => ShareTransport::Kcp,
        _ => ShareTransport::Tcp,
    };

    ParsedShareUri {
        protocol,
        user_id,
        host,
        port,
        port_hop: None,
        remark,
        flow: query.get("flow").cloned().filter(|s| !s.is_empty()),
        encryption: query.get("encryption").cloned().filter(|s| !s.is_empty()),
        security,
        transport,
        obfs_salamander_password: None,
        pin_sha256: None,
    }
}

fn parse_hy2_fields(
    user_id: String,
    host: String,
    port: Option<u16>,
    port_hop: Option<String>,
    remark: Option<String>,
    query: &HashMap<String, String>,
) -> ParsedShareUri {
    let security = ShareSecurity::Tls {
        server_name: query.get("sni").cloned(),
        insecure: query_flag(query, "insecure"),
        alpn: Vec::new(),
    };
    let obfs_salamander_password = query
        .get("obfs")
        .is_some_and(|v| v.eq_ignore_ascii_case("salamander"))
        .then(|| query.get("obfs-password").cloned())
        .flatten()
        .filter(|s| !s.is_empty());

    ParsedShareUri {
        protocol: ShareProtocol::Hysteria,
        user_id,
        host,
        port,
        port_hop,
        remark,
        flow: None,
        encryption: None,
        security,
        transport: ShareTransport::Tcp,
        obfs_salamander_password,
        pin_sha256: query.get("pinSHA256").cloned().filter(|s| !s.is_empty()),
    }
}

fn query_flag(query: &HashMap<String, String>, key: &str) -> bool {
    query.get(key).is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn split_alpn(value: Option<&String>) -> Vec<String> {
    value
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
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

    // ─── Import: parse_share_uri ────────────────────────────────────────────

    #[test]
    fn pct_decode_round_trips_pct_encode() {
        let original = "p@ss word/with?special#chars";
        assert_eq!(pct_decode(&pct_encode(original)), original);
    }

    #[test]
    fn pct_decode_passes_through_malformed_escape() {
        assert_eq!(pct_decode("100%-off"), "100%-off");
    }

    #[test]
    fn parses_vless_reality_round_trip() {
        let uri = build_share_uri(&reality_tcp_vless()).expect("uri");
        let parsed = parse_share_uri(&uri).expect("parse");
        assert_eq!(parsed.protocol, ShareProtocol::Vless);
        assert_eq!(parsed.user_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(parsed.host, "203.0.113.10");
        assert_eq!(parsed.port, Some(443));
        assert_eq!(parsed.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(parsed.encryption.as_deref(), Some("none"));
        assert_eq!(parsed.remark.as_deref(), Some("demo"));
        assert_eq!(parsed.transport, ShareTransport::Tcp);
        match parsed.security {
            ShareSecurity::Reality {
                public_key,
                short_id,
                server_name,
                fingerprint,
                spider_x,
                ..
            } => {
                assert_eq!(public_key, "RGhjWSrEM-rYV-nrfeDNswssqctjn8GFalDEuEcII1c");
                assert_eq!(short_id, "abcd");
                assert_eq!(server_name, "www.example.com");
                assert_eq!(fingerprint, "chrome");
                assert_eq!(spider_x, "/");
            }
            other => panic!("expected Reality, got {other:?}"),
        }
    }

    #[test]
    fn parses_vless_tls_ws_round_trip() {
        let uri = build_share_uri(&ShareUriRequest {
            protocol: ShareProtocol::Vless,
            user_id: "u".to_owned(),
            address: "h".to_owned(),
            port: 443,
            remark: None,
            flow: None,
            encryption: "none".to_owned(),
            security: ShareSecurity::Tls {
                server_name: Some("sni.example".to_owned()),
                insecure: true,
                alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            },
            transport: ShareTransport::Ws {
                path: "/ray?ed=2048".to_owned(),
                host: Some("example.com".to_owned()),
            },
            port_hop: None,
            obfs_salamander_password: None,
            pin_sha256: None,
        })
        .expect("uri");
        let parsed = parse_share_uri(&uri).expect("parse");
        match parsed.security {
            ShareSecurity::Tls {
                server_name,
                insecure,
                alpn,
            } => {
                assert_eq!(server_name.as_deref(), Some("sni.example"));
                assert!(insecure);
                assert_eq!(alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
            }
            other => panic!("expected Tls, got {other:?}"),
        }
        match parsed.transport {
            ShareTransport::Ws { path, host } => {
                assert_eq!(path, "/ray?ed=2048");
                assert_eq!(host.as_deref(), Some("example.com"));
            }
            other => panic!("expected Ws, got {other:?}"),
        }
    }

    #[test]
    fn parses_trojan_none_grpc() {
        let parsed = parse_share_uri(
            "trojan://p%40ss@example.com:8443?security=none&type=grpc&serviceName=svc#remark",
        )
        .expect("parse");
        assert_eq!(parsed.protocol, ShareProtocol::Trojan);
        assert_eq!(parsed.user_id, "p@ss");
        assert_eq!(parsed.security, ShareSecurity::None);
        assert_eq!(parsed.remark.as_deref(), Some("remark"));
        match parsed.transport {
            ShareTransport::Grpc { service_name } => assert_eq!(service_name, "svc"),
            other => panic!("expected Grpc, got {other:?}"),
        }
    }

    #[test]
    fn parses_hy2_with_obfs_and_pin_and_hop() {
        let uri = "hy2://secret-auth@203.0.113.10:443,5000-6000?obfs=salamander&obfs-password=cat&sni=www.example.com&insecure=1&pinSHA256=deadbeef#hy";
        let parsed = parse_share_uri(uri).expect("parse");
        assert_eq!(parsed.protocol, ShareProtocol::Hysteria);
        assert_eq!(parsed.user_id, "secret-auth");
        assert_eq!(parsed.port, Some(443));
        assert_eq!(parsed.port_hop.as_deref(), Some("443,5000-6000"));
        assert_eq!(parsed.obfs_salamander_password.as_deref(), Some("cat"));
        assert_eq!(parsed.pin_sha256.as_deref(), Some("deadbeef"));
        assert_eq!(parsed.remark.as_deref(), Some("hy"));
        match parsed.security {
            ShareSecurity::Tls {
                server_name,
                insecure,
                ..
            } => {
                assert_eq!(server_name.as_deref(), Some("www.example.com"));
                assert!(insecure);
            }
            other => panic!("expected Tls, got {other:?}"),
        }
    }

    #[test]
    fn parses_hysteria2_scheme_alias() {
        let parsed = parse_share_uri("hysteria2://auth@host:443").expect("parse");
        assert_eq!(parsed.protocol, ShareProtocol::Hysteria);
    }

    #[test]
    fn parses_ipv6_host() {
        let parsed = parse_share_uri("vless://u@[2001:db8::1]:443?security=none").expect("parse");
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, Some(443));
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let error = parse_share_uri("ss://foo@host:443").unwrap_err();
        assert!(error.detail().contains("Unsupported scheme"));
    }

    #[test]
    fn rejects_missing_scheme_separator() {
        let error = parse_share_uri("not a uri at all").unwrap_err();
        assert!(error.detail().contains("scheme"));
    }

    #[test]
    fn rejects_missing_userinfo() {
        let error = parse_share_uri("vless://host:443?security=none").unwrap_err();
        assert!(error.detail().contains('@'));
    }

    #[test]
    fn rejects_empty_credential() {
        let error = parse_share_uri("vless://@host:443").unwrap_err();
        assert!(error.detail().contains("Empty credential"));
    }

    #[test]
    fn defaults_to_none_security_and_tcp_transport_when_absent() {
        let parsed = parse_share_uri("vless://u@host:443").expect("parse");
        assert_eq!(parsed.security, ShareSecurity::None);
        assert_eq!(parsed.transport, ShareTransport::Tcp);
    }

    #[test]
    fn plain_scalar_port_has_no_hop() {
        let parsed = parse_share_uri("hy2://auth@host:443").expect("parse");
        assert_eq!(parsed.port, Some(443));
        assert!(parsed.port_hop.is_none());
    }
}
