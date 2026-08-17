//! TLS 1.3 handshake probing (follow-up to Roadmap §3:131 — AS-range REALITY candidate scan).
//!
//! Checks whether a host negotiates TLS 1.3, an ALPN protocol in `{h2, http/1.1}` (h3 is
//! QUIC/UDP-only and unobservable via a TCP handshake — out of scope, agreed with the user), and a
//! key-exchange group in `{X25519, X25519MLKEM768}` — the REALITY `dest` candidate criteria this
//! whole module exists to check. Uses `rustls` with the `aws-lc-rs` crypto provider specifically
//! because `ring` (already in this workspace via `russh`) cannot negotiate or even recognize
//! `X25519MLKEM768` — only `aws-lc-rs` implements it. `x509-parser` extracts the leaf
//! certificate's SAN `dNSName` entries — deliberately not hand-rolled, unlike every other parser
//! in `netinfo`: X.509/DER parsing is exactly the kind of security-adjacent complexity where a
//! well-tested library beats a bespoke implementation.
//!
//! This is a read-only reconnaissance client: it completes the TLS handshake to observe what the
//! server negotiates, then closes — no application data is ever sent or received. Certificate
//! chain validation is intentionally skipped ([`NoVerifier`]) — the goal is to inspect whatever
//! the server presents, not to establish a trusted session.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, NamedGroup, SignatureScheme};

use super::{NetInfoError, NetInfoErrorKind, NetInfoResult};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// What a completed (or attempted) TLS handshake against one host revealed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsProbeResult {
    /// `true` when TLS 1.3 was negotiated.
    pub tls13: bool,
    /// Negotiated ALPN protocol (`"h2"`, `"http/1.1"`, or whatever else the server picked).
    pub alpn: Option<String>,
    /// Negotiated key-exchange group, e.g. `"X25519"` or `"X25519MLKEM768"`.
    pub negotiated_group: Option<String>,
    /// `dNSName` entries from the leaf certificate's Subject Alternative Name extension.
    pub cert_sans: Vec<String>,
}

/// Builds a `rustls` client config for REALITY-candidate probing: TLS 1.3 only, `aws-lc-rs`
/// crypto provider with key-exchange groups restricted to `[X25519MLKEM768, X25519]` (offered in
/// that preference order, mirroring modern Chrome's post-quantum-first uTLS fingerprint — the
/// server picks whichever it supports), ALPN offering `h2` and `http/1.1`, and no certificate
/// verification (see module doc). Build **once** per scan and reuse — construction isn't free and
/// nothing about it varies per candidate IP.
pub fn build_probe_tls_client_config() -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        rustls::crypto::aws_lc_rs::kx_group::X25519,
    ];

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is always a supported protocol version")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Completes a TLS handshake to `ip:port` with SNI `sni` and reports what was negotiated.
///
/// Sends no application data — the handshake itself is the entire probe.
pub fn probe_tls(
    ip: IpAddr,
    port: u16,
    sni: &str,
    config: Arc<ClientConfig>,
) -> NetInfoResult<TlsProbeResult> {
    let server_name = ServerName::try_from(sni.to_owned()).map_err(|_| {
        NetInfoError::new(
            NetInfoErrorKind::InvalidHost,
            format!("`{sni}` is not a valid TLS server name"),
        )
    })?;

    let mut conn = ClientConnection::new(config, server_name).map_err(|error| {
        NetInfoError::new(
            NetInfoErrorKind::ConnectionFailed,
            format!("could not set up TLS client: {error}"),
        )
    })?;

    let mut sock = TcpStream::connect_timeout(&SocketAddr::new(ip, port), PROBE_TIMEOUT)
        .map_err(|error| {
            NetInfoError::new(
                NetInfoErrorKind::ConnectionFailed,
                format!("could not connect to {ip}:{port}: {error}"),
            )
        })?;
    sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok();
    sock.set_write_timeout(Some(PROBE_TIMEOUT)).ok();

    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|error| {
            NetInfoError::new(
                NetInfoErrorKind::ConnectionFailed,
                format!("TLS handshake with {ip}:{port} failed: {error}"),
            )
        })?;
    }

    let tls13 = conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
    let alpn = conn
        .alpn_protocol()
        .map(|proto| String::from_utf8_lossy(proto).into_owned());
    let negotiated_group = conn
        .negotiated_key_exchange_group()
        .map(|group| named_group_label(group.name()));
    let cert_sans = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(extract_san_dns_names)
        .transpose()?
        .unwrap_or_default();

    // Best-effort close — we only wanted the handshake, no data was ever exchanged.
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);

    Ok(TlsProbeResult {
        tls13,
        alpn,
        negotiated_group,
        cert_sans,
    })
}

/// Whether `probe` satisfies every REALITY `dest` candidate criterion this module checks.
pub fn is_valid_reality_candidate(probe: &TlsProbeResult) -> bool {
    probe.tls13
        && matches!(probe.alpn.as_deref(), Some("h2") | Some("http/1.1"))
        && matches!(
            probe.negotiated_group.as_deref(),
            Some("X25519") | Some("X25519MLKEM768")
        )
}

fn named_group_label(group: NamedGroup) -> String {
    match group {
        NamedGroup::X25519 => "X25519".to_owned(),
        NamedGroup::X25519MLKEM768 => "X25519MLKEM768".to_owned(),
        other => format!("{other:?}"),
    }
}

fn extract_san_dns_names(cert: &CertificateDer<'_>) -> NetInfoResult<Vec<String>> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|error| {
        NetInfoError::new(
            NetInfoErrorKind::ParseFailed,
            format!("could not parse peer certificate: {error}"),
        )
    })?;

    let Ok(Some(san)) = parsed.subject_alternative_name() else {
        return Ok(Vec::new());
    };

    let names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(dns) => Some((*dns).to_owned()),
            _ => None,
        })
        .collect();
    Ok(names)
}

/// Accepts any certificate unconditionally — this client only ever inspects a handshake, never
/// exchanges application data, and must never be reused anywhere a trusted session is needed.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(tls13: bool, alpn: Option<&str>, group: Option<&str>) -> TlsProbeResult {
        TlsProbeResult {
            tls13,
            alpn: alpn.map(str::to_owned),
            negotiated_group: group.map(str::to_owned),
            cert_sans: Vec::new(),
        }
    }

    #[test]
    fn valid_when_all_three_criteria_hold() {
        assert!(is_valid_reality_candidate(&probe(
            true,
            Some("h2"),
            Some("X25519")
        )));
        assert!(is_valid_reality_candidate(&probe(
            true,
            Some("http/1.1"),
            Some("X25519MLKEM768")
        )));
    }

    #[test]
    fn invalid_without_tls13() {
        assert!(!is_valid_reality_candidate(&probe(
            false,
            Some("h2"),
            Some("X25519")
        )));
    }

    #[test]
    fn invalid_with_unlisted_alpn() {
        assert!(!is_valid_reality_candidate(&probe(
            true,
            Some("http/1.0"),
            Some("X25519")
        )));
    }

    #[test]
    fn invalid_without_alpn() {
        assert!(!is_valid_reality_candidate(&probe(true, None, Some("X25519"))));
    }

    #[test]
    fn invalid_with_unlisted_curve() {
        assert!(!is_valid_reality_candidate(&probe(
            true,
            Some("h2"),
            Some("secp256r1")
        )));
    }

    #[test]
    fn named_group_label_uses_explicit_strings_for_known_groups() {
        assert_eq!(named_group_label(NamedGroup::X25519), "X25519");
        assert_eq!(
            named_group_label(NamedGroup::X25519MLKEM768),
            "X25519MLKEM768"
        );
    }
}
