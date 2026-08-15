//! Hysteria2 `pinSHA256` certificate fingerprint (local hash, no remote round-trip).
//!
//! Hashes the leaf certificate's DER bytes with SHA-256, matching the format Hysteria2 clients
//! compare against (`sha256.Sum256(rawCert)`, hex-encoded, no colons) — see
//! <https://github.com/apernet/hysteria> (`fillTLSConfig` / `normalizeCertHash`). The remote
//! `certificateFile` bytes are fetched by the caller over SFTP; this module only hashes them.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Computes the lowercase-hex SHA-256 fingerprint of a certificate file's DER bytes.
///
/// Accepts either PEM text (uses the **first** `CERTIFICATE` block — the leaf/end-entity cert,
/// matching what a TLS handshake actually presents to clients) or raw DER bytes.
pub fn cert_pin_sha256(file_bytes: &[u8]) -> Result<String, String> {
    let der = match std::str::from_utf8(file_bytes) {
        Ok(text) if text.contains(PEM_BEGIN) => extract_first_pem_der(text)?,
        _ => file_bytes.to_vec(),
    };
    if der.is_empty() {
        return Err("Certificate file is empty.".to_owned());
    }
    let digest = Sha256::digest(&der);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn extract_first_pem_der(text: &str) -> Result<Vec<u8>, String> {
    let start = text
        .find(PEM_BEGIN)
        .ok_or_else(|| "No PEM CERTIFICATE block found.".to_owned())?
        + PEM_BEGIN.len();
    let end = text[start..]
        .find(PEM_END)
        .ok_or_else(|| "Unterminated PEM CERTIFICATE block.".to_owned())?
        + start;
    let body: String = text[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD
        .decode(body)
        .map_err(|error| format!("Certificate PEM body is not valid base64: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_der_bytes_directly() {
        let der = b"\x30\x82\x01\x00fake-der-bytes";
        let pin = cert_pin_sha256(der).expect("pin");
        assert_eq!(pin.len(), 64);
        assert!(
            pin.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn hashes_pem_body_after_base64_decode() {
        let der = b"hello-cert-bytes";
        let b64 = STANDARD.encode(der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        let pin_from_pem = cert_pin_sha256(pem.as_bytes()).expect("pin");
        let pin_from_der = cert_pin_sha256(der).expect("pin");
        assert_eq!(pin_from_pem, pin_from_der);
    }

    #[test]
    fn uses_first_certificate_block_when_chain_present() {
        let leaf = b"leaf-cert-bytes";
        let chain = b"chain-cert-bytes";
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(leaf),
            STANDARD.encode(chain)
        );
        let pin = cert_pin_sha256(pem.as_bytes()).expect("pin");
        assert_eq!(pin, cert_pin_sha256(leaf).unwrap());
    }

    #[test]
    fn rejects_empty_input() {
        assert!(cert_pin_sha256(b"").is_err());
    }
}
