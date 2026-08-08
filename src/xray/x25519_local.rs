//! Local X25519 helpers for Reality share material (no remote CLI).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use x25519_dalek::{PublicKey, StaticSecret};

/// Derives the Reality client PublicKey (`pbk`) from a server `privateKey`.
///
/// Encoding matches `xray x25519` output: URL-safe base64 without padding.
/// Never logs the private key.
pub fn public_key_from_private_key(private_key: &str) -> Result<String, String> {
    let private_key = private_key.trim();
    if private_key.is_empty() {
        return Err("Reality privateKey is empty.".to_owned());
    }
    let bytes = decode_x25519_key(private_key)
        .ok_or_else(|| "Reality privateKey is not valid URL-safe base64 (32 bytes).".to_owned())?;
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    Ok(URL_SAFE_NO_PAD.encode(public.as_bytes()))
}

fn decode_x25519_key(value: &str) -> Option<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD.decode(value.as_bytes()).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_fixture_public_key() {
        let private = "0EiEonMUwJyuyI4Q8tdGIRvjV_aaOfeFC7TSsohh5mk";
        let public = public_key_from_private_key(private).expect("derive");
        assert_eq!(public, "RGhjWSrEM-rYV-nrfeDNswssqctjn8GFalDEuEcII1c");
    }

    #[test]
    fn rejects_empty_and_bad_length() {
        assert!(public_key_from_private_key("").is_err());
        assert!(public_key_from_private_key("not-base64!!!").is_err());
        assert!(public_key_from_private_key("YQ").is_err()); // 1 byte
    }
}
