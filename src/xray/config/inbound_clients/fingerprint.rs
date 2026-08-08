//! JSON object fingerprint (SHA-256 of canonical JSON).

use sha2::{Digest, Sha256};
use serde_json::Value;

use crate::xray::config::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// SHA-256 hex digest of the full canonical JSON value.
///
/// Uses `serde_json::to_vec` (BTree map key order). Store/log only the hash.
pub fn json_value_fingerprint(value: &Value) -> ConfigModifyResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::SerializationFailed,
            format!("failed to canonicalize JSON for fingerprint: {error}"),
        )
    })?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Verifies `expected` matches the current JSON value.
pub fn verify_json_fingerprint(
    value: &Value,
    expected: &str,
    what: &str,
) -> ConfigModifyResult<()> {
    let actual = json_value_fingerprint(value)?;
    if actual != expected {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::FingerprintMismatch,
            format!("{what} changed since it was loaded for editing"),
        ));
    }
    Ok(())
}

/// SHA-256 hex digest of the full canonical client JSON object.
pub fn client_fingerprint(client: &Value) -> ConfigModifyResult<String> {
    json_value_fingerprint(client)
}

/// Verifies `expected` matches the current client object.
pub fn verify_client_fingerprint(client: &Value, expected: &str) -> ConfigModifyResult<()> {
    verify_json_fingerprint(client, expected, "client")
}

/// SHA-256 hex digest of the full canonical inbound JSON object.
pub fn inbound_fingerprint(inbound: &Value) -> ConfigModifyResult<String> {
    json_value_fingerprint(inbound)
}

/// Verifies `expected` matches the current inbound object.
pub fn verify_inbound_fingerprint(inbound: &Value, expected: &str) -> ConfigModifyResult<()> {
    verify_json_fingerprint(inbound, expected, "inbound")
}
