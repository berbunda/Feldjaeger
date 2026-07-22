//! Serialize editable Xray configuration fragments to JSON bytes.

use serde_json::Value;

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Serializes a JSON value to pretty-printed UTF-8 bytes.
///
/// Used for write-back of a single source file root. Does not log or return
/// secret field values in error messages.
pub fn serialize_json_value(value: &Value) -> ConfigModifyResult<Vec<u8>> {
    serde_json::to_vec_pretty(value).map_err(|error| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::SerializationFailed,
            format!("failed to serialize configuration JSON: {error}"),
        )
    })
}

/// Validates that `bytes` parse as a JSON object (pre-upload check).
pub fn validate_serialized_json(bytes: &[u8]) -> ConfigModifyResult<Value> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("serialized configuration is not UTF-8: {error}"),
        )
    })?;
    let value: Value = serde_json::from_str(text).map_err(|error| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("serialized configuration is not valid JSON: {error}"),
        )
    })?;
    if !value.is_object() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "serialized configuration root must be a JSON object".to_owned(),
        ));
    }
    Ok(value)
}
