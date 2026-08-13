//! Outbound General fields (tag / sendThrough) + Shell edit identity.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Full-state General form payload for an outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundGeneral {
    /// Outbound tag; empty/whitespace omits the key. Immutable on Shell Save by design —
    /// rename is a standalone action, `rename_outbound_tag` (Roadmap §2.4:99).
    pub tag: Option<String>,
    /// `sendThrough` bind address; empty omits the key.
    pub send_through: Option<String>,
}

/// Identity + fingerprint for an outbound Shell Save (mirrors [`super::InboundRef`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRef {
    /// Merged outbound index at edit intent.
    pub outbound_index: usize,
    /// SHA-256 hex of the full canonical outbound JSON at edit intent.
    pub expected_fingerprint: String,
}

/// Reads General fields for UI drafts from an outbound value.
pub fn parse_outbound_general(outbound: &Value) -> OutboundGeneral {
    OutboundGeneral {
        tag: outbound.get("tag").and_then(Value::as_str).map(str::to_owned),
        send_through: outbound
            .get("sendThrough")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// Applies General fields onto an outbound object in place.
pub fn apply_outbound_general(
    outbound: &mut Value,
    general: &OutboundGeneral,
) -> ConfigModifyResult<()> {
    let object = outbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound is not a JSON object".to_owned(),
        )
    })?;

    apply_optional_string(object, "tag", general.tag.as_deref());
    apply_optional_string(object, "sendThrough", general.send_through.as_deref());

    Ok(())
}

fn apply_optional_string(object: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        Some(text) => {
            object.insert(key.to_owned(), Value::String(text.to_owned()));
        }
        None => {
            object.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_reads_tag_and_send_through() {
        let outbound = json!({"tag": "direct", "sendThrough": "0.0.0.0", "protocol": "freedom"});
        let general = parse_outbound_general(&outbound);
        assert_eq!(general.tag.as_deref(), Some("direct"));
        assert_eq!(general.send_through.as_deref(), Some("0.0.0.0"));
    }

    #[test]
    fn apply_omits_empty_fields_and_preserves_siblings() {
        let mut outbound = json!({"protocol": "freedom", "settings": {}, "mux": {"enabled": true}});
        apply_outbound_general(
            &mut outbound,
            &OutboundGeneral {
                tag: Some("direct".to_owned()),
                send_through: Some(String::new()),
            },
        )
        .expect("apply");
        assert_eq!(outbound["tag"], "direct");
        assert!(outbound.get("sendThrough").is_none());
        assert_eq!(outbound["mux"]["enabled"], true);
    }
}
