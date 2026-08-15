//! Inbound General fields (tag / listen / port).

use serde_json::{Map, Number, Value};

use super::listen::validate_listen_address;
use crate::xray::config::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Full-state General form payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundGeneral {
    /// Inbound tag; empty/whitespace omits the key.
    pub tag: Option<String>,
    /// Listen address; empty omits the key.
    pub listen: Option<String>,
    /// Port when scalar; `None` omits the key.
    pub port: Option<u64>,
}

/// Returns true when `port` is absent or a scalar number / decimal string.
pub fn port_is_shell_editable(inbound: &Value) -> bool {
    match inbound.get("port") {
        None => true,
        Some(Value::Null) => true,
        Some(Value::Number(n)) => n.as_u64().is_some(),
        Some(Value::String(s)) => s.trim().parse::<u64>().is_ok(),
        Some(_) => false,
    }
}

/// Applies General fields onto an inbound object in place.
///
/// A non-scalar `port` (range string / array / mixed list) is preserved byte-for-byte and never
/// touched here — the General tab keeps it read-only, so `general.port` cannot represent it and
/// must not overwrite or clear it (Roadmap §3:118; no coercion to scalar).
pub fn apply_inbound_general(
    inbound: &mut Value,
    general: &InboundGeneral,
) -> ConfigModifyResult<()> {
    let port_editable = port_is_shell_editable(inbound);

    if let Some(port) = general.port {
        if port > u64::from(u16::MAX) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("port out of range: {port}"),
            ));
        }
    }

    if let Some(listen) = &general.listen {
        let trimmed = listen.trim();
        if !trimmed.is_empty() {
            validate_listen_address(trimmed)?;
        }
    }

    let object = inbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound is not a JSON object".to_owned(),
        )
    })?;

    apply_optional_string(object, "tag", general.tag.as_deref());
    apply_optional_string(object, "listen", general.listen.as_deref());
    if port_editable {
        apply_optional_port(object, general.port);
    }

    Ok(())
}

/// Compact display text for a non-scalar `port` (range string / array / mixed list), for the
/// General tab's read-only note. `None` when `port` is absent, scalar, or the inbound has no
/// `port` key at all — [`port_is_shell_editable`] covers those cases instead.
pub fn raw_port_display(inbound: &Value) -> Option<String> {
    if port_is_shell_editable(inbound) {
        return None;
    }
    let port = inbound.get("port")?;
    Some(match port {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

/// First port number in a [`port_hop_syntax`] string (`"443,5000-6000"` → `443`), for scalar
/// fallbacks (e.g. share-URI port validation) when only the hop form is available.
pub fn first_hop_port(hop: &str) -> Option<u64> {
    let first_entry = hop.split(',').next()?.trim();
    let head = first_entry.split('-').next()?.trim();
    head.parse().ok()
}

/// Flattens a non-scalar `port` into Hysteria2 URI "port hopping" syntax (`123,5000-6000`) —
/// comma-separated ports/ranges, no brackets or quotes. This is also a valid Xray-core `port`
/// string in its own right. `None` when `port` is absent or scalar (Roadmap §3:121).
pub fn port_hop_syntax(inbound: &Value) -> Option<String> {
    if port_is_shell_editable(inbound) {
        return None;
    }
    match inbound.get("port")? {
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() { None } else { Some(s.to_owned()) }
        }
        Value::Array(items) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(|item| match item {
                    Value::Number(n) => Some(n.to_string()),
                    Value::String(s) => {
                        let s = s.trim();
                        (!s.is_empty()).then(|| s.to_owned())
                    }
                    _ => None,
                })
                .collect();
            (!parts.is_empty()).then(|| parts.join(","))
        }
        _ => None,
    }
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

fn apply_optional_port(object: &mut Map<String, Value>, port: Option<u64>) {
    match port {
        Some(port) => {
            object.insert(key_port(), Value::Number(Number::from(port)));
        }
        None => {
            object.remove("port");
        }
    }
}

fn key_port() -> String {
    "port".to_owned()
}

/// Reads General fields for UI drafts from an inbound value.
pub fn parse_inbound_general(inbound: &Value) -> InboundGeneral {
    let tag = inbound
        .get("tag")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let listen = inbound
        .get("listen")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let port = match inbound.get("port") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    };
    InboundGeneral { tag, listen, port }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn port_hop_syntax_none_for_scalar_or_absent() {
        assert_eq!(port_hop_syntax(&json!({"port": 443})), None);
        assert_eq!(port_hop_syntax(&json!({"port": "443"})), None);
        assert_eq!(port_hop_syntax(&json!({})), None);
    }

    #[test]
    fn port_hop_syntax_passes_through_string_form() {
        assert_eq!(
            port_hop_syntax(&json!({"port": "443,5000-6000"})),
            Some("443,5000-6000".to_owned())
        );
    }

    #[test]
    fn port_hop_syntax_flattens_array_form() {
        assert_eq!(
            port_hop_syntax(&json!({"port": [443, "5000-6000", 8443]})),
            Some("443,5000-6000,8443".to_owned())
        );
    }

    #[test]
    fn first_hop_port_extracts_leading_number() {
        assert_eq!(first_hop_port("443,5000-6000"), Some(443));
        assert_eq!(first_hop_port("5000-6000"), Some(5000));
        assert_eq!(first_hop_port("5000-6000,443"), Some(5000));
        assert_eq!(first_hop_port("not-a-port"), None);
    }
}
