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
pub fn apply_inbound_general(
    inbound: &mut Value,
    general: &InboundGeneral,
) -> ConfigModifyResult<()> {
    if !port_is_shell_editable(inbound) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound port shape is not supported for shell editing (scalar only)".to_owned(),
        ));
    }

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
    apply_optional_port(object, general.port);

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
