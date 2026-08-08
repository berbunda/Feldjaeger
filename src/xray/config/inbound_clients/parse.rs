//! Parse inbound client JSON into typed models + extras.

use serde_json::{Map, Value};

use crate::xray::config::inbound_clients::{
    HysteriaClient, InboundClient, InboundClientProtocol, TrojanClient, VlessClient,
};
use crate::xray::config::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::secret::SecretString;

/// Parses one client object for the given protocol.
pub fn parse_inbound_client(
    protocol: InboundClientProtocol,
    value: &Value,
) -> ConfigModifyResult<InboundClient> {
    let object = value.as_object().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "client entry must be a JSON object".to_owned(),
        )
    })?;

    match protocol {
        InboundClientProtocol::Vless => Ok(InboundClient::Vless(parse_vless(object)?)),
        InboundClientProtocol::Trojan => Ok(InboundClient::Trojan(parse_trojan(object)?)),
        InboundClientProtocol::Hysteria => Ok(InboundClient::Hysteria(parse_hysteria(object)?)),
        InboundClientProtocol::Tunnel => Err(ConfigModifyError::new(
            ConfigModifyErrorKind::UnsupportedInbound,
            "Tunnel inbound has no client objects".to_owned(),
        )),
    }
}

fn parse_vless(object: &Map<String, Value>) -> ConfigModifyResult<VlessClient> {
    let id = required_string(object, "id")?;
    let email = optional_string(object, "email");
    let flow = optional_string(object, "flow");
    let level = optional_level(object)?;
    let extras = extras_map(object, VlessClient::KNOWN_KEYS);
    Ok(VlessClient {
        id,
        email,
        flow,
        level,
        extras,
    })
}

fn parse_trojan(object: &Map<String, Value>) -> ConfigModifyResult<TrojanClient> {
    let password = SecretString::new(required_string(object, "password")?);
    let email = optional_string(object, "email");
    let level = optional_level(object)?;
    let extras = extras_map(object, TrojanClient::KNOWN_KEYS);
    Ok(TrojanClient {
        password,
        email,
        level,
        extras,
    })
}

fn parse_hysteria(object: &Map<String, Value>) -> ConfigModifyResult<HysteriaClient> {
    let auth = SecretString::new(required_string(object, "auth")?);
    let email = optional_string(object, "email");
    let level = optional_level(object)?;
    let extras = extras_map(object, HysteriaClient::KNOWN_KEYS);
    Ok(HysteriaClient {
        auth,
        email,
        level,
        extras,
    })
}

fn required_string(object: &Map<String, Value>, key: &str) -> ConfigModifyResult<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("client.{key} must be a non-empty string"),
            )
        })
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
}

fn optional_level(object: &Map<String, Value>) -> ConfigModifyResult<u32> {
    match object.get("level") {
        None => Ok(0),
        Some(Value::Null) => Ok(0),
        Some(Value::Number(number)) => number.as_u64().map(|n| n as u32).ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "client.level must be a non-negative integer".to_owned(),
            )
        }),
        Some(_) => Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "client.level must be a number".to_owned(),
        )),
    }
}

fn extras_map(object: &Map<String, Value>, known: &[&str]) -> Map<String, Value> {
    object
        .iter()
        .filter(|(key, _)| !known.iter().any(|known_key| known_key == key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}
