//! Serialize typed inbound clients back to JSON (preserve extras).

use serde_json::{Map, Value};

use crate::xray::config::inbound_clients::{
    HysteriaClient, InboundClient, TrojanClient, VlessClient, SecretFieldDraft,
};
use crate::xray::secret::SecretString;

/// Writes a typed client to a JSON object (known fields + extras).
pub fn write_inbound_client(client: &InboundClient) -> Value {
    match client {
        InboundClient::Vless(client) => write_vless(client),
        InboundClient::Trojan(client) => write_trojan(client),
        InboundClient::Hysteria(client) => write_hysteria(client),
    }
}

fn write_vless(client: &VlessClient) -> Value {
    let mut object = Map::new();
    object.insert("id".to_owned(), Value::String(client.id.clone()));
    if let Some(email) = &client.email {
        object.insert("email".to_owned(), Value::String(email.clone()));
    }
    if let Some(flow) = &client.flow {
        if !flow.trim().is_empty() {
            object.insert("flow".to_owned(), Value::String(flow.clone()));
        }
    }
    if client.level != 0 {
        object.insert("level".to_owned(), Value::Number(client.level.into()));
    }
    merge_extras(&mut object, &client.extras);
    Value::Object(object)
}

fn write_trojan(client: &TrojanClient) -> Value {
    let mut object = Map::new();
    object.insert(
        "password".to_owned(),
        Value::String(client.password.expose().to_owned()),
    );
    if let Some(email) = &client.email {
        object.insert("email".to_owned(), Value::String(email.clone()));
    }
    if client.level != 0 {
        object.insert("level".to_owned(), Value::Number(client.level.into()));
    }
    // Never write flow onto Trojan.
    merge_extras(&mut object, &client.extras);
    object.remove("flow");
    Value::Object(object)
}

fn write_hysteria(client: &HysteriaClient) -> Value {
    let mut object = Map::new();
    object.insert(
        "auth".to_owned(),
        Value::String(client.auth.expose().to_owned()),
    );
    if let Some(email) = &client.email {
        object.insert("email".to_owned(), Value::String(email.clone()));
    }
    if client.level != 0 {
        object.insert("level".to_owned(), Value::Number(client.level.into()));
    }
    merge_extras(&mut object, &client.extras);
    Value::Object(object)
}

fn merge_extras(object: &mut Map<String, Value>, extras: &Map<String, Value>) {
    for (key, value) in extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
}

/// Applies a secret draft onto an existing secret.
pub fn apply_secret_draft(current: &SecretString, draft: SecretFieldDraft) -> SecretString {
    match draft {
        SecretFieldDraft::Preserve => current.clone(),
        SecretFieldDraft::Replace(secret) => secret,
    }
}
