//! Deterministic `settings.clients` / `settings.users` key resolution.

use serde_json::Value;

use crate::xray::config::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::config::inbound_clients::InboundClientProtocol;

/// Which array key holds inbound clients/users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientsArrayKey {
    /// Classic / widely deployed key.
    Clients,
    /// Official docs key for some protocols (VLESS UserObject, Hysteria users).
    Users,
}

impl ClientsArrayKey {
    /// Wire field name under `settings`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clients => "clients",
            Self::Users => "users",
        }
    }
}

/// Resolve the array key for an existing inbound.
///
/// Both `clients` and `users` present → [`ConfigModifyErrorKind::AmbiguousClientsArray`].
pub fn resolve_clients_array_key(inbound: &Value) -> ConfigModifyResult<Option<ClientsArrayKey>> {
    let Some(settings) = inbound.get("settings") else {
        return Ok(None);
    };
    let has_clients = settings.get("clients").and_then(Value::as_array).is_some();
    let has_users = settings.get("users").and_then(Value::as_array).is_some();
    match (has_clients, has_users) {
        (true, true) => Err(ConfigModifyError::new(
            ConfigModifyErrorKind::AmbiguousClientsArray,
            "inbound settings contain both clients and users arrays".to_owned(),
        )),
        (true, false) => Ok(Some(ClientsArrayKey::Clients)),
        (false, true) => Ok(Some(ClientsArrayKey::Users)),
        (false, false) => Ok(None),
    }
}

/// Resolve key for mutation, creating a default when neither array exists.
pub fn resolve_or_create_clients_array_key(
    inbound: &Value,
    protocol: InboundClientProtocol,
) -> ConfigModifyResult<ClientsArrayKey> {
    match resolve_clients_array_key(inbound)? {
        Some(key) => Ok(key),
        None => Ok(default_create_key(protocol)),
    }
}

fn default_create_key(protocol: InboundClientProtocol) -> ClientsArrayKey {
    match protocol {
        InboundClientProtocol::Hysteria => ClientsArrayKey::Users,
        InboundClientProtocol::Vless
        | InboundClientProtocol::Trojan
        | InboundClientProtocol::Tunnel => ClientsArrayKey::Clients,
    }
}
