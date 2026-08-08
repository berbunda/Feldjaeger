//! Trojan inbound client model (types in Lake 1; mutate in Lake 2).

use serde_json::{Map, Value};

use crate::xray::secret::SecretString;

/// Typed Trojan client with unknown fields preserved in `extras`.
#[derive(Clone, PartialEq)]
pub struct TrojanClient {
    /// Auth password (secret).
    pub password: SecretString,
    /// Stats / log email.
    pub email: Option<String>,
    /// Policy level (default 0).
    pub level: u32,
    /// Unknown object keys preserved on write-back.
    pub extras: Map<String, Value>,
}

impl TrojanClient {
    /// Known JSON keys handled by this type.
    pub const KNOWN_KEYS: &'static [&'static str] = &["password", "email", "level"];
}

impl std::fmt::Debug for TrojanClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanClient")
            .field("password", &self.password)
            .field("email", &self.email)
            .field("level", &self.level)
            .field("extras", &self.extras)
            .finish()
    }
}
