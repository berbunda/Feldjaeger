//! Hysteria inbound user model.

use serde_json::{Map, Value};

use crate::xray::secret::SecretString;

/// Typed Hysteria user with unknown fields preserved in `extras`.
///
/// Official docs: `auth`, `email`, `level`.
#[derive(Clone, PartialEq)]
pub struct HysteriaClient {
    /// Per-user auth string (secret).
    pub auth: SecretString,
    /// Stats / log email.
    pub email: Option<String>,
    /// Policy level (default 0).
    pub level: u32,
    /// Unknown object keys preserved on write-back.
    pub extras: Map<String, Value>,
}

impl HysteriaClient {
    /// Known JSON keys handled by this type.
    pub const KNOWN_KEYS: &'static [&'static str] = &["auth", "email", "level"];
}

impl std::fmt::Debug for HysteriaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysteriaClient")
            .field("auth", &self.auth)
            .field("email", &self.email)
            .field("level", &self.level)
            .field("extras", &self.extras)
            .finish()
    }
}
