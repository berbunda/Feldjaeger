//! VLESS inbound client model.

use serde_json::{Map, Value};

/// Typed VLESS client with unknown fields preserved in `extras`.
#[derive(Debug, Clone, PartialEq)]
pub struct VlessClient {
    /// Client `id` (UUID or custom string).
    pub id: String,
    /// Stats / log email.
    pub email: Option<String>,
    /// Optional XTLS flow.
    pub flow: Option<String>,
    /// Policy level (default 0).
    pub level: u32,
    /// Unknown object keys preserved on write-back.
    pub extras: Map<String, Value>,
}

impl VlessClient {
    /// Known JSON keys handled by this type (not stored in extras).
    pub const KNOWN_KEYS: &'static [&'static str] = &["id", "email", "flow", "level"];
}
