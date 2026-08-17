//! VLESS inbound client model.

use serde_json::{Map, Value};

use crate::xray::config::reverse_proxy::ReverseTagDraft;

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
    /// Portal-side VLESS-native reverse proxy registration (Roadmap §2.1:58): declares this
    /// client as the public-facing outbound pool for a bridge. `None` = ordinary client.
    /// <https://xtls.github.io/en/document/level-2/vless_reverse.html>
    pub reverse: Option<ReverseTagDraft>,
    /// Unknown object keys preserved on write-back.
    pub extras: Map<String, Value>,
}

impl VlessClient {
    /// Known JSON keys handled by this type (not stored in extras).
    pub const KNOWN_KEYS: &'static [&'static str] = &["id", "email", "flow", "level", "reverse"];
}
