//! Inbound shell edit (D027 Lake 1: General + Sniffing).
//!
//! Mutates top-level inbound fields and `sniffing` in place. Never rewrites
//! opaque `settings` / `streamSettings` / `allocate` objects.

mod general;
mod listen;
mod sniffing;

use crate::xray::config::editable::InboundLocation;
use crate::xray::config::inbound_clients::InboundClientProtocol;

pub use general::{InboundGeneral, apply_inbound_general, parse_inbound_general, port_is_shell_editable};
pub use listen::validate_listen_address;
pub use sniffing::{
    KNOWN_DEST_OVERRIDE, SniffingSettings, SniffingWriteOutcome, apply_inbound_sniffing,
    parse_sniffing_settings, sniffing_is_absent_defaults,
};

/// Identity for inbound shell mutations (config-dir safe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRef {
    /// Owning inbound location in the editable model.
    pub location: InboundLocation,
    /// Protocol of the inbound (must be shell-editable Tier‑2).
    pub protocol: InboundClientProtocol,
    /// SHA-256 hex of the full canonical inbound JSON at edit intent.
    pub expected_fingerprint: String,
}
