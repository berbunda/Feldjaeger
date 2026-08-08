//! Typed inbound client models (Tier‑2: VLESS, Trojan, Hysteria).
//!
//! Tunnel is shell-editable without client mutate.
//! Client mutate is enabled when [`InboundClientProtocol::mutate_enabled`] is true.

mod array_key;
mod fingerprint;
mod hysteria;
mod parse;
mod trojan;
mod vless;
mod write;

use crate::xray::config::editable::InboundLocation;
use crate::xray::config::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::secret::SecretString;

pub use array_key::{
    ClientsArrayKey, resolve_clients_array_key, resolve_or_create_clients_array_key,
};
pub use fingerprint::{
    client_fingerprint, inbound_fingerprint, json_value_fingerprint, verify_client_fingerprint,
    verify_inbound_fingerprint, verify_json_fingerprint,
};
pub use hysteria::HysteriaClient;
pub use parse::parse_inbound_client;
pub use trojan::TrojanClient;
pub use vless::VlessClient;
pub use write::{apply_secret_draft, write_inbound_client};

/// Wire protocol for Tier‑2 inbound clients / shell-editable inbounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InboundClientProtocol {
    /// `protocol: "vless"`.
    Vless,
    /// `protocol: "trojan"`.
    Trojan,
    /// `protocol: "hysteria"` (verify before Lake 3 mutate).
    Hysteria,
    /// `protocol: "tunnel"` (dokodemo-door successor; shell only, no Users).
    Tunnel,
}

impl InboundClientProtocol {
    /// Parse from inbound `protocol` string (case-insensitive).
    ///
    /// Legacy `"dokodemo-door"` is intentionally not mapped (read-only in GUI).
    pub fn from_wire(protocol: &str) -> Option<Self> {
        match protocol.trim().to_ascii_lowercase().as_str() {
            "vless" => Some(Self::Vless),
            "trojan" => Some(Self::Trojan),
            "hysteria" => Some(Self::Hysteria),
            "tunnel" => Some(Self::Tunnel),
            _ => None,
        }
    }

    /// Stable wire string.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Hysteria => "hysteria",
            Self::Tunnel => "tunnel",
        }
    }

    /// Whether mutate (add/update/delete) is enabled for this lake.
    pub fn mutate_enabled(self) -> bool {
        matches!(self, Self::Vless | Self::Trojan | Self::Hysteria)
    }

    /// Whether inbound shell edit (General / Protocol / Sniffing / …) is enabled.
    pub fn shell_edit_enabled(self) -> bool {
        matches!(
            self,
            Self::Vless | Self::Trojan | Self::Hysteria | Self::Tunnel
        )
    }

    /// Error when mutate is attempted before the lake ships.
    pub fn require_mutate_enabled(self) -> ConfigModifyResult<()> {
        if self.mutate_enabled() {
            Ok(())
        } else {
            Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UnsupportedInbound,
                format!(
                    "client editing for {} is not enabled yet",
                    self.as_wire()
                ),
            ))
        }
    }

    /// Error when shell edit is attempted on a non-shell-editable protocol.
    pub fn require_shell_edit_enabled(self) -> ConfigModifyResult<()> {
        if self.shell_edit_enabled() {
            Ok(())
        } else {
            Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UnsupportedInbound,
                format!("shell editing for {} is not supported", self.as_wire()),
            ))
        }
    }
}

/// Typed inbound client (Approach B).
#[derive(Debug, Clone, PartialEq)]
pub enum InboundClient {
    /// VLESS client object.
    Vless(VlessClient),
    /// Trojan client object.
    Trojan(TrojanClient),
    /// Hysteria user object.
    Hysteria(HysteriaClient),
}

impl InboundClient {
    /// Protocol discriminant.
    pub fn protocol(&self) -> InboundClientProtocol {
        match self {
            Self::Vless(_) => InboundClientProtocol::Vless,
            Self::Trojan(_) => InboundClientProtocol::Trojan,
            Self::Hysteria(_) => InboundClientProtocol::Hysteria,
        }
    }
}

/// Required identity for every client mutation (config-dir safe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRef {
    /// Owning inbound location in the editable model.
    pub location: InboundLocation,
    /// Zero-based index inside the inbound clients/users array.
    pub client_index: usize,
    /// Protocol of the parent inbound.
    pub protocol: InboundClientProtocol,
    /// SHA-256 hex of the full canonical client JSON at edit/delete intent.
    pub expected_fingerprint: String,
}

/// Draft for secret fields on edit (Trojan password / Hysteria auth).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretFieldDraft {
    /// Leave the existing JSON value untouched.
    Preserve,
    /// Replace with a non-empty secret.
    Replace(SecretString),
}
