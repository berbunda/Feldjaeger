//! Shared types for Cloudflare WARP (Xray WireGuard outbound) integration.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::xray::secret::SecretString;

/// Well-known Cloudflare WARP WireGuard peer public key (not a secret).
pub const CLOUDFLARE_WARP_PEER_PUBLIC_KEY: &str =
    "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

/// Default outbound tag proposed for a new managed WARP outbound.
pub const DEFAULT_WARP_OUTBOUND_TAG: &str = "warp";

/// Managed tools directory on the remote Linux host.
pub const MANAGED_TOOLS_DIR: &str = "/usr/local/lib/feldjaeger/tools";

/// Managed WARP state directory (credentials + ownership marker).
pub const MANAGED_WARP_DIR: &str = "/usr/local/lib/feldjaeger/warp";

/// Helper executable file name inside [`MANAGED_TOOLS_DIR`].
pub const HELPER_FILE_NAME: &str = "wgcf-cli";

/// Registration account file produced by `wgcf-cli register`.
pub const REGISTRATION_FILE_NAME: &str = "wgcf.json";

/// Generated Xray outbound file produced by `wgcf-cli generate --xray`.
pub const GENERATED_XRAY_FILE_NAME: &str = "wgcf.xray.json";

/// Ownership marker file (non-secret) stored next to registration data.
pub const OWNERSHIP_FILE_NAME: &str = "ownership.json";

/// Pinned approved helper release tag (ArchiveNetwork/wgcf-cli).
pub const APPROVED_HELPER_VERSION: &str = "v0.3.6";

/// GitHub release base URL for the pinned helper version.
pub const HELPER_RELEASE_BASE_URL: &str =
    "https://github.com/ArchiveNetwork/wgcf-cli/releases/download/v0.3.6";

/// High-level WARP integration state for discovery and GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WarpIntegrationState {
    /// No managed WARP outbound and no usable helper/registration.
    #[default]
    NotConfigured,
    /// Approved helper is missing from the managed tools directory.
    HelperMissing,
    /// Helper present; registration data missing.
    RegistrationMissing,
    /// Registration present; Xray outbound missing.
    ConfigurationMissing,
    /// Managed outbound present in Xray configuration.
    Configured,
    /// Last connectivity probe reported WARP active.
    Connected,
    /// Last connectivity probe failed.
    ConnectionFailed,
    /// Managed outbound exists but required WireGuard fields are invalid.
    Invalid,
    /// Compatible WireGuard outbound exists but is not Feldjäger-managed.
    External,
    /// State could not be classified.
    Unknown,
}

impl WarpIntegrationState {
    /// Stable English label for Status / GUI.
    pub fn label(self) -> &'static str {
        match self {
            Self::NotConfigured => "Not configured",
            Self::HelperMissing => "Helper not installed",
            Self::RegistrationMissing => "Ready to register",
            Self::ConfigurationMissing => "Registration present",
            Self::Configured => "Configured",
            Self::Connected => "Connected",
            Self::ConnectionFailed => "Connection failed",
            Self::Invalid => "Invalid configuration",
            Self::External => "External WARP outbound detected",
            Self::Unknown => "Unknown",
        }
    }
}

/// Classification of a WireGuard / possible-WARP outbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarpOutboundClassification {
    /// Feldjäger-managed WARP outbound (local/remote ownership metadata).
    Managed,
    /// Explicitly external WireGuard outbound (must not be mutated silently).
    External,
    /// Looks like Cloudflare WARP but is not owned by Feldjäger.
    PossibleWarp,
    /// WireGuard outbound missing required fields.
    Invalid,
    /// Not classifiable as WARP-related.
    Unknown,
}

impl WarpOutboundClassification {
    /// Stable English label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Managed => "Managed",
            Self::External => "External",
            Self::PossibleWarp => "Possible WARP",
            Self::Invalid => "Invalid",
            Self::Unknown => "Unknown",
        }
    }
}

/// Parsed WARP WireGuard credentials (never logged in full).
#[derive(Clone, PartialEq, Eq)]
pub struct WarpCredentials {
    /// WireGuard private key (`secretKey`).
    pub private_key: SecretString,
    /// Peer public key.
    pub peer_public_key: String,
    /// Assigned interface addresses (IPv4 / IPv6 CIDRs).
    pub addresses: Vec<String>,
    /// Peer endpoint `host:port`.
    pub endpoint: String,
    /// Optional WireGuard reserved bytes.
    pub reserved: Option<Vec<u8>>,
    /// Optional MTU.
    pub mtu: Option<u32>,
    /// Optional domain strategy from the generated outbound.
    pub domain_strategy: Option<String>,
    /// Full generated outbound JSON value (preserves unknown supported fields).
    pub outbound_value: Value,
}

impl fmt::Debug for WarpCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WarpCredentials")
            .field("private_key", &self.private_key)
            .field("peer_public_key", &self.peer_public_key)
            .field("addresses", &self.addresses)
            .field("endpoint", &self.endpoint)
            .field("reserved", &self.reserved.as_ref().map(|_| "[PRESENT]"))
            .field("mtu", &self.mtu)
            .field("domain_strategy", &self.domain_strategy)
            .field("outbound_value", &"[REDACTED]")
            .finish()
    }
}

/// Non-secret ownership record persisted locally and/or on the remote host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpOwnershipRecord {
    /// Outbound tag owned by Feldjäger for this host.
    pub outbound_tag: String,
    /// Whether Feldjäger currently manages this outbound.
    pub managed: bool,
    /// Optional helper version recorded at last successful setup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_version: Option<String>,
}

/// Safe summary for GUI / Status (never includes private keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpSummary {
    /// Coarse integration state.
    pub state: WarpIntegrationState,
    /// Detected helper version when installed.
    pub helper_version: Option<String>,
    /// Whether the approved helper binary exists in the managed tools dir.
    pub helper_installed: bool,
    /// Whether remote registration data exists under the managed WARP dir.
    pub registration_present: bool,
    /// Managed / proposed outbound tag.
    pub outbound_tag: Option<String>,
    /// Peer endpoint when known.
    pub endpoint: Option<String>,
    /// Assigned addresses when known (no secrets).
    pub addresses: Vec<String>,
    /// Classification of the primary related outbound, when any.
    pub outbound_classification: Option<WarpOutboundClassification>,
    /// Number of routing rules referencing the outbound tag.
    pub routing_reference_count: usize,
    /// Human-readable routing reference summaries (rule index + criteria).
    pub routing_references: Vec<String>,
    /// Non-fatal warnings safe for UI.
    pub warnings: Vec<String>,
    /// Whether Xray restart is recommended after the last mutating op.
    pub restart_recommended: bool,
    /// Last connectivity result label, when a test was run.
    pub connectivity_status: Option<String>,
    /// Whether IPv4 appeared available in the last test (when known).
    pub ipv4_available: Option<bool>,
    /// Whether IPv6 appeared available in the last test (when known).
    pub ipv6_available: Option<bool>,
    /// Whether Cloudflare reported WARP active in the last test (when known).
    pub warp_active: Option<bool>,
    /// Observed public IP from a diagnostic (never a secret).
    pub observed_public_ip: Option<String>,
    /// Outbound-specific test availability note.
    pub connectivity_note: Option<String>,
    /// Remote OS / arch labels when probed.
    pub remote_os: Option<String>,
    /// Remote architecture when probed.
    pub remote_arch: Option<String>,
    /// Xray version string when known from discovery.
    pub xray_version: Option<String>,
    /// Compatibility warning when WireGuard support is uncertain.
    pub compatibility_warning: Option<String>,
}

impl Default for WarpSummary {
    fn default() -> Self {
        Self {
            state: WarpIntegrationState::NotConfigured,
            helper_version: None,
            helper_installed: false,
            registration_present: false,
            outbound_tag: None,
            endpoint: None,
            addresses: Vec::new(),
            outbound_classification: None,
            routing_reference_count: 0,
            routing_references: Vec::new(),
            warnings: Vec::new(),
            restart_recommended: false,
            connectivity_status: None,
            ipv4_available: None,
            ipv6_available: None,
            warp_active: None,
            observed_public_ip: None,
            connectivity_note: None,
            remote_os: None,
            remote_arch: None,
            xray_version: None,
            compatibility_warning: None,
        }
    }
}

/// Result of a WARP connectivity probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpConnectivityResult {
    /// Whether the probe could run at all.
    pub available: bool,
    /// High-level status text (`Connected`, `Connection failed`, …).
    pub status: String,
    /// Cloudflare `warp=` field when parsed (`on` / `plus` / `off`).
    pub warp_active: Option<bool>,
    /// IPv4 reachability through the probe path when known.
    pub ipv4_available: Option<bool>,
    /// IPv6 reachability through the probe path when known.
    pub ipv6_available: Option<bool>,
    /// Observed public IP when safely extracted.
    pub observed_public_ip: Option<String>,
    /// Extra note (e.g. outbound-specific test unavailable).
    pub note: Option<String>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

/// Proposed outbound change shown before commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpProposedChange {
    /// Outbound tag that will be written.
    pub outbound_tag: String,
    /// Endpoint summary (no private key).
    pub endpoint: String,
    /// Assigned addresses.
    pub addresses: Vec<String>,
    /// Whether `reserved` is present.
    pub has_reserved: bool,
    /// Optional MTU.
    pub mtu: Option<u32>,
    /// Redacted one-line summary for confirmation UI.
    pub summary_line: String,
}

/// Maps remote `uname -m` to a wgcf-cli Linux asset stem.
pub fn helper_asset_stem_for_arch(uname_m: &str) -> Option<&'static str> {
    match uname_m.trim() {
        "x86_64" | "amd64" => Some("wgcf-cli-linux-64"),
        "aarch64" | "arm64" => Some("wgcf-cli-linux-arm64-v8a"),
        "armv7l" | "armv7" => Some("wgcf-cli-linux-arm32-v7a"),
        "i386" | "i686" => Some("wgcf-cli-linux-32"),
        _ => None,
    }
}

/// Returns `true` when an endpoint string looks Cloudflare-related.
pub fn endpoint_looks_like_cloudflare(endpoint: &str) -> bool {
    let lower = endpoint.to_ascii_lowercase();
    lower.contains("cloudflare") || lower.contains("engage.cloudflareclient.com")
}

/// Returns `true` when a tag name is a WARP hint (not proof).
pub fn tag_looks_like_warp_hint(tag: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    lower == "warp"
        || lower == "warp-out"
        || lower == "cloudflare"
        || lower.starts_with("warp-")
        || lower.starts_with("warp_")
}

/// Suggests a unique outbound tag given existing tags.
pub fn suggest_unique_outbound_tag(existing: &[String], preferred: &str) -> String {
    let preferred = preferred.trim();
    let base = if preferred.is_empty() {
        DEFAULT_WARP_OUTBOUND_TAG
    } else {
        preferred
    };
    if !tag_taken(existing, base) {
        return base.to_owned();
    }
    let mut index = 2u32;
    loop {
        let candidate = format!("{base}-{index}");
        if !tag_taken(existing, &candidate) {
            return candidate;
        }
        index = index.saturating_add(1);
        if index > 10_000 {
            return format!("{base}-{}", uuid_like_suffix());
        }
    }
}

fn tag_taken(existing: &[String], tag: &str) -> bool {
    existing
        .iter()
        .any(|item| item.eq_ignore_ascii_case(tag))
}

fn uuid_like_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", nanos % 0xffff)
}
