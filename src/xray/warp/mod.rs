//! Cloudflare WARP (Xray WireGuard outbound) integration.
//!
//! Manages the approved `wgcf-cli` helper binary, Cloudflare WARP device
//! registration, generated Xray outbound credentials, and a non-secret
//! ownership marker on a Linux remote host over SSH.
//!
//! This module never writes Xray's `config.json`. [`WarpManager::discover`]
//! is read-only; [`WarpManager::prepare_managed_outbound`] and
//! [`WarpManager::regenerate_credentials`] return [`WarpCredentials`] plus a
//! [`WarpProposedChange`] (and a registration backup path for regenerate)
//! for the application layer's configuration-modify pipeline to apply after
//! user confirmation.

mod configuration;
mod connectivity;
mod detect;
mod error;
mod helper;
mod manager;
mod parse;
mod registration;
mod remote;
#[cfg(test)]
mod tests;
mod types;

pub use configuration::WarpConfigurationService;
pub use connectivity::WarpConnectivityService;
pub use detect::{
    classify_wireguard_outbound, count_routing_references, detect_warp_outbounds, wireguard_probe,
    DetectedWarpOutbound, WireguardProbe,
};
pub use error::{WarpError, WarpErrorKind, WarpResult};
pub use helper::{WarpHelperInfo, WarpHelperManager};
pub use manager::{WarpAdoptionOutcome, WarpManager, WarpRemovalPlan};
pub use parse::{
    outbound_value_with_tag, parse_generated_xray_outbound, parse_generated_xray_value,
    peer_is_cloudflare_warp, proposed_change_from_credentials,
};
pub use registration::{WarpRegistrationOutcome, WarpRegistrationService};
pub use types::{
    endpoint_looks_like_cloudflare, helper_asset_stem_for_arch, suggest_unique_outbound_tag,
    tag_looks_like_warp_hint, SecretString, WarpConnectivityResult, WarpCredentials,
    WarpIntegrationState, WarpOutboundClassification, WarpOwnershipRecord, WarpProposedChange,
    WarpSummary, APPROVED_HELPER_VERSION, CLOUDFLARE_WARP_PEER_PUBLIC_KEY,
    DEFAULT_WARP_OUTBOUND_TAG, GENERATED_XRAY_FILE_NAME, HELPER_FILE_NAME,
    HELPER_RELEASE_BASE_URL, MANAGED_TOOLS_DIR, MANAGED_WARP_DIR, OWNERSHIP_FILE_NAME,
    REGISTRATION_FILE_NAME,
};
