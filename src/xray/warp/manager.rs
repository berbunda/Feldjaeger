//! Cloudflare WARP integration orchestrator.
//!
//! Coordinates the helper, registration, configuration, and connectivity
//! services. [`WarpManager`] never writes Xray's `config.json` itself —
//! [`WarpManager::prepare_managed_outbound`] and
//! [`WarpManager::regenerate_credentials`] return credentials plus a
//! [`WarpProposedChange`] for the application layer's config-modify pipeline
//! to apply after user confirmation.

use feldjaeger_ssh::{RemotePath, SshSession};

use super::configuration::WarpConfigurationService;
use super::connectivity::WarpConnectivityService;
use super::detect::{count_routing_references, detect_warp_outbounds, wireguard_probe};
use super::error::{WarpError, WarpErrorKind, WarpResult};
use super::helper::{WarpHelperInfo, WarpHelperManager};
use super::parse::proposed_change_from_credentials;
use super::registration::WarpRegistrationService;
use super::types::{
    suggest_unique_outbound_tag, WarpConnectivityResult, WarpCredentials, WarpIntegrationState,
    WarpOutboundClassification, WarpOwnershipRecord, WarpProposedChange, WarpSummary,
};
use crate::xray::config::XrayConfigSections;

/// Minimum Xray version known to support the WireGuard outbound protocol.
const MIN_WIREGUARD_XRAY_VERSION: (u64, u64, u64) = (1, 6, 5);

/// Text shown when the detected Xray version may not support WireGuard.
const COMPATIBILITY_WARNING: &str =
    "The installed Xray version may not support this WARP configuration.";

/// Outcome of a successful adoption of an existing Possible WARP outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpAdoptionOutcome {
    /// Ownership record that must be persisted remotely.
    pub ownership: WarpOwnershipRecord,
    /// Safe confirmation summary (no secrets).
    pub summary_line: String,
    /// Outbound tag that will be managed.
    pub outbound_tag: String,
    /// Endpoint shown to the administrator.
    pub endpoint: Option<String>,
    /// Assigned addresses shown to the administrator.
    pub addresses: Vec<String>,
}

/// Plan describing whether a managed WARP outbound may be removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpRemovalPlan {
    /// Tag that would be removed from Xray configuration.
    pub outbound_tag: String,
    /// Routing / config references that currently block removal.
    pub blocking_references: Vec<String>,
}

impl WarpRemovalPlan {
    /// Returns `true` when removal is blocked by configuration references.
    pub fn is_blocked(&self) -> bool {
        !self.blocking_references.is_empty()
    }
}

/// Orchestrates discovery, helper install/remove, registration, and Xray
/// outbound generation for the Cloudflare WARP integration.
#[derive(Debug, Clone, Copy, Default)]
pub struct WarpManager {
    helper: WarpHelperManager,
    registration: WarpRegistrationService,
    configuration: WarpConfigurationService,
    connectivity: WarpConnectivityService,
}

impl WarpManager {
    /// Creates a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read-only discovery: helper state, registration presence, and
    /// classification of any WireGuard outbound already in `sections`.
    pub async fn discover<S: SshSession + Sync>(
        &self,
        session: &S,
        sections: &XrayConfigSections,
        ownership: Option<&WarpOwnershipRecord>,
        xray_version: Option<&str>,
    ) -> WarpResult<WarpSummary> {
        let helper_info = self.helper.discover_helper(session).await?;
        let registration_present = self.registration.registration_exists(session).await?;
        let detected = detect_warp_outbounds(sections, ownership);

        let mut summary = WarpSummary {
            helper_version: helper_info.version.clone(),
            helper_installed: helper_info.installed,
            registration_present,
            xray_version: xray_version.map(str::to_owned),
            ..WarpSummary::default()
        };

        if let Some(outbound) = primary_outbound(&detected) {
            summary.outbound_tag = outbound.tag.clone();
            summary.endpoint = outbound.endpoint.clone();
            summary.addresses = outbound.addresses.clone();
            summary.outbound_classification = Some(outbound.classification);

            if let Some(tag) = &outbound.tag {
                let (count, refs) =
                    count_routing_references(sections.routing_summary().as_ref(), tag);
                summary.routing_reference_count = count;
                summary.routing_references = refs;
            }

            match outbound.classification {
                WarpOutboundClassification::External => summary.warnings.push(
                    "An external WireGuard outbound was detected; Feldjäger will not modify it automatically."
                        .to_owned(),
                ),
                WarpOutboundClassification::PossibleWarp => summary.warnings.push(
                    "A WireGuard outbound resembling Cloudflare WARP was detected but is not Feldjäger-managed."
                        .to_owned(),
                ),
                WarpOutboundClassification::Invalid => summary
                    .warnings
                    .push("A WireGuard outbound is missing required fields.".to_owned()),
                WarpOutboundClassification::Managed | WarpOutboundClassification::Unknown => {}
            }
        }

        summary.state =
            derive_state(helper_info.installed, registration_present, summary.outbound_classification);

        if let Some(version) = xray_version
            && let Some(parsed) = parse_loose_semver(version)
            && parsed < MIN_WIREGUARD_XRAY_VERSION
        {
            summary.compatibility_warning = Some(COMPATIBILITY_WARNING.to_owned());
        }

        Ok(summary)
    }

    /// Downloads, verifies, and installs the pinned helper release.
    pub async fn install_helper<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> WarpResult<WarpSummary> {
        let info = self.helper.install_helper(session).await?;
        Ok(summary_from_helper(info))
    }

    /// Removes only the managed helper binary; never touches registration,
    /// generated outbound files, or the ownership marker.
    pub async fn remove_helper_only<S: SshSession + Sync>(&self, session: &S) -> WarpResult<()> {
        self.helper.remove_helper(session).await
    }

    /// Explicitly adopts an existing Possible WARP outbound without regenerating credentials.
    ///
    /// Validates required WireGuard fields and builds an ownership record.
    /// Does not write Xray config or ownership until the application layer
    /// persists them after confirmation.
    pub fn prepare_adoption(
        &self,
        sections: &XrayConfigSections,
        outbound_tag: &str,
        helper_version: Option<&str>,
    ) -> WarpResult<WarpAdoptionOutcome> {
        let tag = outbound_tag.trim();
        if tag.is_empty() {
            return Err(WarpError::new(
                WarpErrorKind::ManagedOutboundMissing,
                "outbound tag must not be empty",
            ));
        }

        let outbound = sections
            .outbounds()
            .iter()
            .find(|entry| {
                entry
                    .value()
                    .get("tag")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|existing| existing.eq_ignore_ascii_case(tag))
            })
            .ok_or_else(|| {
                WarpError::new(
                    WarpErrorKind::ManagedOutboundMissing,
                    format!("outbound tag not found: {tag}"),
                )
            })?;

        let probe = wireguard_probe(outbound.value());
        if !probe.structurally_valid {
            return Err(WarpError::new(
                WarpErrorKind::GeneratedConfigurationInvalid,
                "WireGuard outbound is missing required fields",
            ));
        }

        let ownership = WarpOwnershipRecord {
            outbound_tag: tag.to_owned(),
            managed: true,
            helper_version: helper_version.map(str::to_owned),
        };

        Ok(WarpAdoptionOutcome {
            ownership,
            summary_line: format!(
                "Adopt outbound `{tag}` (endpoint={}; addresses={})",
                probe.endpoint.as_deref().unwrap_or("—"),
                if probe.addresses.is_empty() {
                    "—".to_owned()
                } else {
                    probe.addresses.join(",")
                }
            ),
            outbound_tag: tag.to_owned(),
            endpoint: probe.endpoint,
            addresses: probe.addresses,
        })
    }

    /// Builds a removal plan for a Feldjäger-managed WARP outbound.
    ///
    /// When routing references exist, [`WarpRemovalPlan::is_blocked`] is true
    /// and the caller must not delete the outbound.
    pub fn plan_remove_managed_outbound(
        &self,
        sections: &XrayConfigSections,
        ownership: &WarpOwnershipRecord,
    ) -> WarpResult<WarpRemovalPlan> {
        if !ownership.managed {
            return Err(WarpError::new(
                WarpErrorKind::ManagedOutboundMissing,
                "ownership marker does not mark a managed WARP outbound",
            ));
        }

        let tag = ownership.outbound_tag.trim();
        if tag.is_empty() {
            return Err(WarpError::new(
                WarpErrorKind::ManagedOutboundMissing,
                "managed outbound tag is empty",
            ));
        }

        let exists = sections.outbounds().iter().any(|entry| {
            entry
                .value()
                .get("tag")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|existing| existing.eq_ignore_ascii_case(tag))
        });
        if !exists {
            return Err(WarpError::new(
                WarpErrorKind::ManagedOutboundMissing,
                format!("managed outbound tag not found: {tag}"),
            ));
        }

        let (_count, refs) = count_routing_references(sections.routing_summary().as_ref(), tag);
        Ok(WarpRemovalPlan {
            outbound_tag: tag.to_owned(),
            blocking_references: refs,
        })
    }

    /// Registers a device (if needed) and generates Xray outbound
    /// credentials, returning them alongside a proposed outbound change.
    ///
    /// Does not write `config.json` — the caller applies the change.
    pub async fn prepare_managed_outbound<S: SshSession + Sync>(
        &self,
        session: &S,
        existing_tags: &[String],
        preferred_tag: &str,
        force_register: bool,
    ) -> WarpResult<(WarpCredentials, WarpProposedChange)> {
        let helper_info = self.helper.discover_helper(session).await?;
        let helper_path = helper_info.path.ok_or_else(|| {
            WarpError::new(
                WarpErrorKind::HelperMissing,
                "install the WARP helper before registering",
            )
        })?;

        self.registration
            .register(session, &helper_path, force_register)
            .await?;
        let credentials = self
            .configuration
            .generate_xray_outbound(session, &helper_path)
            .await?;
        let tag = suggest_unique_outbound_tag(existing_tags, preferred_tag);
        let proposed = proposed_change_from_credentials(&credentials, &tag);
        Ok((credentials, proposed))
    }

    /// Re-registers (backing up the previous registration first) and
    /// regenerates Xray outbound credentials for `outbound_tag`.
    ///
    /// On register/generate failure after the backup, the previous
    /// registration is restored automatically. The backup path is also
    /// returned so callers can restore if a later config write fails.
    pub async fn regenerate_credentials<S: SshSession + Sync>(
        &self,
        session: &S,
        outbound_tag: &str,
        force: bool,
    ) -> WarpResult<(WarpCredentials, WarpProposedChange, Option<RemotePath>)> {
        let helper_info = self.helper.discover_helper(session).await?;
        let helper_path = helper_info.path.ok_or_else(|| {
            WarpError::new(
                WarpErrorKind::HelperMissing,
                "WARP helper is not installed",
            )
        })?;

        let backup = self.registration.backup_registration(session).await?;

        if let Err(error) = self
            .registration
            .register(session, &helper_path, force)
            .await
        {
            self.restore_backup_best_effort(session, backup.as_ref())
                .await;
            return Err(error);
        }

        match self
            .configuration
            .generate_xray_outbound(session, &helper_path)
            .await
        {
            Ok(credentials) => {
                let proposed = proposed_change_from_credentials(&credentials, outbound_tag);
                Ok((credentials, proposed, backup))
            }
            Err(error) => {
                self.restore_backup_best_effort(session, backup.as_ref())
                    .await;
                Err(error)
            }
        }
    }

    /// Restores a registration backup produced during regenerate/setup.
    pub async fn restore_registration_backup<S: SshSession + Sync>(
        &self,
        session: &S,
        backup_path: &RemotePath,
    ) -> WarpResult<()> {
        self.registration
            .restore_registration_backup(session, backup_path)
            .await
    }

    /// Runs the (always unavailable) outbound-specific test plus a safe
    /// endpoint-reachability probe.
    pub async fn test_connectivity<S: SshSession + Sync>(
        &self,
        session: &S,
        outbound_tag: Option<&str>,
    ) -> WarpResult<WarpConnectivityResult> {
        self.connectivity
            .test_connectivity(session, outbound_tag)
            .await
    }

    /// Reads the ownership marker, when present.
    pub async fn read_ownership<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> WarpResult<Option<WarpOwnershipRecord>> {
        self.configuration.read_ownership(session).await
    }

    /// Writes the ownership marker.
    pub async fn write_ownership<S: SshSession + Sync>(
        &self,
        session: &S,
        record: &WarpOwnershipRecord,
    ) -> WarpResult<()> {
        self.configuration.write_ownership(session, record).await
    }

    async fn restore_backup_best_effort<S: SshSession + Sync>(
        &self,
        session: &S,
        backup: Option<&feldjaeger_ssh::RemotePath>,
    ) {
        if let Some(backup_path) = backup {
            let _ = self
                .registration
                .restore_registration_backup(session, backup_path)
                .await;
        }
    }
}

fn summary_from_helper(info: WarpHelperInfo) -> WarpSummary {
    WarpSummary {
        state: if info.installed {
            WarpIntegrationState::RegistrationMissing
        } else {
            WarpIntegrationState::HelperMissing
        },
        helper_installed: info.installed,
        helper_version: info.version,
        ..WarpSummary::default()
    }
}

fn primary_outbound(
    detected: &[super::detect::DetectedWarpOutbound],
) -> Option<&super::detect::DetectedWarpOutbound> {
    detected
        .iter()
        .find(|outbound| outbound.classification == WarpOutboundClassification::Managed)
        .or_else(|| {
            detected
                .iter()
                .find(|outbound| outbound.classification == WarpOutboundClassification::PossibleWarp)
        })
        .or_else(|| {
            detected
                .iter()
                .find(|outbound| outbound.classification == WarpOutboundClassification::External)
        })
        .or_else(|| detected.first())
}

fn derive_state(
    helper_installed: bool,
    registration_present: bool,
    classification: Option<WarpOutboundClassification>,
) -> WarpIntegrationState {
    // A pre-existing outbound's classification reflects reality regardless of
    // Feldjäger's own helper/registration state, so it takes priority.
    match classification {
        Some(WarpOutboundClassification::External)
        | Some(WarpOutboundClassification::PossibleWarp) => {
            return WarpIntegrationState::External;
        }
        Some(WarpOutboundClassification::Invalid) => return WarpIntegrationState::Invalid,
        Some(WarpOutboundClassification::Managed)
        | Some(WarpOutboundClassification::Unknown)
        | None => {}
    }

    if !helper_installed {
        return WarpIntegrationState::HelperMissing;
    }
    if !registration_present {
        return WarpIntegrationState::RegistrationMissing;
    }
    match classification {
        Some(WarpOutboundClassification::Managed) => WarpIntegrationState::Configured,
        _ => WarpIntegrationState::ConfigurationMissing,
    }
}

/// Loosely parses a leading `major.minor.patch` from a free-form version
/// string (e.g. `"Xray 25.7.1"`, `"v1.6.4"`). Returns `None` when no digits
/// are found at all.
fn parse_loose_semver(text: &str) -> Option<(u64, u64, u64)> {
    let start = text.find(|c: char| c.is_ascii_digit())?;
    let rest = &text[start..];
    let mut parts = rest.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor, patch))
}
