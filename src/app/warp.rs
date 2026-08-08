//! Cloudflare WARP page model and async workers for [`super::ApplicationService`].
//!
//! GUI never builds shell commands, parses raw Xray JSON, or touches SSH.
//! All remote work goes through [`WarpManager`] and the shared config-modify
//! pipeline.

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::{error, info, warn};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::app::status::SshStatus;
use crate::logging::redact::{sanitize_detail, user_message_see_log};
use crate::remote::RemoteAdmin;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    add_outbound, outbound_value_with_tag, remove_outbound, replace_outbound, AddOutboundRequest,
    DiscoveryState, EditableXrayConfig, RemoveOutboundRequest, ReplaceOutboundRequest,
    WarpConnectivityResult, WarpCredentials, WarpError, WarpErrorKind, WarpIntegrationState,
    WarpManager, WarpOutboundClassification, WarpOwnershipRecord, WarpProposedChange,
    WarpRemovalPlan, WarpSummary, DEFAULT_WARP_OUTBOUND_TAG,
};

use super::warp_ops::{
    apply_add_outbound, apply_remove_outbound, apply_replace_outbound, map_config_error_to_warp,
    WarpConfigWriteSuccess,
};

/// Async Cloudflare WARP operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarpOperation {
    /// Read-only discovery refresh.
    Discover,
    /// Install / update the approved helper.
    InstallHelper,
    /// Full managed setup: register → generate → write outbound → ownership.
    Setup,
    /// Adopt an existing Possible WARP outbound.
    Adopt,
    /// Outbound-scoped connectivity probe (may report unavailable).
    TestConnectivity,
    /// Regenerate credentials and replace managed outbound settings.
    Regenerate,
    /// Remove Feldjäger-managed WARP outbound (+ ownership).
    RemoveIntegration,
    /// Remove only the managed helper binary.
    RemoveHelper,
}

impl WarpOperation {
    /// Status Bar text while the operation runs.
    pub fn status_message(self) -> &'static str {
        match self {
            Self::Discover => "Checking WARP integration...",
            Self::InstallHelper => "Installing WARP helper...",
            Self::Setup => "Registering WARP device...",
            Self::Adopt => "Adopting WARP outbound...",
            Self::TestConnectivity => "Testing WARP connectivity...",
            Self::Regenerate => "Generating Xray outbound...",
            Self::RemoveIntegration => "Removing WARP integration...",
            Self::RemoveHelper => "Removing WARP helper...",
        }
    }
}

/// GUI lifecycle for WARP operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum WarpUiState {
    /// Idle; last snapshot may still be present.
    #[default]
    Idle,
    /// Operation in flight.
    Busy(WarpOperation),
    /// Last operation failed with a classified kind.
    Failed {
        /// Error classification for GUI state labels.
        kind: WarpErrorKind,
        /// Safe user-facing detail.
        detail: String,
    },
}

impl WarpUiState {
    /// Returns `true` while a WARP worker is running.
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Busy(_))
    }
}

/// Pending confirmation dialog before a destructive / mutating step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarpPendingConfirm {
    /// Confirm helper install on the remote host.
    InstallHelper,
    /// Confirm full managed setup with proposed tag.
    Setup {
        /// Preferred outbound tag (editable before confirm).
        preferred_tag: String,
    },
    /// Confirm adoption of an existing Possible WARP outbound.
    Adopt {
        /// Outbound tag to adopt.
        outbound_tag: String,
        /// Safe summary line.
        summary_line: String,
    },
    /// Confirm credential regeneration.
    Regenerate,
    /// Confirm managed integration removal.
    RemoveIntegration {
        /// Tag that will be removed.
        outbound_tag: String,
        /// Blocking routing references (empty when safe).
        blocking_references: Vec<String>,
    },
    /// Confirm helper-only removal.
    RemoveHelper,
    /// Offer restart after a successful config mutation.
    RestartXray,
}

/// Coarse page availability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarpPageState {
    /// SSH not connected.
    NoSshConnection,
    /// Discovery not completed.
    DiscoveryRequired,
    /// Xray not found on host.
    XrayNotInstalled,
    /// Configuration not loaded into editable model.
    ConfigurationNotLoaded,
    /// Ready to show WARP info / run ops.
    Ready,
    /// Last WARP op failed (see ui_state).
    Error,
}

impl WarpPageState {
    /// Short label for diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            Self::NoSshConnection => "No SSH connection",
            Self::DiscoveryRequired => "Run discovery first",
            Self::XrayNotInstalled => "Xray not discovered",
            Self::ConfigurationNotLoaded => "Configuration not loaded",
            Self::Ready => "Ready",
            Self::Error => "Error",
        }
    }
}

/// Read-only model consumed by the Cloudflare WARP GUI page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpPageModel {
    /// Coarse page availability.
    pub page_state: WarpPageState,
    /// Last discovery summary when available.
    pub summary: Option<WarpSummary>,
    /// Async UI state.
    pub ui_state: WarpUiState,
    /// Pending confirmation dialog, if any.
    pub pending_confirm: Option<WarpPendingConfirm>,
    /// Draft preferred tag for setup (GUI-editable).
    pub preferred_tag: String,
    /// Last proposed change awaiting apply (setup / regenerate), safe summary.
    pub proposed_change: Option<WarpProposedChange>,
    /// Whether Refresh may be started.
    pub can_discover: bool,
    /// Whether Install helper may be started.
    pub can_install_helper: bool,
    /// Whether managed setup may be started.
    pub can_setup: bool,
    /// Whether Adopt may be started.
    pub can_adopt: bool,
    /// Whether Test WARP may be started.
    pub can_test: bool,
    /// Whether Regenerate may be started.
    pub can_regenerate: bool,
    /// Whether Remove integration may be started.
    pub can_remove_integration: bool,
    /// Whether Remove helper may be started.
    pub can_remove_helper: bool,
    /// Optional blocked reason when actions are disabled.
    pub blocked_reason: Option<String>,
    /// Success notice after adding outbound (routing unchanged).
    pub routing_notice: Option<String>,
    /// Restart recommendation after mutating ops.
    pub restart_recommended: bool,
}

/// Successful / failed worker outcome delivered to the GUI thread.
#[derive(Debug)]
pub struct WarpOutcome {
    /// Which operation ran.
    pub operation: WarpOperation,
    /// Generation token used to reject stale results.
    pub generation: u64,
    /// Operation result payload.
    pub result: Result<WarpOutcomePayload, WarpError>,
}

/// Payload carried by a successful WARP worker.
#[derive(Debug)]
pub enum WarpOutcomePayload {
    /// Discovery / helper install summary.
    Summary(WarpSummary),
    /// Setup completed: summary + editable config + notices.
    Setup {
        /// Updated summary.
        summary: WarpSummary,
        /// Editable config after outbound add.
        editable: EditableXrayConfig,
        /// Ownership written remotely.
        ownership: WarpOwnershipRecord,
        /// Proposed change that was applied.
        proposed: WarpProposedChange,
    },
    /// Adoption completed.
    Adopted {
        /// Updated summary.
        summary: WarpSummary,
        /// Ownership written remotely.
        ownership: WarpOwnershipRecord,
    },
    /// Connectivity probe result.
    Connectivity {
        /// Updated summary with connectivity fields.
        summary: WarpSummary,
        /// Raw probe result.
        result: WarpConnectivityResult,
    },
    /// Credential regeneration completed.
    Regenerated {
        /// Updated summary.
        summary: WarpSummary,
        /// Editable config after replace.
        editable: EditableXrayConfig,
        /// Proposed change that was applied.
        proposed: WarpProposedChange,
    },
    /// Managed integration removed.
    Removed {
        /// Updated summary.
        summary: WarpSummary,
        /// Editable config after outbound remove.
        editable: EditableXrayConfig,
    },
    /// Helper removed only.
    HelperRemoved {
        /// Updated summary.
        summary: WarpSummary,
    },
}

/// Builds the Cloudflare WARP page model from application state.
pub fn build_warp_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    has_editable: bool,
    summary: Option<&WarpSummary>,
    ui_state: &WarpUiState,
    pending_confirm: Option<&WarpPendingConfirm>,
    preferred_tag: &str,
    proposed_change: Option<&WarpProposedChange>,
    remote_busy: bool,
    routing_notice: Option<&str>,
) -> WarpPageModel {
    let (page_state, blocked_reason) = match ssh {
        SshStatus::Connected => match discovery {
            DiscoveryState::Succeeded(installation) => {
                if installation.binary_path.is_none() {
                    (
                        WarpPageState::XrayNotInstalled,
                        Some("Xray binary not found. Unsupported installation.".to_owned()),
                    )
                } else if !has_editable {
                    (
                        WarpPageState::ConfigurationNotLoaded,
                        Some(
                            "Configuration not loaded. Discover Xray again after the config becomes readable."
                                .to_owned(),
                        ),
                    )
                } else if matches!(ui_state, WarpUiState::Failed { .. }) {
                    (WarpPageState::Error, None)
                } else {
                    (WarpPageState::Ready, None)
                }
            }
            DiscoveryState::NotFound { .. } => (
                WarpPageState::XrayNotInstalled,
                Some("Xray is not installed on this host.".to_owned()),
            ),
            DiscoveryState::Failed { .. } => (
                WarpPageState::DiscoveryRequired,
                Some("Discovery failed. Re-run discovery on the Connection page.".to_owned()),
            ),
            DiscoveryState::Idle | DiscoveryState::Discovering => (
                WarpPageState::DiscoveryRequired,
                Some("Run discovery on the Connection page first.".to_owned()),
            ),
        },
        _ => (
            WarpPageState::NoSshConnection,
            Some("Connect over SSH first.".to_owned()),
        ),
    };

    let can_act = (page_state == WarpPageState::Ready
        || (page_state == WarpPageState::Error
            && matches!(discovery, DiscoveryState::Succeeded(_))
            && has_editable))
        && !remote_busy
        && !ui_state.is_busy();

    let classification = summary.and_then(|s| s.outbound_classification);
    let state = summary.map(|s| s.state);
    let helper_installed = summary.is_some_and(|s| s.helper_installed);
    let managed = classification == Some(WarpOutboundClassification::Managed)
        || state == Some(WarpIntegrationState::Configured)
        || state == Some(WarpIntegrationState::Connected);
    let possible = classification == Some(WarpOutboundClassification::PossibleWarp)
        || state == Some(WarpIntegrationState::External);

    let can_discover = can_act;
    let can_install_helper = can_act;
    let can_setup = can_act
        && !managed
        && classification != Some(WarpOutboundClassification::External);
    let can_adopt = can_act && possible && !managed;
    let can_test = can_act && (managed || possible);
    let can_regenerate = can_act && managed;
    let can_remove_integration = can_act && managed;
    let can_remove_helper = can_act && helper_installed;

    let restart_recommended = summary.is_some_and(|s| s.restart_recommended);

    WarpPageModel {
        page_state,
        summary: summary.cloned(),
        ui_state: ui_state.clone(),
        pending_confirm: pending_confirm.cloned(),
        preferred_tag: preferred_tag.to_owned(),
        proposed_change: proposed_change.cloned(),
        can_discover,
        can_install_helper,
        can_setup,
        can_adopt,
        can_test,
        can_regenerate,
        can_remove_integration,
        can_remove_helper,
        blocked_reason,
        routing_notice: routing_notice.map(str::to_owned),
        restart_recommended,
    }
}

/// Maps a WARP error to a short Status Bar / UI message (no secrets).
pub fn user_facing_warp_error(error: &WarpError) -> String {
    let detail = sanitize_detail(error.detail());
    if detail.is_empty() {
        error.kind().label().to_owned()
    } else {
        format!("{}: {}", error.kind().label(), detail)
    }
}

/// Arguments for a WARP worker that may mutate Xray configuration.
#[derive(Debug, Clone)]
pub struct WarpWorkerContext {
    /// Preferred outbound tag for setup.
    pub preferred_tag: String,
    /// Optional tag to adopt.
    pub adopt_tag: Option<String>,
    /// Editable configuration snapshot (required for mutating ops).
    pub editable: Option<EditableXrayConfig>,
    /// Xray version string when known.
    pub xray_version: Option<String>,
    /// Existing outbound tags for uniqueness.
    pub existing_tags: Vec<String>,
    /// Hint for post-write `xray run -test` (IB-L6).
    pub validate_hint: crate::app::config_write::RemoteConfigValidateHint,
}

/// Runs a WARP operation on a background worker connection.
pub async fn run_warp_operation<B: SshBackend>(
    client: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    operation: WarpOperation,
    generation: u64,
    context: WarpWorkerContext,
) -> WarpOutcome
where
    B::Session: Sync,
{
    let request = build_connect_request(profile, secrets);
    let session = match client.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            let detail = sanitize_detail(error.message());
            error!(
                target: "app",
                operation = ?operation,
                detail = %detail,
                "WARP SSH connect failed"
            );
            return WarpOutcome {
                operation,
                generation,
                result: Err(WarpError::new(
                    WarpErrorKind::NoSshConnection,
                    user_message_see_log("Unable to connect to server."),
                )),
            };
        }
    };

    let result = execute_warp_operation(&session, remote, operation, context).await;

    if let Err(error) = session.disconnect().await {
        error!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "WARP session disconnect failed"
        );
    }

    WarpOutcome {
        operation,
        generation,
        result,
    }
}

async fn execute_warp_operation<S: SshSession + Sync>(
    session: &S,
    remote: &RemoteAdmin,
    operation: WarpOperation,
    context: WarpWorkerContext,
) -> Result<WarpOutcomePayload, WarpError> {
    let manager = WarpManager::new();

    match operation {
        WarpOperation::Discover => {
            info!(target: "app", "WARP detection started");
            let ownership = manager.read_ownership(session).await?;
            let sections = context
                .editable
                .as_ref()
                .map(|editable| editable.sections().clone())
                .ok_or_else(|| {
                    WarpError::new(
                        WarpErrorKind::XrayNotDiscovered,
                        "configuration not loaded",
                    )
                })?;
            let summary = manager
                .discover(
                    session,
                    &sections,
                    ownership.as_ref(),
                    context.xray_version.as_deref(),
                )
                .await?;
            Ok(WarpOutcomePayload::Summary(summary))
        }
        WarpOperation::InstallHelper => {
            info!(target: "app", "WARP helper install started");
            let summary = manager.install_helper(session).await?;
            info!(target: "app", "WARP helper installed");
            Ok(WarpOutcomePayload::Summary(summary))
        }
        WarpOperation::Setup => {
            let mut editable = context.editable.ok_or_else(|| {
                WarpError::new(
                    WarpErrorKind::XrayNotDiscovered,
                    "configuration not loaded",
                )
            })?;
            info!(target: "app", "WARP registration started");
            let (credentials, proposed) = manager
                .prepare_managed_outbound(
                    session,
                    &context.existing_tags,
                    &context.preferred_tag,
                    false,
                )
                .await?;
            info!(target: "app", "WARP registration completed");
            let write = commit_add_outbound(
                remote,
                session,
                &mut editable,
                &credentials,
                &proposed,
                &context.validate_hint,
            )
            .await?;
            let ownership = WarpOwnershipRecord {
                outbound_tag: proposed.outbound_tag.clone(),
                managed: true,
                helper_version: None,
            };
            manager.write_ownership(session, &ownership).await?;
            info!(target: "app", "WARP outbound added");
            let summary = manager
                .discover(
                    session,
                    write.editable.sections(),
                    Some(&ownership),
                    context.xray_version.as_deref(),
                )
                .await?;
            let mut summary = summary;
            summary.restart_recommended = true;
            Ok(WarpOutcomePayload::Setup {
                summary,
                editable: write.editable,
                ownership,
                proposed,
            })
        }
        WarpOperation::Adopt => {
            let editable = context.editable.ok_or_else(|| {
                WarpError::new(
                    WarpErrorKind::XrayNotDiscovered,
                    "configuration not loaded",
                )
            })?;
            let tag = context.adopt_tag.ok_or_else(|| {
                WarpError::new(
                    WarpErrorKind::ManagedOutboundMissing,
                    "adoption tag missing",
                )
            })?;
            let adoption = manager.prepare_adoption(editable.sections(), &tag, None)?;
            // Backup path: write ownership only after confirming structure; config unchanged.
            manager
                .write_ownership(session, &adoption.ownership)
                .await?;
            info!(target: "app", "WARP outbound adopted");
            let summary = manager
                .discover(
                    session,
                    editable.sections(),
                    Some(&adoption.ownership),
                    context.xray_version.as_deref(),
                )
                .await?;
            Ok(WarpOutcomePayload::Adopted {
                summary,
                ownership: adoption.ownership,
            })
        }
        WarpOperation::TestConnectivity => {
            let ownership = manager.read_ownership(session).await?;
            let tag = ownership
                .as_ref()
                .filter(|record| record.managed)
                .map(|record| record.outbound_tag.as_str());
            let result = manager.test_connectivity(session, tag).await?;
            let sections = context
                .editable
                .as_ref()
                .map(|editable| editable.sections().clone())
                .ok_or_else(|| {
                    WarpError::new(
                        WarpErrorKind::XrayNotDiscovered,
                        "configuration not loaded",
                    )
                })?;
            let mut summary = manager
                .discover(
                    session,
                    &sections,
                    ownership.as_ref(),
                    context.xray_version.as_deref(),
                )
                .await?;
            apply_connectivity_to_summary(&mut summary, &result);
            if result.available && result.warp_active == Some(true) {
                info!(target: "app", "WARP connectivity test succeeded");
            }
            Ok(WarpOutcomePayload::Connectivity { summary, result })
        }
        WarpOperation::Regenerate => {
            let mut editable = context.editable.ok_or_else(|| {
                WarpError::new(
                    WarpErrorKind::XrayNotDiscovered,
                    "configuration not loaded",
                )
            })?;
            let ownership = manager.read_ownership(session).await?.ok_or_else(|| {
                WarpError::new(
                    WarpErrorKind::ManagedOutboundMissing,
                    "no managed WARP ownership marker",
                )
            })?;
            if !ownership.managed {
                return Err(WarpError::new(
                    WarpErrorKind::ManagedOutboundMissing,
                    "ownership marker is not managed",
                ));
            }
            info!(target: "app", "WARP credential regeneration started");
            let (credentials, proposed, backup) = manager
                .regenerate_credentials(session, &ownership.outbound_tag, true)
                .await?;
            let write = match commit_replace_outbound(
                remote,
                session,
                &mut editable,
                &credentials,
                &proposed,
                &context.validate_hint,
            )
            .await
            {
                Ok(write) => write,
                Err(error) => {
                    if let Some(backup_path) = backup.as_ref() {
                        if let Err(restore_error) = manager
                            .restore_registration_backup(session, backup_path)
                            .await
                        {
                            warn!(
                                target: "app",
                                detail = %sanitize_detail(restore_error.detail()),
                                "failed to restore WARP registration after config write failure"
                            );
                        }
                    }
                    return Err(error);
                }
            };
            manager.write_ownership(session, &ownership).await?;
            info!(target: "app", "WARP credentials regenerated");
            let mut summary = manager
                .discover(
                    session,
                    write.editable.sections(),
                    Some(&ownership),
                    context.xray_version.as_deref(),
                )
                .await?;
            summary.restart_recommended = true;
            Ok(WarpOutcomePayload::Regenerated {
                summary,
                editable: write.editable,
                proposed,
            })
        }
        WarpOperation::RemoveIntegration => {
            let mut editable = context.editable.ok_or_else(|| {
                WarpError::new(
                    WarpErrorKind::XrayNotDiscovered,
                    "configuration not loaded",
                )
            })?;
            let ownership = manager.read_ownership(session).await?.ok_or_else(|| {
                WarpError::new(
                    WarpErrorKind::ManagedOutboundMissing,
                    "no managed WARP ownership marker",
                )
            })?;
            let plan = manager.plan_remove_managed_outbound(editable.sections(), &ownership)?;
            if plan.is_blocked() {
                return Err(WarpError::new(
                    WarpErrorKind::ConfigurationReferencePreventsRemoval,
                    format!(
                        "resolve references first: {}",
                        plan.blocking_references.join("; ")
                    ),
                ));
            }
            let write =
                commit_remove_outbound(remote, session, &mut editable, &plan, &context.validate_hint)
                    .await?;
            // Clear managed flag but preserve registration files on disk.
            let cleared = WarpOwnershipRecord {
                outbound_tag: ownership.outbound_tag.clone(),
                managed: false,
                helper_version: ownership.helper_version.clone(),
            };
            manager.write_ownership(session, &cleared).await?;
            info!(target: "app", "WARP integration removed");
            let mut summary = manager
                .discover(
                    session,
                    write.editable.sections(),
                    Some(&cleared),
                    context.xray_version.as_deref(),
                )
                .await?;
            summary.restart_recommended = true;
            Ok(WarpOutcomePayload::Removed {
                summary,
                editable: write.editable,
            })
        }
        WarpOperation::RemoveHelper => {
            manager.remove_helper_only(session).await?;
            info!(target: "app", "WARP helper removed");
            let ownership = manager.read_ownership(session).await?;
            let sections = context
                .editable
                .as_ref()
                .map(|editable| editable.sections().clone())
                .ok_or_else(|| {
                    WarpError::new(
                        WarpErrorKind::XrayNotDiscovered,
                        "configuration not loaded",
                    )
                })?;
            let summary = manager
                .discover(
                    session,
                    &sections,
                    ownership.as_ref(),
                    context.xray_version.as_deref(),
                )
                .await?;
            Ok(WarpOutcomePayload::HelperRemoved { summary })
        }
    }
}

async fn commit_add_outbound<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    editable: &mut EditableXrayConfig,
    credentials: &WarpCredentials,
    proposed: &WarpProposedChange,
    validate_hint: &crate::app::config_write::RemoteConfigValidateHint,
) -> Result<WarpConfigWriteSuccess, WarpError> {
    let outbound = outbound_value_with_tag(credentials, &proposed.outbound_tag);
    let outcome = add_outbound(
        editable,
        AddOutboundRequest {
            outbound,
            preferred_source_file: None,
        },
    )
    .map_err(map_config_error_to_warp)?;
    apply_add_outbound(remote, session, editable, outcome, validate_hint).await
}

async fn commit_replace_outbound<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    editable: &mut EditableXrayConfig,
    credentials: &WarpCredentials,
    proposed: &WarpProposedChange,
    validate_hint: &crate::app::config_write::RemoteConfigValidateHint,
) -> Result<WarpConfigWriteSuccess, WarpError> {
    let outbound = outbound_value_with_tag(credentials, &proposed.outbound_tag);
    let outcome = replace_outbound(
        editable,
        ReplaceOutboundRequest {
            tag: proposed.outbound_tag.clone(),
            outbound,
        },
    )
    .map_err(map_config_error_to_warp)?;
    apply_replace_outbound(remote, session, editable, outcome, validate_hint).await
}

async fn commit_remove_outbound<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    editable: &mut EditableXrayConfig,
    plan: &WarpRemovalPlan,
    validate_hint: &crate::app::config_write::RemoteConfigValidateHint,
) -> Result<WarpConfigWriteSuccess, WarpError> {
    let outcome = remove_outbound(
        editable,
        RemoveOutboundRequest {
            tag: plan.outbound_tag.clone(),
        },
    )
    .map_err(map_config_error_to_warp)?;
    apply_remove_outbound(remote, session, editable, outcome, validate_hint).await
}

fn apply_connectivity_to_summary(summary: &mut WarpSummary, result: &WarpConnectivityResult) {
    summary.connectivity_status = Some(result.status.clone());
    summary.ipv4_available = result.ipv4_available;
    summary.ipv6_available = result.ipv6_available;
    summary.warp_active = result.warp_active;
    summary.observed_public_ip = result.observed_public_ip.clone();
    summary.connectivity_note = result.note.clone();
    if result.available && result.warp_active == Some(true) {
        summary.state = WarpIntegrationState::Connected;
    } else if result.available && result.warp_active == Some(false) {
        summary.state = WarpIntegrationState::ConnectionFailed;
        warn!(target: "app", "WARP inactive according to connectivity probe");
    }
    for warning in &result.warnings {
        if !summary.warnings.iter().any(|existing| existing == warning) {
            summary.warnings.push(warning.clone());
        }
    }
}

/// Default preferred tag for new setups.
pub fn default_preferred_tag() -> String {
    DEFAULT_WARP_OUTBOUND_TAG.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_model_requires_ssh() {
        let model = build_warp_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            false,
            None,
            &WarpUiState::Idle,
            None,
            DEFAULT_WARP_OUTBOUND_TAG,
            None,
            false,
            None,
        );
        assert_eq!(model.page_state, WarpPageState::NoSshConnection);
        assert!(!model.can_setup);
    }

    #[test]
    fn status_messages_match_spec() {
        assert_eq!(
            WarpOperation::Discover.status_message(),
            "Checking WARP integration..."
        );
        assert_eq!(
            WarpOperation::InstallHelper.status_message(),
            "Installing WARP helper..."
        );
        assert_eq!(
            WarpOperation::TestConnectivity.status_message(),
            "Testing WARP connectivity..."
        );
    }
}
