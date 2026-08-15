//! Inbound shell edit drafts and remote mutation orchestration (D027 / IB-L1).

use std::time::Duration;

use feldjaeger_ssh::{RemotePath, SshBackend, SshSession};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::app::config_write::{RemoteConfigValidateHint, write_config_validated};
use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::remote::RemoteAdmin;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    AddInboundRequest, ConfigModifyError, ConfigModifyErrorKind, DeleteInboundRequest,
    DuplicateInboundRequest, EditableXrayConfig, InboundGeneral, InboundProtocolDraft, InboundRef,
    InboundSecurityDraft, ModifyConfigOutcome, SniffingSettings, SniffingWriteOutcome,
    UpdateInboundGeneralRequest, UpdateInboundShellRequest, UpdateInboundSniffingRequest,
    add_inbound, cert_pin_sha256, delete_inbound, duplicate_inbound, effective_security,
    update_inbound_general, update_inbound_shell, update_inbound_sniffing,
};

/// Timeout for remote `xray x25519` keygen.
const KEYGEN_TIMEOUT: Duration = Duration::from_secs(30);

// ─── Legacy (D027 General/Sniffing) ──────────────────────────────────────────

/// Which inbound shell mutation is in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundShellMutationKind {
    /// General (tag / listen / port) Save.
    General,
    /// Sniffing Save.
    Sniffing,
}

impl InboundShellMutationKind {
    /// Status Bar label while the mutation runs.
    pub fn busy_label(self) -> &'static str {
        match self {
            Self::General => "Updating inbound...",
            Self::Sniffing => "Updating sniffing...",
        }
    }
}

/// In-memory shell edit session for one inbound (shared fingerprint).
///
/// Used by legacy code paths; new code uses [`InboundEditorSession`].
#[derive(Debug, Clone, PartialEq)]
pub struct InboundShellDrafts {
    /// Selected inbound index in the merged list.
    pub inbound_index: usize,
    /// Identity + fingerprint captured at first Edit intent.
    pub inbound_ref: InboundRef,
    /// General form draft when editing; `None` = view mode for General.
    pub general: Option<InboundGeneral>,
    /// Sniffing form draft when editing; `None` = view mode for Sniffing.
    pub sniffing: Option<SniffingSettings>,
}

impl InboundShellDrafts {
    /// True when either tab holds an edit draft.
    pub fn is_editing(&self) -> bool {
        self.general.is_some() || self.sniffing.is_some()
    }
}

/// Outcome delivered from the inbound-shell worker thread.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundShellMutationOutcome {
    /// Operation that completed.
    pub kind: InboundShellMutationKind,
    /// Success payload or classified error.
    pub result: Result<InboundShellMutationSuccess, ConfigModifyError>,
}

/// Successful shell mutation (remote write skipped on sniffing NoWrite).
#[derive(Debug, Clone, PartialEq)]
pub struct InboundShellMutationSuccess {
    /// Editable model after the in-memory mutation.
    pub editable: EditableXrayConfig,
    /// Whether a remote write occurred.
    pub wrote_remote: bool,
}

// ─── IB-L1 unified editor session ────────────────────────────────────────────

/// Which high-level inbound mutation is in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundMutationKind {
    /// Unified Shell Save (General + Protocol + Sniffing + Security).
    Shell,
    /// Add new inbound.
    Add,
    /// Delete an existing inbound.
    Delete,
    /// Duplicate an existing inbound.
    Duplicate,
    /// Generate x25519 key pair for Reality.
    GenerateX25519,
    /// Generate mldsa65 seed/verify for Reality.
    GenerateMldsa65,
    /// Generate VLESS decryption/encryption via `xray vlessenc`.
    GenerateVlessEnc,
    /// Fetch a TLS certificate's SHA-256 pin for Hysteria2 `pinSHA256` (Roadmap §3:121).
    FetchCertPin,
    /// Replace an inbound's entire JSON object (raw JSON escape hatch, Roadmap §3:125).
    ReplaceRawJson,
}

impl InboundMutationKind {
    /// Status Bar label while the mutation runs.
    pub fn busy_label(self) -> &'static str {
        match self {
            Self::Shell => "Saving inbound...",
            Self::Add => "Adding inbound...",
            Self::Delete => "Deleting inbound...",
            Self::Duplicate => "Duplicating inbound...",
            Self::GenerateX25519 => "Generating x25519 key pair...",
            Self::GenerateMldsa65 => "Generating mldsa65 key pair...",
            Self::GenerateVlessEnc => "Generating VLESS encryption...",
            Self::FetchCertPin => "Fetching certificate pin...",
            Self::ReplaceRawJson => "Saving raw JSON...",
        }
    }
}

/// Key pair returned from keygen; carried in the outcome without logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519Result {
    /// Server private key (written into Reality draft).
    pub private_key: String,
    /// Client public key for display only (ephemeral in session).
    pub public_key: String,
}

/// Seed / verify pair from mldsa65 keygen; never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mldsa65Result {
    /// Server `realitySettings.mldsa65Seed`.
    pub seed: String,
    /// Client verify string (ephemeral UI only).
    pub verify: String,
}

/// Selected `vlessenc` pair applied into the Protocol draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessEncResult {
    /// Written to `settings.decryption`.
    pub decryption: String,
    /// Ephemeral client encryption (UI copy-out only).
    pub encryption: String,
    /// Which auth block was selected.
    pub auth: crate::xray::VlessEncAuthKind,
}

/// Unified inbound mutation outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundMutationOutcome {
    /// Which kind completed.
    pub kind: InboundMutationKind,
    /// Result payload.
    pub result: Result<InboundMutationSuccess, ConfigModifyError>,
}

/// Success payload variants for the unified inbound mutation.
#[derive(Debug, Clone, PartialEq)]
pub enum InboundMutationSuccess {
    /// Shell Save completed.
    Shell {
        /// Updated in-memory config after shell mutation.
        editable: EditableXrayConfig,
        /// Whether the remote file was rewritten.
        wrote_remote: bool,
        /// Routing `inboundTag` rules still pointing at the pre-rename tag, when the tag
        /// changed (Roadmap §3:119). Never blocks the Save; surfaced as a warning only.
        stale_references: Vec<String>,
    },
    /// Add Inbound completed.
    Add {
        /// Updated in-memory config with the new inbound appended.
        editable: EditableXrayConfig,
    },
    /// Delete Inbound completed.
    Delete {
        /// Updated in-memory config after removal.
        editable: EditableXrayConfig,
        /// Merged index that was removed.
        deleted_index: usize,
    },
    /// Duplicate Inbound completed.
    Duplicate {
        /// Updated in-memory config with the clone appended.
        editable: EditableXrayConfig,
        /// Merged index of the new copy.
        new_index: usize,
    },
    /// x25519 keygen completed.
    X25519(X25519Result),
    /// mldsa65 keygen completed.
    Mldsa65(Mldsa65Result),
    /// vlessenc completed for the chosen auth block.
    VlessEnc(VlessEncResult),
    /// Certificate pin fetch completed (Roadmap §3:121): lowercase-hex SHA-256 of the leaf
    /// certificate's DER bytes, for Hysteria2 `pinSHA256`.
    CertPin(String),
    /// Raw JSON replace completed (Roadmap §3:125 escape hatch).
    RawJson {
        /// Updated in-memory config after the replace.
        editable: EditableXrayConfig,
    },
}

/// IB-L1 unified inbound editor session.
///
/// Replaces `InboundShellDrafts` for the new 6-tab inbound editor UI.
/// `is_add = true` means an Add Inbound flow; `inbound_ref` is `None` in that case.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundEditorSession {
    /// Inbound index in the merged list (`usize::MAX` for Add).
    pub inbound_index: usize,
    /// Identity + fingerprint for Shell Save; `None` for Add.
    pub inbound_ref: Option<InboundRef>,
    /// General tab draft.
    pub general: InboundGeneral,
    /// Protocol tab draft.
    pub protocol: InboundProtocolDraft,
    /// Stream tab draft (IB-L3).
    pub stream: crate::xray::InboundStreamDraft,
    /// Sniffing tab draft.
    pub sniffing: SniffingSettings,
    /// Security tab draft (Some for VLESS and Trojan).
    pub security: Option<InboundSecurityDraft>,
    /// `true` when this is an Add Inbound flow (not editing existing).
    pub is_add: bool,
    /// Ephemeral public key from the last successful x25519 keygen.
    /// Shown in the Security tab; never written to config.
    pub ephemeral_public_key: Option<String>,
    /// Ephemeral mldsa65 verify from the last successful mldsa65 keygen.
    /// Shown in the Security tab; never written to config.
    pub ephemeral_mldsa65_verify: Option<String>,
    /// Ephemeral client encryption from last `vlessenc` Generate (Protocol tab).
    pub ephemeral_client_encryption: Option<String>,
    /// Preferred `vlessenc` auth block for the next Generate.
    pub vlessenc_auth: crate::xray::VlessEncAuthKind,
    /// `true` when any field differs from the initial load value.
    pub dirty: bool,
    /// Last redacted structural diff preview (IB-L5); cleared when drafts change.
    pub diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
    /// Whether loaded clients use Vision flow (filters Stream methods).
    ///
    /// Refreshed on open and after successful Users mutate; not derived from
    /// unsaved Users form drafts.
    pub vision_active: bool,
}

// ─── Legacy workers (General / Sniffing) ─────────────────────────────────────

/// Applies General update locally then writes safely over SSH.
pub async fn run_update_inbound_general<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    editable: EditableXrayConfig,
    request: UpdateInboundGeneralRequest,
    validate_hint: RemoteConfigValidateHint,
) -> InboundShellMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    run_shell_mutation(
        backend,
        profile,
        secrets,
        remote,
        editable,
        InboundShellMutationKind::General,
        validate_hint,
        |config| {
            let outcome = update_inbound_general(config, request)?;
            Ok((outcome, true))
        },
    )
    .await
}

/// Applies Sniffing update; skips remote write when outcome is NoWrite.
pub async fn run_update_inbound_sniffing<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    editable: EditableXrayConfig,
    request: UpdateInboundSniffingRequest,
    validate_hint: RemoteConfigValidateHint,
) -> InboundShellMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    run_shell_mutation(
        backend,
        profile,
        secrets,
        remote,
        editable,
        InboundShellMutationKind::Sniffing,
        validate_hint,
        |config| {
            let (outcome, write) = update_inbound_sniffing(config, request)?;
            let wrote = write == SniffingWriteOutcome::Written;
            Ok((outcome, wrote))
        },
    )
    .await
}

async fn run_shell_mutation<B, F>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    kind: InboundShellMutationKind,
    validate_hint: RemoteConfigValidateHint,
    mutate: F,
) -> InboundShellMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
    F: FnOnce(&mut EditableXrayConfig) -> Result<(ModifyConfigOutcome, bool), ConfigModifyError>,
{
    let (outcome, wrote_remote) = match mutate(&mut editable) {
        Ok(value) => value,
        Err(error) => {
            return InboundShellMutationOutcome {
                kind,
                result: Err(error),
            };
        }
    };

    if !wrote_remote {
        info!(target: "app", kind = ?kind, "inbound shell mutation skipped remote write");
        return InboundShellMutationOutcome {
            kind,
            result: Ok(InboundShellMutationSuccess {
                editable,
                wrote_remote: false,
            }),
        };
    }

    let request = build_connect_request(profile, secrets);
    info!(
        target: "app",
        kind = ?kind,
        host = %request.profile.host,
        path = %outcome.source_file,
        "inbound shell mutation connect"
    );

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            return InboundShellMutationOutcome {
                kind,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result =
        write_modified_file(remote, &session, &outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "inbound shell mutation disconnect warning"
        );
    }

    match write_result {
        Ok(()) => InboundShellMutationOutcome {
            kind,
            result: Ok(InboundShellMutationSuccess {
                editable,
                wrote_remote: true,
            }),
        },
        Err(error) => InboundShellMutationOutcome {
            kind,
            result: Err(error),
        },
    }
}

// ─── IB-L1 unified mutation workers ──────────────────────────────────────────

/// Unified Shell Save: General + Protocol + Sniffing + Security (Trojan).
pub async fn run_update_inbound_shell<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: UpdateInboundShellRequest,
    validate_hint: RemoteConfigValidateHint,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let inbound_index = request.inbound_ref.location.inbound_index;
    let old_tag = editable
        .sections()
        .inbounds()
        .get(inbound_index)
        .and_then(|inbound| inbound.value().get("tag"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mutate_result = update_inbound_shell(&mut editable, request);

    let (outcome, sniff_write) = match mutate_result {
        Ok(pair) => pair,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::Shell,
                result: Err(error),
            };
        }
    };

    // Sniffing-only NoWrite still means General/Protocol/Security may have changed.
    // Always write to remote when at least one of those was mutated; here we
    // always reach remote for Shell (outcome always contains serialized bytes).
    let _ = sniff_write; // sniff write outcome recorded but we always write for Shell

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "inbound shell save connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::Shell,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    if let Some(inbound) = editable.sections().inbounds().get(inbound_index) {
        if let Err(error) = verify_remote_tls_cert_paths(&session, inbound.value()).await {
            if let Err(disconnect_error) = session.disconnect().await {
                warn!(
                    target: "app",
                    detail = %crate::logging::redact::sanitize_detail(disconnect_error.message()),
                    "inbound shell save disconnect warning"
                );
            }
            return InboundMutationOutcome {
                kind: InboundMutationKind::Shell,
                result: Err(error),
            };
        }
    }

    let write_result =
        write_modified_file(remote, &session, &outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "inbound shell save disconnect warning"
        );
    }

    match write_result {
        Ok(()) => {
            let stale_references = inbound_stale_tag_references(&editable, inbound_index, old_tag.as_deref());
            InboundMutationOutcome {
                kind: InboundMutationKind::Shell,
                result: Ok(InboundMutationSuccess::Shell {
                    editable,
                    wrote_remote: true,
                    stale_references,
                }),
            }
        }
        Err(error) => InboundMutationOutcome {
            kind: InboundMutationKind::Shell,
            result: Err(error),
        },
    }
}

/// Routing `inboundTag` rules still pointing at the pre-Save tag, when the tag changed during a
/// Shell Save (Roadmap §3:119; v1 — warn only, never blocks). Empty when the tag didn't change,
/// was absent before, or has no routing references.
fn inbound_stale_tag_references(
    editable: &EditableXrayConfig,
    inbound_index: usize,
    old_tag: Option<&str>,
) -> Vec<String> {
    let Some(old_tag) = old_tag else {
        return Vec::new();
    };
    let new_tag = editable
        .sections()
        .inbounds()
        .get(inbound_index)
        .and_then(|inbound| inbound.value().get("tag"))
        .and_then(serde_json::Value::as_str);
    if new_tag.is_some_and(|new_tag| new_tag == old_tag) {
        return Vec::new();
    }
    crate::xray::inbound_tag_references(editable.sections(), old_tag)
}

/// Add Inbound: appends a new inbound and writes to remote.
pub async fn run_add_inbound<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: AddInboundRequest,
    validate_hint: RemoteConfigValidateHint,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let outcome = match add_inbound(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::Add,
                result: Err(error),
            };
        }
    };

    let inbound_index = editable.sections().inbounds().len().saturating_sub(1);

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "add inbound connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::Add,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    if let Some(inbound) = editable.sections().inbounds().get(inbound_index) {
        if let Err(error) = verify_remote_tls_cert_paths(&session, inbound.value()).await {
            if let Err(disconnect_error) = session.disconnect().await {
                warn!(
                    target: "app",
                    detail = %crate::logging::redact::sanitize_detail(disconnect_error.message()),
                    "add inbound disconnect warning"
                );
            }
            return InboundMutationOutcome {
                kind: InboundMutationKind::Add,
                result: Err(error),
            };
        }
    }

    let write_result =
        write_modified_file(remote, &session, &outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "add inbound disconnect warning"
        );
    }

    match write_result {
        Ok(()) => InboundMutationOutcome {
            kind: InboundMutationKind::Add,
            result: Ok(InboundMutationSuccess::Add { editable }),
        },
        Err(error) => InboundMutationOutcome {
            kind: InboundMutationKind::Add,
            result: Err(error),
        },
    }
}

/// Delete Inbound: removes by index and writes to remote.
pub async fn run_delete_inbound<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: DeleteInboundRequest,
    validate_hint: RemoteConfigValidateHint,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let deleted_index = request.inbound_index;
    let outcome = match delete_inbound(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::Delete,
                result: Err(error),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "delete inbound connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::Delete,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result =
        write_modified_file(remote, &session, &outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "delete inbound disconnect warning"
        );
    }

    match write_result {
        Ok(()) => InboundMutationOutcome {
            kind: InboundMutationKind::Delete,
            result: Ok(InboundMutationSuccess::Delete {
                editable,
                deleted_index,
            }),
        },
        Err(error) => InboundMutationOutcome {
            kind: InboundMutationKind::Delete,
            result: Err(error),
        },
    }
}

/// Duplicate Inbound: deep-copies with a unique tag and writes to remote.
pub async fn run_duplicate_inbound<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: DuplicateInboundRequest,
    validate_hint: RemoteConfigValidateHint,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let outcome = match duplicate_inbound(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::Duplicate,
                result: Err(error),
            };
        }
    };

    let new_index = editable.sections().inbounds().len().saturating_sub(1);

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "duplicate inbound connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::Duplicate,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let write_result =
        write_modified_file(remote, &session, &outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "duplicate inbound disconnect warning"
        );
    }

    match write_result {
        Ok(()) => InboundMutationOutcome {
            kind: InboundMutationKind::Duplicate,
            result: Ok(InboundMutationSuccess::Duplicate {
                editable,
                new_index,
            }),
        },
        Err(error) => InboundMutationOutcome {
            kind: InboundMutationKind::Duplicate,
            result: Err(error),
        },
    }
}

/// Generate x25519 key pair on the remote host via `xray x25519`.
///
/// Never logs private or public key material.
pub async fn run_generate_x25519<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    binary_path: String,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        "x25519 keygen connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::GenerateX25519,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let keygen_result = timeout(
        KEYGEN_TIMEOUT,
        crate::xray::run_x25519(&session, &binary_path),
    )
    .await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "x25519 keygen disconnect warning"
        );
    }

    match keygen_result {
        Err(_elapsed) => InboundMutationOutcome {
            kind: InboundMutationKind::GenerateX25519,
            result: Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ConnectionLost,
                "x25519 keygen timed out after 30 seconds".to_owned(),
            )),
        },
        Ok(Err(cli_error)) => InboundMutationOutcome {
            kind: InboundMutationKind::GenerateX25519,
            result: Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UploadFailed,
                sanitize_detail(&cli_error.message()),
            )),
        },
        Ok(Ok(pair)) => InboundMutationOutcome {
            kind: InboundMutationKind::GenerateX25519,
            result: Ok(InboundMutationSuccess::X25519(X25519Result {
                private_key: pair.private_key,
                public_key: pair.public_key,
            })),
        },
    }
}

/// Generate mldsa65 seed/verify on the remote host via `xray mldsa65`.
///
/// Never logs seed or verify material.
pub async fn run_generate_mldsa65<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    binary_path: String,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        "mldsa65 keygen connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::GenerateMldsa65,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let keygen_result = timeout(
        KEYGEN_TIMEOUT,
        crate::xray::run_mldsa65(&session, &binary_path),
    )
    .await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "mldsa65 keygen disconnect warning"
        );
    }

    match keygen_result {
        Err(_elapsed) => InboundMutationOutcome {
            kind: InboundMutationKind::GenerateMldsa65,
            result: Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ConnectionLost,
                "mldsa65 keygen timed out after 30 seconds".to_owned(),
            )),
        },
        Ok(Err(cli_error)) => InboundMutationOutcome {
            kind: InboundMutationKind::GenerateMldsa65,
            result: Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UploadFailed,
                sanitize_detail(&cli_error.message()),
            )),
        },
        Ok(Ok(pair)) => InboundMutationOutcome {
            kind: InboundMutationKind::GenerateMldsa65,
            result: Ok(InboundMutationSuccess::Mldsa65(Mldsa65Result {
                seed: pair.seed,
                verify: pair.verify,
            })),
        },
    }
}

/// Generate VLESS encryption pair on the remote host via `xray vlessenc`.
pub async fn run_generate_vlessenc<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    binary_path: String,
    auth: crate::xray::VlessEncAuthKind,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        "vlessenc connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::GenerateVlessEnc,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let keygen_result = timeout(
        KEYGEN_TIMEOUT,
        crate::xray::run_vlessenc(&session, &binary_path),
    )
    .await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "vlessenc disconnect warning"
        );
    }

    match keygen_result {
        Err(_elapsed) => InboundMutationOutcome {
            kind: InboundMutationKind::GenerateVlessEnc,
            result: Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ConnectionLost,
                "vlessenc timed out after 30 seconds".to_owned(),
            )),
        },
        Ok(Err(cli_error)) => InboundMutationOutcome {
            kind: InboundMutationKind::GenerateVlessEnc,
            result: Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UploadFailed,
                sanitize_detail(&cli_error.message()),
            )),
        },
        Ok(Ok(output)) => {
            let pair = output.pair_for(auth).clone();
            InboundMutationOutcome {
                kind: InboundMutationKind::GenerateVlessEnc,
                result: Ok(InboundMutationSuccess::VlessEnc(VlessEncResult {
                    decryption: pair.decryption,
                    encryption: pair.encryption,
                    auth,
                })),
            }
        }
    }
}

/// Fetches a remote TLS `certificateFile` over SFTP and hashes it into a Hysteria2 `pinSHA256`
/// fingerprint (Roadmap §3:121). Never logs certificate bytes.
pub async fn run_fetch_cert_pin<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    certificate_path: String,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let path = match RemotePath::new(&certificate_path) {
        Ok(path) => path,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::FetchCertPin,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        "cert pin fetch connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::FetchCertPin,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    let read_result = timeout(KEYGEN_TIMEOUT, session.read_file(&path)).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "cert pin fetch disconnect warning"
        );
    }

    let bytes = match read_result {
        Err(_elapsed) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::FetchCertPin,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    "certificate fetch timed out after 30 seconds".to_owned(),
                )),
            };
        }
        Ok(Err(error)) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::FetchCertPin,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::UploadFailed,
                    format!(
                        "Failed to read certificate '{certificate_path}': {}",
                        sanitize_detail(error.message())
                    ),
                )),
            };
        }
        Ok(Ok(bytes)) => bytes,
    };

    match cert_pin_sha256(&bytes) {
        Ok(pin) => InboundMutationOutcome {
            kind: InboundMutationKind::FetchCertPin,
            result: Ok(InboundMutationSuccess::CertPin(pin)),
        },
        Err(detail) => InboundMutationOutcome {
            kind: InboundMutationKind::FetchCertPin,
            result: Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                detail,
            )),
        },
    }
}

/// Replaces an inbound's entire JSON object wholesale — any protocol, including unsupported
/// ones (Roadmap §3:125 raw JSON escape hatch).
pub async fn run_replace_inbound_raw_json<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    remote: &RemoteAdmin,
    mut editable: EditableXrayConfig,
    request: crate::xray::ReplaceInboundRawJsonRequest,
    validate_hint: RemoteConfigValidateHint,
) -> InboundMutationOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let inbound_index = request.inbound_index;
    let outcome = match crate::xray::replace_inbound_raw_json(&mut editable, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::ReplaceRawJson,
                result: Err(error),
            };
        }
    };

    let request_conn = build_connect_request(profile, secrets);
    info!(
        target: "app",
        host = %request_conn.profile.host,
        path = %outcome.source_file,
        "replace inbound raw json connect"
    );

    let session = match backend.connect(&request_conn).await {
        Ok(s) => s,
        Err(error) => {
            return InboundMutationOutcome {
                kind: InboundMutationKind::ReplaceRawJson,
                result: Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ConnectionLost,
                    sanitize_detail(error.message()),
                )),
            };
        }
    };

    if let Some(inbound) = editable.sections().inbounds().get(inbound_index)
        && let Err(error) = verify_remote_tls_cert_paths(&session, inbound.value()).await
    {
        if let Err(disconnect_error) = session.disconnect().await {
            warn!(
                target: "app",
                detail = %crate::logging::redact::sanitize_detail(disconnect_error.message()),
                "replace inbound raw json disconnect warning"
            );
        }
        return InboundMutationOutcome {
            kind: InboundMutationKind::ReplaceRawJson,
            result: Err(error),
        };
    }

    let write_result =
        write_modified_file(remote, &session, &outcome, &validate_hint).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "replace inbound raw json disconnect warning"
        );
    }

    match write_result {
        Ok(()) => InboundMutationOutcome {
            kind: InboundMutationKind::ReplaceRawJson,
            result: Ok(InboundMutationSuccess::RawJson { editable }),
        },
        Err(error) => InboundMutationOutcome {
            kind: InboundMutationKind::ReplaceRawJson,
            result: Err(error),
        },
    }
}

// ─── Shared SSH helpers ───────────────────────────────────────────────────────

/// After local G12, probes non-empty `certificateFile` / `keyFile` via SFTP.
async fn verify_remote_tls_cert_paths<S: SshSession + Sync>(
    session: &S,
    inbound: &serde_json::Value,
) -> Result<(), ConfigModifyError> {
    if effective_security(inbound) != "tls" {
        return Ok(());
    }

    let mut missing = Vec::new();
    for path_str in tls_certificate_file_paths(inbound) {
        let path = RemotePath::new(&path_str).map_err(|error| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                sanitize_detail(error.message()),
            )
        })?;
        match session.path_is_file(&path).await {
            Ok(true) => {}
            Ok(false) => missing.push(path_str),
            Err(error) => {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::UploadFailed,
                    format!(
                        "Failed to check TLS path '{}': {}",
                        path_str,
                        sanitize_detail(error.message())
                    ),
                ));
            }
        }
    }

    if missing.is_empty() {
        return Ok(());
    }

    Err(ConfigModifyError::new(
        ConfigModifyErrorKind::ValidationFailed,
        format!(
            "TLS certificate/key file not found on remote: {}",
            missing.join(", ")
        ),
    ))
}

/// Collects non-empty trimmed `certificateFile` / `keyFile` from `tlsSettings.certificates[]`.
fn tls_certificate_file_paths(inbound: &serde_json::Value) -> Vec<String> {
    let Some(certs) = inbound
        .get("streamSettings")
        .and_then(|s| s.get("tlsSettings"))
        .and_then(|t| t.get("certificates"))
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };

    let mut paths = Vec::new();
    for cert in certs {
        for key in ["certificateFile", "keyFile"] {
            if let Some(path) = cert
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                paths.push(path.to_owned());
            }
        }
    }
    paths
}

async fn write_modified_file<S: SshSession + Sync>(
    remote: &RemoteAdmin,
    session: &S,
    outcome: &ModifyConfigOutcome,
    validate_hint: &RemoteConfigValidateHint,
) -> Result<(), ConfigModifyError> {
    let path = RemotePath::new(&outcome.source_file).map_err(|error| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            sanitize_detail(error.message()),
        )
    })?;

    write_config_validated(
        remote,
        session,
        &path,
        &outcome.serialized,
        validate_hint,
    )
    .await
}

fn sanitize_detail(message: &str) -> String {
    crate::logging::redact::sanitize_detail(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::XrayConfigParser;

    fn editable_from(json: &str) -> EditableXrayConfig {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file("/etc/xray/config.json", json);
        assert!(outcome.is_success(), "{:?}", outcome.errors());
        let root: serde_json::Value = serde_json::from_str(json).expect("json");
        EditableXrayConfig::from_single_file("/etc/xray/config.json", root, outcome.into_sections())
    }

    #[test]
    fn stale_tag_references_empty_when_tag_unchanged() {
        let editable = editable_from(
            r#"{
                "inbounds":[{"tag":"in-1","protocol":"vless","port":443}],
                "routing":{"rules":[{"inboundTag":["in-1"],"outboundTag":"direct"}]}
            }"#,
        );
        assert!(inbound_stale_tag_references(&editable, 0, Some("in-1")).is_empty());
    }

    #[test]
    fn stale_tag_references_empty_when_old_tag_had_no_refs() {
        let editable = editable_from(
            r#"{
                "inbounds":[{"tag":"in-2","protocol":"vless","port":443}],
                "routing":{"rules":[{"inboundTag":["other"],"outboundTag":"direct"}]}
            }"#,
        );
        assert!(inbound_stale_tag_references(&editable, 0, Some("in-1")).is_empty());
    }

    #[test]
    fn stale_tag_references_lists_rules_after_rename() {
        let editable = editable_from(
            r#"{
                "inbounds":[{"tag":"in-2","protocol":"vless","port":443}],
                "routing":{"rules":[{"inboundTag":["in-1"],"outboundTag":"direct"}]}
            }"#,
        );
        let refs = inbound_stale_tag_references(&editable, 0, Some("in-1"));
        assert_eq!(refs.len(), 1);
        assert!(refs[0].contains("inboundTag"));
    }
}
