//! Application actions that modify Xray configuration (inbounds, clients, log, outbounds).
//!
//! GUI code constructs these requests and passes them to [`ApplicationService`](crate::app::ApplicationService);
//! it must never mutate [`XrayConfigSections`](super::XrayConfigSections) directly.

use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::compatibility::check_inbound_compatibility;
use super::editable::EditableXrayConfig;
use super::inbound_clients::{
    HysteriaClient, InboundClient, InboundClientProtocol, SecretFieldDraft,
    TrojanClient, VlessClient, apply_secret_draft, parse_inbound_client,
    verify_client_fingerprint, write_inbound_client,
};
use super::inbound_edit::{
    InboundGeneral, InboundRef, SniffingSettings, SniffingWriteOutcome, apply_inbound_general,
    apply_inbound_sniffing,
};
use super::inbound_fallbacks::reconcile_inbound_fallbacks;
use super::inbound_protocol::{InboundProtocolDraft, apply_inbound_protocol};
use super::inbound_security::{
    InboundSecurityDraft, InboundSecurityMode, apply_inbound_security,
};
use super::inbound_stream::{InboundStreamDraft, apply_inbound_stream, apply_tunnel_sockopt};
use super::log_settings::{apply_log_settings_to_value, validate_log_settings, LogSettings};
use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::outbound_edit::{OutboundGeneral, OutboundRef, apply_outbound_general};
use super::outbound_protocol::{OutboundSettingsDraft, apply_outbound_settings, is_shell_editable_protocol};
use super::serialize::validate_serialized_json;
use crate::xray::secret::SecretString;

/// Request to add a VLESS client to a supported inbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddUserRequest {
    /// Merged inbound index that receives the new client.
    pub inbound_index: usize,
    /// Client email (stats / logs identifier).
    pub email: String,
    /// Client UUID. When `None`, a new UUID v4 is generated.
    pub id: Option<String>,
    /// Optional XTLS flow. Empty / whitespace-only values omit the field.
    pub flow: Option<String>,
    /// Policy level (default 0).
    pub level: u32,
}

/// Enum client Add request (IB-L1: VLESS | Trojan | Hysteria).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddInboundClientRequest {
    /// VLESS client.
    Vless(AddUserRequest),
    /// Trojan client.
    Trojan {
        /// Merged inbound index.
        inbound_index: usize,
        /// Client email.
        email: String,
        /// Non-empty password.
        password: SecretString,
        /// Policy level.
        level: u32,
    },
    /// Hysteria client.
    Hysteria {
        /// Merged inbound index.
        inbound_index: usize,
        /// Client email.
        email: String,
        /// Non-empty auth string.
        auth: SecretString,
        /// Policy level.
        level: u32,
    },
}

/// Request to update editable fields of an existing VLESS client.
///
/// UUID / `id` is intentionally not part of this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateUserRequest {
    /// Merged inbound index that owns the client.
    pub inbound_index: usize,
    /// Zero-based index inside the inbound clients/users array.
    pub client_index: usize,
    /// Replacement email.
    pub email: String,
    /// Replacement flow. Empty / whitespace-only values remove the field.
    pub flow: Option<String>,
    /// Policy level.
    pub level: u32,
    /// Fingerprint from edit intent; when `Some`, must match before write.
    pub expected_fingerprint: Option<String>,
}

/// Enum client Update request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateInboundClientRequest {
    /// VLESS email/flow/level.
    Vless(UpdateUserRequest),
    /// Trojan email/level + password draft.
    Trojan {
        /// Merged inbound index.
        inbound_index: usize,
        /// Client index.
        client_index: usize,
        /// Replacement email.
        email: String,
        /// Password draft (Preserve or Replace).
        password: SecretFieldDraft,
        /// Policy level.
        level: u32,
        /// Optional fingerprint check.
        expected_fingerprint: Option<String>,
    },
    /// Hysteria email/level + auth draft.
    Hysteria {
        /// Merged inbound index.
        inbound_index: usize,
        /// Client index.
        client_index: usize,
        /// Replacement email.
        email: String,
        /// Auth draft (Preserve or Replace).
        auth: SecretFieldDraft,
        /// Policy level.
        level: u32,
        /// Optional fingerprint check.
        expected_fingerprint: Option<String>,
    },
}

/// Request to delete one VLESS client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteUserRequest {
    /// Merged inbound index that owns the client.
    pub inbound_index: usize,
    /// Zero-based index inside the inbound clients/users array.
    pub client_index: usize,
    /// Fingerprint from delete intent; when `Some`, must match before delete.
    pub expected_fingerprint: Option<String>,
}

/// Enum client Delete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteInboundClientRequest {
    /// Delete by index (protocol checked via mutate gate).
    Client(DeleteUserRequest),
}

/// Request to replace the top-level Xray `log` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateLogSettingsRequest {
    /// Validated draft settings to write.
    pub settings: LogSettings,
}

/// Request to append a WireGuard (or other) outbound object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOutboundRequest {
    /// Full outbound JSON object (must include `protocol` and `tag`).
    pub outbound: Value,
    /// Optional preferred source file for confdir layouts.
    pub preferred_source_file: Option<String>,
}

/// Request to replace an existing outbound identified by tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceOutboundRequest {
    /// Existing outbound tag to replace.
    pub tag: String,
    /// Replacement outbound JSON object (tag should match `tag`).
    pub outbound: Value,
}

/// Request to remove an outbound by tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveOutboundRequest {
    /// Outbound tag to remove.
    pub tag: String,
}

/// Add a shell-editable outbound (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOutboundShellRequest {
    /// General fields (tag required).
    pub general: OutboundGeneral,
    /// Protocol-tab draft.
    pub settings: OutboundSettingsDraft,
    /// Preferred primary config path.
    pub preferred_source_file: Option<String>,
}

/// Shell Save for an existing shell-editable outbound (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
///
/// Tag rename is not supported here (Roadmap §2.4:99, separate follow-up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateOutboundShellRequest {
    /// Outbound identity + fingerprint at edit intent.
    pub outbound_ref: OutboundRef,
    /// General fields (tag must match the existing outbound).
    pub general: OutboundGeneral,
    /// Protocol-tab draft.
    pub settings: OutboundSettingsDraft,
}

/// Request to update inbound General fields (tag / listen / port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInboundGeneralRequest {
    /// Inbound identity + fingerprint at edit intent.
    pub inbound_ref: InboundRef,
    /// Full-state General form values.
    pub general: InboundGeneral,
}

/// Request to update inbound sniffing settings.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateInboundSniffingRequest {
    /// Inbound identity + fingerprint at edit intent.
    pub inbound_ref: InboundRef,
    /// Full-state sniffing form values.
    pub sniffing: SniffingSettings,
}

/// Single Shell Save covering General + Protocol + Sniffing (+ Security for Trojan).
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateInboundShellRequest {
    /// Inbound identity + fingerprint at edit intent.
    pub inbound_ref: InboundRef,
    /// General form values.
    pub general: InboundGeneral,
    /// Protocol-tab draft.
    pub protocol: InboundProtocolDraft,
    /// Stream-tab draft (IB-L3).
    pub stream: InboundStreamDraft,
    /// Sniffing form values.
    pub sniffing: SniffingSettings,
    /// Security draft: required Reality for Trojan; optional none/reality for VLESS (IB-L4).
    pub security: Option<InboundSecurityDraft>,
}

/// Add inbound (VLESS minimal or Trojan + Reality).
#[derive(Debug, Clone, PartialEq)]
pub struct AddInboundRequest {
    /// Wire protocol.
    pub protocol: InboundClientProtocol,
    /// General fields (tag/listen/port required as per form).
    pub general: InboundGeneral,
    /// Protocol draft (VLESS decryption / Trojan unit).
    pub protocol_draft: InboundProtocolDraft,
    /// Stream draft (IB-L3).
    pub stream: InboundStreamDraft,
    /// Sniffing (defaults ok).
    pub sniffing: SniffingSettings,
    /// Reality required when protocol is Trojan; optional for VLESS (none or reality).
    pub security: Option<InboundSecurityDraft>,
    /// Preferred primary config path.
    pub preferred_source_file: Option<String>,
}

/// Request to delete an entire inbound from the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteInboundRequest {
    /// Merged inbound index.
    pub inbound_index: usize,
    /// Fingerprint from delete intent; when `Some`, must match before delete.
    pub expected_fingerprint: Option<String>,
}

/// Request to duplicate an inbound (deep JSON copy with a unique tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateInboundRequest {
    /// Merged inbound index to clone.
    pub inbound_index: usize,
}

/// Result of a successful in-memory modification before remote write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyConfigOutcome {
    /// Absolute/relative path of the file that must be backed up and rewritten.
    pub source_file: String,
    /// Serialized JSON bytes for that file (after mutation).
    pub serialized: Vec<u8>,
    /// Serialized JSON bytes for that file before mutation (conflict detection).
    pub original_serialized: Vec<u8>,
}

/// Alias retained for existing VLESS user call sites.
pub type ModifyUserOutcome = ModifyConfigOutcome;

/// Adds a VLESS client to the editable configuration model.
pub fn add_user(
    config: &mut EditableXrayConfig,
    request: AddUserRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    add_inbound_client(config, AddInboundClientRequest::Vless(request))
}

/// Adds a VLESS or Trojan client.
pub fn add_inbound_client(
    config: &mut EditableXrayConfig,
    request: AddInboundClientRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    match request {
        AddInboundClientRequest::Vless(request) => add_vless_client(config, request),
        AddInboundClientRequest::Trojan {
            inbound_index,
            email,
            password,
            level,
        } => add_trojan_client(config, inbound_index, email, password, level),
        AddInboundClientRequest::Hysteria {
            inbound_index,
            email,
            auth,
            level,
        } => add_hysteria_client(config, inbound_index, email, auth, level),
    }
}

fn add_vless_client(
    config: &mut EditableXrayConfig,
    request: AddUserRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    // Guard: only VLESS inbounds accept VLESS clients.
    let protocol = config
        .sections()
        .inbounds()
        .get(request.inbound_index)
        .and_then(|i| i.value().get("protocol"))
        .and_then(serde_json::Value::as_str)
        .and_then(InboundClientProtocol::from_wire);
    if !matches!(protocol, Some(InboundClientProtocol::Vless)) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::UnsupportedInbound,
            String::new(),
        ));
    }

    let email = normalize_email(&request.email)?;
    let id = match request.id {
        Some(value) => {
            let trimmed = value.trim().to_owned();
            if trimmed.is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "UUID must not be empty".to_owned(),
                ));
            }
            trimmed
        }
        None => Uuid::new_v4().to_string(),
    };
    let flow = normalize_optional_flow(request.flow);

    validate_no_uuid_conflict(config, request.inbound_index, &id, None)?;
    validate_no_email_conflict(config, request.inbound_index, &email, None)?;

    let typed = InboundClient::Vless(VlessClient {
        id,
        email: Some(email),
        flow,
        level: request.level,
        extras: Map::new(),
    });
    let client = write_inbound_client(&typed);

    let original_by_file = snapshot_all_roots(config)?;

    let (location, _) = config.with_clients_mut(request.inbound_index, |clients| {
        clients.push(client.clone());
        Ok(())
    })?;

    if let Err(error) = check_inbound_after_client_mutate(config, request.inbound_index) {
        let _ = config.with_clients_mut(request.inbound_index, |clients| {
            let _ = clients.pop();
            Ok(())
        });
        return Err(error);
    }

    finish_modification(config, &location.source_file, &original_by_file)
}

fn add_trojan_client(
    config: &mut EditableXrayConfig,
    inbound_index: usize,
    email: String,
    password: SecretString,
    level: u32,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let email = normalize_email(&email)?;
    if password.expose().trim().is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Trojan password must not be empty".to_owned(),
        ));
    }
    validate_no_email_conflict(config, inbound_index, &email, None)?;

    let typed = InboundClient::Trojan(TrojanClient {
        password,
        email: Some(email),
        level,
        extras: Map::new(),
    });
    let client = write_inbound_client(&typed);
    let original_by_file = snapshot_all_roots(config)?;
    let (location, _) = config.with_clients_mut(inbound_index, |clients| {
        clients.push(client.clone());
        Ok(())
    })?;
    finish_modification(config, &location.source_file, &original_by_file)
}

fn add_hysteria_client(
    config: &mut EditableXrayConfig,
    inbound_index: usize,
    email: String,
    auth: SecretString,
    level: u32,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let email = normalize_email(&email)?;
    if auth.expose().trim().is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Hysteria auth must not be empty".to_owned(),
        ));
    }
    validate_no_email_conflict(config, inbound_index, &email, None)?;

    let typed = InboundClient::Hysteria(HysteriaClient {
        auth,
        email: Some(email),
        level,
        extras: Map::new(),
    });
    let client = write_inbound_client(&typed);
    let original_by_file = snapshot_all_roots(config)?;
    let (location, _) = config.with_clients_mut(inbound_index, |clients| {
        clients.push(client.clone());
        Ok(())
    })?;
    finish_modification(config, &location.source_file, &original_by_file)
}


/// Updates email/flow/level of an existing VLESS client while preserving unknown fields.
pub fn update_user(
    config: &mut EditableXrayConfig,
    request: UpdateUserRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    update_inbound_client(config, UpdateInboundClientRequest::Vless(request))
}

/// Updates a VLESS or Trojan client.
pub fn update_inbound_client(
    config: &mut EditableXrayConfig,
    request: UpdateInboundClientRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    match request {
        UpdateInboundClientRequest::Vless(request) => update_vless_client(config, request),
        UpdateInboundClientRequest::Trojan {
            inbound_index,
            client_index,
            email,
            password,
            level,
            expected_fingerprint,
        } => update_trojan_client(
            config,
            inbound_index,
            client_index,
            email,
            password,
            level,
            expected_fingerprint,
        ),
        UpdateInboundClientRequest::Hysteria {
            inbound_index,
            client_index,
            email,
            auth,
            level,
            expected_fingerprint,
        } => update_hysteria_client(
            config,
            inbound_index,
            client_index,
            email,
            auth,
            level,
            expected_fingerprint,
        ),
    }
}

fn update_vless_client(
    config: &mut EditableXrayConfig,
    request: UpdateUserRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let email = normalize_email(&request.email)?;
    let flow = normalize_optional_flow(request.flow);

    validate_no_email_conflict(
        config,
        request.inbound_index,
        &email,
        Some(request.client_index),
    )?;

    let original_by_file = snapshot_all_roots(config)?;

    let previous_client = config
        .client_object(request.inbound_index, request.client_index)?
        .clone();

    let (location, _) = config.with_clients_mut(request.inbound_index, |clients| {
        let client = clients.get_mut(request.client_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::UserNotFound, String::new())
        })?;

        if let Some(expected) = &request.expected_fingerprint {
            verify_client_fingerprint(client, expected)?;
        }

        let parsed = parse_inbound_client(InboundClientProtocol::Vless, client)?;
        let InboundClient::Vless(mut vless) = parsed else {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UnsupportedInbound,
                String::new(),
            ));
        };

        vless.email = Some(email.clone());
        vless.flow = flow.clone();
        vless.level = request.level;
        // id and extras preserved from parse.

        *client = write_inbound_client(&InboundClient::Vless(vless));
        Ok(())
    })?;

    if let Err(error) = check_inbound_after_client_mutate(config, request.inbound_index) {
        let _ = config.with_clients_mut(request.inbound_index, |clients| {
            if let Some(slot) = clients.get_mut(request.client_index) {
                *slot = previous_client;
            }
            Ok(())
        });
        return Err(error);
    }

    finish_modification(config, &location.source_file, &original_by_file)
}

fn update_trojan_client(
    config: &mut EditableXrayConfig,
    inbound_index: usize,
    client_index: usize,
    email: String,
    password: SecretFieldDraft,
    level: u32,
    expected_fingerprint: Option<String>,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let email = normalize_email(&email)?;
    if let SecretFieldDraft::Replace(ref secret) = password
        && secret.expose().trim().is_empty()
    {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Trojan password must not be empty".to_owned(),
        ));
    }
    validate_no_email_conflict(config, inbound_index, &email, Some(client_index))?;

    let original_by_file = snapshot_all_roots(config)?;
    let (location, _) = config.with_clients_mut(inbound_index, |clients| {
        let client = clients.get_mut(client_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::UserNotFound, String::new())
        })?;
        if let Some(expected) = &expected_fingerprint {
            verify_client_fingerprint(client, expected)?;
        }
        let parsed = parse_inbound_client(InboundClientProtocol::Trojan, client)?;
        let InboundClient::Trojan(mut trojan) = parsed else {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UnsupportedInbound,
                String::new(),
            ));
        };
        trojan.password = apply_secret_draft(&trojan.password, password.clone());
        trojan.email = Some(email.clone());
        trojan.level = level;
        *client = write_inbound_client(&InboundClient::Trojan(trojan));
        Ok(())
    })?;
    finish_modification(config, &location.source_file, &original_by_file)
}

fn update_hysteria_client(
    config: &mut EditableXrayConfig,
    inbound_index: usize,
    client_index: usize,
    email: String,
    auth: SecretFieldDraft,
    level: u32,
    expected_fingerprint: Option<String>,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let email = normalize_email(&email)?;
    if let SecretFieldDraft::Replace(ref secret) = auth
        && secret.expose().trim().is_empty()
    {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Hysteria auth must not be empty".to_owned(),
        ));
    }
    validate_no_email_conflict(config, inbound_index, &email, Some(client_index))?;

    let original_by_file = snapshot_all_roots(config)?;
    let (location, _) = config.with_clients_mut(inbound_index, |clients| {
        let client = clients.get_mut(client_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::UserNotFound, String::new())
        })?;
        if let Some(expected) = &expected_fingerprint {
            verify_client_fingerprint(client, expected)?;
        }
        let parsed = parse_inbound_client(InboundClientProtocol::Hysteria, client)?;
        let InboundClient::Hysteria(mut hysteria) = parsed else {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UnsupportedInbound,
                String::new(),
            ));
        };
        hysteria.auth = apply_secret_draft(&hysteria.auth, auth.clone());
        hysteria.email = Some(email.clone());
        hysteria.level = level;
        *client = write_inbound_client(&InboundClient::Hysteria(hysteria));
        Ok(())
    })?;
    finish_modification(config, &location.source_file, &original_by_file)
}


/// Updates inbound General fields while preserving opaque settings/streamSettings.
pub fn update_inbound_general(
    config: &mut EditableXrayConfig,
    request: UpdateInboundGeneralRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let inbound_index = request.inbound_ref.location.inbound_index;
    validate_no_duplicate_inbound_tag(
        config,
        inbound_index,
        request.general.tag.as_deref(),
    )?;

    let original_by_file = snapshot_all_roots(config)?;
    let (location, _) = config.with_inbound_mut(
        inbound_index,
        &request.inbound_ref.expected_fingerprint,
        |inbound| apply_inbound_general(inbound, &request.general),
    )?;
    finish_modification(config, &location.source_file, &original_by_file)
}

/// Updates inbound sniffing while preserving extras and unknown destOverride tokens.
pub fn update_inbound_sniffing(
    config: &mut EditableXrayConfig,
    request: UpdateInboundSniffingRequest,
) -> ConfigModifyResult<(ModifyConfigOutcome, SniffingWriteOutcome)> {
    use super::inbound_clients::verify_inbound_fingerprint;

    let inbound_index = request.inbound_ref.location.inbound_index;
    let location = config.require_shell_editable_inbound(inbound_index)?;
    let inbound_value = config.sections().inbounds()[location.inbound_index].value();
    verify_inbound_fingerprint(inbound_value, &request.inbound_ref.expected_fingerprint)?;

    let mut probe = inbound_value.clone();
    let probe_outcome = apply_inbound_sniffing(&mut probe, &request.sniffing)?;
    if probe_outcome == SniffingWriteOutcome::NoWrite {
        let original = config.serialize_source_file(&location.source_file)?;
        return Ok((
            ModifyConfigOutcome {
                source_file: location.source_file,
                serialized: original.clone(),
                original_serialized: original,
            },
            SniffingWriteOutcome::NoWrite,
        ));
    }

    let original_by_file = snapshot_all_roots(config)?;
    let (location, write_outcome) = config.with_inbound_mut(
        inbound_index,
        &request.inbound_ref.expected_fingerprint,
        |inbound| apply_inbound_sniffing(inbound, &request.sniffing),
    )?;
    let outcome = finish_modification(config, &location.source_file, &original_by_file)?;
    Ok((outcome, write_outcome))
}

/// Composed Shell Save: General + Protocol + Stream + Security + Sniffing + CompatibilityGate.
///
/// Trojan requires Reality security. VLESS may use none or reality (IB-L4).
/// Clients/users array bytes are never rewritten by this path.
pub fn update_inbound_shell(
    config: &mut EditableXrayConfig,
    request: UpdateInboundShellRequest,
) -> ConfigModifyResult<(ModifyConfigOutcome, SniffingWriteOutcome)> {
    let inbound_index = request.inbound_ref.location.inbound_index;
    validate_no_duplicate_inbound_tag(
        config,
        inbound_index,
        request.general.tag.as_deref(),
    )?;

    let protocol = request.inbound_ref.protocol;
    if protocol == InboundClientProtocol::Trojan {
        let security = request.security.as_ref().ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "Trojan Shell Save requires TLS or Reality security settings".to_owned(),
            )
        })?;
        if security.mode == InboundSecurityMode::None {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                super::compatibility::CompatibilityGateId::G6
                    .message()
                    .to_owned(),
            ));
        }
    }

    let original_by_file = snapshot_all_roots(config)?;
    let sniffing_draft = request.sniffing.clone();

    let (location, write_outcome) = config.with_inbound_mut(
        inbound_index,
        &request.inbound_ref.expected_fingerprint,
        |inbound| {
            let clients_before = clients_users_snapshot(inbound);

            apply_inbound_general(inbound, &request.general)?;
            apply_inbound_protocol(inbound, &request.protocol)?;

            // Tunnel: leave streamSettings/security on disk except sockopt.tproxy (Roadmap
            // §2.3:88); GUI does not otherwise edit them.
            if protocol == InboundClientProtocol::Tunnel {
                apply_tunnel_sockopt(inbound, &request.stream)?;
            } else {
                apply_inbound_stream(inbound, &request.stream)?;
                if let Some(security) = request.security.as_ref() {
                    apply_inbound_security(inbound, security)?;
                }
                // Wave C2: strip fallbacks when not TCP+TLS/Reality; else patch ALPN.
                let _ = reconcile_inbound_fallbacks(inbound)?;
            }

            let sniff_outcome = apply_inbound_sniffing(inbound, &sniffing_draft)?;
            check_inbound_compatibility(inbound)?;

            let clients_after = clients_users_snapshot(inbound);
            if !clients_users_equivalent_for_shell(
                &clients_before,
                &clients_after,
                protocol,
            ) {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "shell save must not modify clients/users arrays".to_owned(),
                ));
            }
            Ok(sniff_outcome)
        },
    )?;

    let outcome = finish_modification(config, &location.source_file, &original_by_file)?;
    Ok((outcome, write_outcome))
}

fn clients_users_snapshot(inbound: &Value) -> (Option<Value>, Option<Value>) {
    let settings = inbound.get("settings");
    (
        settings.and_then(|s| s.get("clients")).cloned(),
        settings.and_then(|s| s.get("users")).cloned(),
    )
}

/// Shell save must not add/remove/reorder clients.
fn clients_users_equivalent_for_shell(
    before: &(Option<Value>, Option<Value>),
    after: &(Option<Value>, Option<Value>),
    _protocol: InboundClientProtocol,
) -> bool {
    before == after
}

/// Appends a new inbound (empty clients) to the primary config file.
pub fn add_inbound(
    config: &mut EditableXrayConfig,
    request: AddInboundRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {

    let tag = request
        .general
        .tag
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "inbound tag is required".to_owned(),
            )
        })?;
    validate_no_duplicate_inbound_tag(config, usize::MAX, Some(tag))?;

    let inbound = build_add_inbound_value(&request)?;
    check_inbound_compatibility(&inbound)?;

    let original_by_file = snapshot_all_roots(config)?;
    let location = config.add_inbound_value(
        inbound,
        request.preferred_source_file.as_deref(),
    )?;
    finish_modification(config, &location.source_file, &original_by_file)
}

/// Deletes an inbound by merged index (with optional fingerprint check).
///
/// Allowed for **any** protocol. Hard-blocks when the inbound `tag` is still
/// listed in `routing.rules[].inboundTag`.
pub fn delete_inbound(
    config: &mut EditableXrayConfig,
    request: DeleteInboundRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let _ = config.locate_inbound(request.inbound_index)?;
    if let Some(expected) = &request.expected_fingerprint {
        let actual = config.inbound_object_fingerprint(request.inbound_index)?;
        if actual != *expected {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::FingerprintMismatch,
                String::new(),
            ));
        }
    }

    let inbound_tag = config
        .sections()
        .inbounds()
        .get(request.inbound_index)
        .and_then(|s| s.value().get("tag"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned);

    if let Some(tag) = &inbound_tag {
        let refs = super::tag_refs::inbound_tag_references(config.sections(), tag);
        if !refs.is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                super::tag_refs::format_tag_reference_block("inbound", tag, &refs),
            ));
        }
    }

    let original_by_file = snapshot_all_roots(config)?;
    let location = config.remove_inbound_at(request.inbound_index)?;
    finish_modification(config, &location.source_file, &original_by_file)
}

/// Request to delete an outbound by merged index (GUI Delete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOutboundRequest {
    /// Merged outbound index.
    pub outbound_index: usize,
    /// Fingerprint from delete intent; when `Some`, must match before delete.
    pub expected_fingerprint: Option<String>,
}

/// Deletes an outbound by merged index (with optional fingerprint check).
///
/// Hard-blocks when the outbound `tag` is referenced by routing rules or
/// balancer selectors.
pub fn delete_outbound(
    config: &mut EditableXrayConfig,
    request: DeleteOutboundRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let _ = config.locate_outbound(request.outbound_index)?;
    if let Some(expected) = &request.expected_fingerprint {
        let actual = config.outbound_object_fingerprint(request.outbound_index)?;
        if actual != *expected {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::FingerprintMismatch,
                String::new(),
            ));
        }
    }

    let outbound_tag = config
        .sections()
        .outbounds()
        .get(request.outbound_index)
        .and_then(|s| s.value().get("tag"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned);

    if let Some(tag) = &outbound_tag {
        let refs = super::tag_refs::outbound_tag_references(config.sections(), tag);
        if !refs.is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                super::tag_refs::format_tag_reference_block("outbound", tag, &refs),
            ));
        }
    }

    let original_by_file = snapshot_all_roots(config)?;
    let location = config.remove_outbound_at(request.outbound_index)?;
    finish_outbound_modification(config, &location.source_file, &original_by_file)
}

/// Deep-copies an inbound into the same source file with a unique tag.
pub fn duplicate_inbound(
    config: &mut EditableXrayConfig,
    request: DuplicateInboundRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let _ = config.require_shell_editable_inbound(request.inbound_index)?;
    let source = config
        .sections()
        .inbounds()
        .get(request.inbound_index)
        .ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
        })?;
    let source_file = source.source_file().to_owned();
    let mut clone = source.value().clone();
    let base_tag = clone
        .get("tag")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned);
    let new_tag = unique_inbound_copy_tag(config, base_tag.as_deref());
    let object = clone.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        )
    })?;
    object.insert("tag".to_owned(), Value::String(new_tag));

    check_inbound_compatibility(&clone)?;

    let original_by_file = snapshot_all_roots(config)?;
    let location = config.add_inbound_value(clone, Some(&source_file))?;
    finish_modification(config, &location.source_file, &original_by_file)
}

fn unique_inbound_copy_tag(config: &EditableXrayConfig, base: Option<&str>) -> String {
    let base = base.unwrap_or("inbound");
    let candidates = std::iter::once(format!("{base}-copy")).chain((2u32..).map(|n| {
        format!("{base}-copy-{n}")
    }));
    for candidate in candidates {
        let taken = config.sections().inbounds().iter().any(|entry| {
            entry
                .value()
                .get("tag")
                .and_then(Value::as_str)
                .is_some_and(|existing| existing == candidate)
        });
        if !taken {
            return candidate;
        }
    }
    format!("{base}-copy-{}", Uuid::new_v4())
}

fn build_add_inbound_value(request: &AddInboundRequest) -> ConfigModifyResult<Value> {
    let settings = match request.protocol {
        InboundClientProtocol::Hysteria => json!({ "version": 2, "users": [] }),
        InboundClientProtocol::Tunnel => json!({}),
        _ => json!({ "clients": [] }),
    };
    let mut inbound = json!({
        "listen": "0.0.0.0",
        "protocol": request.protocol.as_wire(),
        "settings": settings,
    });

    apply_inbound_general(&mut inbound, &request.general)?;
    apply_inbound_protocol(&mut inbound, &request.protocol_draft)?;

    match request.protocol {
        InboundClientProtocol::Vless => {
            if let Some(security) = request.security.as_ref() {
                apply_inbound_security(&mut inbound, security)?;
            }
        }
        InboundClientProtocol::Trojan => {
            let security = request.security.as_ref().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "Trojan add requires TLS or Reality security settings".to_owned(),
                )
            })?;
            if security.mode == InboundSecurityMode::None {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    super::compatibility::CompatibilityGateId::G6
                        .message()
                        .to_owned(),
                ));
            }
            apply_inbound_security(&mut inbound, security)?;
        }
        InboundClientProtocol::Hysteria => {
            let security = request.security.as_ref().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "Hysteria add requires TLS security settings".to_owned(),
                )
            })?;
            if security.mode != InboundSecurityMode::Tls {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    super::compatibility::CompatibilityGateId::G10
                        .message()
                        .to_owned(),
                ));
            }
            apply_inbound_security(&mut inbound, security)?;
        }
        InboundClientProtocol::Tunnel => {
            // No security draft; stream defaults to tcp/none via stream draft.
        }
    }

    apply_inbound_stream(&mut inbound, &request.stream)?;

    // Wave C2: strip fallbacks when not TCP+TLS/Reality; else patch ALPN.
    if request.protocol != InboundClientProtocol::Tunnel {
        let _ = reconcile_inbound_fallbacks(&mut inbound)?;
    }

    // Apply sniffing when non-default; absent defaults leave key omitted.
    let _ = apply_inbound_sniffing(&mut inbound, &request.sniffing)?;
    Ok(inbound)
}

/// Deletes one VLESS client from the editable configuration model.
pub fn delete_user(
    config: &mut EditableXrayConfig,
    request: DeleteUserRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    delete_inbound_client(config, DeleteInboundClientRequest::Client(request))
}

/// Deletes one inbound client (VLESS or Trojan).
pub fn delete_inbound_client(
    config: &mut EditableXrayConfig,
    request: DeleteInboundClientRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let DeleteInboundClientRequest::Client(request) = request;
    let original_by_file = snapshot_all_roots(config)?;

    let (location, _) = config.with_clients_mut(request.inbound_index, |clients| {
        let client = clients.get(request.client_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::UserNotFound, String::new())
        })?;
        if let Some(expected) = &request.expected_fingerprint {
            verify_client_fingerprint(client, expected)?;
        }
        clients.remove(request.client_index);
        Ok(())
    })?;

    finish_modification(config, &location.source_file, &original_by_file)
}

/// Updates the top-level `log` settings while preserving unknown fields.
pub fn update_log_settings(
    config: &mut EditableXrayConfig,
    request: UpdateLogSettingsRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    validate_log_settings(&request.settings)?;

    let original_by_file = snapshot_all_roots(config)?;

    let (source_file, _) =
        config.with_log_mut(|value| apply_log_settings_to_value(value, &request.settings))?;

    let serialized = config.serialize_source_file(&source_file)?;
    validate_serialized_json(&serialized)?;
    validate_log_structure_after_edit(config, &source_file)?;

    let original_serialized = original_by_file
        .get(&source_file)
        .cloned()
        .unwrap_or_else(|| b"{}\n".to_vec());

    Ok(ModifyConfigOutcome {
        source_file,
        serialized,
        original_serialized,
    })
}

/// Appends an outbound object without touching routing or unrelated sections.
pub fn add_outbound(
    config: &mut EditableXrayConfig,
    request: AddOutboundRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    validate_outbound_object(&request.outbound)?;
    let original_by_file = snapshot_all_roots(config)?;
    let location = config.add_outbound_value(
        request.outbound,
        request.preferred_source_file.as_deref(),
    )?;
    finish_outbound_modification(config, &location.source_file, &original_by_file)
}

/// Replaces an existing outbound by tag (credentials regenerate / adopt write-back).
pub fn replace_outbound(
    config: &mut EditableXrayConfig,
    request: ReplaceOutboundRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let tag = normalize_outbound_tag(&request.tag)?;
    validate_outbound_object(&request.outbound)?;

    let outbound_tag = request
        .outbound
        .get("tag")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "outbound tag must not be empty".to_owned(),
            )
        })?;
    if !outbound_tag.eq_ignore_ascii_case(&tag) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "replacement outbound tag must match the target tag".to_owned(),
        ));
    }

    let index = config.find_outbound_index_by_tag(&tag).ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::OutboundNotFound,
            format!("outbound tag not found: {tag}"),
        )
    })?;

    let original_by_file = snapshot_all_roots(config)?;
    let location = config.replace_outbound_value(index, request.outbound)?;
    finish_outbound_modification(config, &location.source_file, &original_by_file)
}

/// Removes an outbound by tag.
///
/// Hard-blocks when the tag is still referenced by routing rules or balancer selectors.
pub fn remove_outbound(
    config: &mut EditableXrayConfig,
    request: RemoveOutboundRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let tag = normalize_outbound_tag(&request.tag)?;
    let index = config.find_outbound_index_by_tag(&tag).ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::OutboundNotFound,
            format!("outbound tag not found: {tag}"),
        )
    })?;

    let refs = super::tag_refs::outbound_tag_references(config.sections(), &tag);
    if !refs.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            super::tag_refs::format_tag_reference_block("outbound", &tag, &refs),
        ));
    }

    let original_by_file = snapshot_all_roots(config)?;
    let location = config.remove_outbound_at(index)?;
    finish_outbound_modification(config, &location.source_file, &original_by_file)
}

/// Adds a new shell-editable outbound (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
pub fn add_outbound_shell(
    config: &mut EditableXrayConfig,
    request: AddOutboundShellRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let protocol = outbound_settings_protocol_name(&request.settings);
    let mut outbound = json!({ "protocol": protocol, "settings": {} });
    apply_outbound_general(&mut outbound, &request.general)?;
    apply_outbound_settings(&mut outbound, &request.settings)?;
    add_outbound(
        config,
        AddOutboundRequest {
            outbound,
            preferred_source_file: request.preferred_source_file,
        },
    )
}

/// Maps a Protocol-tab draft to its Xray `protocol` string.
fn outbound_settings_protocol_name(settings: &OutboundSettingsDraft) -> &'static str {
    match settings {
        OutboundSettingsDraft::Freedom { .. } => "freedom",
        OutboundSettingsDraft::Blackhole { .. } => "blackhole",
    }
}

/// Shell Save for an existing shell-editable outbound (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
///
/// Fingerprint-checked (mirrors [`update_inbound_shell`]); tag rename is rejected by the
/// underlying [`replace_outbound`] tag-match guard (Roadmap §2.4:99 will relax this).
pub fn update_outbound_shell(
    config: &mut EditableXrayConfig,
    request: UpdateOutboundShellRequest,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let index = request.outbound_ref.outbound_index;
    let _ = config.locate_outbound(index)?;
    let actual = config.outbound_object_fingerprint(index)?;
    if actual != request.outbound_ref.expected_fingerprint {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::FingerprintMismatch,
            String::new(),
        ));
    }

    let original_tag = config
        .sections()
        .outbounds()
        .get(index)
        .and_then(|o| o.value().get("tag"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "outbound tag is required".to_owned(),
            )
        })?;

    let mut outbound = config.sections().outbounds()[index].value().clone();
    apply_outbound_general(&mut outbound, &request.general)?;
    apply_outbound_settings(&mut outbound, &request.settings)?;

    replace_outbound(
        config,
        ReplaceOutboundRequest {
            tag: original_tag,
            outbound,
        },
    )
}

fn finish_modification(
    config: &EditableXrayConfig,
    source_file: &str,
    original_by_file: &std::collections::BTreeMap<String, Vec<u8>>,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let serialized = config.serialize_source_file(source_file)?;
    validate_serialized_json(&serialized)?;
    validate_structure_after_edit(config, source_file)?;
    let original_serialized = original_by_file.get(source_file).cloned().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "original source snapshot missing".to_owned(),
        )
    })?;
    Ok(ModifyUserOutcome {
        source_file: source_file.to_owned(),
        serialized,
        original_serialized,
    })
}

fn finish_outbound_modification(
    config: &EditableXrayConfig,
    source_file: &str,
    original_by_file: &std::collections::BTreeMap<String, Vec<u8>>,
) -> ConfigModifyResult<ModifyConfigOutcome> {
    let serialized = config.serialize_source_file(source_file)?;
    validate_serialized_json(&serialized)?;
    validate_outbound_structure_after_edit(config, source_file)?;
    let original_serialized = original_by_file.get(source_file).cloned().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "original source snapshot missing".to_owned(),
        )
    })?;
    Ok(ModifyConfigOutcome {
        source_file: source_file.to_owned(),
        serialized,
        original_serialized,
    })
}

fn snapshot_all_roots(
    config: &EditableXrayConfig,
) -> ConfigModifyResult<std::collections::BTreeMap<String, Vec<u8>>> {
    let mut map = std::collections::BTreeMap::new();
    for path in config.file_roots().keys() {
        map.insert(path.clone(), config.serialize_source_file(path)?);
    }
    Ok(map)
}

fn validate_no_duplicate_inbound_tag(
    config: &EditableXrayConfig,
    inbound_index: usize,
    new_tag: Option<&str>,
) -> ConfigModifyResult<()> {
    let Some(tag) = new_tag.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(());
    };
    for (index, inbound) in config.sections().inbounds().iter().enumerate() {
        if index == inbound_index {
            continue;
        }
        let Some(existing) = inbound.value().get("tag").and_then(|v: &Value| v.as_str()) else {
            continue;
        };
        if existing == tag {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("inbound tag already in use: {tag}"),
            ));
        }
    }
    Ok(())
}

fn validate_log_structure_after_edit(
    config: &EditableXrayConfig,
    source_file: &str,
) -> ConfigModifyResult<()> {
    let root = config.file_roots().get(source_file).ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "modified source file missing from editable config".to_owned(),
        )
    })?;
    let log = root.get("log").ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "modified file must contain a log object".to_owned(),
        )
    })?;
    if !log.is_object() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::MalformedLogObject,
            "log section must be a JSON object".to_owned(),
        ));
    }
    Ok(())
}

fn validate_structure_after_edit(
    config: &EditableXrayConfig,
    source_file: &str,
) -> ConfigModifyResult<()> {
    let root = config.file_roots().get(source_file).ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "modified source file missing from editable config".to_owned(),
        )
    })?;
    let inbounds = root
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "modified file must contain an inbounds array".to_owned(),
            )
        })?;
    if inbounds.is_empty() {
        // Empty inbounds array is structurally valid JSON; keep allowed.
    }
    Ok(())
}

fn validate_outbound_structure_after_edit(
    config: &EditableXrayConfig,
    source_file: &str,
) -> ConfigModifyResult<()> {
    let root = config.file_roots().get(source_file).ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "modified source file missing from editable config".to_owned(),
        )
    })?;
    let outbounds = root.get("outbounds").ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "modified file must contain an outbounds array".to_owned(),
        )
    })?;
    if !outbounds.is_array() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbounds must be a JSON array".to_owned(),
        ));
    }
    Ok(())
}

fn validate_outbound_object(outbound: &Value) -> ConfigModifyResult<()> {
    let object = outbound.as_object().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound must be a JSON object".to_owned(),
        )
    })?;
    let protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "outbound protocol is required".to_owned(),
            )
        })?;
    if !protocol.eq_ignore_ascii_case("wireguard") && !is_shell_editable_protocol(protocol) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "only wireguard, freedom, or blackhole outbounds may be written by this path".to_owned(),
        ));
    }
    let tag = object
        .get("tag")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "outbound tag must not be empty".to_owned(),
            )
        })?;
    let _ = tag;
    let settings = object.get("settings").ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound settings are required".to_owned(),
        )
    })?;
    if !settings.is_object() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound settings must be a JSON object".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_outbound_tag(tag: &str) -> ConfigModifyResult<String> {
    let trimmed = tag.trim().to_owned();
    if trimmed.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound tag must not be empty".to_owned(),
        ));
    }
    Ok(trimmed)
}

fn normalize_email(email: &str) -> ConfigModifyResult<String> {
    let trimmed = email.trim().to_owned();
    if trimmed.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "email must not be empty".to_owned(),
        ));
    }
    Ok(trimmed)
}

fn normalize_optional_flow(flow: Option<String>) -> Option<String> {
    flow.and_then(|value| {
        let trimmed = value.trim().to_owned();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn validate_no_uuid_conflict(
    config: &EditableXrayConfig,
    inbound_index: usize,
    id: &str,
    except_client: Option<usize>,
) -> ConfigModifyResult<()> {
    let location = config.require_vless_inbound(inbound_index)?;
    let inbound = config.sections().inbounds()[location.inbound_index].value();
    let clients = inbound
        .get("settings")
        .and_then(|settings| {
            settings
                .get("clients")
                .or_else(|| settings.get("users"))
                .and_then(Value::as_array)
        })
        .cloned()
        .unwrap_or_default();

    for (index, client) in clients.iter().enumerate() {
        if except_client == Some(index) {
            continue;
        }
        if client.get("id").and_then(Value::as_str) == Some(id) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UuidConflict,
                "a client with this UUID already exists in the inbound".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_no_email_conflict(
    config: &EditableXrayConfig,
    inbound_index: usize,
    email: &str,
    except_client: Option<usize>,
) -> ConfigModifyResult<()> {
    let location = config.require_vless_inbound(inbound_index)?;
    let inbound = config.sections().inbounds()[location.inbound_index].value();
    let clients = inbound
        .get("settings")
        .and_then(|settings| {
            settings
                .get("clients")
                .or_else(|| settings.get("users"))
                .and_then(Value::as_array)
        })
        .cloned()
        .unwrap_or_default();

    for (index, client) in clients.iter().enumerate() {
        if except_client == Some(index) {
            continue;
        }
        if client.get("email").and_then(Value::as_str) == Some(email) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::EmailConflict,
                "a client with this email already exists in the inbound".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Generates a new UUID v4 string for Add User forms.
pub fn generate_client_uuid() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a new auth string for Add Hysteria user forms.
pub fn generate_client_auth() -> String {
    Uuid::new_v4().to_string()
}

fn check_inbound_after_client_mutate(
    config: &EditableXrayConfig,
    inbound_index: usize,
) -> ConfigModifyResult<()> {
    let inbound = config
        .sections()
        .inbounds()
        .get(inbound_index)
        .ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
        })?;
    check_inbound_compatibility(inbound.value())
}

