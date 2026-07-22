//! Application actions that add, update, or delete VLESS clients.
//!
//! GUI code constructs these requests and passes them to [`ApplicationService`](crate::app::ApplicationService);
//! it must never mutate [`XrayConfigSections`](super::XrayConfigSections) directly.

use serde_json::{Map, Value};
use uuid::Uuid;

use super::editable::EditableXrayConfig;
use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::serialize::validate_serialized_json;

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
}

/// Request to delete one VLESS client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteUserRequest {
    /// Merged inbound index that owns the client.
    pub inbound_index: usize,
    /// Zero-based index inside the inbound clients/users array.
    pub client_index: usize,
}

/// Result of a successful in-memory modification before remote write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyUserOutcome {
    /// Absolute/relative path of the file that must be backed up and rewritten.
    pub source_file: String,
    /// Serialized JSON bytes for that file.
    pub serialized: Vec<u8>,
}

/// Adds a VLESS client to the editable configuration model.
pub fn add_user(
    config: &mut EditableXrayConfig,
    request: AddUserRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
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

    let mut client = Map::new();
    client.insert("id".to_owned(), Value::String(id));
    client.insert("email".to_owned(), Value::String(email));
    if let Some(flow) = flow {
        client.insert("flow".to_owned(), Value::String(flow));
    }
    let client = Value::Object(client);

    let (location, _) = config.with_clients_mut(request.inbound_index, |clients| {
        clients.push(client.clone());
        Ok(())
    })?;

    finish_modification(config, &location.source_file)
}

/// Updates email/flow of an existing VLESS client while preserving unknown fields.
pub fn update_user(
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

    let (location, _) = config.with_clients_mut(request.inbound_index, |clients| {
        let client = clients.get_mut(request.client_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::UserNotFound, String::new())
        })?;
        let object = client.as_object_mut().ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "client entry must be a JSON object".to_owned(),
            )
        })?;

        object.insert("email".to_owned(), Value::String(email.clone()));
        match &flow {
            Some(value) => {
                object.insert("flow".to_owned(), Value::String(value.clone()));
            }
            None => {
                object.remove("flow");
            }
        }
        Ok(())
    })?;

    finish_modification(config, &location.source_file)
}

/// Deletes one VLESS client from the editable configuration model.
pub fn delete_user(
    config: &mut EditableXrayConfig,
    request: DeleteUserRequest,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let (location, _) = config.with_clients_mut(request.inbound_index, |clients| {
        if request.client_index >= clients.len() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UserNotFound,
                String::new(),
            ));
        }
        clients.remove(request.client_index);
        Ok(())
    })?;

    finish_modification(config, &location.source_file)
}

fn finish_modification(
    config: &EditableXrayConfig,
    source_file: &str,
) -> ConfigModifyResult<ModifyUserOutcome> {
    let serialized = config.serialize_source_file(source_file)?;
    validate_serialized_json(&serialized)?;
    validate_structure_after_edit(config, source_file)?;
    Ok(ModifyUserOutcome {
        source_file: source_file.to_owned(),
        serialized,
    })
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
