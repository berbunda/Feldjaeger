//! Editable Xray configuration with per-file roots for safe write-back.
//!
//! Keeps the merged [`XrayConfigSections`] model for GUI summaries while retaining
//! each source file's original root JSON object. Modifications update both so that
//! config-directory mode rewrites only the affected file.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sections::XrayConfigSections;
use super::serialize::serialize_json_value;
use super::users::{SUPPORTED_USER_PROTOCOL, extract_vless_clients};
use super::{
    BurstObservatorySummary, DnsSummary, FakeDnsSummary, InboundSummary, ObservatorySummary,
    OutboundSummary, PolicySummary, RoutingSummary, VlessClientSummary, burst_observatory_summary,
    dns_summary, fakedns_summary, inbound_summaries, observatory_summary, outbound_summaries,
    policy_summary, routing_summary,
};

/// In-memory editable configuration used by the modification layer.
///
/// [`file_roots`](Self::file_roots) maps absolute/relative source paths to the
/// original root JSON object of that file. Client edits mutate both the merged
/// sections and the matching root so serialization can target a single path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditableXrayConfig {
    sections: XrayConfigSections,
    file_roots: BTreeMap<String, Value>,
}

impl EditableXrayConfig {
    /// Creates an editable config from merged sections and per-file roots.
    pub fn new(sections: XrayConfigSections, file_roots: BTreeMap<String, Value>) -> Self {
        Self {
            sections,
            file_roots,
        }
    }

    /// Builds from a single-file parse: one root object plus sourced sections.
    pub fn from_single_file(
        source_file: impl Into<String>,
        root: Value,
        sections: XrayConfigSections,
    ) -> Self {
        let source_file = source_file.into();
        let mut file_roots = BTreeMap::new();
        file_roots.insert(source_file, root);
        Self {
            sections,
            file_roots,
        }
    }

    /// Merged section model (read-only).
    pub fn sections(&self) -> &XrayConfigSections {
        &self.sections
    }

    /// Mutable merged section model.
    pub fn sections_mut(&mut self) -> &mut XrayConfigSections {
        &mut self.sections
    }

    /// Per-file root JSON objects keyed by source path.
    pub fn file_roots(&self) -> &BTreeMap<String, Value> {
        &self.file_roots
    }

    /// Refreshable inbound summaries from the current sections.
    pub fn inbound_summaries(&self) -> Vec<InboundSummary> {
        inbound_summaries(&self.sections)
    }

    /// Refreshable VLESS client summaries from the current sections.
    pub fn vless_clients(&self) -> Vec<VlessClientSummary> {
        extract_vless_clients(&self.sections)
    }

    /// Refreshable outbound summaries from the current sections.
    pub fn outbound_summaries(&self) -> Vec<OutboundSummary> {
        outbound_summaries(&self.sections)
    }

    /// Refreshable DNS summary from the current sections.
    pub fn dns_summary(&self) -> Option<DnsSummary> {
        dns_summary(&self.sections)
    }

    /// Refreshable FakeDNS summary from the current sections.
    pub fn fakedns_summary(&self) -> Option<FakeDnsSummary> {
        fakedns_summary(&self.sections)
    }

    /// Refreshable Observatory summary from the current sections.
    pub fn observatory_summary(&self) -> Option<ObservatorySummary> {
        observatory_summary(&self.sections)
    }

    /// Refreshable Burst Observatory summary from the current sections.
    pub fn burst_observatory_summary(&self) -> Option<BurstObservatorySummary> {
        burst_observatory_summary(&self.sections)
    }

    /// Refreshable routing summary from the current sections.
    pub fn routing_summary(&self) -> Option<RoutingSummary> {
        routing_summary(&self.sections)
    }

    /// Refreshable policy summary from the current sections.
    pub fn policy_summary(&self) -> Option<PolicySummary> {
        policy_summary(&self.sections)
    }

    /// Serializes the JSON root for `source_file`.
    pub fn serialize_source_file(&self, source_file: &str) -> ConfigModifyResult<Vec<u8>> {
        let root = self.file_roots.get(source_file).ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::SerializationFailed,
                format!("source file not present in editable config: {source_file}"),
            )
        })?;
        serialize_json_value(root)
    }

    /// Locates an inbound by merged index and returns its source path + within-file index.
    pub fn locate_inbound(&self, inbound_index: usize) -> ConfigModifyResult<InboundLocation> {
        let inbound = self.sections.inbounds().get(inbound_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
        })?;

        let source_file = inbound.source_file().to_owned();
        let within_file_index = self
            .sections
            .inbounds()
            .iter()
            .take(inbound_index)
            .filter(|entry| entry.source_file() == source_file)
            .count();

        Ok(InboundLocation {
            inbound_index,
            source_file,
            within_file_index,
        })
    }

    /// Ensures the inbound is VLESS and returns its location.
    pub fn require_vless_inbound(
        &self,
        inbound_index: usize,
    ) -> ConfigModifyResult<InboundLocation> {
        let location = self.locate_inbound(inbound_index)?;
        let inbound = &self.sections.inbounds()[location.inbound_index];
        if !is_vless_protocol(inbound.value()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UnsupportedInbound,
                String::new(),
            ));
        }
        Ok(location)
    }

    /// Applies `op` to the merged inbound clients array, then syncs the file root.
    pub fn with_clients_mut<F, R>(
        &mut self,
        inbound_index: usize,
        op: F,
    ) -> ConfigModifyResult<(InboundLocation, R)>
    where
        F: FnOnce(&mut Vec<Value>) -> ConfigModifyResult<R>,
    {
        let location = self.require_vless_inbound(inbound_index)?;

        let result = {
            let inbound = self
                .sections
                .inbounds_mut()
                .get_mut(location.inbound_index)
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
                })?;
            let clients = clients_array_mut(inbound.value_mut())?;
            op(clients)?
        };

        let merged_clients = {
            let inbound = self.sections.inbounds()[location.inbound_index].value();
            clients_array_snapshot(inbound)?
        };

        {
            let root = self
                .file_roots
                .get_mut(&location.source_file)
                .ok_or_else(|| {
                    ConfigModifyError::new(
                        ConfigModifyErrorKind::InboundNotFound,
                        "source file root missing".to_owned(),
                    )
                })?;
            let file_inbound = root
                .as_object_mut()
                .and_then(|object| object.get_mut("inbounds"))
                .and_then(Value::as_array_mut)
                .and_then(|inbounds| inbounds.get_mut(location.within_file_index))
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
                })?;
            let clients = clients_array_mut(file_inbound)?;
            *clients = merged_clients;
        }

        Ok((location, result))
    }
}

/// Locates one inbound across the merged model and its originating file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundLocation {
    /// Index in the merged inbound list.
    pub inbound_index: usize,
    /// Path of the file that owns this inbound.
    pub source_file: String,
    /// Index inside that file's `inbounds` array.
    pub within_file_index: usize,
}

/// Parses file contents into roots for an [`EditableXrayConfig`].
pub fn parse_file_roots(
    files: impl IntoIterator<Item = (String, String)>,
) -> ConfigModifyResult<BTreeMap<String, Value>> {
    let mut entries: Vec<(String, String)> = files.into_iter().collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut file_roots = BTreeMap::new();
    for (path, contents) in entries {
        let root: Value = serde_json::from_str(&contents).map_err(|error| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("invalid JSON while building editable roots: {error}"),
            )
        })?;
        if !root.is_object() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "config root must be a JSON object".to_owned(),
            ));
        }
        file_roots.insert(path, root);
    }

    Ok(file_roots)
}

/// Ensures `settings` exists as an object on an inbound value.
pub(crate) fn ensure_settings_object(
    inbound: &mut Value,
) -> ConfigModifyResult<&mut Map<String, Value>> {
    let object = inbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        )
    })?;

    if !object.contains_key("settings") {
        object.insert("settings".to_owned(), Value::Object(Map::new()));
    }

    object
        .get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "inbound settings must be a JSON object".to_owned(),
            )
        })
}

/// Returns the clients/users array key present on the inbound (`clients` preferred).
pub(crate) fn clients_array_key(inbound: &Value) -> &'static str {
    let Some(settings) = inbound.get("settings") else {
        return "clients";
    };
    if settings.get("clients").and_then(Value::as_array).is_some() {
        return "clients";
    }
    if settings.get("users").and_then(Value::as_array).is_some() {
        return "users";
    }
    "clients"
}

/// Mutable access to the clients/users array, creating `clients` when absent.
pub(crate) fn clients_array_mut(inbound: &mut Value) -> ConfigModifyResult<&mut Vec<Value>> {
    let key = clients_array_key(inbound).to_owned();
    let settings = ensure_settings_object(inbound)?;

    if !settings.contains_key(&key) {
        settings.insert(key.clone(), Value::Array(Vec::new()));
    }

    settings
        .get_mut(&key)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("inbound settings.{key} must be a JSON array"),
            )
        })
}

fn clients_array_snapshot(inbound: &Value) -> ConfigModifyResult<Vec<Value>> {
    let key = clients_array_key(inbound);
    inbound
        .get("settings")
        .and_then(|settings| settings.get(key))
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("inbound settings.{key} must be a JSON array"),
            )
        })
}

pub(crate) fn is_vless_protocol(inbound: &Value) -> bool {
    inbound
        .get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|protocol| protocol.eq_ignore_ascii_case(SUPPORTED_USER_PROTOCOL))
}
