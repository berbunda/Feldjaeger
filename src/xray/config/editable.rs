//! Editable Xray configuration with per-file roots for safe write-back.
//!
//! Keeps the merged [`XrayConfigSections`] model for GUI summaries while retaining
//! each source file's original root JSON object. Modifications update both so that
//! config-directory mode rewrites only the affected file.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::log_settings::{LogSettings, log_settings_from_section};
use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sections::XrayConfigSections;
use super::serialize::serialize_json_value;
use super::sourced_section::SourcedSection;
use super::users::extract_vless_clients;
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

    /// Returns the first (or only) source file path, useful as a preferred write target.
    pub fn primary_source_file(&self) -> Option<&str> {
        self.file_roots.keys().next().map(String::as_str)
    }

    /// Inserts a new, empty (`{}`) file root (confdir file add; Roadmap §2.5:107).
    pub fn insert_empty_file_root(&mut self, path: String) -> ConfigModifyResult<()> {
        if self.file_roots.contains_key(&path) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("file already present in configuration: {path}"),
            ));
        }
        self.file_roots.insert(path, Value::Object(Map::new()));
        Ok(())
    }

    /// Removes a file root (confdir file remove; Roadmap §2.5:107).
    ///
    /// Does **not** check whether the file is empty of sections — callers (`modify.rs`) must
    /// gate that via [`XrayConfigSections::sections_in_file`] before calling this.
    pub fn remove_file_root(&mut self, path: &str) -> ConfigModifyResult<()> {
        if self.file_roots.remove(path).is_none() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("file not present in configuration: {path}"),
            ));
        }
        Ok(())
    }

    /// Refreshable inbound summaries from the current sections.
    pub fn inbound_summaries(&self) -> Vec<InboundSummary> {
        inbound_summaries(&self.sections)
    }

    /// Refreshable VLESS client summaries from the current sections.
    pub fn vless_clients(&self) -> Vec<VlessClientSummary> {
        extract_vless_clients(&self.sections)
    }

    /// All inbound clients (VLESS + Trojan) from the current sections.
    pub fn inbound_clients(&self) -> Vec<crate::xray::config::users::InboundClientSummary> {
        crate::xray::config::users::extract_inbound_clients(&self.sections)
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

    /// Typed `log` settings derived from the current sections.
    pub fn log_settings(&self) -> LogSettings {
        log_settings_from_section(self.sections.log())
    }

    /// Applies `op` to the `log` object, creating it when absent, then syncs the file root.
    ///
    /// When the section is missing, a target file is chosen: the sole file root when there
    /// is only one, otherwise the lexicographically first path that already exists in
    /// [`file_roots`](Self::file_roots). The `log` object is not created merely by opening
    /// the Log Settings page — only when this method runs during a save.
    pub fn with_log_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.log() {
            section.source_file().to_owned()
        } else {
            resolve_log_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.log().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_log(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().log_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "log section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .log()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "log section missing after edit".to_owned(),
                )
            })?;

        {
            let root = self.file_roots.get_mut(&source_file).ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    format!("source file root missing: {source_file}"),
                )
            })?;
            let object = root.as_object_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "config root must be a JSON object".to_owned(),
                )
            })?;
            object.insert("log".to_owned(), merged);
        }

        Ok((source_file, result))
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
    /// Ensures the inbound is a Tier‑2 protocol with mutate enabled (Lake 1: VLESS).
    pub fn require_tier2_mutate_inbound(
        &self,
        inbound_index: usize,
    ) -> ConfigModifyResult<InboundLocation> {
        use super::inbound_clients::InboundClientProtocol;

        let location = self.locate_inbound(inbound_index)?;
        let inbound = &self.sections.inbounds()[location.inbound_index];
        let protocol = inbound
            .value()
            .get("protocol")
            .and_then(Value::as_str)
            .and_then(InboundClientProtocol::from_wire);
        let Some(protocol) = protocol else {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UnsupportedInbound,
                String::new(),
            ));
        };
        protocol.require_mutate_enabled()?;
        // Ambiguous arrays fail early on read path used by mutate.
        let _ = super::inbound_clients::resolve_clients_array_key(inbound.value())?;
        Ok(location)
    }

    /// Ensures the inbound uses the VLESS protocol (legacy alias).
    pub fn require_vless_inbound(
        &self,
        inbound_index: usize,
    ) -> ConfigModifyResult<InboundLocation> {
        self.require_tier2_mutate_inbound(inbound_index)
    }

    /// SHA-256 fingerprint of a client object at `(inbound_index, client_index)`.
    pub fn client_fingerprint(
        &self,
        inbound_index: usize,
        client_index: usize,
    ) -> ConfigModifyResult<String> {
        use super::inbound_clients::client_fingerprint;

        let _ = self.require_tier2_mutate_inbound(inbound_index)?;
        let inbound = self.sections.inbounds().get(inbound_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
        })?;
        let clients = clients_array_snapshot(inbound.value())?;
        let client = clients.get(client_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::UserNotFound, String::new())
        })?;
        client_fingerprint(client)
    }

    /// Borrowed client JSON for Share URI (password/id only — never log).
    pub fn client_object(
        &self,
        inbound_index: usize,
        client_index: usize,
    ) -> ConfigModifyResult<&Value> {
        let _ = self.require_tier2_mutate_inbound(inbound_index)?;
        let inbound = self.sections.inbounds().get(inbound_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
        })?;
        let key = clients_array_key(inbound.value())?;
        let array = inbound
            .value()
            .get("settings")
            .and_then(|s| s.get(key))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ConfigModifyError::new(ConfigModifyErrorKind::UserNotFound, String::new())
            })?;
        array.get(client_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::UserNotFound, String::new())
        })
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
        let location = self.require_tier2_mutate_inbound(inbound_index)?;

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

    /// Applies `op` to the full Tier‑2 inbound object, then syncs it into the file root.
    ///
    /// Mutates an inbound and may rewrite non-client keys under `settings`
    /// (for example protocol-level fields) while preserving unknown client extras.
    pub fn with_tier2_inbound_mut<F, R>(
        &mut self,
        inbound_index: usize,
        op: F,
    ) -> ConfigModifyResult<(InboundLocation, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let location = self.require_tier2_mutate_inbound(inbound_index)?;

        let result = {
            let inbound = self
                .sections
                .inbounds_mut()
                .get_mut(location.inbound_index)
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
                })?;
            op(inbound.value_mut())?
        };

        let merged_inbound = self.sections.inbounds()[location.inbound_index]
            .value()
            .clone();

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
            *file_inbound = merged_inbound;
        }

        Ok((location, result))
    }

    /// Replaces the full inbound object at `inbound_index` wholesale, then syncs it into the
    /// file root — any protocol, including unsupported ones (Roadmap §3:125 raw JSON escape
    /// hatch). Callers are responsible for fingerprint verification and any tag-uniqueness
    /// check before calling this (see `modify::replace_inbound_raw_json`).
    pub fn replace_inbound_value(
        &mut self,
        inbound_index: usize,
        new_value: Value,
    ) -> ConfigModifyResult<InboundLocation> {
        if !new_value.is_object() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "inbound must be a JSON object".to_owned(),
            ));
        }

        let location = self.locate_inbound(inbound_index)?;

        {
            let inbound = self
                .sections
                .inbounds_mut()
                .get_mut(location.inbound_index)
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
                })?;
            *inbound.value_mut() = new_value;
        }

        let merged_inbound = self.sections.inbounds()[location.inbound_index]
            .value()
            .clone();

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
            *file_inbound = merged_inbound;
        }

        Ok(location)
    }

    /// Ensures the inbound supports shell edit (Tier‑2), independent of client mutate lakes.
    ///
    /// Does **not** check AmbiguousClientsArray or [`InboundClientProtocol::mutate_enabled`].
    pub fn require_shell_editable_inbound(
        &self,
        inbound_index: usize,
    ) -> ConfigModifyResult<InboundLocation> {
        use super::inbound_clients::InboundClientProtocol;

        let location = self.locate_inbound(inbound_index)?;
        let inbound = &self.sections.inbounds()[location.inbound_index];
        let protocol = inbound
            .value()
            .get("protocol")
            .and_then(Value::as_str)
            .and_then(InboundClientProtocol::from_wire);
        let Some(protocol) = protocol else {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::UnsupportedInbound,
                "shell editing is not supported for this inbound protocol".to_owned(),
            ));
        };
        protocol.require_shell_edit_enabled()?;
        Ok(location)
    }

    /// SHA-256 fingerprint of the full inbound object at `inbound_index`.
    ///
    /// Available for any protocol (including unsupported) — used by Delete.
    pub fn inbound_object_fingerprint(
        &self,
        inbound_index: usize,
    ) -> ConfigModifyResult<String> {
        use super::inbound_clients::inbound_fingerprint;

        let _ = self.locate_inbound(inbound_index)?;
        let inbound = self.sections.inbounds().get(inbound_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
        })?;
        inbound_fingerprint(inbound.value())
    }

    /// SHA-256 fingerprint of the full outbound object at `outbound_index`.
    pub fn outbound_object_fingerprint(
        &self,
        outbound_index: usize,
    ) -> ConfigModifyResult<String> {
        use super::inbound_clients::inbound_fingerprint;

        let _ = self.locate_outbound(outbound_index)?;
        let outbound = self.sections.outbounds().get(outbound_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::OutboundNotFound, String::new())
        })?;
        inbound_fingerprint(outbound.value())
    }

    /// Applies `op` to the inbound object, then syncs the **full** inbound Value into the file root.
    pub fn with_inbound_mut<F, R>(
        &mut self,
        inbound_index: usize,
        expected_fingerprint: &str,
        op: F,
    ) -> ConfigModifyResult<(InboundLocation, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        use super::inbound_clients::verify_inbound_fingerprint;

        let location = self.require_shell_editable_inbound(inbound_index)?;

        let result = {
            let inbound = self
                .sections
                .inbounds_mut()
                .get_mut(location.inbound_index)
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
                })?;
            verify_inbound_fingerprint(inbound.value(), expected_fingerprint)?;
            op(inbound.value_mut())?
        };

        let merged_inbound = self.sections.inbounds()[location.inbound_index]
            .value()
            .clone();

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
            *file_inbound = merged_inbound;
        }

        Ok((location, result))
    }

    /// Locates an outbound by merged index.
    pub fn locate_outbound(&self, outbound_index: usize) -> ConfigModifyResult<OutboundLocation> {
        let outbound = self.sections.outbounds().get(outbound_index).ok_or_else(|| {
            ConfigModifyError::new(ConfigModifyErrorKind::OutboundNotFound, String::new())
        })?;

        let source_file = outbound.source_file().to_owned();
        let within_file_index = self
            .sections
            .outbounds()
            .iter()
            .take(outbound_index)
            .filter(|entry| entry.source_file() == source_file)
            .count();

        Ok(OutboundLocation {
            outbound_index,
            source_file,
            within_file_index,
        })
    }

    /// Finds the merged outbound index whose `tag` matches (case-insensitive).
    pub fn find_outbound_index_by_tag(&self, tag: &str) -> Option<usize> {
        self.sections.outbounds().iter().position(|outbound| {
            outbound
                .value()
                .get("tag")
                .and_then(Value::as_str)
                .is_some_and(|existing| existing.eq_ignore_ascii_case(tag))
        })
    }

    /// Returns `true` when any outbound already uses `tag` (case-insensitive).
    pub fn outbound_tag_taken(&self, tag: &str) -> bool {
        self.find_outbound_index_by_tag(tag).is_some()
    }

    /// Appends an outbound object to a chosen file root and the merged sections.
    ///
    /// Creates an `outbounds` array on the target file when missing. Does not
    /// mutate routing, DNS, or inbounds.
    pub fn add_outbound_value(
        &mut self,
        outbound: Value,
        preferred_source_file: Option<&str>,
    ) -> ConfigModifyResult<OutboundLocation> {
        if !outbound.is_object() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "outbound must be a JSON object".to_owned(),
            ));
        }

        if let Some(tag) = outbound.get("tag").and_then(Value::as_str) {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "outbound tag must not be empty".to_owned(),
                ));
            }
            if self.outbound_tag_taken(trimmed) {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::OutboundTagConflict,
                    format!("outbound tag already exists: {trimmed}"),
                ));
            }
        }

        let source_file = resolve_outbound_target_file(&self.file_roots, preferred_source_file)?;

        {
            let root = self.file_roots.get_mut(&source_file).ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    format!("source file root missing: {source_file}"),
                )
            })?;
            let object = root.as_object_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "config root must be a JSON object".to_owned(),
                )
            })?;
            if !object.contains_key("outbounds") {
                object.insert("outbounds".to_owned(), Value::Array(Vec::new()));
            }
            let outbounds = object
                .get_mut("outbounds")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    ConfigModifyError::new(
                        ConfigModifyErrorKind::ValidationFailed,
                        "outbounds must be a JSON array".to_owned(),
                    )
                })?;
            outbounds.push(outbound.clone());
        }

        let within_file_index = {
            let root = self.file_roots.get(&source_file).ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    format!("source file root missing: {source_file}"),
                )
            })?;
            root.get("outbounds")
                .and_then(Value::as_array)
                .map(|items| items.len().saturating_sub(1))
                .unwrap_or(0)
        };

        self.sections
            .push_outbound(SourcedSection::new(source_file.clone(), outbound));
        let outbound_index = self.sections.outbounds().len().saturating_sub(1);

        Ok(OutboundLocation {
            outbound_index,
            source_file,
            within_file_index,
        })
    }

    /// Replaces the outbound object at `outbound_index` while keeping its source file.
    ///
    /// The replacement must keep a unique tag (or the same tag as before).
    pub fn replace_outbound_value(
        &mut self,
        outbound_index: usize,
        outbound: Value,
    ) -> ConfigModifyResult<OutboundLocation> {
        if !outbound.is_object() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "outbound must be a JSON object".to_owned(),
            ));
        }

        let location = self.locate_outbound(outbound_index)?;
        let previous_tag = self.sections.outbounds()[location.outbound_index]
            .value()
            .get("tag")
            .and_then(Value::as_str)
            .map(str::to_owned);

        if let Some(tag) = outbound.get("tag").and_then(Value::as_str) {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "outbound tag must not be empty".to_owned(),
                ));
            }
            let conflict = self.sections.outbounds().iter().enumerate().any(|(index, entry)| {
                if index == location.outbound_index {
                    return false;
                }
                entry
                    .value()
                    .get("tag")
                    .and_then(Value::as_str)
                    .is_some_and(|existing| existing.eq_ignore_ascii_case(trimmed))
            });
            if conflict {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::OutboundTagConflict,
                    format!("outbound tag already exists: {trimmed}"),
                ));
            }
            // Preserve previous tag when caller omitted intentional rename semantics.
            let _ = previous_tag;
        }

        {
            let section = self
                .sections
                .outbounds_mut()
                .get_mut(location.outbound_index)
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::OutboundNotFound, String::new())
                })?;
            *section.value_mut() = outbound.clone();
        }

        {
            let root = self
                .file_roots
                .get_mut(&location.source_file)
                .ok_or_else(|| {
                    ConfigModifyError::new(
                        ConfigModifyErrorKind::OutboundNotFound,
                        "source file root missing".to_owned(),
                    )
                })?;
            let file_outbound = root
                .as_object_mut()
                .and_then(|object| object.get_mut("outbounds"))
                .and_then(Value::as_array_mut)
                .and_then(|outbounds| outbounds.get_mut(location.within_file_index))
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::OutboundNotFound, String::new())
                })?;
            *file_outbound = outbound;
        }

        Ok(location)
    }

    /// Removes the outbound at `outbound_index` from the merged model and its file root.
    pub fn remove_outbound_at(&mut self, outbound_index: usize) -> ConfigModifyResult<OutboundLocation> {
        let location = self.locate_outbound(outbound_index)?;

        self.sections.outbounds_mut().remove(location.outbound_index);

        {
            let root = self
                .file_roots
                .get_mut(&location.source_file)
                .ok_or_else(|| {
                    ConfigModifyError::new(
                        ConfigModifyErrorKind::OutboundNotFound,
                        "source file root missing".to_owned(),
                    )
                })?;
            let outbounds = root
                .as_object_mut()
                .and_then(|object| object.get_mut("outbounds"))
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::OutboundNotFound, String::new())
                })?;
            if location.within_file_index >= outbounds.len() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::OutboundNotFound,
                    String::new(),
                ));
            }
            outbounds.remove(location.within_file_index);
        }

        Ok(location)
    }

    /// Removes the inbound at `inbound_index` from the merged model and its file root.
    pub fn remove_inbound_at(&mut self, inbound_index: usize) -> ConfigModifyResult<InboundLocation> {
        let location = self.locate_inbound(inbound_index)?;

        if location.inbound_index >= self.sections.inbounds().len() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::InboundNotFound,
                String::new(),
            ));
        }
        self.sections.inbounds_list_mut().remove(location.inbound_index);

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
            let inbounds = root
                .as_object_mut()
                .and_then(|object| object.get_mut("inbounds"))
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    ConfigModifyError::new(ConfigModifyErrorKind::InboundNotFound, String::new())
                })?;
            if location.within_file_index >= inbounds.len() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::InboundNotFound,
                    String::new(),
                ));
            }
            inbounds.remove(location.within_file_index);
        }

        Ok(location)
    }

    /// Appends an inbound object to the primary/target file root and merged sections.
    pub fn add_inbound_value(
        &mut self,
        inbound: Value,
        preferred_source_file: Option<&str>,
    ) -> ConfigModifyResult<InboundLocation> {
        if !inbound.is_object() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "inbound must be a JSON object".to_owned(),
            ));
        }

        if let Some(tag) = inbound.get("tag").and_then(Value::as_str) {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "inbound tag must not be empty".to_owned(),
                ));
            }
            let conflict = self.sections.inbounds().iter().any(|entry| {
                entry
                    .value()
                    .get("tag")
                    .and_then(Value::as_str)
                    .is_some_and(|existing| existing == trimmed)
            });
            if conflict {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    format!("inbound tag already in use: {trimmed}"),
                ));
            }
        }

        let source_file = resolve_inbound_target_file(&self.file_roots, preferred_source_file)?;

        {
            let root = self.file_roots.get_mut(&source_file).ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    format!("source file root missing: {source_file}"),
                )
            })?;
            let object = root.as_object_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "config root must be a JSON object".to_owned(),
                )
            })?;
            if !object.contains_key("inbounds") {
                object.insert("inbounds".to_owned(), Value::Array(Vec::new()));
            }
            let inbounds = object
                .get_mut("inbounds")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    ConfigModifyError::new(
                        ConfigModifyErrorKind::ValidationFailed,
                        "inbounds must be a JSON array".to_owned(),
                    )
                })?;
            inbounds.push(inbound.clone());
        }

        let within_file_index = {
            let root = self.file_roots.get(&source_file).ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    format!("source file root missing: {source_file}"),
                )
            })?;
            root.get("inbounds")
                .and_then(Value::as_array)
                .map(|items| items.len().saturating_sub(1))
                .unwrap_or(0)
        };

        self.sections
            .push_inbound(SourcedSection::new(source_file.clone(), inbound));
        let inbound_index = self.sections.inbounds().len().saturating_sub(1);

        Ok(InboundLocation {
            inbound_index,
            source_file,
            within_file_index,
        })
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

/// Locates one outbound across the merged model and its originating file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundLocation {
    /// Index in the merged outbound list.
    pub outbound_index: usize,
    /// Path of the file that owns this outbound.
    pub source_file: String,
    /// Index inside that file's `outbounds` array.
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

/// Returns the clients/users array key, or errors if both are present.
pub(crate) fn clients_array_key(inbound: &Value) -> ConfigModifyResult<&'static str> {
    use super::inbound_clients::{ClientsArrayKey, resolve_clients_array_key};
    match resolve_clients_array_key(inbound)? {
        Some(ClientsArrayKey::Clients) => Ok("clients"),
        Some(ClientsArrayKey::Users) => Ok("users"),
        None => Ok("clients"),
    }
}

/// Mutable access to the clients/users array, creating the protocol default when absent.
pub(crate) fn clients_array_mut(inbound: &mut Value) -> ConfigModifyResult<&mut Vec<Value>> {
    use super::inbound_clients::{
        InboundClientProtocol, resolve_or_create_clients_array_key,
    };

    let protocol = inbound
        .get("protocol")
        .and_then(Value::as_str)
        .and_then(InboundClientProtocol::from_wire)
        .unwrap_or(InboundClientProtocol::Vless);
    let key = resolve_or_create_clients_array_key(inbound, protocol)?.as_str().to_owned();
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
    let key = clients_array_key(inbound)?;
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

fn resolve_log_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a log section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests logging ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("log"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_outbound_target_file(
    file_roots: &BTreeMap<String, Value>,
    preferred_source_file: Option<&str>,
) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host an outbound".to_owned(),
        ));
    }

    if let Some(preferred) = preferred_source_file
        && file_roots.contains_key(preferred)
    {
        return Ok(preferred.to_owned());
    }

    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }

    // Prefer a file that already owns an outbounds array.
    if let Some(path) = file_roots.iter().find_map(|(path, root)| {
        root.get("outbounds")
            .and_then(Value::as_array)
            .map(|_| path.clone())
    }) {
        return Ok(path);
    }

    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("outbound"))
    {
        return Ok(path.clone());
    }

    Ok(file_roots.keys().next().expect("non-empty").clone())
}

/// Resolves the IB-L1 primary file for a new inbound (preferred → single → inbounds owner → config name).
fn resolve_inbound_target_file(
    file_roots: &BTreeMap<String, Value>,
    preferred_source_file: Option<&str>,
) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host an inbound".to_owned(),
        ));
    }

    if let Some(preferred) = preferred_source_file
        && file_roots.contains_key(preferred)
    {
        return Ok(preferred.to_owned());
    }

    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }

    if let Some(path) = file_roots.iter().find_map(|(path, root)| {
        root.get("inbounds")
            .and_then(Value::as_array)
            .map(|_| path.clone())
    }) {
        return Ok(path);
    }

    if let Some(path) = file_roots.keys().find(|path| {
        let lower = path.to_ascii_lowercase();
        lower.ends_with("config.json") || lower.contains("/config.") || lower.contains("\\config.")
    }) {
        return Ok(path.clone());
    }

    Err(ConfigModifyError::new(
        ConfigModifyErrorKind::ValidationFailed,
        "could not resolve primary config file for inbound add".to_owned(),
    ))
}
