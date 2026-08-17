//! Editable Xray configuration with per-file roots for safe write-back.
//!
//! Keeps the merged [`XrayConfigSections`] model for GUI summaries while retaining
//! each source file's original root JSON object. Modifications update both so that
//! config-directory mode rewrites only the affected file.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::api_settings::{ApiSettings, api_settings_from_section};
use super::dns_settings::{DnsSettings, dns_settings_from_section};
use super::fakedns_settings::{FakeDnsSettings, fakedns_settings_from_section};
use super::burst_observatory_settings::{
    BurstObservatorySettings, burst_observatory_settings_from_section,
};
use super::env_settings::{EnvSettings, env_settings_from_section};
use super::version_settings::{VersionSettings, version_settings_from_section};
use super::geodata_settings::{GeodataSettings, geodata_settings_from_section};
use super::log_settings::{LogSettings, log_settings_from_section};
use super::metrics_settings::{MetricsSettings, metrics_settings_from_section};
use super::observatory_settings::{ObservatorySettings, observatory_settings_from_section};
use super::policy_settings::{PolicySettings, policy_settings_from_section};
use super::routing_settings::{RoutingSettings, routing_settings_from_section};
use super::stats_settings::{StatsSettings, stats_settings_from_section};
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

    /// Typed `api` settings derived from the current sections (Roadmap §2.1:54).
    pub fn api_settings(&self) -> ApiSettings {
        api_settings_from_section(self.sections.api())
    }

    /// Typed `dns` settings derived from the current sections (Roadmap §2.1:46).
    pub fn dns_settings(&self) -> DnsSettings {
        dns_settings_from_section(self.sections.dns())
    }

    /// Typed `fakedns` settings derived from the current sections (Roadmap §2.1:47).
    pub fn fakedns_settings(&self) -> FakeDnsSettings {
        fakedns_settings_from_section(self.sections.fakedns())
    }

    /// Typed `routing` settings derived from the current sections (Roadmap §2.1:48).
    pub fn routing_settings(&self) -> RoutingSettings {
        routing_settings_from_section(self.sections.routing())
    }

    /// Typed `policy` settings derived from the current sections (Roadmap §2.1:49).
    pub fn policy_settings(&self) -> PolicySettings {
        policy_settings_from_section(self.sections.policy())
    }

    /// Typed `observatory` settings derived from the current sections (Roadmap §2.1:50).
    pub fn observatory_settings(&self) -> ObservatorySettings {
        observatory_settings_from_section(self.sections.observatory())
    }

    /// Typed `metrics` settings derived from the current sections (Roadmap §2.1:53).
    pub fn metrics_settings(&self) -> MetricsSettings {
        metrics_settings_from_section(self.sections.metrics())
    }

    /// Typed `env` settings derived from the current sections (Roadmap §2.1:55).
    pub fn env_settings(&self) -> EnvSettings {
        env_settings_from_section(self.sections.env())
    }

    /// Typed `version` settings derived from the current sections (Roadmap §2.1:56).
    pub fn version_settings(&self) -> VersionSettings {
        version_settings_from_section(self.sections.version())
    }

    /// Typed `geodata` settings derived from the current sections (Roadmap §2.1:57).
    pub fn geodata_settings(&self) -> GeodataSettings {
        geodata_settings_from_section(self.sections.geodata())
    }

    /// Typed `burstObservatory` settings derived from the current sections (Roadmap §2.1:51).
    pub fn burst_observatory_settings(&self) -> BurstObservatorySettings {
        burst_observatory_settings_from_section(self.sections.burst_observatory())
    }

    /// Typed `stats` settings derived from the current sections (Roadmap §2.1:52).
    pub fn stats_settings(&self) -> StatsSettings {
        stats_settings_from_section(self.sections.stats())
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

    /// Applies `op` to the `api` object, creating it when absent, then syncs the file root
    /// (Roadmap §2.1:54). Mirrors [`with_log_mut`](Self::with_log_mut); the `api` object is not
    /// created merely by opening the API Settings page — only when this method runs during a
    /// save.
    pub fn with_api_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.api() {
            section.source_file().to_owned()
        } else {
            resolve_api_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.api().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_api(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().api_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "api section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .api()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "api section missing after edit".to_owned(),
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
            object.insert("api".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `dns` object, creating it when absent, then syncs the file root
    /// (Roadmap §2.1:46). Mirrors [`with_log_mut`](Self::with_log_mut)/[`with_api_mut`](Self::with_api_mut);
    /// the `dns` object is not created merely by opening the DNS page — only when this method
    /// runs during a save.
    pub fn with_dns_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.dns() {
            section.source_file().to_owned()
        } else {
            resolve_dns_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.dns().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_dns(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().dns_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "dns section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .dns()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "dns section missing after edit".to_owned(),
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
            object.insert("dns".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `fakedns` value, creating it (as `Value::Null`, immediately replaced by
    /// `op`) when absent, then syncs the file root (Roadmap §2.1:47). Unlike
    /// [`with_log_mut`](Self::with_log_mut)/[`with_dns_mut`](Self::with_dns_mut), the section is
    /// not always a JSON object — `op` (typically [`super::apply_fakedns_settings_to_value`])
    /// replaces the whole value wholesale (object for one pool, array otherwise), so there is no
    /// "must already be an object" precondition here. The `fakedns` value is not created merely by
    /// opening the FakeDNS page — only when this method runs during a save.
    pub fn with_fakedns_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.fakedns() {
            section.source_file().to_owned()
        } else {
            resolve_fakedns_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.fakedns().is_none() {
                self.sections
                    .set_fakedns(Some(SourcedSection::new(source_file.clone(), Value::Null)));
            }

            let section = self.sections_mut().fakedns_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "fakedns section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .fakedns()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "fakedns section missing after edit".to_owned(),
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
            object.insert("fakedns".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `routing` object, creating it when absent, then syncs the file root
    /// (Roadmap §2.1:48). Mirrors [`with_dns_mut`](Self::with_dns_mut) — `routing` is always an
    /// object (unlike `fakedns`, which may also be an array), so this follows the same
    /// "must already be an object" shape. The `routing` object is not created merely by opening
    /// the Routing page — only when this method runs during a save.
    pub fn with_routing_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.routing() {
            section.source_file().to_owned()
        } else {
            resolve_routing_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.routing().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_routing(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().routing_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "routing section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .routing()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "routing section missing after edit".to_owned(),
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
            object.insert("routing".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `policy` object, creating it when absent, then syncs the file root
    /// (Roadmap §2.1:49). Mirrors [`with_dns_mut`](Self::with_dns_mut) — `policy` is always an
    /// object. The `policy` object is not created merely by opening the Policy page — only when
    /// this method runs during a save.
    pub fn with_policy_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.policy() {
            section.source_file().to_owned()
        } else {
            resolve_policy_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.policy().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_policy(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().policy_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "policy section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .policy()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "policy section missing after edit".to_owned(),
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
            object.insert("policy".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `observatory` object, creating it when absent, then syncs the file
    /// root (Roadmap §2.1:50). Mirrors [`with_dns_mut`](Self::with_dns_mut) — `observatory` is
    /// always an object. The `observatory` object is not created merely by opening the
    /// Observatory page — only when this method runs during a save.
    pub fn with_observatory_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.observatory() {
            section.source_file().to_owned()
        } else {
            resolve_observatory_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.observatory().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_observatory(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().observatory_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "observatory section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .observatory()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "observatory section missing after edit".to_owned(),
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
            object.insert("observatory".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `metrics` object, creating it when absent, then syncs the file root
    /// (Roadmap §2.1:53). Mirrors [`with_api_mut`](Self::with_api_mut) — `metrics` is always an
    /// object, always exists once created (unlike `stats`, §2.1:52, which can be removed
    /// entirely). The `metrics` object is not created merely by opening the Metrics Settings page
    /// — only when this method runs during a save.
    pub fn with_metrics_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.metrics() {
            section.source_file().to_owned()
        } else {
            resolve_metrics_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.metrics().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_metrics(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().metrics_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "metrics section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .metrics()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "metrics section missing after edit".to_owned(),
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
            object.insert("metrics".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `env` object, creating it when absent, then syncs the file root
    /// (Roadmap §2.1:55). Mirrors [`with_api_mut`](Self::with_api_mut) — `env` is always an
    /// object, always exists once created (unlike `stats`, §2.1:52). The `env` object is not
    /// created merely by opening the Env Settings page — only when this method runs during a
    /// save.
    pub fn with_env_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.env() {
            section.source_file().to_owned()
        } else {
            resolve_env_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.env().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_env(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().env_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "env section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .env()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "env section missing after edit".to_owned(),
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
            object.insert("env".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `version` object, creating it when absent, then syncs the file root
    /// (Roadmap §2.1:56). Mirrors [`with_api_mut`](Self::with_api_mut) — `version` is always an
    /// object, always exists once created (unlike `stats`, §2.1:52). The `version` object is not
    /// created merely by opening the Version Settings page — only when this method runs during a
    /// save.
    pub fn with_version_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.version() {
            section.source_file().to_owned()
        } else {
            resolve_version_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.version().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_version(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().version_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "version section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .version()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "version section missing after edit".to_owned(),
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
            object.insert("version".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `geodata` object, creating it when absent, then syncs the file root
    /// (Roadmap §2.1:57). Mirrors [`with_api_mut`](Self::with_api_mut) — `geodata` is always an
    /// object, always exists once created (unlike `stats`, §2.1:52). The `geodata` object is not
    /// created merely by opening the GeoData Settings page — only when this method runs during a
    /// save.
    pub fn with_geodata_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.geodata() {
            section.source_file().to_owned()
        } else {
            resolve_geodata_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.geodata().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_geodata(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().geodata_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "geodata section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .geodata()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "geodata section missing after edit".to_owned(),
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
            object.insert("geodata".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `burstObservatory` object, creating it when absent, then syncs the
    /// file root (Roadmap §2.1:51). Mirrors [`with_dns_mut`](Self::with_dns_mut) —
    /// `burstObservatory` is always an object. The `burstObservatory` object is not created
    /// merely by opening the BurstObservatory page — only when this method runs during a save.
    pub fn with_burst_observatory_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Value) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.burst_observatory() {
            section.source_file().to_owned()
        } else {
            resolve_burst_observatory_target_file(&self.file_roots)?
        };

        let result = {
            if self.sections.burst_observatory().is_none() {
                let value = Value::Object(serde_json::Map::new());
                self.sections
                    .set_burst_observatory(Some(SourcedSection::new(source_file.clone(), value)));
            }

            let section = self.sections_mut().burst_observatory_mut().ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "burstObservatory section missing after create".to_owned(),
                )
            })?;
            op(section.value_mut())?
        };

        let merged = self
            .sections
            .burst_observatory()
            .map(|section| section.value().clone())
            .ok_or_else(|| {
                ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "burstObservatory section missing after edit".to_owned(),
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
            object.insert("burstObservatory".to_owned(), merged);
        }

        Ok((source_file, result))
    }

    /// Applies `op` to the `stats` value, letting it decide the key's fate entirely (Roadmap
    /// §2.1:52). Unlike every other `with_*_mut` in this module, `stats` is not always an
    /// object: `StatsObject` has no documented fields (see `stats_settings.rs` module docs), and
    /// its only meaningful state is presence vs. absence, so `op` receives `&mut Option<Value>`
    /// rather than `&mut Value` — setting it to `None` **removes** the key from the config
    /// entirely (rather than leaving an object with no fields set, the way e.g. `dns` never gets
    /// removed once created). The `stats` value is not created merely by opening the Stats
    /// Settings page — only when this method runs during a save.
    pub fn with_stats_mut<F, R>(&mut self, op: F) -> ConfigModifyResult<(String, R)>
    where
        F: FnOnce(&mut Option<Value>) -> ConfigModifyResult<R>,
    {
        let source_file = if let Some(section) = self.sections.stats() {
            section.source_file().to_owned()
        } else {
            resolve_stats_target_file(&self.file_roots)?
        };

        let mut value = self.sections.stats().map(|section| section.value().clone());
        let result = op(&mut value)?;

        match &value {
            Some(new_value) => {
                self.sections
                    .set_stats(Some(SourcedSection::new(source_file.clone(), new_value.clone())));
            }
            None => {
                self.sections.set_stats(None);
            }
        }

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
            match value {
                Some(new_value) => {
                    object.insert("stats".to_owned(), new_value);
                }
                None => {
                    object.remove("stats");
                }
            }
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

fn resolve_api_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host an api section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests API ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("api"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_dns_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a dns section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests DNS ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("dns"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_fakedns_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a fakedns section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests FakeDNS ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("fakedns"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_routing_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a routing section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests routing ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("routing"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_policy_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a policy section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests policy ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("policy"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_observatory_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host an observatory section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests observatory ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("observatory"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_burst_observatory_target_file(
    file_roots: &BTreeMap<String, Value>,
) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a burstObservatory section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests burstObservatory ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("burst"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_stats_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a stats section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests stats ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("stats"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_metrics_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a metrics section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests metrics ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("metrics"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_env_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host an env section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests env ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("env"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_geodata_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a geodata section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests geodata ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("geodata"))
    {
        return Ok(path.clone());
    }
    Ok(file_roots.keys().next().expect("non-empty").clone())
}

fn resolve_version_target_file(file_roots: &BTreeMap<String, Value>) -> ConfigModifyResult<String> {
    if file_roots.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "no configuration files available to host a version section".to_owned(),
        ));
    }
    if file_roots.len() == 1 {
        return Ok(file_roots.keys().next().expect("len == 1").clone());
    }
    // Prefer an existing file whose name suggests version ownership.
    if let Some(path) = file_roots
        .keys()
        .find(|path| path.to_ascii_lowercase().contains("version"))
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
