//! Internal Xray configuration section model.

use std::collections::BTreeMap;

use serde_json::Value;

use super::sourced_section::SourcedSection;
use super::summary::{
    BurstObservatorySummary, DnsSummary, FakeDnsSummary, InboundSummary, ObservatorySummary,
    OutboundSummary, PolicySummary, RoutingSummary, burst_observatory_summary, dns_summary,
    fakedns_summary, inbound_summaries, observatory_summary, outbound_summaries, policy_summary,
    routing_summary,
};

/// Known top-level Xray section names recognized by the typed model.
///
/// Any other top-level key is stored in [`XrayConfigSections::extra_sections`].
pub const KNOWN_SECTION_NAMES: &[&str] = &[
    "env",
    "version",
    "geodata",
    "log",
    "api",
    "dns",
    "fakedns",
    "routing",
    "policy",
    "stats",
    "reverse",
    "observatory",
    "burstObservatory",
    "metrics",
    "inbounds",
    "outbounds",
];

/// Lossless in-memory model of Xray top-level configuration sections.
///
/// Known sections are exposed as optional sourced values. Array sections
/// (`inbounds`, `outbounds`) keep entry order and per-entry source files.
/// Unrecognized top-level keys are retained in [`extra_sections`](Self::extra_sections)
/// so future write-back can restore them without data loss.
///
/// Nested content remains [`serde_json::Value`] until a dedicated GUI area
/// needs stronger typing (Users, Inbounds, DNS, …).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XrayConfigSections {
    env: Option<SourcedSection<Value>>,
    version: Option<SourcedSection<Value>>,
    geodata: Option<SourcedSection<Value>>,
    log: Option<SourcedSection<Value>>,
    api: Option<SourcedSection<Value>>,
    dns: Option<SourcedSection<Value>>,
    fakedns: Option<SourcedSection<Value>>,
    routing: Option<SourcedSection<Value>>,
    policy: Option<SourcedSection<Value>>,
    stats: Option<SourcedSection<Value>>,
    reverse: Option<SourcedSection<Value>>,
    observatory: Option<SourcedSection<Value>>,
    burst_observatory: Option<SourcedSection<Value>>,
    metrics: Option<SourcedSection<Value>>,
    inbounds: Vec<SourcedSection<Value>>,
    outbounds: Vec<SourcedSection<Value>>,
    /// Unknown top-level sections in encounter order (key → sourced value).
    extra_sections: Vec<(String, SourcedSection<Value>)>,
}

impl XrayConfigSections {
    /// Creates an empty configuration with no sections.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` when no sections or array entries are present.
    pub fn is_empty(&self) -> bool {
        self.env.is_none()
            && self.version.is_none()
            && self.geodata.is_none()
            && self.log.is_none()
            && self.api.is_none()
            && self.dns.is_none()
            && self.fakedns.is_none()
            && self.routing.is_none()
            && self.policy.is_none()
            && self.stats.is_none()
            && self.reverse.is_none()
            && self.observatory.is_none()
            && self.burst_observatory.is_none()
            && self.metrics.is_none()
            && self.inbounds.is_empty()
            && self.outbounds.is_empty()
            && self.extra_sections.is_empty()
    }

    /// `env` section, if present.
    pub fn env(&self) -> Option<&SourcedSection<Value>> {
        self.env.as_ref()
    }

    /// Mutable `env` section, if present.
    pub fn env_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.env.as_mut()
    }

    /// `version` section, if present.
    pub fn version(&self) -> Option<&SourcedSection<Value>> {
        self.version.as_ref()
    }

    /// Mutable `version` section, if present.
    pub fn version_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.version.as_mut()
    }

    /// `geodata` section, if present.
    pub fn geodata(&self) -> Option<&SourcedSection<Value>> {
        self.geodata.as_ref()
    }

    /// Mutable `geodata` section, if present.
    pub fn geodata_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.geodata.as_mut()
    }

    /// `log` section, if present.
    pub fn log(&self) -> Option<&SourcedSection<Value>> {
        self.log.as_ref()
    }

    /// Mutable `log` section, if present.
    pub fn log_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.log.as_mut()
    }

    /// `api` section, if present.
    pub fn api(&self) -> Option<&SourcedSection<Value>> {
        self.api.as_ref()
    }

    /// Mutable `api` section, if present.
    pub fn api_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.api.as_mut()
    }

    /// `dns` section, if present.
    pub fn dns(&self) -> Option<&SourcedSection<Value>> {
        self.dns.as_ref()
    }

    /// Mutable `dns` section, if present.
    pub fn dns_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.dns.as_mut()
    }

    /// `fakedns` section, if present.
    ///
    /// Official Xray allows either a single FakeDnsObject or an array of pools.
    /// The value is retained losslessly as JSON.
    pub fn fakedns(&self) -> Option<&SourcedSection<Value>> {
        self.fakedns.as_ref()
    }

    /// Mutable `fakedns` section, if present.
    pub fn fakedns_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.fakedns.as_mut()
    }

    /// `routing` section, if present.
    pub fn routing(&self) -> Option<&SourcedSection<Value>> {
        self.routing.as_ref()
    }

    /// Mutable `routing` section, if present.
    pub fn routing_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.routing.as_mut()
    }

    /// `policy` section, if present.
    pub fn policy(&self) -> Option<&SourcedSection<Value>> {
        self.policy.as_ref()
    }

    /// Mutable `policy` section, if present.
    pub fn policy_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.policy.as_mut()
    }

    /// `stats` section, if present.
    pub fn stats(&self) -> Option<&SourcedSection<Value>> {
        self.stats.as_ref()
    }

    /// Mutable `stats` section, if present.
    pub fn stats_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.stats.as_mut()
    }

    /// `reverse` section, if present.
    pub fn reverse(&self) -> Option<&SourcedSection<Value>> {
        self.reverse.as_ref()
    }

    /// `observatory` section, if present.
    pub fn observatory(&self) -> Option<&SourcedSection<Value>> {
        self.observatory.as_ref()
    }

    /// Mutable `observatory` section, if present.
    pub fn observatory_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.observatory.as_mut()
    }

    /// `burstObservatory` section, if present.
    pub fn burst_observatory(&self) -> Option<&SourcedSection<Value>> {
        self.burst_observatory.as_ref()
    }

    /// Mutable `burstObservatory` section, if present.
    pub fn burst_observatory_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.burst_observatory.as_mut()
    }

    /// `metrics` section, if present.
    pub fn metrics(&self) -> Option<&SourcedSection<Value>> {
        self.metrics.as_ref()
    }

    /// Mutable `metrics` section, if present.
    pub fn metrics_mut(&mut self) -> Option<&mut SourcedSection<Value>> {
        self.metrics.as_mut()
    }

    /// Inbound entries in preserved order.
    pub fn inbounds(&self) -> &[SourcedSection<Value>] {
        &self.inbounds
    }

    /// Mutable inbound entries for the configuration modification layer.
    pub fn inbounds_mut(&mut self) -> &mut [SourcedSection<Value>] {
        &mut self.inbounds
    }

    /// Outbound entries in preserved order.
    pub fn outbounds(&self) -> &[SourcedSection<Value>] {
        &self.outbounds
    }

    /// Unknown top-level sections in encounter order.
    pub fn extra_sections(&self) -> &[(String, SourcedSection<Value>)] {
        &self.extra_sections
    }

    /// Looks up an unknown section by name.
    pub fn extra_section(&self, name: &str) -> Option<&SourcedSection<Value>> {
        self.extra_sections
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, section)| section)
    }

    /// Read-only inbound summaries for GUI lists.
    pub fn inbound_summaries(&self) -> Vec<InboundSummary> {
        inbound_summaries(self)
    }

    /// Read-only outbound summaries for GUI lists.
    pub fn outbound_summaries(&self) -> Vec<OutboundSummary> {
        outbound_summaries(self)
    }

    /// Read-only DNS summary for the GUI, when the section is present.
    pub fn dns_summary(&self) -> Option<DnsSummary> {
        dns_summary(self)
    }

    /// Read-only FakeDNS summary for the GUI, when the section is present.
    pub fn fakedns_summary(&self) -> Option<FakeDnsSummary> {
        fakedns_summary(self)
    }

    /// Read-only Observatory summary for the GUI, when the section is present.
    pub fn observatory_summary(&self) -> Option<ObservatorySummary> {
        observatory_summary(self)
    }

    /// Read-only Burst Observatory summary when the section is present.
    pub fn burst_observatory_summary(&self) -> Option<BurstObservatorySummary> {
        burst_observatory_summary(self)
    }

    /// Read-only routing summary for the GUI, when the section is present.
    pub fn routing_summary(&self) -> Option<RoutingSummary> {
        routing_summary(self)
    }

    /// Read-only policy summary for the GUI, when the section is present.
    pub fn policy_summary(&self) -> Option<PolicySummary> {
        policy_summary(self)
    }

    /// Compatibility view: unknown sections as a name → value map (sorted keys).
    ///
    /// Prefer [`extra_sections`](Self::extra_sections) when order or source
    /// files matter.
    pub fn extra_map(&self) -> BTreeMap<String, Value> {
        self.extra_sections
            .iter()
            .map(|(key, section)| (key.clone(), section.value().clone()))
            .collect()
    }

    /// Human-readable labels for every section (known or unknown) sourced from `path`.
    ///
    /// Empty when nothing in the merged config came from that file — used to gate confdir
    /// file removal (Roadmap §2.5:107) and to describe a file's contents in the GUI.
    pub fn sections_in_file(&self, path: &str) -> Vec<String> {
        let mut labels = Vec::new();

        let scalar_sections: &[(&str, Option<&SourcedSection<Value>>)] = &[
            ("env", self.env.as_ref()),
            ("version", self.version.as_ref()),
            ("geodata", self.geodata.as_ref()),
            ("log", self.log.as_ref()),
            ("api", self.api.as_ref()),
            ("dns", self.dns.as_ref()),
            ("fakedns", self.fakedns.as_ref()),
            ("routing", self.routing.as_ref()),
            ("policy", self.policy.as_ref()),
            ("stats", self.stats.as_ref()),
            ("reverse", self.reverse.as_ref()),
            ("observatory", self.observatory.as_ref()),
            ("burstObservatory", self.burst_observatory.as_ref()),
            ("metrics", self.metrics.as_ref()),
        ];
        for (name, section) in scalar_sections {
            if section.is_some_and(|s| s.source_file() == path) {
                labels.push((*name).to_owned());
            }
        }

        let inbound_count = self
            .inbounds
            .iter()
            .filter(|s| s.source_file() == path)
            .count();
        if inbound_count > 0 {
            labels.push(format!("{inbound_count} inbound(s)"));
        }
        let outbound_count = self
            .outbounds
            .iter()
            .filter(|s| s.source_file() == path)
            .count();
        if outbound_count > 0 {
            labels.push(format!("{outbound_count} outbound(s)"));
        }

        for (name, section) in &self.extra_sections {
            if section.source_file() == path {
                labels.push(format!("unknown section `{name}`"));
            }
        }

        labels
    }

    /// `true` when no section (known or unknown) in the merged config is sourced from `path`.
    pub fn is_file_empty(&self, path: &str) -> bool {
        self.sections_in_file(path).is_empty()
    }

    pub(crate) fn set_log(&mut self, section: Option<SourcedSection<Value>>) {
        self.log = section;
    }

    pub(crate) fn set_api(&mut self, section: Option<SourcedSection<Value>>) {
        self.api = section;
    }

    pub(crate) fn set_dns(&mut self, section: Option<SourcedSection<Value>>) {
        self.dns = section;
    }

    pub(crate) fn set_fakedns(&mut self, section: Option<SourcedSection<Value>>) {
        self.fakedns = section;
    }

    pub(crate) fn set_routing(&mut self, section: Option<SourcedSection<Value>>) {
        self.routing = section;
    }

    pub(crate) fn set_policy(&mut self, section: Option<SourcedSection<Value>>) {
        self.policy = section;
    }

    pub(crate) fn set_stats(&mut self, section: Option<SourcedSection<Value>>) {
        self.stats = section;
    }

    pub(crate) fn set_reverse(&mut self, section: Option<SourcedSection<Value>>) {
        self.reverse = section;
    }

    pub(crate) fn set_observatory(&mut self, section: Option<SourcedSection<Value>>) {
        self.observatory = section;
    }

    pub(crate) fn set_burst_observatory(&mut self, section: Option<SourcedSection<Value>>) {
        self.burst_observatory = section;
    }

    pub(crate) fn set_metrics(&mut self, section: Option<SourcedSection<Value>>) {
        self.metrics = section;
    }

    pub(crate) fn set_env(&mut self, section: Option<SourcedSection<Value>>) {
        self.env = section;
    }

    pub(crate) fn set_version(&mut self, section: Option<SourcedSection<Value>>) {
        self.version = section;
    }

    pub(crate) fn set_geodata(&mut self, section: Option<SourcedSection<Value>>) {
        self.geodata = section;
    }

    pub(crate) fn push_inbound(&mut self, inbound: SourcedSection<Value>) {
        self.inbounds.push(inbound);
    }

    /// Mutable access to merged inbounds as a Vec (config-modify layer only).
    pub(crate) fn inbounds_list_mut(&mut self) -> &mut Vec<SourcedSection<Value>> {
        &mut self.inbounds
    }

    pub(crate) fn push_outbound(&mut self, outbound: SourcedSection<Value>) {
        self.outbounds.push(outbound);
    }

    /// Mutable access to merged outbounds (config-modify layer only).
    pub(crate) fn outbounds_mut(&mut self) -> &mut Vec<SourcedSection<Value>> {
        &mut self.outbounds
    }

    pub(crate) fn push_extra(&mut self, name: String, section: SourcedSection<Value>) {
        if let Some((_, existing)) = self.extra_sections.iter_mut().find(|(key, _)| *key == name) {
            *existing = section;
            return;
        }
        self.extra_sections.push((name, section));
    }

    pub fn is_known_section(name: &str) -> bool {
        KNOWN_SECTION_NAMES.contains(&name)
    }
}

/// Backward-compatible alias for the internal configuration model.
///
/// Prefer [`XrayConfigSections`] in new code.
pub type XrayConfig = XrayConfigSections;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::config::parser::XrayConfigParser;

    fn sections_from(path: &str, json: &str) -> XrayConfigSections {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file(path, json);
        assert!(outcome.is_success(), "{:?}", outcome.errors());
        outcome.into_sections()
    }

    #[test]
    fn empty_file_has_no_sections() {
        let sections = sections_from("/etc/xray/config.json", r#"{}"#);
        assert!(sections.sections_in_file("/etc/xray/config.json").is_empty());
        assert!(sections.is_file_empty("/etc/xray/config.json"));
    }

    #[test]
    fn known_scalar_section_is_reported() {
        let sections = sections_from("/etc/xray/config.json", r#"{"policy":{"levels":{}}}"#);
        let labels = sections.sections_in_file("/etc/xray/config.json");
        assert_eq!(labels, vec!["policy".to_owned()]);
        assert!(!sections.is_file_empty("/etc/xray/config.json"));
    }

    #[test]
    fn inbounds_and_outbounds_are_counted() {
        let sections = sections_from(
            "/etc/xray/config.json",
            r#"{
                "inbounds":[{"protocol":"vless","tag":"a"},{"protocol":"vless","tag":"b"}],
                "outbounds":[{"protocol":"freedom","tag":"direct"}]
            }"#,
        );
        let labels = sections.sections_in_file("/etc/xray/config.json");
        assert!(labels.contains(&"2 inbound(s)".to_owned()));
        assert!(labels.contains(&"1 outbound(s)".to_owned()));
    }

    #[test]
    fn unknown_top_level_key_is_reported() {
        let sections = sections_from("/etc/xray/config.json", r#"{"futureSection":{"a":1}}"#);
        let labels = sections.sections_in_file("/etc/xray/config.json");
        assert_eq!(labels, vec!["unknown section `futureSection`".to_owned()]);
    }

    #[test]
    fn different_path_reports_nothing() {
        let sections = sections_from("/etc/xray/config.json", r#"{"policy":{}}"#);
        assert!(sections.sections_in_file("/etc/xray/other.json").is_empty());
        assert!(sections.is_file_empty("/etc/xray/other.json"));
    }
}
