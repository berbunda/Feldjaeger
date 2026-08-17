//! Typed editor model for the Xray top-level `routing` object (Roadmap §2.1:48).
//!
//! Field semantics follow the official RoutingObject / RuleObject / BalancerObject documentation:
//! <https://xtls.github.io/ru/config/routing.html>
//!
//! This is the *editing* counterpart to the read-only [`super::RoutingSummary`] used elsewhere in
//! the crate (e.g. `LoadedConfigSnapshot::Loaded.routing`, the Routing page's browsing table);
//! `RoutingSummary` is left untouched and keeps covering the same subset of fields it already did
//! for lightweight display. This module covers every documented field of `RoutingObject`,
//! `RuleObject`, `BalancerObject`, `StrategyObject`/`StrategySettingsObject`/`CostObject`, and
//! `WebhookObject`, mirroring the `dns`/`fakedns` editor pattern (`dns_settings.rs`,
//! `fakedns_settings.rs`) one tier up in structural complexity again: `rules[]` and `balancers[]`
//! are both arrays of objects with per-entry unknown-field preservation (`extra`, same idiom as
//! `FakeDnsPoolEntry::extra`), and `sourceIP`/`source` is the alias-collapse case this module owns
//! (an on-disk `source` key is read as `sourceIP` when the canonical key is absent, and only
//! `sourceIP` is ever written back — matching how `dns_settings.rs` documents the `clientIp`/
//! `clientIP` casing split rather than "fixing" it).
//!
//! `routing.domainMatcher` is deliberately **not** exposed here as an editable field. It is
//! already read (and shown read-only) by [`super::RoutingSummary`], but a check against
//! Xray-core's JSON config parser (`infra/conf/router.go`) and the current official
//! `config/routing.html` page found no trace of it in either — it appears to be undocumented or
//! dead in current Xray-core. Since [`apply_routing_settings_to_value`] only inserts/removes the
//! keys this module knows about and otherwise mutates the existing `routing` object in place
//! (never rebuilding it from scratch — the same convention `apply_dns_settings_to_value` uses),
//! an existing on-disk `domainMatcher` key round-trips untouched without needing a dedicated
//! "extra" slot at the top level.
//!
//! The rule-level `type` field (traditionally always the literal `"field"` in modern Xray-core;
//! confirmed *not* present in `RouterRule`/`RawFieldRule` in the current source) is treated the
//! same way, one level down: preserved verbatim in [`RoutingRuleEntry::extra`] if present on disk,
//! never invented or forced on save.

use serde_json::{Map, Number, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// `routing.domainStrategy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainStrategy {
    /// `"AsIs"` — the documented default.
    AsIs,
    /// `"IPIfNonMatch"`.
    IpIfNonMatch,
    /// `"IPOnDemand"`.
    IpOnDemand,
    /// Unsupported existing value preserved verbatim.
    Unknown(String),
}

impl DomainStrategy {
    /// Effective default when the field is omitted (Xray default).
    pub fn default_effective() -> Self {
        Self::AsIs
    }

    /// Stable wire value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::AsIs => "AsIs",
            Self::IpIfNonMatch => "IPIfNonMatch",
            Self::IpOnDemand => "IPOnDemand",
            Self::Unknown(raw) => raw.as_str(),
        }
    }

    /// Display label for UI.
    pub fn display_label(&self) -> String {
        match self {
            Self::Unknown(raw) => format!("Unknown ({raw})"),
            other => other.as_str().to_owned(),
        }
    }

    fn parse(value: Option<&Value>) -> Self {
        let Some(Value::String(raw)) = value else {
            return Self::default_effective();
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::default_effective();
        }
        match trimmed {
            "AsIs" => Self::AsIs,
            "IPIfNonMatch" => Self::IpIfNonMatch,
            "IPOnDemand" => Self::IpOnDemand,
            _ => Self::Unknown(trimmed.to_owned()),
        }
    }
}

/// `routing.rules[].network`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkKind {
    /// `"tcp"`.
    Tcp,
    /// `"udp"`.
    Udp,
    /// `"tcp,udp"`.
    TcpUdp,
    /// Unsupported existing value preserved verbatim.
    Unknown(String),
}

impl NetworkKind {
    /// Stable wire value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::TcpUdp => "tcp,udp",
            Self::Unknown(raw) => raw.as_str(),
        }
    }

    /// Display label for UI.
    pub fn display_label(&self) -> String {
        match self {
            Self::Unknown(raw) => format!("Unknown ({raw})"),
            other => other.as_str().to_owned(),
        }
    }

    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "tcp,udp" | "udp,tcp" => Self::TcpUdp,
            _ => Self::Unknown(raw.trim().to_owned()),
        }
    }

    fn parse_optional(value: Option<&Value>) -> Option<Self> {
        let text = value.and_then(Value::as_str)?.trim();
        if text.is_empty() {
            return None;
        }
        Some(Self::parse(text))
    }
}

/// `routing.balancers[].strategy.type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BalancerStrategyType {
    /// `"random"` — the documented default.
    Random,
    /// `"roundRobin"`.
    RoundRobin,
    /// `"leastPing"` — requires `observatory`/`burstObservatory` coverage.
    LeastPing,
    /// `"leastLoad"` — requires `observatory`/`burstObservatory` coverage.
    LeastLoad,
    /// Unsupported existing value preserved verbatim.
    Unknown(String),
}

impl BalancerStrategyType {
    /// Effective default when `strategy`/`strategy.type` is omitted.
    pub fn default_effective() -> Self {
        Self::Random
    }

    /// Stable wire value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Random => "random",
            Self::RoundRobin => "roundRobin",
            Self::LeastPing => "leastPing",
            Self::LeastLoad => "leastLoad",
            Self::Unknown(raw) => raw.as_str(),
        }
    }

    /// Display label for UI.
    pub fn display_label(&self) -> String {
        match self {
            Self::Unknown(raw) => format!("Unknown ({raw})"),
            other => other.as_str().to_owned(),
        }
    }

    fn parse(value: Option<&Value>) -> Self {
        let Some(Value::String(raw)) = value else {
            return Self::default_effective();
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::default_effective();
        }
        match trimmed.to_ascii_lowercase().as_str() {
            "random" => Self::Random,
            "roundrobin" => Self::RoundRobin,
            "leastping" => Self::LeastPing,
            "leastload" => Self::LeastLoad,
            _ => Self::Unknown(trimmed.to_owned()),
        }
    }
}

/// `RuleObject.webhook` (`WebhookObject`).
#[derive(Debug, Clone, PartialEq)]
pub struct WebhookEntry {
    /// `url` — required by the spec. Kept as a plain (possibly empty) string, like
    /// [`super::DnsServerEntry::address`], so a malformed on-disk entry stays visible/fixable;
    /// [`validate_routing_settings`] rejects saving with an empty url.
    pub url: String,
    /// `deduplication` (seconds). `None` omits the key.
    pub deduplication: Option<u64>,
    /// `headers`, in source/edit order.
    pub headers: Vec<(String, String)>,
}

impl WebhookEntry {
    /// A blank webhook for the GUI's "Add webhook" action.
    pub fn blank() -> Self {
        Self {
            url: String::new(),
            deduplication: None,
            headers: Vec::new(),
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("url".to_owned(), Value::String(self.url.clone()));
        if let Some(deduplication) = self.deduplication {
            object.insert("deduplication".to_owned(), Value::from(deduplication));
        }
        if !self.headers.is_empty() {
            object.insert("headers".to_owned(), pairs_to_object(&self.headers));
        }
        Value::Object(object)
    }
}

/// One `routing.balancers[].strategy.settings.costs[]` entry (`CostObject`).
#[derive(Debug, Clone, PartialEq)]
pub struct CostEntry {
    /// `regexp` — whether `match` is a regular expression.
    pub regexp: bool,
    /// `match` — outbound tag match text. Rust field name avoids the `match` keyword.
    pub match_value: String,
    /// `value` — weight (higher = less likely to be selected).
    pub value: f64,
}

impl CostEntry {
    /// A blank cost entry for the GUI's "Add cost" action.
    pub fn blank() -> Self {
        Self {
            regexp: false,
            match_value: String::new(),
            value: 0.0,
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("regexp".to_owned(), Value::Bool(self.regexp));
        object.insert("match".to_owned(), Value::String(self.match_value.clone()));
        object.insert("value".to_owned(), number_from_f64(self.value));
        Value::Object(object)
    }
}

/// `StrategyObject.settings` for `leastLoad` (`StrategySettingsObject`); other strategy types
/// generally ignore this, but it is preserved/editable regardless (`rules.md`: prefer
/// compatibility over convenience — this module does not gate the field on the selected type).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StrategySettingsEntry {
    /// `expected` — number of best nodes to distribute traffic across.
    pub expected: Option<i64>,
    /// `maxRTT` — max acceptable RTT (e.g. `"1s"`), kept as free text (Xray duration string).
    pub max_rtt: Option<String>,
    /// `tolerance` — acceptable failure-measurement fraction (e.g. `0.01` = 1%).
    pub tolerance: Option<f64>,
    /// `baselines` — RTT standard-deviation baselines (e.g. `["1s"]`), free-text durations.
    pub baselines: Vec<String>,
    /// `costs` — per-outbound weight overrides.
    pub costs: Vec<CostEntry>,
}

impl StrategySettingsEntry {
    fn to_value(&self) -> Value {
        let mut object = Map::new();
        if let Some(expected) = self.expected {
            object.insert("expected".to_owned(), Value::from(expected));
        }
        if let Some(max_rtt) = &self.max_rtt {
            object.insert("maxRTT".to_owned(), Value::String(max_rtt.clone()));
        }
        if let Some(tolerance) = self.tolerance {
            object.insert("tolerance".to_owned(), number_from_f64(tolerance));
        }
        if !self.baselines.is_empty() {
            object.insert("baselines".to_owned(), string_vec_to_value(&self.baselines));
        }
        if !self.costs.is_empty() {
            let costs: Vec<Value> = self.costs.iter().map(CostEntry::to_value).collect();
            object.insert("costs".to_owned(), Value::Array(costs));
        }
        Value::Object(object)
    }
}

/// `routing.balancers[].strategy` (`StrategyObject`).
#[derive(Debug, Clone, PartialEq)]
pub struct StrategyEntry {
    /// `type`.
    pub strategy_type: BalancerStrategyType,
    /// `settings` — meaningful for `leastLoad`, optional for other types.
    pub settings: Option<StrategySettingsEntry>,
}

impl StrategyEntry {
    /// A blank strategy (`random`, no settings) for the GUI's "Add strategy" action.
    pub fn blank() -> Self {
        Self {
            strategy_type: BalancerStrategyType::default_effective(),
            settings: None,
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "type".to_owned(),
            Value::String(self.strategy_type.as_str().to_owned()),
        );
        if let Some(settings) = &self.settings {
            object.insert("settings".to_owned(), settings.to_value());
        }
        Value::Object(object)
    }
}

/// One `routing.balancers[]` entry (`BalancerObject`).
#[derive(Debug, Clone, PartialEq)]
pub struct BalancerEntry {
    /// `tag` — required, matched against `RuleObject.balancerTag`.
    pub tag: String,
    /// `selector` — outbound tag prefixes.
    pub selector: Vec<String>,
    /// `fallbackTag`. `None` omits the key.
    pub fallback_tag: Option<String>,
    /// `strategy`. `None` omits the key (Xray default: `random`).
    pub strategy: Option<StrategyEntry>,
    /// Unrecognized JSON keys on this balancer object, preserved verbatim.
    pub extra: Map<String, Value>,
}

impl BalancerEntry {
    /// A blank balancer for the GUI's "Add balancer" action.
    pub fn blank() -> Self {
        Self {
            tag: String::new(),
            selector: Vec::new(),
            fallback_tag: None,
            strategy: None,
            extra: Map::new(),
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("tag".to_owned(), Value::String(self.tag.clone()));
        if !self.selector.is_empty() {
            object.insert("selector".to_owned(), string_vec_to_value(&self.selector));
        }
        if let Some(fallback_tag) = &self.fallback_tag {
            object.insert("fallbackTag".to_owned(), Value::String(fallback_tag.clone()));
        }
        if let Some(strategy) = &self.strategy {
            object.insert("strategy".to_owned(), strategy.to_value());
        }
        for (key, value) in &self.extra {
            object.entry(key.clone()).or_insert_with(|| value.clone());
        }
        Value::Object(object)
    }
}

/// One `routing.rules[]` entry (`RuleObject`).
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingRuleEntry {
    /// `ruleTag` — identifies the rule in Info-level logs.
    pub rule_tag: Option<String>,
    /// `domain` match expressions.
    pub domain: Vec<String>,
    /// `ip` match expressions.
    pub ip: Vec<String>,
    /// `port` — single port, range (`"1000-2000"`), or mixed list (`"53,443,1000-2000"`), kept as
    /// free text since Xray accepts either a bare number or a string and only the string form
    /// supports ranges/lists.
    pub port: Option<String>,
    /// `sourcePort`, same shape as `port`.
    pub source_port: Option<String>,
    /// `localPort`, same shape as `port`.
    pub local_port: Option<String>,
    /// `network`.
    pub network: Option<NetworkKind>,
    /// `sourceIP` match expressions (alias `source` is read but never written — see module docs).
    pub source_ip: Vec<String>,
    /// `localIP` match expressions.
    pub local_ip: Vec<String>,
    /// `user` email match expressions.
    pub user: Vec<String>,
    /// `vlessRoute`, same shape as `port`.
    pub vless_route: Option<String>,
    /// `inboundTag` match values.
    pub inbound_tag: Vec<String>,
    /// `protocol` sniffed-protocol match values (`http`/`tls`/`quic`/`bittorrent` are documented,
    /// but the field accepts any string — the GUI offers the four as checkboxes plus free text).
    pub protocol: Vec<String>,
    /// `attrs` — HTTP header match object, in source/edit order.
    pub attrs: Vec<(String, String)>,
    /// `process` match expressions (Windows/Linux only per the spec).
    pub process: Vec<String>,
    /// `outboundTag` — target outbound. Per the docs, wins over `balancerTag` when both are set.
    pub outbound_tag: Option<String>,
    /// `balancerTag` — target balancer.
    pub balancer_tag: Option<String>,
    /// `webhook`. `None` omits the key.
    pub webhook: Option<WebhookEntry>,
    /// Unrecognized JSON keys on this rule object (including a legacy/undocumented `type`, if
    /// present), preserved verbatim and round-tripped on save — see module docs.
    pub extra: Map<String, Value>,
}

impl RoutingRuleEntry {
    /// A blank rule for the GUI's "Add rule" action. Invalid until `outboundTag` or
    /// `balancerTag` is set — [`validate_routing_settings`] rejects saving otherwise, the same
    /// idiom as `DnsServerEntry::blank()`'s empty `address`.
    pub fn blank() -> Self {
        Self {
            rule_tag: None,
            domain: Vec::new(),
            ip: Vec::new(),
            port: None,
            source_port: None,
            local_port: None,
            network: None,
            source_ip: Vec::new(),
            local_ip: Vec::new(),
            user: Vec::new(),
            vless_route: None,
            inbound_tag: Vec::new(),
            protocol: Vec::new(),
            attrs: Vec::new(),
            process: Vec::new(),
            outbound_tag: None,
            balancer_tag: None,
            webhook: None,
            extra: Map::new(),
        }
    }

    fn to_value(&self) -> Value {
        let mut object = Map::new();
        if let Some(rule_tag) = &self.rule_tag {
            object.insert("ruleTag".to_owned(), Value::String(rule_tag.clone()));
        }
        if !self.domain.is_empty() {
            object.insert("domain".to_owned(), string_vec_to_value(&self.domain));
        }
        if !self.ip.is_empty() {
            object.insert("ip".to_owned(), string_vec_to_value(&self.ip));
        }
        if let Some(port) = &self.port {
            object.insert("port".to_owned(), Value::String(port.clone()));
        }
        if let Some(source_port) = &self.source_port {
            object.insert("sourcePort".to_owned(), Value::String(source_port.clone()));
        }
        if let Some(local_port) = &self.local_port {
            object.insert("localPort".to_owned(), Value::String(local_port.clone()));
        }
        if let Some(network) = &self.network {
            object.insert("network".to_owned(), Value::String(network.as_str().to_owned()));
        }
        if !self.source_ip.is_empty() {
            object.insert("sourceIP".to_owned(), string_vec_to_value(&self.source_ip));
        }
        if !self.local_ip.is_empty() {
            object.insert("localIP".to_owned(), string_vec_to_value(&self.local_ip));
        }
        if !self.user.is_empty() {
            object.insert("user".to_owned(), string_vec_to_value(&self.user));
        }
        if let Some(vless_route) = &self.vless_route {
            object.insert("vlessRoute".to_owned(), Value::String(vless_route.clone()));
        }
        if !self.inbound_tag.is_empty() {
            object.insert("inboundTag".to_owned(), string_vec_to_value(&self.inbound_tag));
        }
        if !self.protocol.is_empty() {
            object.insert("protocol".to_owned(), string_vec_to_value(&self.protocol));
        }
        if !self.attrs.is_empty() {
            object.insert("attrs".to_owned(), pairs_to_object(&self.attrs));
        }
        if !self.process.is_empty() {
            object.insert("process".to_owned(), string_vec_to_value(&self.process));
        }
        if let Some(outbound_tag) = &self.outbound_tag {
            object.insert("outboundTag".to_owned(), Value::String(outbound_tag.clone()));
        }
        if let Some(balancer_tag) = &self.balancer_tag {
            object.insert("balancerTag".to_owned(), Value::String(balancer_tag.clone()));
        }
        if let Some(webhook) = &self.webhook {
            object.insert("webhook".to_owned(), webhook.to_value());
        }
        for (key, value) in &self.extra {
            object.entry(key.clone()).or_insert_with(|| value.clone());
        }
        Value::Object(object)
    }
}

/// Typed view of the Xray `routing` section for editing.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingSettings {
    /// `domainStrategy`. Always written (even when it equals the documented default), mirroring
    /// `DnsSettings::query_strategy`.
    pub domain_strategy: DomainStrategy,
    /// Configured rules, in source/edit order — order is significant (first match wins).
    pub rules: Vec<RoutingRuleEntry>,
    /// Configured balancers, in source/edit order.
    pub balancers: Vec<BalancerEntry>,
    /// `true` when a top-level `routing` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `routing` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (unknown values, malformed optional fields/entries).
    pub warnings: Vec<String>,
}

impl RoutingSettings {
    /// Effective defaults when the `routing` object is absent (display only).
    pub fn defaults() -> Self {
        Self {
            domain_strategy: DomainStrategy::default_effective(),
            rules: Vec::new(),
            balancers: Vec::new(),
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`RoutingSettings`] from an optional sourced `routing` section.
pub fn routing_settings_from_section(section: Option<&SourcedSection<Value>>) -> RoutingSettings {
    let Some(section) = section else {
        return RoutingSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed routing object: expected a JSON object.".to_owned());
        return RoutingSettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..RoutingSettings::defaults()
        };
    }

    let domain_strategy = DomainStrategy::parse(value.get("domainStrategy"));
    if let DomainStrategy::Unknown(raw) = &domain_strategy {
        warnings.push(format!("Unknown domainStrategy: {raw}"));
    }

    let rules = parse_rules(value.get("rules"), &mut warnings);
    let balancers = parse_balancers(value.get("balancers"), &mut warnings);

    RoutingSettings {
        domain_strategy,
        rules,
        balancers,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
}

const KNOWN_RULE_KEYS: &[&str] = &[
    "ruleTag",
    "domain",
    "ip",
    "port",
    "sourcePort",
    "localPort",
    "network",
    "sourceIP",
    "source",
    "localIP",
    "user",
    "vlessRoute",
    "inboundTag",
    "protocol",
    "attrs",
    "process",
    "outboundTag",
    "balancerTag",
    "webhook",
];

const KNOWN_BALANCER_KEYS: &[&str] = &["tag", "selector", "fallbackTag", "strategy"];

fn parse_rules(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<RoutingRuleEntry> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    array
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let position = index + 1;
            match entry.as_object() {
                Some(object) => Some(rule_from_object(object, position, warnings)),
                None => {
                    warnings.push(format!(
                        "Routing rule {position} has an unsupported shape and was skipped."
                    ));
                    None
                }
            }
        })
        .collect()
}

fn rule_from_object(
    object: &Map<String, Value>,
    position: usize,
    warnings: &mut Vec<String>,
) -> RoutingRuleEntry {
    let mut source_ip = string_array_field(object.get("sourceIP"));
    if source_ip.is_empty() {
        source_ip = string_array_field(object.get("source"));
    }

    let network = NetworkKind::parse_optional(object.get("network"));
    if let Some(NetworkKind::Unknown(raw)) = &network {
        warnings.push(format!("Routing rule {position}: unknown network value: {raw}"));
    }

    let webhook = webhook_from_value(object.get("webhook"), warnings, position);

    let extra: Map<String, Value> = object
        .iter()
        .filter(|(key, _)| !KNOWN_RULE_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    RoutingRuleEntry {
        rule_tag: string_field(object.get("ruleTag")),
        domain: string_array_field(object.get("domain")),
        ip: string_array_field(object.get("ip")),
        port: scalar_or_string_field(object.get("port")),
        source_port: scalar_or_string_field(object.get("sourcePort")),
        local_port: scalar_or_string_field(object.get("localPort")),
        network,
        source_ip,
        local_ip: string_array_field(object.get("localIP")),
        user: string_array_field(object.get("user")),
        vless_route: scalar_or_string_field(object.get("vlessRoute")),
        inbound_tag: string_array_field(object.get("inboundTag")),
        protocol: string_array_field(object.get("protocol")),
        attrs: attrs_pairs(object.get("attrs")),
        process: string_array_field(object.get("process")),
        outbound_tag: string_field(object.get("outboundTag")),
        balancer_tag: string_field(object.get("balancerTag")),
        webhook,
        extra,
    }
}

fn webhook_from_value(
    value: Option<&Value>,
    warnings: &mut Vec<String>,
    rule_position: usize,
) -> Option<WebhookEntry> {
    let value = value?;
    let Some(object) = value.as_object() else {
        warnings.push(format!(
            "Routing rule {rule_position}: webhook has an unsupported shape and was skipped."
        ));
        return None;
    };

    let url = match object.get("url") {
        Some(Value::String(text)) => text.clone(),
        _ => {
            warnings.push(format!("Routing rule {rule_position}: webhook is missing a url."));
            String::new()
        }
    };
    let deduplication = object.get("deduplication").and_then(Value::as_u64);
    let headers = object
        .get("headers")
        .and_then(Value::as_object)
        .map(object_to_pairs)
        .unwrap_or_default();

    Some(WebhookEntry {
        url,
        deduplication,
        headers,
    })
}

fn attrs_pairs(value: Option<&Value>) -> Vec<(String, String)> {
    value
        .and_then(Value::as_object)
        .map(object_to_pairs)
        .unwrap_or_default()
}

fn object_to_pairs(object: &Map<String, Value>) -> Vec<(String, String)> {
    object
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|v| (key.clone(), v.to_owned())))
        .collect()
}

fn parse_balancers(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<BalancerEntry> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    array
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let position = index + 1;
            match entry.as_object() {
                Some(object) => Some(balancer_from_object(object, position, warnings)),
                None => {
                    warnings.push(format!(
                        "Balancer {position} has an unsupported shape and was skipped."
                    ));
                    None
                }
            }
        })
        .collect()
}

fn balancer_from_object(
    object: &Map<String, Value>,
    position: usize,
    warnings: &mut Vec<String>,
) -> BalancerEntry {
    let tag = string_field(object.get("tag")).unwrap_or_default();
    if tag.is_empty() {
        warnings.push(format!("Balancer {position} is missing a tag."));
    }

    let strategy = object
        .get("strategy")
        .and_then(Value::as_object)
        .map(|s| strategy_from_object(s, position, warnings));

    let extra: Map<String, Value> = object
        .iter()
        .filter(|(key, _)| !KNOWN_BALANCER_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    BalancerEntry {
        tag,
        selector: string_array_field(object.get("selector")),
        fallback_tag: string_field(object.get("fallbackTag")),
        strategy,
        extra,
    }
}

fn strategy_from_object(
    object: &Map<String, Value>,
    position: usize,
    warnings: &mut Vec<String>,
) -> StrategyEntry {
    let strategy_type = BalancerStrategyType::parse(object.get("type"));
    if let BalancerStrategyType::Unknown(raw) = &strategy_type {
        warnings.push(format!("Balancer {position}: unknown strategy type: {raw}"));
    }
    let settings = object
        .get("settings")
        .and_then(Value::as_object)
        .map(|s| strategy_settings_from_object(s, position, warnings));
    StrategyEntry {
        strategy_type,
        settings,
    }
}

fn strategy_settings_from_object(
    object: &Map<String, Value>,
    position: usize,
    warnings: &mut Vec<String>,
) -> StrategySettingsEntry {
    let costs = object
        .get("costs")
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| match entry.as_object() {
                    Some(object) => Some(cost_from_object(object)),
                    None => {
                        warnings.push(format!(
                            "Balancer {position} cost #{} has an unsupported shape and was skipped.",
                            index + 1
                        ));
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    StrategySettingsEntry {
        expected: object.get("expected").and_then(Value::as_i64),
        max_rtt: string_field(object.get("maxRTT")),
        tolerance: object.get("tolerance").and_then(Value::as_f64),
        baselines: string_array_field(object.get("baselines")),
        costs,
    }
}

fn cost_from_object(object: &Map<String, Value>) -> CostEntry {
    CostEntry {
        regexp: bool_field(object.get("regexp")),
        match_value: string_field(object.get("match")).unwrap_or_default(),
        value: object.get("value").and_then(Value::as_f64).unwrap_or(0.0),
    }
}

/// Applies typed settings onto a `routing` JSON object, preserving unknown keys (including
/// `domainMatcher` — see module docs).
pub fn apply_routing_settings_to_value(
    target: &mut Value,
    settings: &RoutingSettings,
) -> ConfigModifyResult<()> {
    let object = match target {
        Value::Object(map) => map,
        Value::Null => {
            *target = Value::Object(Map::new());
            target.as_object_mut().expect("just created object")
        }
        _ => {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "routing section must be a JSON object".to_owned(),
            ));
        }
    };

    object.insert(
        "domainStrategy".to_owned(),
        Value::String(settings.domain_strategy.as_str().to_owned()),
    );

    if settings.rules.is_empty() {
        object.remove("rules");
    } else {
        let rules: Vec<Value> = settings.rules.iter().map(RoutingRuleEntry::to_value).collect();
        object.insert("rules".to_owned(), Value::Array(rules));
    }

    if settings.balancers.is_empty() {
        object.remove("balancers");
    } else {
        let balancers: Vec<Value> = settings.balancers.iter().map(BalancerEntry::to_value).collect();
        object.insert("balancers".to_owned(), Value::Array(balancers));
    }

    Ok(())
}

/// Creates a fresh `routing` object from settings (no unknown keys).
pub fn routing_settings_to_new_value(settings: &RoutingSettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_routing_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary. Rules/balancers are complex
/// nested structures, so — like `dns_settings_change_summary`'s treatment of `servers`/`hosts` —
/// only the configured count is reported here; the full structural diff is available via
/// "Preview changes".
pub fn routing_settings_change_summary(before: &RoutingSettings, after: &RoutingSettings) -> Vec<String> {
    let mut lines = Vec::new();

    if before.domain_strategy.as_str() != after.domain_strategy.as_str() {
        lines.push(format!(
            "domainStrategy:\n{} → {}",
            before.domain_strategy.as_str(),
            after.domain_strategy.as_str()
        ));
    }
    if before.rules != after.rules {
        lines.push(format!(
            "Routing rules:\n{} → {} configured (see Preview changes for full detail)",
            before.rules.len(),
            after.rules.len()
        ));
    }
    if before.balancers != after.balancers {
        lines.push(format!(
            "Balancers:\n{} → {} configured (see Preview changes for full detail)",
            before.balancers.len(),
            after.balancers.len()
        ));
    }

    lines
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient (`rules.md`: "prefer compatibility over convenience") — most string
/// fields are only checked for control characters; port/RTT/duration grammars are not
/// re-validated here (`xray run -test` already runs after every save). The one structural rule
/// enforced is the documented one: every routing rule needs a target (`outboundTag` or
/// `balancerTag`), and every balancer needs a non-empty, unique `tag`.
pub fn validate_routing_settings(settings: &RoutingSettings) -> ConfigModifyResult<()> {
    for (index, rule) in settings.rules.iter().enumerate() {
        let position = index + 1;
        validate_optional_control_chars(&rule.rule_tag, &format!("Routing rule {position} ruleTag"))?;
        for domain in &rule.domain {
            validate_control_chars(domain, &format!("Routing rule {position} domain entry"))?;
        }
        for ip in &rule.ip {
            validate_control_chars(ip, &format!("Routing rule {position} ip entry"))?;
        }
        validate_optional_control_chars(&rule.port, &format!("Routing rule {position} port"))?;
        validate_optional_control_chars(&rule.source_port, &format!("Routing rule {position} sourcePort"))?;
        validate_optional_control_chars(&rule.local_port, &format!("Routing rule {position} localPort"))?;
        for ip in &rule.source_ip {
            validate_control_chars(ip, &format!("Routing rule {position} sourceIP entry"))?;
        }
        for ip in &rule.local_ip {
            validate_control_chars(ip, &format!("Routing rule {position} localIP entry"))?;
        }
        for user in &rule.user {
            validate_control_chars(user, &format!("Routing rule {position} user entry"))?;
        }
        validate_optional_control_chars(&rule.vless_route, &format!("Routing rule {position} vlessRoute"))?;
        for tag in &rule.inbound_tag {
            validate_control_chars(tag, &format!("Routing rule {position} inboundTag entry"))?;
        }
        for protocol in &rule.protocol {
            validate_control_chars(protocol, &format!("Routing rule {position} protocol entry"))?;
        }
        for (key, value) in &rule.attrs {
            if key.trim().is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    format!("Routing rule {position}: attrs key must not be empty"),
                ));
            }
            validate_control_chars(key, &format!("Routing rule {position} attrs key"))?;
            validate_control_chars(value, &format!("Routing rule {position} attrs value"))?;
        }
        for process in &rule.process {
            validate_control_chars(process, &format!("Routing rule {position} process entry"))?;
        }
        validate_optional_control_chars(&rule.outbound_tag, &format!("Routing rule {position} outboundTag"))?;
        validate_optional_control_chars(&rule.balancer_tag, &format!("Routing rule {position} balancerTag"))?;

        if non_empty(&rule.outbound_tag).is_none() && non_empty(&rule.balancer_tag).is_none() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Routing rule {position} must set outboundTag or balancerTag"),
            ));
        }

        if let Some(webhook) = &rule.webhook {
            if webhook.url.trim().is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    format!("Routing rule {position}: webhook url must not be empty"),
                ));
            }
            validate_control_chars(&webhook.url, &format!("Routing rule {position} webhook url"))?;
            for (key, value) in &webhook.headers {
                validate_control_chars(key, &format!("Routing rule {position} webhook header key"))?;
                validate_control_chars(value, &format!("Routing rule {position} webhook header value"))?;
            }
        }
    }

    let mut seen_tags = std::collections::HashSet::new();
    for (index, balancer) in settings.balancers.iter().enumerate() {
        let position = index + 1;
        if balancer.tag.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("Balancer {position} must have a tag"),
            ));
        }
        validate_control_chars(&balancer.tag, &format!("Balancer {position} tag"))?;
        if !seen_tags.insert(balancer.tag.clone()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("duplicate balancer tag: {}", balancer.tag),
            ));
        }
        for selector in &balancer.selector {
            validate_control_chars(selector, &format!("Balancer {position} selector entry"))?;
        }
        validate_optional_control_chars(&balancer.fallback_tag, &format!("Balancer {position} fallbackTag"))?;

        if let Some(strategy) = &balancer.strategy
            && let Some(settings) = &strategy.settings
        {
            validate_optional_control_chars(
                &settings.max_rtt,
                &format!("Balancer {position} strategy maxRTT"),
            )?;
            for baseline in &settings.baselines {
                validate_control_chars(baseline, &format!("Balancer {position} strategy baseline"))?;
            }
            for (cost_index, cost) in settings.costs.iter().enumerate() {
                let cost_position = cost_index + 1;
                if cost.match_value.trim().is_empty() {
                    return Err(ConfigModifyError::new(
                        ConfigModifyErrorKind::ValidationFailed,
                        format!("Balancer {position} cost {cost_position} must have a match value"),
                    ));
                }
                validate_control_chars(
                    &cost.match_value,
                    &format!("Balancer {position} cost {cost_position} match"),
                )?;
            }
        }
    }

    Ok(())
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn validate_control_chars(value: &str, field: &str) -> ConfigModifyResult<()> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field} must not contain control characters"),
        ));
    }
    Ok(())
}

fn validate_optional_control_chars(value: &Option<String>, field: &str) -> ConfigModifyResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    validate_control_chars(value, field)
}

fn number_from_f64(value: f64) -> Value {
    Number::from_f64(value).map(Value::Number).unwrap_or(Value::Null)
}

fn pairs_to_object(pairs: &[(String, String)]) -> Value {
    let mut object = Map::new();
    for (key, value) in pairs {
        object.insert(key.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}

fn string_vec_to_value(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn string_field(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        _ => None,
    }
}

fn scalar_or_string_field(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn string_array_field(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn bool_field(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(value: Value) -> SourcedSection<Value> {
        SourcedSection::new("/etc/xray/config.json", value)
    }

    #[test]
    fn missing_routing_object_uses_defaults() {
        let settings = routing_settings_from_section(None);
        assert!(!settings.section_present);
        assert_eq!(settings.domain_strategy, DomainStrategy::AsIs);
        assert!(settings.rules.is_empty());
        assert!(settings.balancers.is_empty());
    }

    #[test]
    fn malformed_routing_object_warns() {
        let settings = routing_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed routing object"))
        );
    }

    #[test]
    fn domain_strategy_round_trips_and_defaults() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "domainStrategy": "IPOnDemand"
        }))));
        assert_eq!(settings.domain_strategy, DomainStrategy::IpOnDemand);

        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["domainStrategy"], "IPOnDemand");
    }

    #[test]
    fn unknown_domain_strategy_preserved_and_warned() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "domainStrategy": "FutureStrategy"
        }))));
        assert_eq!(
            settings.domain_strategy,
            DomainStrategy::Unknown("FutureStrategy".to_owned())
        );
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("Unknown domainStrategy: FutureStrategy"))
        );
    }

    #[test]
    fn rule_with_domain_and_outbound_round_trips() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{ "domain": ["geosite:google"], "outboundTag": "proxy" }]
        }))));
        assert_eq!(settings.rules.len(), 1);
        assert_eq!(settings.rules[0].domain, vec!["geosite:google".to_owned()]);
        assert_eq!(settings.rules[0].outbound_tag.as_deref(), Some("proxy"));

        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["rules"][0]["domain"], json!(["geosite:google"]));
        assert_eq!(value["rules"][0]["outboundTag"], "proxy");
    }

    #[test]
    fn source_alias_is_read_but_source_ip_is_written() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{ "source": ["10.0.0.0/8"], "outboundTag": "direct" }]
        }))));
        assert_eq!(settings.rules[0].source_ip, vec!["10.0.0.0/8".to_owned()]);

        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["rules"][0]["sourceIP"], json!(["10.0.0.0/8"]));
        assert!(value["rules"][0].get("source").is_none());
    }

    #[test]
    fn source_ip_preferred_when_both_present() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{
                "sourceIP": ["1.1.1.1"],
                "source": ["2.2.2.2"],
                "outboundTag": "direct"
            }]
        }))));
        assert_eq!(settings.rules[0].source_ip, vec!["1.1.1.1".to_owned()]);
    }

    #[test]
    fn port_accepts_number_and_string_shapes() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [
                { "port": 443, "outboundTag": "a" },
                { "port": "1000-2000", "outboundTag": "b" }
            ]
        }))));
        assert_eq!(settings.rules[0].port.as_deref(), Some("443"));
        assert_eq!(settings.rules[1].port.as_deref(), Some("1000-2000"));
    }

    #[test]
    fn network_parses_and_warns_on_unknown() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{ "network": "quic", "outboundTag": "direct" }]
        }))));
        assert_eq!(
            settings.rules[0].network,
            Some(NetworkKind::Unknown("quic".to_owned()))
        );
        assert!(settings.warnings.iter().any(|w| w.contains("unknown network")));
    }

    #[test]
    fn network_tcp_udp_round_trips() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{ "network": "tcp,udp", "outboundTag": "direct" }]
        }))));
        assert_eq!(settings.rules[0].network, Some(NetworkKind::TcpUdp));
        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["rules"][0]["network"], "tcp,udp");
    }

    #[test]
    fn attrs_round_trip() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{
                "attrs": { ":method": "GET", "Content-Type": "video/.*" },
                "outboundTag": "direct"
            }]
        }))));
        assert_eq!(settings.rules[0].attrs.len(), 2);
        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["rules"][0]["attrs"][":method"], "GET");
    }

    #[test]
    fn webhook_round_trips() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{
                "outboundTag": "direct",
                "webhook": {
                    "url": "https://example.com/hook",
                    "deduplication": 30,
                    "headers": { "X-Token": "secret" }
                }
            }]
        }))));
        let webhook = settings.rules[0].webhook.as_ref().unwrap();
        assert_eq!(webhook.url, "https://example.com/hook");
        assert_eq!(webhook.deduplication, Some(30));
        assert_eq!(webhook.headers, vec![("X-Token".to_owned(), "secret".to_owned())]);

        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["rules"][0]["webhook"]["url"], "https://example.com/hook");
        assert_eq!(value["rules"][0]["webhook"]["deduplication"], 30);
    }

    #[test]
    fn webhook_missing_url_warns_but_is_kept() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{ "outboundTag": "direct", "webhook": { "deduplication": 5 } }]
        }))));
        assert!(settings.rules[0].webhook.is_some());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("webhook is missing a url"))
        );
    }

    #[test]
    fn unknown_rule_fields_including_legacy_type_are_preserved() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "rules": [{ "type": "field", "outboundTag": "direct", "futureField": 42 }]
        }))));
        assert_eq!(settings.rules[0].extra.get("type"), Some(&json!("field")));
        assert_eq!(settings.rules[0].extra.get("futureField"), Some(&json!(42)));

        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["rules"][0]["type"], "field");
        assert_eq!(value["rules"][0]["futureField"], 42);
    }

    #[test]
    fn apply_preserves_unrelated_top_level_keys_including_domain_matcher() {
        let mut value = json!({
            "domainMatcher": "hybrid",
            "futureField": 1
        });
        let settings = RoutingSettings::defaults();
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["domainMatcher"], "hybrid");
        assert_eq!(value["futureField"], 1);
        assert_eq!(value["domainStrategy"], "AsIs");
    }

    #[test]
    fn balancer_round_trips_selector_and_fallback() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "balancers": [{ "tag": "lb", "selector": ["proxy-"], "fallbackTag": "direct" }]
        }))));
        assert_eq!(settings.balancers.len(), 1);
        assert_eq!(settings.balancers[0].tag, "lb");
        assert_eq!(settings.balancers[0].selector, vec!["proxy-".to_owned()]);
        assert_eq!(settings.balancers[0].fallback_tag.as_deref(), Some("direct"));

        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["balancers"][0]["tag"], "lb");
        assert_eq!(value["balancers"][0]["fallbackTag"], "direct");
    }

    #[test]
    fn balancer_strategy_least_load_with_costs_round_trips() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "balancers": [{
                "tag": "lb",
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "expected": 2,
                        "maxRTT": "1s",
                        "tolerance": 0.1,
                        "baselines": ["400ms", "800ms"],
                        "costs": [{ "regexp": false, "match": "warp", "value": 10.0 }]
                    }
                }
            }]
        }))));
        let strategy = settings.balancers[0].strategy.as_ref().unwrap();
        assert_eq!(strategy.strategy_type, BalancerStrategyType::LeastLoad);
        let s = strategy.settings.as_ref().unwrap();
        assert_eq!(s.expected, Some(2));
        assert_eq!(s.max_rtt.as_deref(), Some("1s"));
        assert_eq!(s.tolerance, Some(0.1));
        assert_eq!(s.baselines.len(), 2);
        assert_eq!(s.costs[0].match_value, "warp");
        assert_eq!(s.costs[0].value, 10.0);

        let mut value = json!({});
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["balancers"][0]["strategy"]["type"], "leastLoad");
        assert_eq!(value["balancers"][0]["strategy"]["settings"]["expected"], 2);
        assert_eq!(
            value["balancers"][0]["strategy"]["settings"]["costs"][0]["match"],
            "warp"
        );
    }

    #[test]
    fn unknown_balancer_strategy_type_preserved_and_warned() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "balancers": [{ "tag": "lb", "strategy": { "type": "futureStrategy" } }]
        }))));
        assert_eq!(
            settings.balancers[0].strategy.as_ref().unwrap().strategy_type,
            BalancerStrategyType::Unknown("futureStrategy".to_owned())
        );
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("unknown strategy type"))
        );
    }

    #[test]
    fn missing_balancer_tag_warns_but_is_kept() {
        let settings = routing_settings_from_section(Some(&section(json!({
            "balancers": [{ "selector": ["direct"] }]
        }))));
        assert_eq!(settings.balancers.len(), 1);
        assert_eq!(settings.balancers[0].tag, "");
        assert!(settings.warnings.iter().any(|w| w.contains("missing a tag")));
    }

    #[test]
    fn change_summary_reports_domain_strategy_and_counts() {
        let before = RoutingSettings::defaults();
        let mut after = before.clone();
        after.domain_strategy = DomainStrategy::IpIfNonMatch;
        after.rules.push(RoutingRuleEntry {
            outbound_tag: Some("direct".to_owned()),
            ..RoutingRuleEntry::blank()
        });
        after.balancers.push(BalancerEntry {
            tag: "lb".to_owned(),
            ..BalancerEntry::blank()
        });
        let summary = routing_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 3);
        assert!(summary[0].contains("domainStrategy"));
        assert!(summary[1].contains("0 → 1"));
        assert!(summary[2].contains("0 → 1"));
    }

    #[test]
    fn change_summary_empty_when_unchanged() {
        let settings = RoutingSettings::defaults();
        assert!(routing_settings_change_summary(&settings, &settings).is_empty());
    }

    #[test]
    fn validation_accepts_defaults() {
        assert!(validate_routing_settings(&RoutingSettings::defaults()).is_ok());
    }

    #[test]
    fn validation_rejects_rule_without_target() {
        let mut settings = RoutingSettings::defaults();
        settings.rules.push(RoutingRuleEntry::blank());
        let error = validate_routing_settings(&settings).unwrap_err();
        assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(error.message().contains("outboundTag or balancerTag"));
    }

    #[test]
    fn validation_accepts_rule_with_balancer_tag_only() {
        let mut settings = RoutingSettings::defaults();
        settings.rules.push(RoutingRuleEntry {
            balancer_tag: Some("lb".to_owned()),
            ..RoutingRuleEntry::blank()
        });
        settings.balancers.push(BalancerEntry {
            tag: "lb".to_owned(),
            ..BalancerEntry::blank()
        });
        assert!(validate_routing_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_control_characters_in_domain() {
        let mut settings = RoutingSettings::defaults();
        settings.rules.push(RoutingRuleEntry {
            domain: vec!["bad\ndomain".to_owned()],
            outbound_tag: Some("direct".to_owned()),
            ..RoutingRuleEntry::blank()
        });
        assert!(validate_routing_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_empty_webhook_url() {
        let mut settings = RoutingSettings::defaults();
        settings.rules.push(RoutingRuleEntry {
            outbound_tag: Some("direct".to_owned()),
            webhook: Some(WebhookEntry::blank()),
            ..RoutingRuleEntry::blank()
        });
        let error = validate_routing_settings(&settings).unwrap_err();
        assert!(error.message().contains("webhook url"));
    }

    #[test]
    fn validation_rejects_empty_balancer_tag() {
        let mut settings = RoutingSettings::defaults();
        settings.balancers.push(BalancerEntry::blank());
        assert!(validate_routing_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_duplicate_balancer_tags() {
        let mut settings = RoutingSettings::defaults();
        settings.balancers.push(BalancerEntry {
            tag: "lb".to_owned(),
            ..BalancerEntry::blank()
        });
        settings.balancers.push(BalancerEntry {
            tag: "lb".to_owned(),
            ..BalancerEntry::blank()
        });
        let error = validate_routing_settings(&settings).unwrap_err();
        assert!(error.message().contains("duplicate balancer tag"));
    }

    #[test]
    fn validation_rejects_empty_cost_match() {
        let mut settings = RoutingSettings::defaults();
        settings.balancers.push(BalancerEntry {
            tag: "lb".to_owned(),
            strategy: Some(StrategyEntry {
                strategy_type: BalancerStrategyType::LeastLoad,
                settings: Some(StrategySettingsEntry {
                    costs: vec![CostEntry::blank()],
                    ..StrategySettingsEntry::default()
                }),
            }),
            ..BalancerEntry::blank()
        });
        let error = validate_routing_settings(&settings).unwrap_err();
        assert!(error.message().contains("cost 1 must have a match value"));
    }

    #[test]
    fn rules_empty_removes_key_on_apply() {
        let mut value = json!({ "rules": [{"outboundTag": "old"}] });
        let settings = RoutingSettings::defaults();
        apply_routing_settings_to_value(&mut value, &settings).unwrap();
        assert!(value.get("rules").is_none());
    }

    #[test]
    fn to_new_value_creates_object_with_no_unknown_keys() {
        let mut settings = RoutingSettings::defaults();
        settings.domain_strategy = DomainStrategy::IpIfNonMatch;
        let value = routing_settings_to_new_value(&settings);
        assert!(value.is_object());
        assert_eq!(value.as_object().unwrap().len(), 1);
        assert_eq!(value["domainStrategy"], "IPIfNonMatch");
    }
}
