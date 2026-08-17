//! Typed editor model for the Xray top-level `dns` object (Roadmap §2.1:46).
//!
//! Field semantics follow the official DnsObject / DnsServerObject documentation:
//! <https://xtls.github.io/en/config/dns.html>
//!
//! This is the *editing* counterpart to the read-only [`super::DnsSummary`] used elsewhere in the
//! crate (e.g. `LoadedConfigSnapshot::Loaded.dns`); `DnsSummary` is left untouched and keeps
//! covering only a subset of fields for lightweight display. This module covers every documented
//! field of both `DnsObject` and `DnsServerObject`, mirroring the `log`/`api` editor pattern
//! (`log_settings.rs`, `api_settings.rs`) one tier up in structural complexity: `servers` is an
//! array of string-or-object entries and `hosts` is a map whose values are a string or an array of
//! strings, so this module also owns the string/object collapse rule for `servers[]` (an entry
//! serializes back to a bare address string when every advanced field is unset/default, matching
//! how a hand-written config typically looks) and the string/array collapse rule for `hosts{}`
//! (a single target serializes as a string, multiple as an array).
//!
//! Note the deliberate upstream casing inconsistency: the top-level EDNS client-subnet field is
//! `clientIp`, but the per-server override is `clientIP` (capital IP) — both are reproduced here
//! exactly as Xray-core expects them, not "fixed" to be consistent.

use serde_json::{Map, Value};

use super::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use super::sourced_section::SourcedSection;

/// `dns.queryStrategy` / per-server `queryStrategy` override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryStrategy {
    /// `"UseIP"` — the documented default.
    UseIp,
    /// `"UseIPv4"`.
    UseIPv4,
    /// `"UseIPv6"`.
    UseIPv6,
    /// `"UseSystem"`.
    UseSystem,
    /// Unsupported existing value preserved verbatim.
    Unknown(String),
}

impl QueryStrategy {
    /// Effective default when the field is omitted (Xray default).
    pub fn default_effective() -> Self {
        Self::UseIp
    }

    /// Stable wire value for supported strategies.
    pub fn as_str(&self) -> &str {
        match self {
            Self::UseIp => "UseIP",
            Self::UseIPv4 => "UseIPv4",
            Self::UseIPv6 => "UseIPv6",
            Self::UseSystem => "UseSystem",
            Self::Unknown(raw) => raw.as_str(),
        }
    }

    /// Display label for UI.
    pub fn display_label(&self) -> String {
        match self {
            Self::UseIp => "UseIP".to_owned(),
            Self::UseIPv4 => "UseIPv4".to_owned(),
            Self::UseIPv6 => "UseIPv6".to_owned(),
            Self::UseSystem => "UseSystem".to_owned(),
            Self::Unknown(raw) => format!("Unknown ({raw})"),
        }
    }

    fn parse(value: Option<&Value>) -> Self {
        let Some(value) = value else {
            return Self::default_effective();
        };
        match value {
            Value::Null => Self::default_effective(),
            Value::String(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Self::default_effective();
                }
                match trimmed.to_ascii_lowercase().as_str() {
                    "useip" => Self::UseIp,
                    "useipv4" => Self::UseIPv4,
                    "useipv6" => Self::UseIPv6,
                    "usesystem" => Self::UseSystem,
                    _ => Self::Unknown(trimmed.to_owned()),
                }
            }
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Parses an optional (server-level override) query strategy: `None` means the key was
    /// absent (inherit the top-level value).
    fn parse_optional(value: Option<&Value>) -> Option<Self> {
        value.map(|v| Self::parse(Some(v)))
    }
}

/// One `servers[]` entry, in either shorthand-string or full-object form on disk — this type is
/// the unified in-memory representation; [`apply_dns_settings_to_value`] decides which JSON shape
/// to emit based on whether any field beyond `address` is set (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerEntry {
    /// `address` — required by the spec. Kept as a plain (possibly empty) string rather than
    /// `Option<String>` so a malformed on-disk entry missing this field is still visible in the
    /// editor (with a warning) instead of being silently dropped; [`validate_dns_settings`]
    /// rejects saving with an empty address.
    pub address: String,
    /// `port`. `None` omits the key (default 53).
    pub port: Option<u16>,
    /// `domains`.
    pub domains: Vec<String>,
    /// `expectedIPs`.
    pub expected_ips: Vec<String>,
    /// `unexpectedIPs`.
    pub unexpected_ips: Vec<String>,
    /// `skipFallback`. Key is written only when `true` (default `false`).
    pub skip_fallback: bool,
    /// `finalQuery`. Key is written only when `true` (default `false`).
    pub final_query: bool,
    /// `timeoutMs`. `None` omits the key (default 4000).
    pub timeout_ms: Option<u32>,
    /// Per-server `tag`. `None` omits the key.
    pub tag: Option<String>,
    /// `clientIP` (capital IP — differs from the top-level `clientIp`). `None` omits the key.
    pub client_ip: Option<String>,
    /// Per-server `queryStrategy` override. `None` omits the key (inherit top-level).
    pub query_strategy: Option<QueryStrategy>,
    /// Per-server `disableCache` override. `None` omits the key (inherit top-level).
    pub disable_cache: Option<bool>,
    /// Per-server `serveStale` override. `None` omits the key (inherit top-level).
    pub serve_stale: Option<bool>,
    /// Per-server `serveExpiredTTL` override. `None` omits the key (inherit top-level).
    pub serve_expired_ttl: Option<i64>,
}

impl DnsServerEntry {
    /// A blank entry for the GUI "Add server" action.
    pub fn blank() -> Self {
        Self {
            address: String::new(),
            port: None,
            domains: Vec::new(),
            expected_ips: Vec::new(),
            unexpected_ips: Vec::new(),
            skip_fallback: false,
            final_query: false,
            timeout_ms: None,
            tag: None,
            client_ip: None,
            query_strategy: None,
            disable_cache: None,
            serve_stale: None,
            serve_expired_ttl: None,
        }
    }

    /// `true` when every field beyond `address` is unset/default — such an entry round-trips as
    /// a bare JSON string rather than an object (see module docs).
    fn is_shorthand_eligible(&self) -> bool {
        self.port.is_none()
            && self.domains.is_empty()
            && self.expected_ips.is_empty()
            && self.unexpected_ips.is_empty()
            && !self.skip_fallback
            && !self.final_query
            && self.timeout_ms.is_none()
            && self.tag.is_none()
            && self.client_ip.is_none()
            && self.query_strategy.is_none()
            && self.disable_cache.is_none()
            && self.serve_stale.is_none()
            && self.serve_expired_ttl.is_none()
    }

    fn to_value(&self) -> Value {
        if self.is_shorthand_eligible() {
            return Value::String(self.address.clone());
        }

        let mut object = Map::new();
        object.insert("address".to_owned(), Value::String(self.address.clone()));
        if let Some(port) = self.port {
            object.insert("port".to_owned(), Value::from(port));
        }
        if !self.domains.is_empty() {
            object.insert("domains".to_owned(), string_vec_to_value(&self.domains));
        }
        if !self.expected_ips.is_empty() {
            object.insert(
                "expectedIPs".to_owned(),
                string_vec_to_value(&self.expected_ips),
            );
        }
        if !self.unexpected_ips.is_empty() {
            object.insert(
                "unexpectedIPs".to_owned(),
                string_vec_to_value(&self.unexpected_ips),
            );
        }
        if self.skip_fallback {
            object.insert("skipFallback".to_owned(), Value::Bool(true));
        }
        if self.final_query {
            object.insert("finalQuery".to_owned(), Value::Bool(true));
        }
        if let Some(timeout_ms) = self.timeout_ms {
            object.insert("timeoutMs".to_owned(), Value::from(timeout_ms));
        }
        if let Some(tag) = &self.tag {
            object.insert("tag".to_owned(), Value::String(tag.clone()));
        }
        if let Some(client_ip) = &self.client_ip {
            object.insert("clientIP".to_owned(), Value::String(client_ip.clone()));
        }
        if let Some(query_strategy) = &self.query_strategy {
            object.insert(
                "queryStrategy".to_owned(),
                Value::String(query_strategy.as_str().to_owned()),
            );
        }
        if let Some(disable_cache) = self.disable_cache {
            object.insert("disableCache".to_owned(), Value::Bool(disable_cache));
        }
        if let Some(serve_stale) = self.serve_stale {
            object.insert("serveStale".to_owned(), Value::Bool(serve_stale));
        }
        if let Some(serve_expired_ttl) = self.serve_expired_ttl {
            object.insert(
                "serveExpiredTTL".to_owned(),
                Value::from(serve_expired_ttl),
            );
        }
        Value::Object(object)
    }
}

/// One `hosts{}` entry: a domain key plus its target(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHostEntry {
    /// Domain (or domain-matching expression) — the JSON object key.
    pub domain: String,
    /// One or more IP/domain targets. Serializes as a plain string when there is exactly one,
    /// otherwise as an array.
    pub targets: Vec<String>,
}

impl DnsHostEntry {
    /// A blank entry for the GUI "Add host" action.
    pub fn blank() -> Self {
        Self {
            domain: String::new(),
            targets: Vec::new(),
        }
    }

    fn to_value(&self) -> Value {
        if self.targets.len() == 1 {
            Value::String(self.targets[0].clone())
        } else {
            string_vec_to_value(&self.targets)
        }
    }
}

/// Typed view of the Xray `dns` section for editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    /// Configured DNS servers, in source/edit order.
    pub servers: Vec<DnsServerEntry>,
    /// Static host mappings, in source/edit order (JSON object keys are alphabetical on disk
    /// since this crate's `serde_json` does not enable `preserve_order`).
    pub hosts: Vec<DnsHostEntry>,
    /// Top-level `clientIp` (EDNS client subnet). `None` omits the key.
    pub client_ip: Option<String>,
    /// `queryStrategy`. Always written (even when it equals the documented default), mirroring
    /// `LogSettings::log_level`.
    pub query_strategy: QueryStrategy,
    /// `disableCache`. Always written.
    pub disable_cache: bool,
    /// `serveStale`. Always written.
    pub serve_stale: bool,
    /// `serveExpiredTTL`. Always written.
    pub serve_expired_ttl: i64,
    /// `disableFallback`. Always written.
    pub disable_fallback: bool,
    /// `disableFallbackIfMatch`. Always written.
    pub disable_fallback_if_match: bool,
    /// `enableParallelQuery`. Always written.
    pub enable_parallel_query: bool,
    /// `useSystemHosts`. Always written.
    pub use_system_hosts: bool,
    /// `tag`. `None` omits the key.
    pub tag: Option<String>,
    /// `true` when a top-level `dns` object existed in the loaded config.
    pub section_present: bool,
    /// Source file owning the `dns` section, when known.
    pub source_file: Option<String>,
    /// Non-fatal warnings (unknown values, malformed optional fields/entries).
    pub warnings: Vec<String>,
}

impl DnsSettings {
    /// Effective defaults when the `dns` object is absent (display only).
    pub fn defaults() -> Self {
        Self {
            servers: Vec::new(),
            hosts: Vec::new(),
            client_ip: None,
            query_strategy: QueryStrategy::default_effective(),
            disable_cache: false,
            serve_stale: false,
            serve_expired_ttl: 0,
            disable_fallback: false,
            disable_fallback_if_match: false,
            enable_parallel_query: false,
            use_system_hosts: false,
            tag: None,
            section_present: false,
            source_file: None,
            warnings: Vec::new(),
        }
    }
}

/// Builds [`DnsSettings`] from an optional sourced `dns` section.
pub fn dns_settings_from_section(section: Option<&SourcedSection<Value>>) -> DnsSettings {
    let Some(section) = section else {
        return DnsSettings::defaults();
    };

    let value = section.value();
    let mut warnings = Vec::new();

    if !value.is_object() {
        warnings.push("Malformed dns object: expected a JSON object.".to_owned());
        return DnsSettings {
            section_present: true,
            source_file: Some(section.source_file().to_owned()),
            warnings,
            ..DnsSettings::defaults()
        };
    }

    let client_ip = string_field(value.get("clientIp"));
    let query_strategy = QueryStrategy::parse(value.get("queryStrategy"));
    if let QueryStrategy::Unknown(raw) = &query_strategy {
        warnings.push(format!("Unknown DNS query strategy: {raw}"));
    }
    let disable_cache = bool_field(value.get("disableCache"));
    let serve_stale = bool_field(value.get("serveStale"));
    let serve_expired_ttl = int_field(value.get("serveExpiredTTL"));
    let disable_fallback = bool_field(value.get("disableFallback"));
    let disable_fallback_if_match = bool_field(value.get("disableFallbackIfMatch"));
    let enable_parallel_query = bool_field(value.get("enableParallelQuery"));
    let use_system_hosts = bool_field(value.get("useSystemHosts"));
    let tag = string_field(value.get("tag"));

    let servers = parse_servers(value.get("servers"), &mut warnings);
    let hosts = parse_hosts(value.get("hosts"), &mut warnings);

    DnsSettings {
        servers,
        hosts,
        client_ip,
        query_strategy,
        disable_cache,
        serve_stale,
        serve_expired_ttl,
        disable_fallback,
        disable_fallback_if_match,
        enable_parallel_query,
        use_system_hosts,
        tag,
        section_present: true,
        source_file: Some(section.source_file().to_owned()),
        warnings,
    }
}

fn parse_servers(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<DnsServerEntry> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    array
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let position = index + 1;
            match entry {
                Value::String(address) => Some(DnsServerEntry {
                    address: address.clone(),
                    ..DnsServerEntry::blank()
                }),
                Value::Object(_) => {
                    let address = string_field(entry.get("address")).unwrap_or_default();
                    if address.is_empty() {
                        warnings.push(format!("DNS server entry {position} is missing an address"));
                    }
                    let query_strategy = QueryStrategy::parse_optional(entry.get("queryStrategy"));
                    if let Some(QueryStrategy::Unknown(raw)) = &query_strategy {
                        warnings.push(format!("Unknown DNS query strategy: {raw}"));
                    }
                    Some(DnsServerEntry {
                        address,
                        port: u16_field(entry.get("port")),
                        domains: string_array_field(entry.get("domains")),
                        expected_ips: string_array_field(entry.get("expectedIPs")),
                        unexpected_ips: string_array_field(entry.get("unexpectedIPs")),
                        skip_fallback: bool_field(entry.get("skipFallback")),
                        final_query: bool_field(entry.get("finalQuery")),
                        timeout_ms: u32_field(entry.get("timeoutMs")),
                        tag: string_field(entry.get("tag")),
                        client_ip: string_field(entry.get("clientIP")),
                        query_strategy,
                        disable_cache: bool_field_optional(entry.get("disableCache")),
                        serve_stale: bool_field_optional(entry.get("serveStale")),
                        serve_expired_ttl: int_field_optional(entry.get("serveExpiredTTL")),
                    })
                }
                _ => {
                    warnings.push(format!(
                        "Unsupported DNS server entry {position}: expected a string or object"
                    ));
                    None
                }
            }
        })
        .collect()
}

fn parse_hosts(value: Option<&Value>, warnings: &mut Vec<String>) -> Vec<DnsHostEntry> {
    let Some(object) = value.and_then(Value::as_object) else {
        return Vec::new();
    };

    object
        .iter()
        .filter_map(|(domain, target)| {
            let targets: Vec<String> = match target {
                Value::String(target) => vec![target.clone()],
                Value::Array(items) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                _ => {
                    warnings.push(format!(
                        "Unsupported hosts target for domain {domain:?}: expected a string or array"
                    ));
                    return None;
                }
            };
            Some(DnsHostEntry {
                domain: domain.clone(),
                targets,
            })
        })
        .collect()
}

/// Applies typed settings onto a `dns` JSON object, preserving unknown keys.
pub fn apply_dns_settings_to_value(target: &mut Value, settings: &DnsSettings) -> ConfigModifyResult<()> {
    let object = match target {
        Value::Object(map) => map,
        Value::Null => {
            *target = Value::Object(Map::new());
            target.as_object_mut().expect("just created object")
        }
        _ => {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "dns section must be a JSON object".to_owned(),
            ));
        }
    };

    if settings.hosts.is_empty() {
        object.remove("hosts");
    } else {
        let mut hosts_map = Map::new();
        for entry in &settings.hosts {
            hosts_map.insert(entry.domain.clone(), entry.to_value());
        }
        object.insert("hosts".to_owned(), Value::Object(hosts_map));
    }

    if settings.servers.is_empty() {
        object.remove("servers");
    } else {
        let servers: Vec<Value> = settings.servers.iter().map(DnsServerEntry::to_value).collect();
        object.insert("servers".to_owned(), Value::Array(servers));
    }

    match &settings.client_ip {
        Some(client_ip) => {
            object.insert("clientIp".to_owned(), Value::String(client_ip.clone()));
        }
        None => {
            object.remove("clientIp");
        }
    }
    object.insert(
        "queryStrategy".to_owned(),
        Value::String(settings.query_strategy.as_str().to_owned()),
    );
    object.insert("disableCache".to_owned(), Value::Bool(settings.disable_cache));
    object.insert("serveStale".to_owned(), Value::Bool(settings.serve_stale));
    object.insert(
        "serveExpiredTTL".to_owned(),
        Value::from(settings.serve_expired_ttl),
    );
    object.insert(
        "disableFallback".to_owned(),
        Value::Bool(settings.disable_fallback),
    );
    object.insert(
        "disableFallbackIfMatch".to_owned(),
        Value::Bool(settings.disable_fallback_if_match),
    );
    object.insert(
        "enableParallelQuery".to_owned(),
        Value::Bool(settings.enable_parallel_query),
    );
    object.insert(
        "useSystemHosts".to_owned(),
        Value::Bool(settings.use_system_hosts),
    );
    match &settings.tag {
        Some(tag) => {
            object.insert("tag".to_owned(), Value::String(tag.clone()));
        }
        None => {
            object.remove("tag");
        }
    }

    Ok(())
}

/// Creates a fresh `dns` object from settings (no unknown keys).
pub fn dns_settings_to_new_value(settings: &DnsSettings) -> Value {
    let mut value = Value::Object(Map::new());
    let _ = apply_dns_settings_to_value(&mut value, settings);
    value
}

/// Human-readable change lines for the save confirmation summary.
pub fn dns_settings_change_summary(before: &DnsSettings, after: &DnsSettings) -> Vec<String> {
    let mut lines = Vec::new();

    if before.client_ip != after.client_ip {
        lines.push(format!(
            "clientIp:\n{} → {}",
            before.client_ip.as_deref().unwrap_or("(none)"),
            after.client_ip.as_deref().unwrap_or("(none)")
        ));
    }
    if before.query_strategy.as_str() != after.query_strategy.as_str() {
        lines.push(format!(
            "queryStrategy:\n{} → {}",
            before.query_strategy.as_str(),
            after.query_strategy.as_str()
        ));
    }
    if before.disable_cache != after.disable_cache {
        lines.push(bool_change_line("disableCache", before.disable_cache, after.disable_cache));
    }
    if before.serve_stale != after.serve_stale {
        lines.push(bool_change_line("serveStale", before.serve_stale, after.serve_stale));
    }
    if before.serve_expired_ttl != after.serve_expired_ttl {
        lines.push(format!(
            "serveExpiredTTL:\n{} → {}",
            before.serve_expired_ttl, after.serve_expired_ttl
        ));
    }
    if before.disable_fallback != after.disable_fallback {
        lines.push(bool_change_line(
            "disableFallback",
            before.disable_fallback,
            after.disable_fallback,
        ));
    }
    if before.disable_fallback_if_match != after.disable_fallback_if_match {
        lines.push(bool_change_line(
            "disableFallbackIfMatch",
            before.disable_fallback_if_match,
            after.disable_fallback_if_match,
        ));
    }
    if before.enable_parallel_query != after.enable_parallel_query {
        lines.push(bool_change_line(
            "enableParallelQuery",
            before.enable_parallel_query,
            after.enable_parallel_query,
        ));
    }
    if before.use_system_hosts != after.use_system_hosts {
        lines.push(bool_change_line(
            "useSystemHosts",
            before.use_system_hosts,
            after.use_system_hosts,
        ));
    }
    if before.tag != after.tag {
        lines.push(format!(
            "tag:\n{} → {}",
            before.tag.as_deref().unwrap_or("(none)"),
            after.tag.as_deref().unwrap_or("(none)")
        ));
    }
    if before.servers != after.servers {
        lines.push(format!(
            "DNS servers:\n{} → {} configured (see Preview changes for full detail)",
            before.servers.len(),
            after.servers.len()
        ));
    }
    if before.hosts != after.hosts {
        lines.push(format!(
            "DNS hosts:\n{} → {} configured (see Preview changes for full detail)",
            before.hosts.len(),
            after.hosts.len()
        ));
    }

    lines
}

fn bool_change_line(label: &str, before: bool, after: bool) -> String {
    format!(
        "{label}:\n{} → {}",
        if before { "true" } else { "false" },
        if after { "true" } else { "false" }
    )
}

/// Validates draft settings before they are written remotely.
///
/// Deliberately lenient (rules.md: "prefer compatibility over convenience") — most string fields
/// are only checked for control characters. `clientIp`/`clientIP` are the one exception: EDNS
/// client-subnet is unambiguously a bare IP address, so those two fields are parsed as
/// [`std::net::IpAddr`].
pub fn validate_dns_settings(settings: &DnsSettings) -> ConfigModifyResult<()> {
    validate_optional_control_chars(&settings.tag, "tag")?;
    validate_optional_ip(&settings.client_ip, "clientIp")?;
    if settings.serve_expired_ttl < 0 {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "serveExpiredTTL must not be negative".to_owned(),
        ));
    }

    for (index, server) in settings.servers.iter().enumerate() {
        let position = index + 1;
        if server.address.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("DNS server {position} must have an address"),
            ));
        }
        validate_control_chars(&server.address, &format!("DNS server {position} address"))?;
        for domain in &server.domains {
            validate_control_chars(domain, &format!("DNS server {position} domain"))?;
        }
        for expected in &server.expected_ips {
            validate_control_chars(expected, &format!("DNS server {position} expectedIPs entry"))?;
        }
        for unexpected in &server.unexpected_ips {
            validate_control_chars(unexpected, &format!("DNS server {position} unexpectedIPs entry"))?;
        }
        validate_optional_control_chars(&server.tag, &format!("DNS server {position} tag"))?;
        validate_optional_ip(&server.client_ip, &format!("DNS server {position} clientIP"))?;
        if let Some(ttl) = server.serve_expired_ttl
            && ttl < 0
        {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("DNS server {position} serveExpiredTTL must not be negative"),
            ));
        }
    }

    let mut seen_domains = std::collections::HashSet::new();
    for (index, host) in settings.hosts.iter().enumerate() {
        let position = index + 1;
        if host.domain.trim().is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("DNS host entry {position} must have a domain"),
            ));
        }
        validate_control_chars(&host.domain, &format!("DNS host entry {position} domain"))?;
        if !seen_domains.insert(host.domain.clone()) {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("duplicate DNS host domain: {}", host.domain),
            ));
        }
        if host.targets.is_empty() {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                format!("DNS host entry {position} ({}) must have at least one target", host.domain),
            ));
        }
        for target in &host.targets {
            validate_control_chars(target, &format!("DNS host entry {position} target"))?;
        }
    }

    Ok(())
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

fn validate_optional_ip(value: &Option<String>, field: &str) -> ConfigModifyResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    validate_control_chars(value, field)?;
    value.parse::<std::net::IpAddr>().map_err(|_| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!("{field} must be a valid IP address"),
        )
    })?;
    Ok(())
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

fn bool_field_optional(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(flag)) => Some(*flag),
        _ => None,
    }
}

fn int_field(value: Option<&Value>) -> i64 {
    value.and_then(Value::as_i64).unwrap_or(0)
}

fn int_field_optional(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

fn u16_field(value: Option<&Value>) -> Option<u16> {
    value
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
}

fn u32_field(value: Option<&Value>) -> Option<u32> {
    value
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(value: Value) -> SourcedSection<Value> {
        SourcedSection::new("/etc/xray/config.json", value)
    }

    #[test]
    fn missing_dns_object_uses_defaults() {
        let settings = dns_settings_from_section(None);
        assert!(!settings.section_present);
        assert_eq!(settings.query_strategy, QueryStrategy::UseIp);
        assert!(!settings.disable_cache);
        assert_eq!(settings.serve_expired_ttl, 0);
        assert!(settings.servers.is_empty());
        assert!(settings.hosts.is_empty());
    }

    #[test]
    fn malformed_dns_object_warns() {
        let settings = dns_settings_from_section(Some(&section(json!("not-an-object"))));
        assert!(settings.section_present);
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.starts_with("Malformed dns object"))
        );
    }

    #[test]
    fn all_top_level_scalars_round_trip() {
        let settings = dns_settings_from_section(Some(&section(json!({
            "clientIp": "1.2.3.4",
            "queryStrategy": "UseIPv4",
            "disableCache": true,
            "serveStale": true,
            "serveExpiredTTL": 30,
            "disableFallback": true,
            "disableFallbackIfMatch": true,
            "enableParallelQuery": true,
            "useSystemHosts": true,
            "tag": "dns-out"
        }))));
        assert_eq!(settings.client_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(settings.query_strategy, QueryStrategy::UseIPv4);
        assert!(settings.disable_cache);
        assert!(settings.serve_stale);
        assert_eq!(settings.serve_expired_ttl, 30);
        assert!(settings.disable_fallback);
        assert!(settings.disable_fallback_if_match);
        assert!(settings.enable_parallel_query);
        assert!(settings.use_system_hosts);
        assert_eq!(settings.tag.as_deref(), Some("dns-out"));

        let mut value = json!({});
        apply_dns_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["clientIp"], "1.2.3.4");
        assert_eq!(value["queryStrategy"], "UseIPv4");
        assert_eq!(value["disableCache"], true);
        assert_eq!(value["serveStale"], true);
        assert_eq!(value["serveExpiredTTL"], 30);
        assert_eq!(value["disableFallback"], true);
        assert_eq!(value["disableFallbackIfMatch"], true);
        assert_eq!(value["enableParallelQuery"], true);
        assert_eq!(value["useSystemHosts"], true);
        assert_eq!(value["tag"], "dns-out");
    }

    #[test]
    fn string_shorthand_server_parses_as_address_only() {
        let settings = dns_settings_from_section(Some(&section(json!({
            "servers": ["8.8.8.8"]
        }))));
        assert_eq!(settings.servers.len(), 1);
        assert_eq!(settings.servers[0].address, "8.8.8.8");
        assert_eq!(settings.servers[0].port, None);
        assert!(settings.servers[0].domains.is_empty());
    }

    #[test]
    fn object_form_server_parses_every_field() {
        let settings = dns_settings_from_section(Some(&section(json!({
            "servers": [{
                "address": "1.1.1.1",
                "port": 853,
                "domains": ["geosite:cn"],
                "expectedIPs": ["geoip:cn"],
                "unexpectedIPs": ["geoip:us"],
                "skipFallback": true,
                "finalQuery": true,
                "timeoutMs": 2000,
                "tag": "server-tag",
                "clientIP": "2.2.2.2",
                "queryStrategy": "UseIPv6",
                "disableCache": true,
                "serveStale": false,
                "serveExpiredTTL": 10
            }]
        }))));
        let server = &settings.servers[0];
        assert_eq!(server.address, "1.1.1.1");
        assert_eq!(server.port, Some(853));
        assert_eq!(server.domains, vec!["geosite:cn".to_owned()]);
        assert_eq!(server.expected_ips, vec!["geoip:cn".to_owned()]);
        assert_eq!(server.unexpected_ips, vec!["geoip:us".to_owned()]);
        assert!(server.skip_fallback);
        assert!(server.final_query);
        assert_eq!(server.timeout_ms, Some(2000));
        assert_eq!(server.tag.as_deref(), Some("server-tag"));
        assert_eq!(server.client_ip.as_deref(), Some("2.2.2.2"));
        assert_eq!(server.query_strategy, Some(QueryStrategy::UseIPv6));
        assert_eq!(server.disable_cache, Some(true));
        assert_eq!(server.serve_stale, Some(false));
        assert_eq!(server.serve_expired_ttl, Some(10));
    }

    #[test]
    fn object_server_missing_address_is_kept_with_warning() {
        let settings = dns_settings_from_section(Some(&section(json!({
            "servers": [{ "port": 53 }]
        }))));
        assert_eq!(settings.servers.len(), 1);
        assert_eq!(settings.servers[0].address, "");
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("entry 1 is missing an address"))
        );
    }

    #[test]
    fn unsupported_server_shape_is_skipped_with_warning() {
        let settings = dns_settings_from_section(Some(&section(json!({
            "servers": [42, "8.8.8.8"]
        }))));
        assert_eq!(settings.servers.len(), 1);
        assert_eq!(settings.servers[0].address, "8.8.8.8");
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("Unsupported DNS server entry 1"))
        );
    }

    #[test]
    fn hosts_single_string_and_array_targets_parse() {
        let settings = dns_settings_from_section(Some(&section(json!({
            "hosts": {
                "single.example": "1.2.3.4",
                "multi.example": ["1.1.1.1", "8.8.8.8"]
            }
        }))));
        let single = settings.hosts.iter().find(|h| h.domain == "single.example").unwrap();
        assert_eq!(single.targets, vec!["1.2.3.4".to_owned()]);
        let multi = settings.hosts.iter().find(|h| h.domain == "multi.example").unwrap();
        assert_eq!(multi.targets, vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()]);
    }

    #[test]
    fn unsupported_hosts_target_shape_is_skipped_with_warning() {
        let settings = dns_settings_from_section(Some(&section(json!({
            "hosts": { "bad.example": 42 }
        }))));
        assert!(settings.hosts.is_empty());
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("Unsupported hosts target for domain"))
        );
    }

    #[test]
    fn unknown_query_strategy_preserved_and_warned() {
        let settings = dns_settings_from_section(Some(&section(json!({
            "queryStrategy": "UseFuture"
        }))));
        assert_eq!(
            settings.query_strategy,
            QueryStrategy::Unknown("UseFuture".to_owned())
        );
        assert!(
            settings
                .warnings
                .iter()
                .any(|w| w.contains("Unknown DNS query strategy: UseFuture"))
        );
    }

    #[test]
    fn apply_preserves_unrelated_json_keys() {
        let mut value = json!({
            "queryStrategy": "UseIP",
            "futureField": 42,
            "nested": { "a": 1 }
        });
        let mut settings = DnsSettings::defaults();
        settings.tag = Some("dns-out".to_owned());
        apply_dns_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["futureField"], 42);
        assert_eq!(value["nested"]["a"], 1);
        assert_eq!(value["tag"], "dns-out");
    }

    #[test]
    fn shorthand_collapse_round_trips_plain_address() {
        let mut settings = DnsSettings::defaults();
        settings.servers.push(DnsServerEntry {
            address: "8.8.8.8".to_owned(),
            ..DnsServerEntry::blank()
        });
        let mut value = json!({});
        apply_dns_settings_to_value(&mut value, &settings).unwrap();
        assert_eq!(value["servers"], json!(["8.8.8.8"]));
    }

    #[test]
    fn server_with_only_port_serializes_as_object() {
        let mut settings = DnsSettings::defaults();
        settings.servers.push(DnsServerEntry {
            address: "8.8.8.8".to_owned(),
            port: Some(53),
            ..DnsServerEntry::blank()
        });
        let mut value = json!({});
        apply_dns_settings_to_value(&mut value, &settings).unwrap();
        assert!(value["servers"][0].is_object());
        assert_eq!(value["servers"][0]["address"], "8.8.8.8");
        assert_eq!(value["servers"][0]["port"], 53);
    }

    #[test]
    fn change_summary_only_lists_touched_fields() {
        let before = DnsSettings::defaults();
        let mut after = before.clone();
        after.disable_cache = true;
        after.tag = Some("dns-out".to_owned());
        let summary = dns_settings_change_summary(&before, &after);
        assert_eq!(summary.len(), 2);
        assert!(summary[0].contains("disableCache"));
        assert!(summary[1].contains("tag"));
    }

    #[test]
    fn validation_accepts_defaults_and_full_settings() {
        assert!(validate_dns_settings(&DnsSettings::defaults()).is_ok());
        let mut settings = DnsSettings::defaults();
        settings.client_ip = Some("1.2.3.4".to_owned());
        settings.servers.push(DnsServerEntry {
            address: "1.1.1.1".to_owned(),
            client_ip: Some("::1".to_owned()),
            ..DnsServerEntry::blank()
        });
        settings.hosts.push(DnsHostEntry {
            domain: "example.com".to_owned(),
            targets: vec!["1.2.3.4".to_owned()],
        });
        assert!(validate_dns_settings(&settings).is_ok());
    }

    #[test]
    fn validation_rejects_blank_server_address() {
        let mut settings = DnsSettings::defaults();
        settings.servers.push(DnsServerEntry::blank());
        let error = validate_dns_settings(&settings).unwrap_err();
        assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn validation_rejects_control_characters() {
        let mut settings = DnsSettings::defaults();
        settings.tag = Some("bad\ntag".to_owned());
        assert!(validate_dns_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_bad_client_ip() {
        let mut settings = DnsSettings::defaults();
        settings.client_ip = Some("not-an-ip".to_owned());
        assert!(validate_dns_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_negative_ttl() {
        let mut settings = DnsSettings::defaults();
        settings.serve_expired_ttl = -1;
        assert!(validate_dns_settings(&settings).is_err());
    }

    #[test]
    fn validation_rejects_duplicate_host_domain() {
        let mut settings = DnsSettings::defaults();
        settings.hosts.push(DnsHostEntry {
            domain: "dup.example".to_owned(),
            targets: vec!["1.2.3.4".to_owned()],
        });
        settings.hosts.push(DnsHostEntry {
            domain: "dup.example".to_owned(),
            targets: vec!["5.6.7.8".to_owned()],
        });
        let error = validate_dns_settings(&settings).unwrap_err();
        assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn validation_rejects_empty_host_targets() {
        let mut settings = DnsSettings::defaults();
        settings.hosts.push(DnsHostEntry {
            domain: "empty.example".to_owned(),
            targets: Vec::new(),
        });
        assert!(validate_dns_settings(&settings).is_err());
    }
}
