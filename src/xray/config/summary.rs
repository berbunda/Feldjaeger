//! Read-only summary views of inbounds, outbounds, DNS, FakeDNS, observatory, routing, and policy for GUI lists.

use std::net::IpAddr;

use serde_json::Value;

use super::sections::XrayConfigSections;
use super::sourced_section::SourcedSection;

/// Read-only description of one configured DNS server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerSummary {
    /// Server address, including unknown future address schemes.
    pub address: Option<String>,
    /// Domain match rules assigned to this server.
    pub domains: Vec<String>,
    /// Expected IP match rules assigned to this server.
    pub expected_ips: Vec<String>,
    /// Whether this server is skipped during fallback.
    pub skip_fallback: Option<bool>,
    /// EDNS client subnet address configured for this server.
    pub client_ip: Option<String>,
}

/// Read-only description of one static DNS host target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHostSummary {
    /// Domain or domain-matching expression.
    pub domain: String,
    /// IPv4, IPv6, or domain alias target.
    pub target: String,
}

/// Read-only description of the configured Xray DNS section.
///
/// The underlying sourced JSON remains the lossless internal model. This
/// summary deliberately exposes only fields supported by the DNS page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSummary {
    /// Global DNS query strategy.
    pub query_strategy: Option<String>,
    /// Whether DNS caching is disabled.
    pub disable_cache: Option<bool>,
    /// Whether fallback queries are disabled.
    pub disable_fallback: Option<bool>,
    /// Whether fallback is disabled after a domain match.
    pub disable_fallback_if_match: Option<bool>,
    /// Routing tag for DNS-generated traffic.
    pub tag: Option<String>,
    /// Configured DNS servers in source order.
    pub servers: Vec<DnsServerSummary>,
    /// Static host mappings, with one row per target.
    pub hosts: Vec<DnsHostSummary>,
    /// File that contributed the DNS section.
    pub source_file: String,
}

/// Lightweight read-only description of a single inbound entry.
///
/// Protocol-specific settings are not deeply inspected; only common top-level
/// fields and a shallow `settings.clients` length are extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSummary {
    /// Zero-based position in the merged inbound list (order preserved).
    pub index: usize,
    /// Inbound `tag`, when present and a string.
    pub tag: Option<String>,
    /// Inbound `protocol` string (including unknown future protocols).
    pub protocol: Option<String>,
    /// Inbound `listen` address, when present and a string.
    pub listen: Option<String>,
    /// Inbound `port` when it is a non-negative JSON number.
    pub port: Option<u64>,
    /// Number of entries in `settings.clients`, when that array exists.
    pub clients_count: Option<usize>,
    /// File that contributed this inbound.
    pub source_file: String,
}

/// Known outbound protocol kinds used for shallow summary generation.
///
/// Unknown / future protocols map to [`OutboundKind::Unknown`] and never panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundKind {
    /// `blackhole` outbound.
    Blackhole,
    /// `dns` outbound.
    Dns,
    /// `freedom` outbound (direct).
    Freedom,
    /// `http` outbound.
    Http,
    /// `hysteria` outbound.
    Hysteria,
    /// `loopback` outbound.
    Loopback,
    /// `shadowsocks` outbound.
    Shadowsocks,
    /// `socks` outbound.
    Socks,
    /// `trojan` outbound.
    Trojan,
    /// `vless` outbound.
    Vless,
    /// `vmess` outbound.
    Vmess,
    /// `wireguard` outbound.
    Wireguard,
    /// Protocol string missing or not in the known set.
    Unknown,
}

impl OutboundKind {
    /// Classifies a protocol string (case-insensitive). Missing → [`Unknown`](Self::Unknown).
    pub fn from_protocol(protocol: Option<&str>) -> Self {
        match protocol.map(str::trim).filter(|text| !text.is_empty()) {
            Some(name) if name.eq_ignore_ascii_case("blackhole") => Self::Blackhole,
            Some(name) if name.eq_ignore_ascii_case("dns") => Self::Dns,
            Some(name) if name.eq_ignore_ascii_case("freedom") => Self::Freedom,
            Some(name) if name.eq_ignore_ascii_case("http") => Self::Http,
            Some(name) if name.eq_ignore_ascii_case("hysteria") => Self::Hysteria,
            Some(name) if name.eq_ignore_ascii_case("loopback") => Self::Loopback,
            Some(name) if name.eq_ignore_ascii_case("shadowsocks") => Self::Shadowsocks,
            Some(name) if name.eq_ignore_ascii_case("socks") => Self::Socks,
            Some(name) if name.eq_ignore_ascii_case("trojan") => Self::Trojan,
            Some(name) if name.eq_ignore_ascii_case("vless") => Self::Vless,
            Some(name) if name.eq_ignore_ascii_case("vmess") => Self::Vmess,
            Some(name) if name.eq_ignore_ascii_case("wireguard") => Self::Wireguard,
            Some(_) | None => Self::Unknown,
        }
    }
}

/// Lightweight read-only description of a single outbound entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSummary {
    /// Zero-based position in the merged outbound list (order preserved).
    pub index: usize,
    /// Outbound `tag`, when present and a string.
    pub tag: Option<String>,
    /// Outbound `protocol` string (including unknown future protocols).
    pub protocol: Option<String>,
    /// Outbound `sendThrough` address, when present and a string.
    pub send_through: Option<String>,
    /// Short protocol-specific summary for the GUI table.
    pub description: String,
    /// File that contributed this outbound.
    pub source_file: String,
}

impl OutboundSummary {
    /// Classified protocol kind for this summary (derived, not stored).
    pub fn kind(&self) -> OutboundKind {
        OutboundKind::from_protocol(self.protocol.as_deref())
    }
}

impl InboundSummary {
    /// Builds a summary from a sourced inbound JSON object.
    pub fn from_sourced(index: usize, sourced: &SourcedSection<Value>) -> Self {
        let value = sourced.value();
        Self {
            index,
            tag: string_field(value, "tag"),
            protocol: string_field(value, "protocol"),
            listen: string_field(value, "listen"),
            port: port_field(value),
            clients_count: clients_count(value),
            source_file: sourced.source_file().to_owned(),
        }
    }
}

impl OutboundSummary {
    /// Builds a summary from a sourced outbound JSON object.
    pub fn from_sourced(index: usize, sourced: &SourcedSection<Value>) -> Self {
        let value = sourced.value();
        let protocol = string_field(value, "protocol");
        let description = outbound_description(protocol.as_deref(), value);
        Self {
            index,
            tag: string_field(value, "tag"),
            protocol,
            send_through: string_field(value, "sendThrough"),
            description,
            source_file: sourced.source_file().to_owned(),
        }
    }
}

impl DnsSummary {
    /// Builds a supported read-only view from a sourced DNS JSON value.
    pub fn from_sourced(sourced: &SourcedSection<Value>) -> Self {
        let value = sourced.value();
        Self {
            query_strategy: string_field(value, "queryStrategy"),
            disable_cache: bool_field(value, "disableCache"),
            disable_fallback: bool_field(value, "disableFallback"),
            disable_fallback_if_match: bool_field(value, "disableFallbackIfMatch"),
            tag: string_field(value, "tag"),
            servers: dns_servers(value),
            hosts: dns_hosts(value),
            source_file: sourced.source_file().to_owned(),
        }
    }
}

/// Collects inbound summaries from a parsed configuration in list order.
pub fn inbound_summaries(sections: &XrayConfigSections) -> Vec<InboundSummary> {
    sections
        .inbounds()
        .iter()
        .enumerate()
        .map(|(index, sourced)| InboundSummary::from_sourced(index, sourced))
        .collect()
}

/// Collects outbound summaries from a parsed configuration in list order.
pub fn outbound_summaries(sections: &XrayConfigSections) -> Vec<OutboundSummary> {
    sections
        .outbounds()
        .iter()
        .enumerate()
        .map(|(index, sourced)| OutboundSummary::from_sourced(index, sourced))
        .collect()
}

/// Builds the DNS summary when a DNS section is present.
pub fn dns_summary(sections: &XrayConfigSections) -> Option<DnsSummary> {
    sections.dns().map(DnsSummary::from_sourced)
}

/// Address family derived from a FakeDNS `ipPool` for display only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FakeDnsAddressFamily {
    /// IPv4 CIDR pool.
    Ipv4,
    /// IPv6 CIDR pool.
    Ipv6,
    /// Missing, malformed, or unrecognized pool address.
    Unknown,
}

impl FakeDnsAddressFamily {
    /// Human-readable label for the GUI.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Unknown => "Unknown",
        }
    }
}

/// Read-only description of one FakeDNS pool entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsPoolSummary {
    /// CIDR block (`ipPool`), when present and a string.
    pub ip_pool: Option<String>,
    /// Maximum Domain-IP mappings (`poolSize`), when present.
    pub pool_size: Option<u64>,
    /// Display-only address family derived from `ipPool`.
    pub address_family: FakeDnsAddressFamily,
}

/// Read-only description of the configured Xray FakeDNS section.
///
/// Official FakeDNS accepts either a single object or an array of pool objects.
/// Both shapes are normalized into [`pools`](Self::pools). Unknown nested keys
/// remain in the lossless JSON and only produce non-fatal warnings here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsSummary {
    /// Normalized FakeDNS pools in source order.
    pub pools: Vec<FakeDnsPoolSummary>,
    /// File that contributed the FakeDNS section.
    pub source_file: String,
    /// Non-fatal FakeDNS-specific warnings (missing fields, bad CIDR, unknowns).
    pub warnings: Vec<String>,
}

impl FakeDnsSummary {
    /// Builds a supported read-only view from a sourced FakeDNS JSON value.
    pub fn from_sourced(sourced: &SourcedSection<Value>) -> Self {
        let value = sourced.value();
        let source_file = sourced.source_file().to_owned();
        let mut warnings = Vec::new();
        let pools = extract_fakedns_pools(value, &mut warnings);
        Self {
            pools,
            source_file,
            warnings,
        }
    }
}

/// Builds the FakeDNS summary when a FakeDNS section is present.
pub fn fakedns_summary(sections: &XrayConfigSections) -> Option<FakeDnsSummary> {
    sections.fakedns().map(FakeDnsSummary::from_sourced)
}

/// Read-only description of the configured Xray background Observatory section.
///
/// Only the supported ObservatoryObject fields are projected. Unknown nested
/// keys remain in the lossless JSON and never cause extraction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatorySummary {
    /// Probe target URL (`probeUrl`).
    pub probe_url: Option<String>,
    /// Probe interval string (`probeInterval`), for example `10s`.
    pub probe_interval: Option<String>,
    /// Outbound tag prefix selectors (`subjectSelector`) in source order.
    pub subject_selectors: Vec<String>,
    /// File that contributed the Observatory section.
    pub source_file: String,
    /// Non-fatal Observatory-specific warnings.
    pub warnings: Vec<String>,
}

impl ObservatorySummary {
    /// Builds a supported read-only view from a sourced Observatory JSON value.
    pub fn from_sourced(sourced: &SourcedSection<Value>) -> Self {
        let value = sourced.value();
        let source_file = sourced.source_file().to_owned();
        let mut warnings = Vec::new();

        if let Some(object) = value.as_object() {
            for key in object.keys() {
                if key != "probeUrl" && key != "probeInterval" && key != "subjectSelector" {
                    warnings.push(format!("unknown field `{key}` is preserved."));
                }
            }
        } else {
            warnings.push("Observatory section has an unsupported shape.".to_owned());
        }

        let probe_url = match value.get("probeUrl") {
            None => {
                warnings.push("`probeUrl` is missing.".to_owned());
                None
            }
            Some(Value::String(text)) => Some(text.clone()),
            Some(_) => {
                warnings.push("`probeUrl` has an unsupported type.".to_owned());
                None
            }
        };

        let probe_interval = match value.get("probeInterval") {
            None => {
                warnings.push("`probeInterval` is missing.".to_owned());
                None
            }
            Some(Value::String(text)) => Some(text.clone()),
            Some(_) => {
                warnings.push("`probeInterval` has an unsupported type.".to_owned());
                None
            }
        };

        let subject_selectors = extract_subject_selectors(value, &mut warnings);

        Self {
            probe_url,
            probe_interval,
            subject_selectors,
            source_file,
            warnings,
        }
    }
}

/// Builds the Observatory summary when an Observatory section is present.
pub fn observatory_summary(sections: &XrayConfigSections) -> Option<ObservatorySummary> {
    sections.observatory().map(ObservatorySummary::from_sourced)
}

/// Read-only projection of Xray's singular Burst Observatory `pingConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstPingConfigSummary {
    /// URL probed through each selected outbound.
    pub destination: Option<String>,
    /// URL used to check local network connectivity.
    pub connectivity: Option<String>,
    /// Probe interval duration.
    pub interval: Option<String>,
    /// Number of recent samples retained by Xray.
    pub sampling: Option<u64>,
    /// Per-probe timeout duration.
    pub timeout: Option<String>,
    /// HTTP method used by the probe.
    pub http_method: Option<String>,
    /// Concise human-readable description for table display.
    pub summary: String,
}

/// Read-only description of the configured Xray Burst Observatory section.
///
/// The underlying sourced JSON remains authoritative and lossless. This
/// projection contains only fields supported by the read-only UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstObservatorySummary {
    /// Outbound tag prefix selectors in source order.
    pub subject_selectors: Vec<String>,
    /// Official singular `pingConfig`, when usable.
    pub ping_config: Option<BurstPingConfigSummary>,
    /// File that contributed the Burst Observatory section.
    pub source_file: String,
    /// Non-fatal section-specific warnings.
    pub warnings: Vec<String>,
}

impl BurstObservatorySummary {
    /// Builds a supported read-only view from sourced Burst Observatory JSON.
    pub fn from_sourced(sourced: &SourcedSection<Value>) -> Self {
        let value = sourced.value();
        let mut warnings = Vec::new();

        if let Some(object) = value.as_object() {
            for key in object.keys() {
                if key != "subjectSelector" && key != "pingConfig" {
                    warnings.push(format!("unknown field `{key}` is preserved."));
                }
            }
        } else {
            warnings.push("BurstObservatory section has an unsupported shape.".to_owned());
        }

        let subject_selectors = extract_subject_selectors(value, &mut warnings);
        let ping_config = extract_burst_ping_config(value, &mut warnings);

        Self {
            subject_selectors,
            ping_config,
            source_file: sourced.source_file().to_owned(),
            warnings,
        }
    }
}

/// Builds the Burst Observatory summary when the section is present.
pub fn burst_observatory_summary(sections: &XrayConfigSections) -> Option<BurstObservatorySummary> {
    sections
        .burst_observatory()
        .map(BurstObservatorySummary::from_sourced)
}

fn extract_burst_ping_config(
    value: &Value,
    warnings: &mut Vec<String>,
) -> Option<BurstPingConfigSummary> {
    let ping = match value.get("pingConfig") {
        None => {
            warnings.push("`pingConfig` is missing.".to_owned());
            return None;
        }
        Some(Value::Object(object)) => object,
        Some(_) => {
            warnings.push("`pingConfig` has an unsupported type.".to_owned());
            return None;
        }
    };

    for key in ping.keys() {
        if !matches!(
            key.as_str(),
            "destination" | "connectivity" | "interval" | "sampling" | "timeout" | "httpMethod"
        ) {
            warnings.push(format!("unknown `pingConfig` field `{key}` is preserved."));
        }
    }

    let destination = optional_string(ping.get("destination"), "pingConfig.destination", warnings);
    let connectivity = optional_string(
        ping.get("connectivity"),
        "pingConfig.connectivity",
        warnings,
    );
    let interval = optional_string(ping.get("interval"), "pingConfig.interval", warnings);
    let timeout = optional_string(ping.get("timeout"), "pingConfig.timeout", warnings);
    let http_method = optional_string(ping.get("httpMethod"), "pingConfig.httpMethod", warnings);
    let sampling = match ping.get("sampling") {
        None => None,
        Some(Value::Number(number)) => number.as_u64().or_else(|| {
            warnings.push("`pingConfig.sampling` must be a non-negative integer.".to_owned());
            None
        }),
        Some(_) => {
            warnings.push("`pingConfig.sampling` has an unsupported type.".to_owned());
            None
        }
    };

    let summary = match (&destination, &interval, sampling) {
        (Some(destination), Some(interval), Some(sampling)) => {
            format!("{destination} every {interval}, {sampling} samples")
        }
        (Some(destination), Some(interval), None) => format!("{destination} every {interval}"),
        (Some(destination), None, _) => destination.clone(),
        (None, Some(interval), _) => format!("Probe every {interval}"),
        (None, None, _) => "Ping configuration".to_owned(),
    };

    Some(BurstPingConfigSummary {
        destination,
        connectivity,
        interval,
        sampling,
        timeout,
        http_method,
        summary,
    })
}

fn optional_string(
    value: Option<&Value>,
    field: &str,
    warnings: &mut Vec<String>,
) -> Option<String> {
    match value {
        None => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => {
            warnings.push(format!("`{field}` has an unsupported type."));
            None
        }
    }
}

fn extract_subject_selectors(value: &Value, warnings: &mut Vec<String>) -> Vec<String> {
    match value.get("subjectSelector") {
        None => {
            warnings.push("`subjectSelector` is missing.".to_owned());
            Vec::new()
        }
        Some(Value::Array(items)) => {
            if items.is_empty() {
                warnings.push("`subjectSelector` is empty.".to_owned());
                return Vec::new();
            }
            let mut selectors = Vec::new();
            for (index, item) in items.iter().enumerate() {
                match item.as_str() {
                    Some(text) => selectors.push(text.to_owned()),
                    None => warnings.push(format!(
                        "`subjectSelector` entry #{} has an unsupported type and was skipped.",
                        index + 1
                    )),
                }
            }
            if selectors.is_empty() && !items.is_empty() {
                warnings.push("`subjectSelector` contained no usable string entries.".to_owned());
            }
            selectors
        }
        Some(_) => {
            warnings.push("`subjectSelector` has an unsupported type.".to_owned());
            Vec::new()
        }
    }
}

fn extract_fakedns_pools(value: &Value, warnings: &mut Vec<String>) -> Vec<FakeDnsPoolSummary> {
    if let Some(object) = value.as_object() {
        return vec![pool_from_object(object, warnings, None)];
    }
    if let Some(items) = value.as_array() {
        if items.is_empty() {
            warnings.push("FakeDNS pool array is empty.".to_owned());
            return Vec::new();
        }
        return items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                let Some(object) = item.as_object() else {
                    warnings.push(format!(
                        "FakeDNS pool #{} has an unsupported shape and was skipped.",
                        index + 1
                    ));
                    return None;
                };
                Some(pool_from_object(object, warnings, Some(index + 1)))
            })
            .collect();
    }

    warnings.push("FakeDNS section has an unsupported shape.".to_owned());
    Vec::new()
}

fn pool_from_object(
    object: &serde_json::Map<String, Value>,
    warnings: &mut Vec<String>,
    pool_number: Option<usize>,
) -> FakeDnsPoolSummary {
    let prefix = match pool_number {
        Some(number) => format!("FakeDNS pool #{number}: "),
        None => String::new(),
    };

    for key in object.keys() {
        if key != "ipPool" && key != "poolSize" {
            warnings.push(format!("{prefix}unknown field `{key}` is preserved."));
        }
    }

    let ip_pool = match object.get("ipPool") {
        None => {
            warnings.push(format!("{prefix}`ipPool` is missing."));
            None
        }
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => {
            warnings.push(format!("{prefix}`ipPool` has an unsupported type."));
            None
        }
    };

    let pool_size = match object.get("poolSize") {
        None => {
            warnings.push(format!("{prefix}`poolSize` is missing."));
            None
        }
        Some(value) => match u64_from_value(value) {
            Some(size) => Some(size),
            None => {
                warnings.push(format!("{prefix}`poolSize` has an unsupported type."));
                None
            }
        },
    };

    let address_family = match ip_pool.as_deref() {
        Some(pool) => match classify_ip_pool(pool) {
            Ok(family) => family,
            Err(reason) => {
                warnings.push(format!("{prefix}{reason}"));
                FakeDnsAddressFamily::Unknown
            }
        },
        None => FakeDnsAddressFamily::Unknown,
    };

    FakeDnsPoolSummary {
        ip_pool,
        pool_size,
        address_family,
    }
}

fn u64_from_value(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    if let Some(number) = value.as_i64() {
        return u64::try_from(number).ok();
    }
    value.as_str()?.parse().ok()
}

/// Classifies a FakeDNS CIDR pool for display and soft validation.
///
/// Returns [`Ok`] with the address family when the CIDR is structurally valid,
/// or [`Err`] with a warning message when the value is malformed.
fn classify_ip_pool(ip_pool: &str) -> Result<FakeDnsAddressFamily, String> {
    let trimmed = ip_pool.trim();
    let Some((address_text, prefix_text)) = trimmed.split_once('/') else {
        return Err("unsupported address format (expected CIDR).".to_owned());
    };

    let address: IpAddr = match address_text.parse() {
        Ok(address) => address,
        Err(_) => return Err("unsupported address format.".to_owned()),
    };
    let prefix: u8 = match prefix_text.parse() {
        Ok(prefix) => prefix,
        Err(_) => return Err("incorrect CIDR prefix.".to_owned()),
    };

    match address {
        IpAddr::V4(_) if prefix <= 32 => Ok(FakeDnsAddressFamily::Ipv4),
        IpAddr::V6(_) if prefix <= 128 => Ok(FakeDnsAddressFamily::Ipv6),
        IpAddr::V4(_) | IpAddr::V6(_) => Err("incorrect CIDR prefix.".to_owned()),
    }
}

/// Read-only description of one routing rule for GUI tables and detail panels.
///
/// Only supported fields are projected. Unknown match keys remain in the
/// underlying lossless JSON and never cause extraction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRuleSummary {
    /// Zero-based position in the `rules` array (order preserved).
    pub index: usize,
    /// Display target: `outboundTag` when present, otherwise `balancerTag`.
    pub target: Option<String>,
    /// Short labels for present match conditions (Domain, IP, …).
    pub criteria: Vec<String>,
    /// Compact one-line summary for the table.
    pub summary: String,
    /// File that contributed the routing section (and therefore this rule).
    pub source_file: String,
    /// Optional `ruleTag`.
    pub rule_tag: Option<String>,
    /// Optional rule `type`.
    pub rule_type: Option<String>,
    /// Domain match expressions.
    pub domain: Vec<String>,
    /// Destination IP match expressions.
    pub ip: Vec<String>,
    /// Destination port (number, range, or mixed list as string).
    pub port: Option<String>,
    /// Source port.
    pub source_port: Option<String>,
    /// Local inbound port.
    pub local_port: Option<String>,
    /// Network (`tcp`, `udp`, or `tcp,udp`).
    pub network: Option<String>,
    /// Source IP match expressions (`sourceIP` / alias `source`).
    pub source_ip: Vec<String>,
    /// Local inbound IP match expressions.
    pub local_ip: Vec<String>,
    /// User email match expressions.
    pub user: Vec<String>,
    /// VLESS route match value.
    pub vless_route: Option<String>,
    /// Inbound tags.
    pub inbound_tag: Vec<String>,
    /// Protocol sniff values.
    pub protocol: Vec<String>,
    /// Compact display of HTTP attribute match object.
    pub attrs_summary: Option<String>,
    /// Process match expressions.
    pub process: Vec<String>,
    /// Target outbound tag.
    pub outbound_tag: Option<String>,
    /// Target balancer tag.
    pub balancer_tag: Option<String>,
}

/// Read-only description of the configured Xray routing section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingSummary {
    /// Domain resolution strategy (`domainStrategy`).
    pub domain_strategy: Option<String>,
    /// Domain matcher implementation (`domainMatcher`).
    pub domain_matcher: Option<String>,
    /// Number of entries in `rules`.
    pub rule_count: usize,
    /// Routing rules in source order.
    pub rules: Vec<RoutingRuleSummary>,
    /// File that contributed the routing section.
    pub source_file: String,
}

impl RoutingSummary {
    /// Builds a supported read-only view from a sourced routing JSON value.
    pub fn from_sourced(sourced: &SourcedSection<Value>) -> Self {
        let value = sourced.value();
        let source_file = sourced.source_file().to_owned();
        let rules = routing_rules(value, &source_file);
        Self {
            domain_strategy: string_field(value, "domainStrategy"),
            domain_matcher: string_field(value, "domainMatcher"),
            rule_count: rules.len(),
            rules,
            source_file,
        }
    }
}

/// Builds the routing summary when a routing section is present.
pub fn routing_summary(sections: &XrayConfigSections) -> Option<RoutingSummary> {
    sections.routing().map(RoutingSummary::from_sourced)
}

/// Read-only description of one user policy level.
///
/// Only supported LevelPolicyObject fields are projected. Unknown keys remain in
/// the underlying lossless JSON and never cause extraction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPolicySummary {
    /// Policy level key from `levels` (JSON object key, kept as string).
    pub level: String,
    /// Handshake timeout in seconds.
    pub handshake: Option<u64>,
    /// Connection idle timeout in seconds.
    pub conn_idle: Option<u64>,
    /// Uplink-only timeout after downlink close, in seconds.
    pub uplink_only: Option<u64>,
    /// Downlink-only timeout after uplink close, in seconds.
    pub downlink_only: Option<u64>,
    /// Internal buffer size in KB.
    pub buffer_size: Option<u64>,
    /// Whether user uplink stats are enabled for this level.
    pub stats_user_uplink: Option<bool>,
    /// Whether user downlink stats are enabled for this level.
    pub stats_user_downlink: Option<bool>,
    /// Whether online-user stats are enabled for this level.
    pub stats_user_online: Option<bool>,
    /// File that contributed the policy section.
    pub source_file: String,
}

/// Read-only description of the system policy object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPolicySummary {
    /// Enable inbound uplink traffic statistics.
    pub stats_inbound_uplink: Option<bool>,
    /// Enable inbound downlink traffic statistics.
    pub stats_inbound_downlink: Option<bool>,
    /// Enable outbound uplink traffic statistics.
    pub stats_outbound_uplink: Option<bool>,
    /// Enable outbound downlink traffic statistics.
    pub stats_outbound_downlink: Option<bool>,
}

/// Read-only description of the configured Xray policy section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySummary {
    /// Number of user levels when `levels` is present (`None` if absent).
    pub user_policy_count: Option<usize>,
    /// User policy levels extracted from `levels`.
    pub user_levels: Vec<UserPolicySummary>,
    /// System policy when the `system` object is present.
    pub system_policy: Option<SystemPolicySummary>,
    /// File that contributed the policy section.
    pub source_file: String,
}

impl PolicySummary {
    /// Builds a supported read-only view from a sourced policy JSON value.
    pub fn from_sourced(sourced: &SourcedSection<Value>) -> Self {
        let value = sourced.value();
        let source_file = sourced.source_file().to_owned();
        let (user_policy_count, user_levels) = policy_user_levels(value, &source_file);
        Self {
            user_policy_count,
            user_levels,
            system_policy: policy_system(value),
            source_file,
        }
    }

    /// Returns `true` when a system policy object was present.
    pub fn has_system_policy(&self) -> bool {
        self.system_policy.is_some()
    }
}

/// Builds the policy summary when a policy section is present.
pub fn policy_summary(sections: &XrayConfigSections) -> Option<PolicySummary> {
    sections.policy().map(PolicySummary::from_sourced)
}

fn policy_user_levels(value: &Value, source_file: &str) -> (Option<usize>, Vec<UserPolicySummary>) {
    let Some(levels) = value.get("levels") else {
        return (None, Vec::new());
    };
    let Some(object) = levels.as_object() else {
        // Non-object `levels` is preserved in lossless JSON but yields no rows.
        return (Some(0), Vec::new());
    };

    let mut user_levels: Vec<UserPolicySummary> = object
        .iter()
        .filter_map(|(level, entry)| {
            entry.as_object().map(|_| UserPolicySummary {
                level: level.clone(),
                handshake: u64_field(entry, "handshake"),
                conn_idle: u64_field(entry, "connIdle"),
                uplink_only: u64_field(entry, "uplinkOnly"),
                downlink_only: u64_field(entry, "downlinkOnly"),
                buffer_size: u64_field(entry, "bufferSize"),
                stats_user_uplink: bool_field(entry, "statsUserUplink"),
                stats_user_downlink: bool_field(entry, "statsUserDownlink"),
                stats_user_online: bool_field(entry, "statsUserOnline"),
                source_file: source_file.to_owned(),
            })
        })
        .collect();

    user_levels.sort_by(|left, right| cmp_policy_level(&left.level, &right.level));
    (Some(user_levels.len()), user_levels)
}

fn policy_system(value: &Value) -> Option<SystemPolicySummary> {
    let system = value.get("system")?;
    system.as_object().map(|_| SystemPolicySummary {
        stats_inbound_uplink: bool_field(system, "statsInboundUplink"),
        stats_inbound_downlink: bool_field(system, "statsInboundDownlink"),
        stats_outbound_uplink: bool_field(system, "statsOutboundUplink"),
        stats_outbound_downlink: bool_field(system, "statsOutboundDownlink"),
    })
}

/// Compares policy level keys numerically when possible, otherwise as strings.
pub fn cmp_policy_level(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<u64>(), right.parse::<u64>()) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => left.cmp(right),
    }
}

fn u64_field(value: &Value, key: &str) -> Option<u64> {
    let field = value.get(key)?;
    if let Some(number) = field.as_u64() {
        return Some(number);
    }
    if let Some(number) = field.as_i64() {
        return u64::try_from(number).ok();
    }
    field.as_str()?.parse().ok()
}

fn routing_rules(value: &Value, source_file: &str) -> Vec<RoutingRuleSummary> {
    value
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .enumerate()
                .filter_map(|(index, rule)| {
                    // Non-object entries are skipped for the GUI projection but do
                    // not fail the whole section (lossless Value still holds them).
                    rule.as_object()
                        .map(|_| RoutingRuleSummary::from_rule_value(index, rule, source_file))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl RoutingRuleSummary {
    fn from_rule_value(index: usize, value: &Value, source_file: &str) -> Self {
        let mut source_ip = string_array_field(value, "sourceIP");
        if source_ip.is_empty() {
            source_ip = string_array_field(value, "source");
        }
        let outbound_tag = string_field(value, "outboundTag");
        let balancer_tag = string_field(value, "balancerTag");
        // Xray: when both are set, outboundTag takes effect.
        let target = outbound_tag.clone().or_else(|| balancer_tag.clone());

        let mut rule = Self {
            index,
            target,
            criteria: Vec::new(),
            summary: String::new(),
            source_file: source_file.to_owned(),
            rule_tag: string_field(value, "ruleTag"),
            rule_type: string_field(value, "type"),
            domain: string_array_field(value, "domain"),
            ip: string_array_field(value, "ip"),
            port: scalar_or_string_field(value, "port"),
            source_port: scalar_or_string_field(value, "sourcePort"),
            local_port: scalar_or_string_field(value, "localPort"),
            network: string_field(value, "network"),
            source_ip,
            local_ip: string_array_field(value, "localIP"),
            user: string_array_field(value, "user"),
            vless_route: scalar_or_string_field(value, "vlessRoute"),
            inbound_tag: string_array_field(value, "inboundTag"),
            protocol: string_array_field(value, "protocol"),
            attrs_summary: attrs_summary_field(value),
            process: string_array_field(value, "process"),
            outbound_tag,
            balancer_tag,
        };
        rule.criteria = rule.criteria_labels();
        rule.summary = build_rule_summary(&rule.condition_snippets());
        rule
    }

    fn criteria_labels(&self) -> Vec<String> {
        let mut labels = Vec::new();
        if !self.domain.is_empty() {
            labels.push("Domain".to_owned());
        }
        if !self.ip.is_empty() {
            labels.push("IP".to_owned());
        }
        if self.port.is_some() {
            labels.push("Port".to_owned());
        }
        if self.source_port.is_some() {
            labels.push("Source Port".to_owned());
        }
        if self.local_port.is_some() {
            labels.push("Local Port".to_owned());
        }
        if self.network.is_some() {
            labels.push("Network".to_owned());
        }
        if !self.source_ip.is_empty() {
            labels.push("Source IP".to_owned());
        }
        if !self.local_ip.is_empty() {
            labels.push("Local IP".to_owned());
        }
        if !self.user.is_empty() {
            labels.push("User".to_owned());
        }
        if self.vless_route.is_some() {
            labels.push("VLESS Route".to_owned());
        }
        if !self.inbound_tag.is_empty() {
            labels.push("Inbound".to_owned());
        }
        if !self.protocol.is_empty() {
            labels.push("Protocol".to_owned());
        }
        if self.attrs_summary.is_some() {
            labels.push("Attribute".to_owned());
        }
        if !self.process.is_empty() {
            labels.push("Process".to_owned());
        }
        labels
    }

    fn condition_snippets(&self) -> Vec<String> {
        let mut snippets = Vec::new();
        push_list_snippet(&mut snippets, "domain", &self.domain);
        push_list_snippet(&mut snippets, "ip", &self.ip);
        if let Some(port) = &self.port {
            snippets.push(format!("port: {port}"));
        }
        if let Some(source_port) = &self.source_port {
            snippets.push(format!("sourcePort: {source_port}"));
        }
        if let Some(local_port) = &self.local_port {
            snippets.push(format!("localPort: {local_port}"));
        }
        if let Some(network) = &self.network {
            snippets.push(format!("network: {network}"));
        }
        push_list_snippet(&mut snippets, "sourceIP", &self.source_ip);
        push_list_snippet(&mut snippets, "localIP", &self.local_ip);
        push_list_snippet(&mut snippets, "user", &self.user);
        if let Some(vless_route) = &self.vless_route {
            snippets.push(format!("vlessRoute: {vless_route}"));
        }
        push_list_snippet(&mut snippets, "inbound", &self.inbound_tag);
        push_list_snippet(&mut snippets, "protocol", &self.protocol);
        if let Some(attrs) = &self.attrs_summary {
            snippets.push(format!("attrs: {attrs}"));
        }
        push_list_snippet(&mut snippets, "process", &self.process);
        snippets
    }
}

fn push_list_snippet(snippets: &mut Vec<String>, label: &str, values: &[String]) {
    if let Some(first) = values.first() {
        if values.len() == 1 {
            snippets.push(format!("{label}: {first}"));
        } else {
            snippets.push(format!("{label}: {first} (+{})", values.len() - 1));
        }
    }
}

fn build_rule_summary(condition_snippets: &[String]) -> String {
    match condition_snippets.len() {
        0 => "—".to_owned(),
        1 => condition_snippets[0].clone(),
        n => format!("{n} совпадающих условия"),
    }
}

fn scalar_or_string_field(value: &Value, key: &str) -> Option<String> {
    let field = value.get(key)?;
    if let Some(text) = field.as_str() {
        return Some(text.to_owned());
    }
    if let Some(number) = field.as_u64() {
        return Some(number.to_string());
    }
    if let Some(number) = field.as_i64() {
        return Some(number.to_string());
    }
    None
}

fn attrs_summary_field(value: &Value) -> Option<String> {
    let attrs = value.get("attrs")?.as_object()?;
    if attrs.is_empty() {
        return None;
    }
    let parts: Vec<String> = attrs
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|text| format!("{key}={text}")))
        .collect();
    if parts.is_empty() {
        Some(format!("{} attribute(s)", attrs.len()))
    } else {
        Some(parts.join(", "))
    }
}

/// Builds a short, read-only protocol summary for the Outbounds table.
///
/// Only a shallow subset of settings is inspected. Unknown protocols never panic.
fn outbound_description(protocol: Option<&str>, value: &Value) -> String {
    match OutboundKind::from_protocol(protocol) {
        OutboundKind::Freedom => "Direct connection".to_owned(),
        OutboundKind::Blackhole => {
            let response_type = value
                .get("settings")
                .and_then(|settings| settings.get("response"))
                .and_then(|response| response.get("type"))
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .unwrap_or("none");
            format!("Response: {response_type}")
        }
        OutboundKind::Wireguard => {
            let peers = value
                .get("settings")
                .and_then(|settings| settings.get("peers"))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            format!("Peers: {peers}")
        }
        OutboundKind::Socks => "Proxy server configured".to_owned(),
        OutboundKind::Dns => {
            let settings = value.get("settings");
            let rewrite_address = settings
                .and_then(|s| s.get("rewriteAddress"))
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty());
            let rule_count = settings
                .and_then(|s| s.get("rules"))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            match rewrite_address {
                Some(address) => {
                    let port = settings
                        .and_then(|s| s.get("rewritePort"))
                        .and_then(Value::as_u64);
                    match port {
                        Some(port) => format!("Rewrite: {address}:{port}"),
                        None => format!("Rewrite: {address}"),
                    }
                }
                None if rule_count > 0 => format!("{rule_count} rule(s)"),
                None => "Default (A/AAAA → internal DNS)".to_owned(),
            }
        }
        OutboundKind::Http
        | OutboundKind::Hysteria
        | OutboundKind::Loopback
        | OutboundKind::Shadowsocks
        | OutboundKind::Trojan
        | OutboundKind::Vless
        | OutboundKind::Vmess
        | OutboundKind::Unknown => "Summary unavailable".to_owned(),
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
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

fn dns_servers(value: &Value) -> Vec<DnsServerSummary> {
    value
        .get("servers")
        .and_then(Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .filter_map(|server| {
                    if let Some(address) = server.as_str() {
                        return Some(DnsServerSummary {
                            address: Some(address.to_owned()),
                            domains: Vec::new(),
                            expected_ips: Vec::new(),
                            skip_fallback: None,
                            client_ip: None,
                        });
                    }
                    server.as_object().map(|_| DnsServerSummary {
                        address: string_field(server, "address"),
                        domains: string_array_field(server, "domains"),
                        expected_ips: string_array_field(server, "expectedIPs"),
                        skip_fallback: bool_field(server, "skipFallback"),
                        client_ip: string_field(server, "clientIP"),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn dns_hosts(value: &Value) -> Vec<DnsHostSummary> {
    let Some(hosts) = value.get("hosts").and_then(Value::as_object) else {
        return Vec::new();
    };

    hosts
        .iter()
        .flat_map(|(domain, target)| {
            let targets: Vec<&str> = if let Some(target) = target.as_str() {
                vec![target]
            } else {
                target
                    .as_array()
                    .map(|items| items.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default()
            };
            targets.into_iter().map(|target| DnsHostSummary {
                domain: domain.clone(),
                target: target.to_owned(),
            })
        })
        .collect()
}

fn port_field(value: &Value) -> Option<u64> {
    let port = value.get("port")?;
    if let Some(number) = port.as_u64() {
        return Some(number);
    }
    // Xray sometimes accepts numeric strings; keep extraction shallow.
    port.as_str()?.parse().ok()
}

fn clients_count(value: &Value) -> Option<usize> {
    let settings = value.get("settings")?;
    if let Some(clients) = settings.get("clients").and_then(Value::as_array) {
        return Some(clients.len());
    }
    // Official VLESS docs also document `users` for the same role.
    settings
        .get("users")
        .and_then(Value::as_array)
        .map(Vec::len)
}
