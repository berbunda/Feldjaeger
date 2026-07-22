//! Read-only Routing page view model for [`super::ApplicationService`].
//!
//! The GUI consumes supported summary fields only and never inspects JSON.

use crate::app::inbounds::{
    LoadedConfigSnapshot, MISSING_FIELD, display_optional_str, display_source_file,
};
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, RoutingRuleSummary, RoutingSummary};

/// Columns that support sorting on the Routing rules table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingSortColumn {
    /// Original config order.
    #[default]
    Index,
    /// Sort by display target (`outboundTag` / `balancerTag`).
    Target,
}

/// Current sort settings for the Routing rules table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoutingSort {
    /// Active sort column.
    pub column: RoutingSortColumn,
    /// `true` for ascending order.
    pub ascending: bool,
}

impl RoutingSort {
    /// Default: preserve config order.
    pub fn by_index() -> Self {
        Self {
            column: RoutingSortColumn::Index,
            ascending: true,
        }
    }
}

/// High-level state shown by the Routing page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded without a routing section.
    RoutingSectionMissing,
    /// Routing section present but `rules` is empty.
    NoRoutingRules,
    /// Routing configuration loaded without warnings.
    ConfigurationLoaded,
    /// Configuration loaded with non-fatal warnings.
    ConfigurationContainsWarnings,
}

impl RoutingPageState {
    /// User-facing explanation for this state.
    pub fn message(self) -> &'static str {
        match self {
            Self::NoSshConnection => {
                "No SSH connection. Connect to a server on the Connection page first."
            }
            Self::XrayNotDiscovered => {
                "Xray installation not discovered. Run Discover Xray on the Connection page."
            }
            Self::ConfigurationNotLoaded => {
                "Configuration not loaded. Discover Xray again after the config becomes readable."
            }
            Self::RoutingSectionMissing => "Routing section is not configured.",
            Self::NoRoutingRules => "No routing rules.",
            Self::ConfigurationLoaded => "Routing configuration loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the details below."
            }
        }
    }

    /// Returns whether supported routing details can be rendered.
    pub fn shows_routing(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings | Self::NoRoutingRules
        )
    }

    /// Returns whether the rules table should be rendered.
    pub fn shows_table(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings
        )
    }
}

/// Read-only model exposed to the Routing page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPageModel {
    /// Coarse page state.
    pub state: RoutingPageState,
    /// Supported routing data, when the section exists.
    pub summary: Option<RoutingSummary>,
    /// Rules to display (already sorted).
    pub rows: Vec<RoutingRuleSummary>,
    /// Non-fatal configuration warnings.
    pub warnings: Vec<String>,
    /// Active sort settings.
    pub sort: RoutingSort,
}

/// Derives the Routing page state from connection, discovery, and config state.
pub fn derive_routing_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> RoutingPageState {
    if ssh != SshStatus::Connected {
        return RoutingPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => RoutingPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                RoutingPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                routing, warnings, ..
            } => {
                if !warnings.is_empty() {
                    RoutingPageState::ConfigurationContainsWarnings
                } else if routing.is_none() {
                    RoutingPageState::RoutingSectionMissing
                } else if routing.as_ref().is_some_and(|r| r.rules.is_empty()) {
                    RoutingPageState::NoRoutingRules
                } else {
                    RoutingPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the read-only Routing page model.
pub fn build_routing_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    sort: RoutingSort,
) -> RoutingPageModel {
    let state = derive_routing_page_state(ssh, discovery, config);
    let summary = config.routing().cloned();
    let mut rows = summary
        .as_ref()
        .map(|routing| routing.rules.clone())
        .unwrap_or_default();
    sort_routing_rule_summaries(&mut rows, sort);
    RoutingPageModel {
        state,
        summary,
        rows,
        warnings: config.warnings().to_vec(),
        sort,
    }
}

/// Sorts routing rule summaries in place according to [`RoutingSort`].
pub fn sort_routing_rule_summaries(rows: &mut [RoutingRuleSummary], sort: RoutingSort) {
    rows.sort_by(|left, right| {
        let ordering = match sort.column {
            RoutingSortColumn::Index => left.index.cmp(&right.index),
            RoutingSortColumn::Target => {
                cmp_optional_str(left.target.as_deref(), right.target.as_deref())
            }
        };
        if sort.ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

fn cmp_optional_str(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
    left.unwrap_or("").cmp(right.unwrap_or(""))
}

/// Formatted general routing fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingGeneralDisplay {
    /// Domain strategy or `—`.
    pub domain_strategy: String,
    /// Domain matcher or `—`.
    pub domain_matcher: String,
    /// Rule count or `—` when summary absent.
    pub rule_count: String,
    /// Basename of the source file.
    pub source_file: String,
}

/// Formats general routing fields for display.
pub fn routing_general_display(summary: &RoutingSummary) -> RoutingGeneralDisplay {
    RoutingGeneralDisplay {
        domain_strategy: display_optional_str(summary.domain_strategy.as_deref()),
        domain_matcher: display_optional_str(summary.domain_matcher.as_deref()),
        rule_count: summary.rule_count.to_string(),
        source_file: display_source_file(&summary.source_file).to_owned(),
    }
}

/// Formatted cells for one routing rule row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRuleRowDisplay {
    /// One-based display index.
    pub index: String,
    /// Target tag or `—`.
    pub target: String,
    /// Comma-separated criteria labels or `—`.
    pub criteria: String,
    /// Compact summary text.
    pub summary: String,
    /// Basename of the source file.
    pub source_file: String,
}

/// Formats one routing rule row.
pub fn routing_rule_row_display(rule: &RoutingRuleSummary) -> RoutingRuleRowDisplay {
    RoutingRuleRowDisplay {
        index: (rule.index + 1).to_string(),
        target: display_optional_str(rule.target.as_deref()),
        criteria: if rule.criteria.is_empty() {
            MISSING_FIELD.to_owned()
        } else {
            rule.criteria.join(", ")
        },
        summary: if rule.summary.is_empty() {
            MISSING_FIELD.to_owned()
        } else {
            rule.summary.clone()
        },
        source_file: display_source_file(&rule.source_file).to_owned(),
    }
}

/// Formats a string list for detail panels.
pub fn display_routing_list(values: &[String]) -> String {
    if values.is_empty() {
        MISSING_FIELD.to_owned()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{ConfigSource, InitSystemKind, XrayConfigParser, XrayInstallation};

    fn succeeded() -> DiscoveryState {
        DiscoveryState::Succeeded(XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: None,
            version: None,
            service_name: None,
            service_state: None,
            exec_start: None,
            config_source: ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        })
    }

    fn loaded(routing: Option<RoutingSummary>, warnings: Vec<String>) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing,
            policy: None,
            vless_clients: Vec::new(),
            warnings,
            editable: None,
        }
    }

    fn parse_routing(source_file: &str, json: &str) -> RoutingSummary {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file(source_file, json);
        assert!(
            !outcome.has_fatal_errors(),
            "unexpected parse errors: {:?}",
            outcome.errors()
        );
        outcome
            .sections()
            .routing_summary()
            .expect("routing summary")
    }

    #[test]
    fn missing_routing_section_is_not_an_error() {
        let model = build_routing_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(None, Vec::new()),
            RoutingSort::by_index(),
        );
        assert_eq!(model.state, RoutingPageState::RoutingSectionMissing);
        assert_eq!(model.state.message(), "Routing section is not configured.");
        assert!(model.summary.is_none());
        assert!(!model.state.shows_table());
    }

    #[test]
    fn empty_routing_rules() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{"routing":{"domainStrategy":"AsIs","rules":[]}}"#,
        );
        let model = build_routing_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary), Vec::new()),
            RoutingSort::by_index(),
        );
        assert_eq!(model.state, RoutingPageState::NoRoutingRules);
        assert_eq!(model.state.message(), "No routing rules.");
        assert!(model.rows.is_empty());
        assert!(model.state.shows_routing());
        assert!(!model.state.shows_table());
    }

    #[test]
    fn one_rule_geosite_outbound() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "domainMatcher": "hybrid",
                    "rules": [
                        {
                            "domain": ["geosite:google"],
                            "outboundTag": "proxy"
                        }
                    ]
                }
            }"#,
        );
        let model = build_routing_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary), Vec::new()),
            RoutingSort::by_index(),
        );
        assert_eq!(model.state, RoutingPageState::ConfigurationLoaded);
        assert_eq!(model.rows.len(), 1);
        let row = routing_rule_row_display(&model.rows[0]);
        assert_eq!(row.index, "1");
        assert_eq!(row.target, "proxy");
        assert_eq!(row.criteria, "Domain");
        assert_eq!(row.summary, "domain: geosite:google");
        assert_eq!(row.source_file, "config.json");

        let general = routing_general_display(model.summary.as_ref().unwrap());
        assert_eq!(general.domain_strategy, "IPIfNonMatch");
        assert_eq!(general.domain_matcher, "hybrid");
        assert_eq!(general.rule_count, "1");
    }

    #[test]
    fn several_rules_including_geoip_protocol_inbound() {
        let summary = parse_routing(
            "/etc/xray/04-routing.json",
            r#"{
                "routing": {
                    "rules": [
                        {"ip":["geoip:private"],"outboundTag":"direct"},
                        {"protocol":["bittorrent"],"outboundTag":"block"},
                        {"inboundTag":["socks-in"],"balancerTag":"round"}
                    ]
                }
            }"#,
        );
        assert_eq!(summary.rule_count, 3);
        assert_eq!(summary.rules[0].summary, "ip: geoip:private");
        assert_eq!(summary.rules[0].target.as_deref(), Some("direct"));
        assert_eq!(summary.rules[1].summary, "protocol: bittorrent");
        assert_eq!(summary.rules[2].summary, "inbound: socks-in");
        assert_eq!(summary.rules[2].target.as_deref(), Some("round"));
        assert_eq!(summary.rules[2].balancer_tag.as_deref(), Some("round"));
        assert_eq!(display_source_file(&summary.source_file), "04-routing.json");
    }

    #[test]
    fn balancer_tag_used_when_outbound_absent() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{"routing":{"rules":[{"network":"tcp","balancerTag":"lb"}]}}"#,
        );
        assert_eq!(summary.rules[0].target.as_deref(), Some("lb"));
        assert_eq!(summary.rules[0].summary, "network: tcp");
    }

    #[test]
    fn outbound_tag_preferred_over_balancer_tag() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{"routing":{"rules":[{"outboundTag":"direct","balancerTag":"lb"}]}}"#,
        );
        assert_eq!(summary.rules[0].target.as_deref(), Some("direct"));
        assert_eq!(summary.rules[0].outbound_tag.as_deref(), Some("direct"));
        assert_eq!(summary.rules[0].balancer_tag.as_deref(), Some("lb"));
    }

    #[test]
    fn unknown_match_condition_is_ignored_in_criteria() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{
                "routing": {
                    "rules": [
                        {
                            "futureMatch": ["x"],
                            "outboundTag": "proxy",
                            "domain": ["example.com"]
                        }
                    ]
                }
            }"#,
        );
        assert_eq!(summary.rules[0].criteria, vec!["Domain".to_owned()]);
        assert_eq!(summary.rules[0].summary, "domain: example.com");
        assert_eq!(summary.rules[0].target.as_deref(), Some("proxy"));
    }

    #[test]
    fn missing_optional_fields_show_dash() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{"routing":{"rules":[{"outboundTag":"direct"}]}}"#,
        );
        let general = routing_general_display(&summary);
        assert_eq!(general.domain_strategy, MISSING_FIELD);
        assert_eq!(general.domain_matcher, MISSING_FIELD);
        let row = routing_rule_row_display(&summary.rules[0]);
        assert_eq!(row.criteria, MISSING_FIELD);
        assert_eq!(row.summary, MISSING_FIELD);
        assert_eq!(row.target, "direct");
    }

    #[test]
    fn multi_criteria_summary_uses_count_text() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{
                "routing": {
                    "rules": [
                        {
                            "domain": ["google.com"],
                            "ip": ["1.1.1.1"],
                            "protocol": ["tls"],
                            "outboundTag": "proxy"
                        }
                    ]
                }
            }"#,
        );
        assert_eq!(summary.rules[0].summary, "3 совпадающих условия");
        assert_eq!(
            summary.rules[0].criteria,
            vec!["Domain".to_owned(), "IP".to_owned(), "Protocol".to_owned()]
        );
    }

    #[test]
    fn configuration_not_loaded_state() {
        let model = build_routing_page_model(
            SshStatus::Connected,
            &succeeded(),
            &LoadedConfigSnapshot::NotLoaded,
            RoutingSort::by_index(),
        );
        assert_eq!(model.state, RoutingPageState::ConfigurationNotLoaded);
        assert!(model.state.message().contains("Configuration not loaded"));
    }

    #[test]
    fn no_ssh_and_not_discovered_states() {
        assert_eq!(
            derive_routing_page_state(
                SshStatus::Disconnected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            RoutingPageState::NoSshConnection
        );
        assert_eq!(
            derive_routing_page_state(
                SshStatus::Connected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            RoutingPageState::XrayNotDiscovered
        );
    }

    #[test]
    fn warnings_with_available_routing() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{"routing":{"rules":[{"ip":["geoip:cn"],"outboundTag":"direct"}]}}"#,
        );
        let model = build_routing_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary), vec!["other section warning".to_owned()]),
            RoutingSort::by_index(),
        );
        assert_eq!(model.state, RoutingPageState::ConfigurationContainsWarnings);
        assert!(model.state.shows_table());
        assert_eq!(model.rows.len(), 1);
    }

    #[test]
    fn sort_by_target() {
        let summary = parse_routing(
            "/etc/xray/config.json",
            r#"{
                "routing": {
                    "rules": [
                        {"outboundTag":"zeta"},
                        {"outboundTag":"alpha"}
                    ]
                }
            }"#,
        );
        let mut rows = summary.rules;
        sort_routing_rule_summaries(
            &mut rows,
            RoutingSort {
                column: RoutingSortColumn::Target,
                ascending: true,
            },
        );
        assert_eq!(rows[0].target.as_deref(), Some("alpha"));
        assert_eq!(rows[1].target.as_deref(), Some("zeta"));
    }

    #[test]
    fn source_file_basename_for_single_and_directory() {
        assert_eq!(
            display_source_file("/usr/local/etc/xray/config.json"),
            "config.json"
        );
        assert_eq!(
            display_source_file("/usr/local/etc/xray/04-routing.json"),
            "04-routing.json"
        );
    }
}
