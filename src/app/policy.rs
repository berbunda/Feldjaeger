//! Read-only Policy page view model for [`super::ApplicationService`].
//!
//! The GUI consumes supported summary fields only and never inspects JSON.

use crate::app::inbounds::{LoadedConfigSnapshot, MISSING_FIELD, display_source_file};
use crate::app::status::SshStatus;
use crate::xray::{
    DiscoveryState, PolicySummary, SystemPolicySummary, UserPolicySummary, cmp_policy_level,
    stats_wiring_warnings,
};

/// Columns that support sorting on the Policy levels table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicySortColumn {
    /// Sort by policy level (numeric-aware).
    #[default]
    Level,
}

/// Current sort settings for the Policy levels table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicySort {
    /// Active sort column.
    pub column: PolicySortColumn,
    /// `true` for ascending order.
    pub ascending: bool,
}

impl PolicySort {
    /// Default: ascending by level.
    pub fn by_level() -> Self {
        Self {
            column: PolicySortColumn::Level,
            ascending: true,
        }
    }
}

/// High-level state shown by the Policy page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded without a policy section.
    PolicySectionMissing,
    /// Policy section present but no user levels.
    NoUserPolicies,
    /// Policy configuration loaded without warnings.
    ConfigurationLoaded,
    /// Configuration loaded with non-fatal warnings.
    ConfigurationContainsWarnings,
}

impl PolicyPageState {
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
            Self::PolicySectionMissing => "Policy section is not configured.",
            Self::NoUserPolicies => "No user policies.",
            Self::ConfigurationLoaded => "Policy configuration loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the details below."
            }
        }
    }

    /// Returns whether supported policy details can be rendered.
    pub fn shows_policy(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings | Self::NoUserPolicies
        )
    }

    /// Returns whether the user-levels table should be rendered.
    pub fn shows_table(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings
        )
    }
}

/// Read-only model exposed to the Policy page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPageModel {
    /// Coarse page state.
    pub state: PolicyPageState,
    /// Supported policy data, when the section exists.
    pub summary: Option<PolicySummary>,
    /// User levels to display (already sorted).
    pub rows: Vec<UserPolicySummary>,
    /// Non-fatal configuration warnings.
    pub warnings: Vec<String>,
    /// Cross-section wiring warnings: `stats` ↔ `policy` ↔ `api` ↔ `metrics` (Roadmap §2.5:106).
    ///
    /// Independent of `warnings` (parse/load warnings) — computed fresh from the loaded
    /// config's raw sections every time the model is built, never persisted.
    pub wiring_warnings: Vec<String>,
    /// Active sort settings.
    pub sort: PolicySort,
}

/// Derives the Policy page state from connection, discovery, and config state.
pub fn derive_policy_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> PolicyPageState {
    if ssh != SshStatus::Connected {
        return PolicyPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => PolicyPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                PolicyPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                policy, warnings, ..
            } => {
                if !warnings.is_empty() {
                    PolicyPageState::ConfigurationContainsWarnings
                } else if policy.is_none() {
                    PolicyPageState::PolicySectionMissing
                } else if policy.as_ref().is_some_and(|p| p.user_levels.is_empty()) {
                    PolicyPageState::NoUserPolicies
                } else {
                    PolicyPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the read-only Policy page model.
pub fn build_policy_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    sort: PolicySort,
) -> PolicyPageModel {
    let state = derive_policy_page_state(ssh, discovery, config);
    let summary = config.policy().cloned();
    let mut rows = summary
        .as_ref()
        .map(|policy| policy.user_levels.clone())
        .unwrap_or_default();
    sort_user_policy_summaries(&mut rows, sort);
    let wiring_warnings = config
        .editable()
        .map(|editable| stats_wiring_warnings(editable.sections()))
        .unwrap_or_default();
    PolicyPageModel {
        state,
        summary,
        rows,
        warnings: config.warnings().to_vec(),
        wiring_warnings,
        sort,
    }
}

/// Sorts user policy summaries in place according to [`PolicySort`].
pub fn sort_user_policy_summaries(rows: &mut [UserPolicySummary], sort: PolicySort) {
    rows.sort_by(|left, right| {
        let ordering = match sort.column {
            PolicySortColumn::Level => cmp_policy_level(&left.level, &right.level),
        };
        if sort.ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

/// Formatted general policy fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGeneralDisplay {
    /// User policy count or `—`.
    pub user_policy_count: String,
    /// Whether system policy is configured (`Configured` or `—`).
    pub system_policy_configured: String,
    /// Basename of the source file.
    pub source_file: String,
}

/// Formats general policy fields for display.
pub fn policy_general_display(summary: &PolicySummary) -> PolicyGeneralDisplay {
    PolicyGeneralDisplay {
        user_policy_count: summary
            .user_policy_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| MISSING_FIELD.to_owned()),
        system_policy_configured: if summary.has_system_policy() {
            "Configured".to_owned()
        } else {
            MISSING_FIELD.to_owned()
        },
        source_file: display_source_file(&summary.source_file).to_owned(),
    }
}

/// Formatted cells for one user policy row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPolicyRowDisplay {
    /// Level key.
    pub level: String,
    /// Handshake timeout or `—`.
    pub handshake: String,
    /// Connection idle timeout or `—`.
    pub conn_idle: String,
    /// Uplink-only timeout or `—`.
    pub uplink_only: String,
    /// Downlink-only timeout or `—`.
    pub downlink_only: String,
    /// Compact stats summary or `—`.
    pub stats: String,
}

/// Formats one user policy row.
pub fn user_policy_row_display(level: &UserPolicySummary) -> UserPolicyRowDisplay {
    UserPolicyRowDisplay {
        level: level.level.clone(),
        handshake: display_optional_u64(level.handshake),
        conn_idle: display_optional_u64(level.conn_idle),
        uplink_only: display_optional_u64(level.uplink_only),
        downlink_only: display_optional_u64(level.downlink_only),
        stats: format_user_stats_cell(level),
    }
}

/// Formatted system policy fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPolicyDisplay {
    /// Inbound uplink stats flag.
    pub stats_inbound_uplink: String,
    /// Inbound downlink stats flag.
    pub stats_inbound_downlink: String,
    /// Outbound uplink stats flag.
    pub stats_outbound_uplink: String,
    /// Outbound downlink stats flag.
    pub stats_outbound_downlink: String,
}

/// Formats system policy flags for display.
pub fn system_policy_display(system: &SystemPolicySummary) -> SystemPolicyDisplay {
    SystemPolicyDisplay {
        stats_inbound_uplink: display_enabled_flag(system.stats_inbound_uplink),
        stats_inbound_downlink: display_enabled_flag(system.stats_inbound_downlink),
        stats_outbound_uplink: display_enabled_flag(system.stats_outbound_uplink),
        stats_outbound_downlink: display_enabled_flag(system.stats_outbound_downlink),
    }
}

/// Formats timeout values for the context-menu copy action.
pub fn format_timeout_values(level: &UserPolicySummary) -> String {
    format!(
        "handshake={}, connIdle={}, uplinkOnly={}, downlinkOnly={}",
        display_optional_u64(level.handshake),
        display_optional_u64(level.conn_idle),
        display_optional_u64(level.uplink_only),
        display_optional_u64(level.downlink_only),
    )
}

/// Formats an optional boolean as Enabled / Disabled / —.
pub fn display_enabled_flag(value: Option<bool>) -> String {
    match value {
        Some(true) => "Enabled".to_owned(),
        Some(false) => "Disabled".to_owned(),
        None => MISSING_FIELD.to_owned(),
    }
}

fn display_optional_u64(value: Option<u64>) -> String {
    value
        .map(|number| number.to_string())
        .unwrap_or_else(|| MISSING_FIELD.to_owned())
}

fn format_user_stats_cell(level: &UserPolicySummary) -> String {
    let mut parts = Vec::new();
    if let Some(enabled) = level.stats_user_uplink {
        parts.push(format!("Uplink: {}", if enabled { "on" } else { "off" }));
    }
    if let Some(enabled) = level.stats_user_downlink {
        parts.push(format!("Downlink: {}", if enabled { "on" } else { "off" }));
    }
    if let Some(enabled) = level.stats_user_online {
        parts.push(format!("Online: {}", if enabled { "on" } else { "off" }));
    }
    if parts.is_empty() {
        MISSING_FIELD.to_owned()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{
        ConfigSource, EditableXrayConfig, InitSystemKind, XrayConfigParser, XrayInstallation,
    };

    fn editable_from(json: &str) -> EditableXrayConfig {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file("/etc/xray/config.json", json);
        assert!(!outcome.has_fatal_errors(), "{:?}", outcome.errors());
        let root: serde_json::Value = serde_json::from_str(json).expect("json");
        EditableXrayConfig::from_single_file("/etc/xray/config.json", root, outcome.into_sections())
    }

    fn loaded_with_editable(editable: EditableXrayConfig) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: editable.policy_summary(),
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: Some(editable),
        }
    }

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

    fn loaded(policy: Option<PolicySummary>, warnings: Vec<String>) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy,
            vless_clients: Vec::new(),
            warnings,
            editable: None,
        }
    }

    fn parse_policy(source_file: &str, json: &str) -> PolicySummary {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file(source_file, json);
        assert!(
            !outcome.has_fatal_errors(),
            "unexpected parse errors: {:?}",
            outcome.errors()
        );
        outcome.sections().policy_summary().expect("policy summary")
    }

    #[test]
    fn missing_policy_section_is_not_an_error() {
        let model = build_policy_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(None, Vec::new()),
            PolicySort::by_level(),
        );
        assert_eq!(model.state, PolicyPageState::PolicySectionMissing);
        assert_eq!(model.state.message(), "Policy section is not configured.");
        assert!(model.summary.is_none());
    }

    #[test]
    fn empty_policy_section() {
        let summary = parse_policy("/etc/xray/config.json", r#"{"policy":{}}"#);
        assert_eq!(summary.user_policy_count, None);
        assert!(summary.user_levels.is_empty());
        assert!(summary.system_policy.is_none());
        let model = build_policy_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary), Vec::new()),
            PolicySort::by_level(),
        );
        assert_eq!(model.state, PolicyPageState::NoUserPolicies);
    }

    #[test]
    fn one_user_level() {
        let summary = parse_policy(
            "/etc/xray/config.json",
            r#"{
                "policy": {
                    "levels": {
                        "0": {
                            "handshake": 4,
                            "connIdle": 300,
                            "uplinkOnly": 2,
                            "downlinkOnly": 5,
                            "bufferSize": 512,
                            "statsUserUplink": true,
                            "statsUserDownlink": false,
                            "statsUserOnline": true
                        }
                    }
                }
            }"#,
        );
        assert_eq!(summary.user_policy_count, Some(1));
        assert_eq!(summary.user_levels.len(), 1);
        let row = user_policy_row_display(&summary.user_levels[0]);
        assert_eq!(row.level, "0");
        assert_eq!(row.handshake, "4");
        assert_eq!(row.conn_idle, "300");
        assert_eq!(row.uplink_only, "2");
        assert_eq!(row.downlink_only, "5");
        assert_eq!(row.stats, "Uplink: on, Downlink: off, Online: on");
        assert_eq!(summary.user_levels[0].buffer_size, Some(512));
    }

    #[test]
    fn several_user_levels_sorted_numerically() {
        let summary = parse_policy(
            "/etc/xray/config.json",
            r#"{
                "policy": {
                    "levels": {
                        "10": {"handshake": 1},
                        "2": {"handshake": 2}
                    }
                }
            }"#,
        );
        assert_eq!(summary.user_levels[0].level, "2");
        assert_eq!(summary.user_levels[1].level, "10");
    }

    #[test]
    fn system_policy_only() {
        let summary = parse_policy(
            "/etc/xray/03-policy.json",
            r#"{
                "policy": {
                    "system": {
                        "statsInboundUplink": true,
                        "statsInboundDownlink": false,
                        "statsOutboundUplink": true,
                        "statsOutboundDownlink": false
                    }
                }
            }"#,
        );
        assert!(summary.user_levels.is_empty());
        assert!(summary.has_system_policy());
        let system = system_policy_display(summary.system_policy.as_ref().unwrap());
        assert_eq!(system.stats_inbound_uplink, "Enabled");
        assert_eq!(system.stats_inbound_downlink, "Disabled");
        assert_eq!(system.stats_outbound_uplink, "Enabled");
        assert_eq!(system.stats_outbound_downlink, "Disabled");
        assert_eq!(display_source_file(&summary.source_file), "03-policy.json");

        let model = build_policy_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary), Vec::new()),
            PolicySort::by_level(),
        );
        assert_eq!(model.state, PolicyPageState::NoUserPolicies);
        assert!(model.state.shows_policy());
    }

    #[test]
    fn user_policy_only() {
        let summary = parse_policy(
            "/etc/xray/config.json",
            r#"{"policy":{"levels":{"1":{"handshake":8}}}}"#,
        );
        assert!(!summary.has_system_policy());
        let general = policy_general_display(&summary);
        assert_eq!(general.user_policy_count, "1");
        assert_eq!(general.system_policy_configured, MISSING_FIELD);
    }

    #[test]
    fn missing_optional_fields_show_dash() {
        let summary = parse_policy("/etc/xray/config.json", r#"{"policy":{"levels":{"0":{}}}}"#);
        let row = user_policy_row_display(&summary.user_levels[0]);
        assert_eq!(row.handshake, MISSING_FIELD);
        assert_eq!(row.conn_idle, MISSING_FIELD);
        assert_eq!(row.uplink_only, MISSING_FIELD);
        assert_eq!(row.downlink_only, MISSING_FIELD);
        assert_eq!(row.stats, MISSING_FIELD);
        assert_eq!(summary.user_levels[0].buffer_size, None);
    }

    #[test]
    fn unknown_fields_are_ignored_in_summary() {
        let summary = parse_policy(
            "/etc/xray/config.json",
            r#"{
                "policy": {
                    "levels": {
                        "0": {
                            "handshake": 4,
                            "futureLevelField": 123
                        }
                    },
                    "system": {
                        "statsInboundUplink": true,
                        "futureSystemField": false
                    },
                    "futurePolicyField": true
                }
            }"#,
        );
        assert_eq!(summary.user_levels[0].handshake, Some(4));
        assert_eq!(
            summary
                .system_policy
                .as_ref()
                .and_then(|system| system.stats_inbound_uplink),
            Some(true)
        );
    }

    #[test]
    fn configuration_not_loaded_state() {
        let model = build_policy_page_model(
            SshStatus::Connected,
            &succeeded(),
            &LoadedConfigSnapshot::NotLoaded,
            PolicySort::by_level(),
        );
        assert_eq!(model.state, PolicyPageState::ConfigurationNotLoaded);
    }

    #[test]
    fn no_ssh_and_not_discovered_states() {
        assert_eq!(
            derive_policy_page_state(
                SshStatus::Disconnected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            PolicyPageState::NoSshConnection
        );
        assert_eq!(
            derive_policy_page_state(
                SshStatus::Connected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            PolicyPageState::XrayNotDiscovered
        );
    }

    #[test]
    fn warnings_with_available_policy() {
        let summary = parse_policy(
            "/etc/xray/config.json",
            r#"{"policy":{"levels":{"0":{"handshake":4}}}}"#,
        );
        let model = build_policy_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary), vec!["dns warning".to_owned()]),
            PolicySort::by_level(),
        );
        assert_eq!(model.state, PolicyPageState::ConfigurationContainsWarnings);
        assert!(model.state.shows_table());
        assert_eq!(model.rows.len(), 1);
    }

    #[test]
    fn wiring_warnings_empty_without_editable_config() {
        let summary = parse_policy(
            "/etc/xray/config.json",
            r#"{"policy":{"levels":{"0":{"handshake":4}}}}"#,
        );
        let model = build_policy_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary), Vec::new()),
            PolicySort::by_level(),
        );
        assert!(model.wiring_warnings.is_empty());
    }

    #[test]
    fn wiring_warnings_surface_stats_policy_mismatch() {
        let editable = editable_from(r#"{"policy":{"levels":{"0":{"statsUserUplink":true}}}}"#);
        let model = build_policy_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded_with_editable(editable),
            PolicySort::by_level(),
        );
        assert_eq!(model.wiring_warnings.len(), 1);
        assert!(model.wiring_warnings[0].contains("stats"));
    }

    #[test]
    fn wiring_warnings_empty_when_aligned() {
        let editable =
            editable_from(r#"{"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true}}}}"#);
        let model = build_policy_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded_with_editable(editable),
            PolicySort::by_level(),
        );
        assert!(model.wiring_warnings.is_empty());
    }

    #[test]
    fn sort_by_level_descending() {
        let summary = parse_policy(
            "/etc/xray/config.json",
            r#"{"policy":{"levels":{"1":{},"10":{},"2":{}}}}"#,
        );
        let mut rows = summary.user_levels;
        sort_user_policy_summaries(
            &mut rows,
            PolicySort {
                column: PolicySortColumn::Level,
                ascending: false,
            },
        );
        assert_eq!(rows[0].level, "10");
        assert_eq!(rows[1].level, "2");
        assert_eq!(rows[2].level, "1");
    }

    #[test]
    fn source_file_basename_for_single_and_directory() {
        assert_eq!(
            display_source_file("/usr/local/etc/xray/config.json"),
            "config.json"
        );
        assert_eq!(
            display_source_file("/usr/local/etc/xray/03-policy.json"),
            "03-policy.json"
        );
    }

    #[test]
    fn timeout_values_copy_format() {
        let summary = parse_policy(
            "/etc/xray/config.json",
            r#"{"policy":{"levels":{"0":{"handshake":4,"connIdle":300}}}}"#,
        );
        assert_eq!(
            format_timeout_values(&summary.user_levels[0]),
            "handshake=4, connIdle=300, uplinkOnly=—, downlinkOnly=—"
        );
    }
}
