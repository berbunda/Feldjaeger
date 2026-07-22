//! Read-only Inbounds page view model for [`super::ApplicationService`].
//!
//! The GUI consumes [`InboundsPageModel`] only — never JSON, SSH, or mutable
//! configuration. Sorting and display formatting live here so they can be
//! unit-tested without egui.

use crate::app::status::SshStatus;
use crate::xray::{
    BurstObservatorySummary, DiscoveryState, DnsSummary, EditableXrayConfig, FakeDnsSummary,
    InboundSummary, ObservatorySummary, OutboundSummary, PolicySummary, RoutingSummary,
    VlessClientSummary,
};

/// Placeholder shown when an optional inbound field is absent.
pub const MISSING_FIELD: &str = "—";

/// Columns that support sorting on the Inbounds table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InboundsSortColumn {
    /// Original discovery / config order.
    #[default]
    Index,
    /// Sort by inbound tag (missing tags sort as empty).
    Tag,
    /// Sort by protocol string.
    Protocol,
    /// Sort by port (missing ports sort last when ascending).
    Port,
}

/// Current sort settings for the Inbounds table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InboundsSort {
    /// Active sort column.
    pub column: InboundsSortColumn,
    /// `true` for ascending order.
    pub ascending: bool,
}

impl InboundsSort {
    /// Default: preserve config order.
    pub fn by_index() -> Self {
        Self {
            column: InboundsSortColumn::Index,
            ascending: true,
        }
    }
}

/// High-level page state shown instead of (or above) the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundsPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Discovery finished but no Xray binary was found.
    NoXrayInstallation,
    /// SSH is up but discovery has not completed successfully.
    DiscoveryNotCompleted,
    /// Xray was found but configuration bytes were not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded and the inbound list is empty.
    NoInbounds,
    /// Configuration loaded with at least one inbound and no warnings.
    ConfigurationLoaded,
    /// Configuration loaded (possibly with rows) but parse/discovery warnings exist.
    ConfigurationContainsWarnings,
}

impl InboundsPageState {
    /// User-facing explanation for empty / blocked states.
    pub fn message(self) -> &'static str {
        match self {
            Self::NoSshConnection => {
                "No SSH connection. Connect to a server on the Connection page first."
            }
            Self::NoXrayInstallation => {
                "No Xray installation. Run Discover Xray on the Connection page."
            }
            Self::DiscoveryNotCompleted => {
                "Discovery not completed. Open Connection and click Discover Xray."
            }
            Self::ConfigurationNotLoaded => {
                "Configuration not loaded. Discover Xray again after the config becomes readable."
            }
            Self::NoInbounds => "No inbounds",
            Self::ConfigurationLoaded => "Configuration loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the list below."
            }
        }
    }

    /// Returns `true` when the inbound table should be rendered.
    pub fn shows_table(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings | Self::NoInbounds
        )
    }
}

/// Snapshot of loaded remote configuration used by read-only pages.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(clippy::large_enum_variant)]
pub enum LoadedConfigSnapshot {
    /// No discovery result that could yield a config yet.
    #[default]
    None,
    /// Discovery found Xray but configuration was not loaded.
    NotLoaded,
    /// Configuration was parsed into summaries.
    Loaded {
        /// Read-only inbound rows for the GUI.
        inbounds: Vec<InboundSummary>,
        /// Read-only outbound rows for the GUI.
        outbounds: Vec<OutboundSummary>,
        /// Read-only DNS section for the GUI.
        dns: Option<DnsSummary>,
        /// Read-only FakeDNS section for the GUI.
        fakedns: Option<FakeDnsSummary>,
        /// Read-only Observatory section for the GUI.
        observatory: Option<ObservatorySummary>,
        /// Read-only Burst Observatory section for the GUI.
        burst_observatory: Option<BurstObservatorySummary>,
        /// Read-only routing section for the GUI.
        routing: Option<RoutingSummary>,
        /// Read-only policy section for the GUI.
        policy: Option<PolicySummary>,
        /// Read-only VLESS client rows for the Users page.
        vless_clients: Vec<VlessClientSummary>,
        /// Non-fatal parse / load warnings (no secrets).
        warnings: Vec<String>,
        /// Editable config retained for future write-back (when available).
        editable: Option<EditableXrayConfig>,
    },
}

impl LoadedConfigSnapshot {
    /// Returns inbound summaries when configuration was loaded.
    pub fn inbounds(&self) -> &[InboundSummary] {
        match self {
            Self::Loaded { inbounds, .. } => inbounds,
            Self::None | Self::NotLoaded => &[],
        }
    }

    /// Returns outbound summaries when configuration was loaded.
    pub fn outbounds(&self) -> &[OutboundSummary] {
        match self {
            Self::Loaded { outbounds, .. } => outbounds,
            Self::None | Self::NotLoaded => &[],
        }
    }

    /// Returns the DNS summary when configuration and the DNS section were loaded.
    pub fn dns(&self) -> Option<&DnsSummary> {
        match self {
            Self::Loaded { dns, .. } => dns.as_ref(),
            Self::None | Self::NotLoaded => None,
        }
    }

    /// Returns the FakeDNS summary when configuration and the FakeDNS section were loaded.
    pub fn fakedns(&self) -> Option<&FakeDnsSummary> {
        match self {
            Self::Loaded { fakedns, .. } => fakedns.as_ref(),
            Self::None | Self::NotLoaded => None,
        }
    }

    /// Returns the Observatory summary when configuration and the section were loaded.
    pub fn observatory(&self) -> Option<&ObservatorySummary> {
        match self {
            Self::Loaded { observatory, .. } => observatory.as_ref(),
            Self::None | Self::NotLoaded => None,
        }
    }

    /// Returns the Burst Observatory summary when its section was loaded.
    pub fn burst_observatory(&self) -> Option<&BurstObservatorySummary> {
        match self {
            Self::Loaded {
                burst_observatory, ..
            } => burst_observatory.as_ref(),
            Self::None | Self::NotLoaded => None,
        }
    }

    /// Returns the routing summary when configuration and the routing section were loaded.
    pub fn routing(&self) -> Option<&RoutingSummary> {
        match self {
            Self::Loaded { routing, .. } => routing.as_ref(),
            Self::None | Self::NotLoaded => None,
        }
    }

    /// Returns the policy summary when configuration and the policy section were loaded.
    pub fn policy(&self) -> Option<&PolicySummary> {
        match self {
            Self::Loaded { policy, .. } => policy.as_ref(),
            Self::None | Self::NotLoaded => None,
        }
    }

    /// Returns VLESS client summaries when configuration was loaded.
    pub fn vless_clients(&self) -> &[VlessClientSummary] {
        match self {
            Self::Loaded { vless_clients, .. } => vless_clients,
            Self::None | Self::NotLoaded => &[],
        }
    }

    /// Returns `true` when a parse produced a usable configuration view.
    pub fn is_loaded(&self) -> bool {
        matches!(self, Self::Loaded { .. })
    }

    /// Warnings attached to a loaded configuration.
    pub fn warnings(&self) -> &[String] {
        match self {
            Self::Loaded { warnings, .. } => warnings,
            Self::None | Self::NotLoaded => &[],
        }
    }

    /// Editable configuration retained from discovery, when available.
    pub fn editable(&self) -> Option<&EditableXrayConfig> {
        match self {
            Self::Loaded { editable, .. } => editable.as_ref(),
            Self::None | Self::NotLoaded => None,
        }
    }
}

/// Read-only model exposed to the Inbounds page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundsPageModel {
    /// Coarse page state.
    pub state: InboundsPageState,
    /// Rows to display (already sorted).
    pub rows: Vec<InboundSummary>,
    /// Warnings to show above the table when present.
    pub warnings: Vec<String>,
    /// Active sort settings.
    pub sort: InboundsSort,
}

/// Derives [`InboundsPageState`] from SSH, discovery, and loaded config.
pub fn derive_inbounds_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> InboundsPageState {
    if ssh != SshStatus::Connected {
        return InboundsPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle | DiscoveryState::Discovering => {
            InboundsPageState::DiscoveryNotCompleted
        }
        DiscoveryState::NotFound { .. } => InboundsPageState::NoXrayInstallation,
        DiscoveryState::Failed { .. } => InboundsPageState::NoXrayInstallation,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                InboundsPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                inbounds, warnings, ..
            } => {
                if !warnings.is_empty() {
                    InboundsPageState::ConfigurationContainsWarnings
                } else if inbounds.is_empty() {
                    InboundsPageState::NoInbounds
                } else {
                    InboundsPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the page model: state + sorted rows + warnings.
pub fn build_inbounds_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    sort: InboundsSort,
) -> InboundsPageModel {
    let state = derive_inbounds_page_state(ssh, discovery, config);
    let mut rows = config.inbounds().to_vec();
    sort_inbound_summaries(&mut rows, sort);
    let warnings = config.warnings().to_vec();
    InboundsPageModel {
        state,
        rows,
        warnings,
        sort,
    }
}

/// Sorts inbound summaries in place according to [`InboundsSort`].
pub fn sort_inbound_summaries(rows: &mut [InboundSummary], sort: InboundsSort) {
    rows.sort_by(|left, right| {
        let ordering = match sort.column {
            InboundsSortColumn::Index => left.index.cmp(&right.index),
            InboundsSortColumn::Tag => cmp_optional_str(left.tag.as_deref(), right.tag.as_deref()),
            InboundsSortColumn::Protocol => {
                cmp_optional_str(left.protocol.as_deref(), right.protocol.as_deref())
            }
            InboundsSortColumn::Port => cmp_optional_port(left.port, right.port),
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

fn cmp_optional_port(left: Option<u64>, right: Option<u64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

/// Formats an optional string field for the table (`—` when absent).
pub fn display_optional_str(value: Option<&str>) -> String {
    value
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| MISSING_FIELD.to_owned())
}

/// Formats an optional port for the table.
pub fn display_optional_port(port: Option<u64>) -> String {
    port.map(|value| value.to_string())
        .unwrap_or_else(|| MISSING_FIELD.to_owned())
}

/// Formats clients count for the table.
pub fn display_clients_count(count: Option<usize>) -> String {
    count
        .map(|value| value.to_string())
        .unwrap_or_else(|| MISSING_FIELD.to_owned())
}

/// Returns the file name portion of a sourced path for read-only display.
pub fn display_source_file(source_file: &str) -> &str {
    let trimmed = source_file.trim_end_matches(['/', '\\']);
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(source_file)
}

/// Display helpers bound to a single [`InboundSummary`] row.
pub fn inbound_row_display(summary: &InboundSummary) -> InboundRowDisplay<'_> {
    InboundRowDisplay {
        tag: display_optional_str(summary.tag.as_deref()),
        protocol: display_optional_str(summary.protocol.as_deref()),
        listen: display_optional_str(summary.listen.as_deref()),
        port: display_optional_port(summary.port),
        clients: display_clients_count(summary.clients_count),
        source_file: display_source_file(&summary.source_file),
    }
}

/// Formatted cell values for one inbound table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRowDisplay<'a> {
    /// Tag or `—`.
    pub tag: String,
    /// Protocol or `—`.
    pub protocol: String,
    /// Listen address or `—`.
    pub listen: String,
    /// Port or `—`.
    pub port: String,
    /// Clients count or `—`.
    pub clients: String,
    /// Basename of the source file.
    pub source_file: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{DiscoveryErrorKind, InitSystemKind};

    fn summary(
        index: usize,
        tag: Option<&str>,
        protocol: Option<&str>,
        listen: Option<&str>,
        port: Option<u64>,
        clients: Option<usize>,
        source: &str,
    ) -> InboundSummary {
        InboundSummary {
            index,
            tag: tag.map(str::to_owned),
            protocol: protocol.map(str::to_owned),
            listen: listen.map(str::to_owned),
            port,
            clients_count: clients,
            source_file: source.to_owned(),
        }
    }

    #[test]
    fn empty_list() {
        let config = LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };
        let model = build_inbounds_page_model(
            SshStatus::Connected,
            &DiscoveryState::Succeeded(dummy_installation()),
            &config,
            InboundsSort::by_index(),
        );
        assert_eq!(model.state, InboundsPageState::NoInbounds);
        assert!(model.rows.is_empty());
        assert_eq!(model.state.message(), "No inbounds");
    }

    #[test]
    fn one_inbound() {
        let config = LoadedConfigSnapshot::Loaded {
            inbounds: vec![summary(
                0,
                Some("vless-in"),
                Some("vless"),
                Some("0.0.0.0"),
                Some(443),
                Some(2),
                "/etc/xray/config.json",
            )],
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };
        let model = build_inbounds_page_model(
            SshStatus::Connected,
            &DiscoveryState::Succeeded(dummy_installation()),
            &config,
            InboundsSort::by_index(),
        );
        assert_eq!(model.state, InboundsPageState::ConfigurationLoaded);
        assert_eq!(model.rows.len(), 1);
        let row = inbound_row_display(&model.rows[0]);
        assert_eq!(row.tag, "vless-in");
        assert_eq!(row.protocol, "vless");
        assert_eq!(row.listen, "0.0.0.0");
        assert_eq!(row.port, "443");
        assert_eq!(row.clients, "2");
        assert_eq!(row.source_file, "config.json");
    }

    #[test]
    fn several_inbounds() {
        let config = LoadedConfigSnapshot::Loaded {
            inbounds: vec![
                summary(
                    0,
                    Some("a"),
                    Some("vless"),
                    None,
                    Some(1),
                    None,
                    "/c/a.json",
                ),
                summary(
                    1,
                    Some("b"),
                    Some("vmess"),
                    None,
                    Some(2),
                    None,
                    "/c/b.json",
                ),
                summary(
                    2,
                    Some("c"),
                    Some("trojan"),
                    None,
                    Some(3),
                    None,
                    "/c/c.json",
                ),
            ],
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        };
        let model = build_inbounds_page_model(
            SshStatus::Connected,
            &DiscoveryState::Succeeded(dummy_installation()),
            &config,
            InboundsSort::by_index(),
        );
        assert_eq!(model.rows.len(), 3);
    }

    #[test]
    fn unknown_protocol_displayed_as_is() {
        let summary = summary(
            0,
            Some("x"),
            Some("future_protocol"),
            None,
            Some(1),
            None,
            "config.json",
        );
        let row = inbound_row_display(&summary);
        assert_eq!(row.protocol, "future_protocol");
    }

    #[test]
    fn missing_listen_tag_port_show_dash() {
        let summary = summary(0, None, Some("vless"), None, None, None, "config.json");
        let row = inbound_row_display(&summary);
        assert_eq!(row.tag, MISSING_FIELD);
        assert_eq!(row.listen, MISSING_FIELD);
        assert_eq!(row.port, MISSING_FIELD);
        assert_eq!(row.clients, MISSING_FIELD);
    }

    #[test]
    fn sort_by_tag() {
        let mut rows = vec![
            summary(
                0,
                Some("zeta"),
                Some("vless"),
                None,
                Some(1),
                None,
                "a.json",
            ),
            summary(
                1,
                Some("alpha"),
                Some("vmess"),
                None,
                Some(2),
                None,
                "b.json",
            ),
        ];
        sort_inbound_summaries(
            &mut rows,
            InboundsSort {
                column: InboundsSortColumn::Tag,
                ascending: true,
            },
        );
        assert_eq!(rows[0].tag.as_deref(), Some("alpha"));
        assert_eq!(rows[1].tag.as_deref(), Some("zeta"));
    }

    #[test]
    fn sort_by_port() {
        let mut rows = vec![
            summary(
                0,
                Some("a"),
                Some("vless"),
                None,
                Some(8443),
                None,
                "a.json",
            ),
            summary(1, Some("b"), Some("vmess"), None, Some(443), None, "b.json"),
            summary(2, Some("c"), Some("trojan"), None, None, None, "c.json"),
        ];
        sort_inbound_summaries(
            &mut rows,
            InboundsSort {
                column: InboundsSortColumn::Port,
                ascending: true,
            },
        );
        assert_eq!(rows[0].port, Some(443));
        assert_eq!(rows[1].port, Some(8443));
        assert_eq!(rows[2].port, None);
    }

    #[test]
    fn source_file_shows_basename_for_single_and_directory() {
        assert_eq!(
            display_source_file("/usr/local/etc/xray/config.json"),
            "config.json"
        );
        assert_eq!(
            display_source_file("/usr/local/etc/xray/03-inbounds.json"),
            "03-inbounds.json"
        );
    }

    #[test]
    fn state_no_ssh_connection() {
        let state = derive_inbounds_page_state(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(state, InboundsPageState::NoSshConnection);
        assert!(state.message().contains("No SSH connection"));
    }

    #[test]
    fn state_configuration_not_loaded() {
        let state = derive_inbounds_page_state(
            SshStatus::Connected,
            &DiscoveryState::Succeeded(dummy_installation()),
            &LoadedConfigSnapshot::NotLoaded,
        );
        assert_eq!(state, InboundsPageState::ConfigurationNotLoaded);
        assert!(state.message().contains("Configuration not loaded"));
    }

    #[test]
    fn state_discovery_not_completed() {
        let state = derive_inbounds_page_state(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(state, InboundsPageState::DiscoveryNotCompleted);
    }

    #[test]
    fn state_no_xray_installation() {
        let state = derive_inbounds_page_state(
            SshStatus::Connected,
            &DiscoveryState::NotFound {
                operating_system: "Debian".to_owned(),
                architecture: "x86_64".to_owned(),
                init_system: InitSystemKind::Systemd,
                warnings: Vec::new(),
            },
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(state, InboundsPageState::NoXrayInstallation);
    }

    #[test]
    fn state_failed_discovery_treated_as_no_installation() {
        let state = derive_inbounds_page_state(
            SshStatus::Connected,
            &DiscoveryState::Failed {
                kind: DiscoveryErrorKind::Unexpected,
                detail: "boom".to_owned(),
            },
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(state, InboundsPageState::NoXrayInstallation);
    }

    #[test]
    fn state_with_warnings() {
        let config = LoadedConfigSnapshot::Loaded {
            inbounds: vec![summary(
                0,
                Some("a"),
                Some("vless"),
                None,
                Some(1),
                None,
                "config.json",
            )],
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: vec!["dns was invalid".to_owned()],
            editable: None,
        };
        let state = derive_inbounds_page_state(
            SshStatus::Connected,
            &DiscoveryState::Succeeded(dummy_installation()),
            &config,
        );
        assert_eq!(state, InboundsPageState::ConfigurationContainsWarnings);
        assert!(state.shows_table());
    }

    fn dummy_installation() -> crate::xray::XrayInstallation {
        crate::xray::XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: None,
            version: None,
            service_name: None,
            service_state: None,
            exec_start: None,
            config_source: crate::xray::ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        }
    }
}
