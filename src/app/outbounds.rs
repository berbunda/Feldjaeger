//! Read-only Outbounds page view model for [`super::ApplicationService`].
//!
//! The GUI consumes [`OutboundsPageModel`] only — never JSON, SSH, or mutable
//! configuration. Sorting and display formatting live here so they can be
//! unit-tested without egui.

use crate::app::inbounds::{LoadedConfigSnapshot, display_optional_str, display_source_file};
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, OutboundSummary};

/// Columns that support sorting on the Outbounds table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutboundsSortColumn {
    /// Original discovery / config order.
    #[default]
    Index,
    /// Sort by outbound tag (missing tags sort as empty).
    Tag,
    /// Sort by protocol string.
    Protocol,
}

/// Current sort settings for the Outbounds table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutboundsSort {
    /// Active sort column.
    pub column: OutboundsSortColumn,
    /// `true` for ascending order.
    pub ascending: bool,
}

impl OutboundsSort {
    /// Default: preserve config order.
    pub fn by_index() -> Self {
        Self {
            column: OutboundsSortColumn::Index,
            ascending: true,
        }
    }
}

/// High-level page state shown instead of (or above) the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundsPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Discovery has not found Xray (idle, in progress, not found, or failed).
    XrayNotDiscovered,
    /// Xray was found but configuration bytes were not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded and the outbound list is empty.
    NoOutbounds,
    /// Configuration loaded with at least one outbound and no warnings.
    ConfigurationLoaded,
    /// Configuration loaded (possibly with rows) but parse/discovery warnings exist.
    ConfigurationContainsWarnings,
}

impl OutboundsPageState {
    /// User-facing explanation for empty / blocked states.
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
            Self::NoOutbounds => "No outbounds",
            Self::ConfigurationLoaded => "Configuration loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the list below."
            }
        }
    }

    /// Returns `true` when the outbound table should be rendered.
    pub fn shows_table(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings
        )
    }
}

/// Read-only model exposed to the Outbounds page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundsPageModel {
    /// Coarse page state.
    pub state: OutboundsPageState,
    /// Rows to display (already sorted).
    pub rows: Vec<OutboundSummary>,
    /// Warnings to show above the table when present.
    pub warnings: Vec<String>,
    /// Active sort settings.
    pub sort: OutboundsSort,
}

/// Derives [`OutboundsPageState`] from SSH, discovery, and loaded config.
pub fn derive_outbounds_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> OutboundsPageState {
    if ssh != SshStatus::Connected {
        return OutboundsPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => OutboundsPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                OutboundsPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                outbounds,
                warnings,
                ..
            } => {
                if !warnings.is_empty() {
                    OutboundsPageState::ConfigurationContainsWarnings
                } else if outbounds.is_empty() {
                    OutboundsPageState::NoOutbounds
                } else {
                    OutboundsPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the page model: state + sorted rows + warnings.
pub fn build_outbounds_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    sort: OutboundsSort,
) -> OutboundsPageModel {
    let state = derive_outbounds_page_state(ssh, discovery, config);
    let mut rows = config.outbounds().to_vec();
    sort_outbound_summaries(&mut rows, sort);
    let warnings = config.warnings().to_vec();
    OutboundsPageModel {
        state,
        rows,
        warnings,
        sort,
    }
}

/// Sorts outbound summaries in place according to [`OutboundsSort`].
pub fn sort_outbound_summaries(rows: &mut [OutboundSummary], sort: OutboundsSort) {
    rows.sort_by(|left, right| {
        let ordering = match sort.column {
            OutboundsSortColumn::Index => left.index.cmp(&right.index),
            OutboundsSortColumn::Tag => cmp_optional_str(left.tag.as_deref(), right.tag.as_deref()),
            OutboundsSortColumn::Protocol => {
                cmp_optional_str(left.protocol.as_deref(), right.protocol.as_deref())
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

/// Display helpers bound to a single [`OutboundSummary`] row.
pub fn outbound_row_display(summary: &OutboundSummary) -> OutboundRowDisplay<'_> {
    OutboundRowDisplay {
        tag: display_optional_str(summary.tag.as_deref()),
        protocol: display_optional_str(summary.protocol.as_deref()),
        send_through: display_optional_str(summary.send_through.as_deref()),
        summary: summary.description.clone(),
        source_file: display_source_file(&summary.source_file),
    }
}

/// Formatted cell values for one outbound table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRowDisplay<'a> {
    /// Tag or `—`.
    pub tag: String,
    /// Protocol or `—`.
    pub protocol: String,
    /// Send Through address or `—`.
    pub send_through: String,
    /// Protocol summary text.
    pub summary: String,
    /// Basename of the source file.
    pub source_file: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::inbounds::MISSING_FIELD;
    use crate::xray::{DiscoveryErrorKind, InitSystemKind, OutboundKind};

    fn summary(
        index: usize,
        tag: Option<&str>,
        protocol: Option<&str>,
        send_through: Option<&str>,
        description: &str,
        source: &str,
    ) -> OutboundSummary {
        OutboundSummary {
            index,
            tag: tag.map(str::to_owned),
            protocol: protocol.map(str::to_owned),
            send_through: send_through.map(str::to_owned),
            description: description.to_owned(),
            source_file: source.to_owned(),
        }
    }

    fn loaded(outbounds: Vec<OutboundSummary>, warnings: Vec<String>) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds,
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings,
            editable: None,
        }
    }

    fn succeeded() -> DiscoveryState {
        DiscoveryState::Succeeded(crate::xray::XrayInstallation {
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
        })
    }

    #[test]
    fn empty_list() {
        let config = loaded(Vec::new(), Vec::new());
        let model = build_outbounds_page_model(
            SshStatus::Connected,
            &succeeded(),
            &config,
            OutboundsSort::by_index(),
        );
        assert_eq!(model.state, OutboundsPageState::NoOutbounds);
        assert!(model.rows.is_empty());
        assert_eq!(model.state.message(), "No outbounds");
    }

    #[test]
    fn one_outbound() {
        let config = loaded(
            vec![summary(
                0,
                Some("direct"),
                Some("freedom"),
                None,
                "Direct connection",
                "/etc/xray/config.json",
            )],
            Vec::new(),
        );
        let model = build_outbounds_page_model(
            SshStatus::Connected,
            &succeeded(),
            &config,
            OutboundsSort::by_index(),
        );
        assert_eq!(model.state, OutboundsPageState::ConfigurationLoaded);
        assert_eq!(model.rows.len(), 1);
        let row = outbound_row_display(&model.rows[0]);
        assert_eq!(row.tag, "direct");
        assert_eq!(row.protocol, "freedom");
        assert_eq!(row.send_through, MISSING_FIELD);
        assert_eq!(row.summary, "Direct connection");
        assert_eq!(row.source_file, "config.json");
    }

    #[test]
    fn several_outbounds() {
        let config = loaded(
            vec![
                summary(
                    0,
                    Some("direct"),
                    Some("freedom"),
                    None,
                    "Direct connection",
                    "a.json",
                ),
                summary(
                    1,
                    Some("block"),
                    Some("blackhole"),
                    None,
                    "Response: none",
                    "b.json",
                ),
                summary(
                    2,
                    Some("proxy"),
                    Some("vless"),
                    None,
                    "Summary unavailable",
                    "c.json",
                ),
            ],
            Vec::new(),
        );
        let model = build_outbounds_page_model(
            SshStatus::Connected,
            &succeeded(),
            &config,
            OutboundsSort::by_index(),
        );
        assert_eq!(model.rows.len(), 3);
    }

    #[test]
    fn unknown_protocol_displayed_with_fallback_summary() {
        let summary = summary(
            0,
            Some("x"),
            Some("future_protocol"),
            None,
            "Summary unavailable",
            "config.json",
        );
        let row = outbound_row_display(&summary);
        assert_eq!(row.protocol, "future_protocol");
        assert_eq!(row.summary, "Summary unavailable");
        assert_eq!(
            OutboundKind::from_protocol(Some("future_protocol")),
            OutboundKind::Unknown
        );
    }

    #[test]
    fn missing_tag_and_send_through_show_dash() {
        let summary = summary(
            0,
            None,
            Some("freedom"),
            None,
            "Direct connection",
            "config.json",
        );
        let row = outbound_row_display(&summary);
        assert_eq!(row.tag, MISSING_FIELD);
        assert_eq!(row.send_through, MISSING_FIELD);
    }

    #[test]
    fn source_file_shows_basename_for_single_and_directory() {
        assert_eq!(
            display_source_file("/usr/local/etc/xray/config.json"),
            "config.json"
        );
        assert_eq!(
            display_source_file("/usr/local/etc/xray/05-outbounds.json"),
            "05-outbounds.json"
        );
    }

    #[test]
    fn sort_by_tag() {
        let mut rows = vec![
            summary(
                0,
                Some("zeta"),
                Some("freedom"),
                None,
                "Direct connection",
                "a.json",
            ),
            summary(
                1,
                Some("alpha"),
                Some("blackhole"),
                None,
                "Response: none",
                "b.json",
            ),
        ];
        sort_outbound_summaries(
            &mut rows,
            OutboundsSort {
                column: OutboundsSortColumn::Tag,
                ascending: true,
            },
        );
        assert_eq!(rows[0].tag.as_deref(), Some("alpha"));
        assert_eq!(rows[1].tag.as_deref(), Some("zeta"));
    }

    #[test]
    fn sort_by_protocol() {
        let mut rows = vec![
            summary(
                0,
                Some("a"),
                Some("vless"),
                None,
                "Summary unavailable",
                "a.json",
            ),
            summary(
                1,
                Some("b"),
                Some("freedom"),
                None,
                "Direct connection",
                "b.json",
            ),
            summary(
                2,
                Some("c"),
                Some("blackhole"),
                None,
                "Response: none",
                "c.json",
            ),
        ];
        sort_outbound_summaries(
            &mut rows,
            OutboundsSort {
                column: OutboundsSortColumn::Protocol,
                ascending: true,
            },
        );
        assert_eq!(rows[0].protocol.as_deref(), Some("blackhole"));
        assert_eq!(rows[1].protocol.as_deref(), Some("freedom"));
        assert_eq!(rows[2].protocol.as_deref(), Some("vless"));
    }

    #[test]
    fn state_configuration_not_loaded() {
        let state = derive_outbounds_page_state(
            SshStatus::Connected,
            &succeeded(),
            &LoadedConfigSnapshot::NotLoaded,
        );
        assert_eq!(state, OutboundsPageState::ConfigurationNotLoaded);
        assert!(state.message().contains("Configuration not loaded"));
    }

    #[test]
    fn state_no_ssh_connection() {
        let state = derive_outbounds_page_state(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(state, OutboundsPageState::NoSshConnection);
    }

    #[test]
    fn state_xray_not_discovered() {
        let state = derive_outbounds_page_state(
            SshStatus::Connected,
            &DiscoveryState::NotFound {
                operating_system: "Debian".to_owned(),
                architecture: "x86_64".to_owned(),
                init_system: InitSystemKind::Systemd,
                warnings: Vec::new(),
            },
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(state, OutboundsPageState::XrayNotDiscovered);
    }

    #[test]
    fn state_failed_discovery_treated_as_not_discovered() {
        let state = derive_outbounds_page_state(
            SshStatus::Connected,
            &DiscoveryState::Failed {
                kind: DiscoveryErrorKind::Unexpected,
                detail: "boom".to_owned(),
            },
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(state, OutboundsPageState::XrayNotDiscovered);
    }

    #[test]
    fn state_with_warnings() {
        let config = loaded(
            vec![summary(
                0,
                Some("direct"),
                Some("freedom"),
                None,
                "Direct connection",
                "config.json",
            )],
            vec!["dns was invalid".to_owned()],
        );
        let state = derive_outbounds_page_state(SshStatus::Connected, &succeeded(), &config);
        assert_eq!(state, OutboundsPageState::ConfigurationContainsWarnings);
        assert!(state.shows_table());
    }
}
