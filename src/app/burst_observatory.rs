//! Read-only Burst Observatory page model.
//!
//! The GUI receives typed display data only and never inspects Xray JSON.

use crate::app::inbounds::{LoadedConfigSnapshot, display_optional_str, display_source_file};
use crate::app::status::SshStatus;
use crate::xray::{BurstObservatorySummary, BurstPingConfigSummary, DiscoveryState};

/// High-level state shown by the Burst Observatory page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurstObservatoryPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration has no Burst Observatory section.
    BurstObservatorySectionMissing,
    /// The section has no usable subject selectors.
    NoSubjectSelectors,
    /// The section has no usable ping configuration.
    NoPingConfigurations,
    /// Supported configuration loaded without warnings.
    ConfigurationLoaded,
    /// Supported configuration loaded with non-fatal warnings.
    ConfigurationContainsWarnings,
}

impl BurstObservatoryPageState {
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
            Self::BurstObservatorySectionMissing => "BurstObservatory section is not configured.",
            Self::NoSubjectSelectors => "No subject selectors configured.",
            Self::NoPingConfigurations => "No ping configurations configured.",
            Self::ConfigurationLoaded => "BurstObservatory configuration loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the details below."
            }
        }
    }

    /// Whether supported Burst Observatory values can be rendered.
    pub fn shows_configuration(self) -> bool {
        matches!(
            self,
            Self::NoSubjectSelectors
                | Self::NoPingConfigurations
                | Self::ConfigurationLoaded
                | Self::ConfigurationContainsWarnings
        )
    }
}

/// Read-only model consumed by the Burst Observatory GUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstObservatoryPageModel {
    /// Coarse lifecycle/content state.
    pub state: BurstObservatoryPageState,
    /// Supported section summary, when present.
    pub summary: Option<BurstObservatorySummary>,
    /// Global and local non-fatal warnings.
    pub warnings: Vec<String>,
}

/// Derives the page state from connection, discovery, and configuration.
pub fn derive_burst_observatory_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> BurstObservatoryPageState {
    if ssh != SshStatus::Connected {
        return BurstObservatoryPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => BurstObservatoryPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                BurstObservatoryPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                burst_observatory,
                warnings,
                ..
            } => {
                let Some(summary) = burst_observatory else {
                    return BurstObservatoryPageState::BurstObservatorySectionMissing;
                };
                if summary.subject_selectors.is_empty() {
                    BurstObservatoryPageState::NoSubjectSelectors
                } else if summary.ping_config.is_none() {
                    BurstObservatoryPageState::NoPingConfigurations
                } else if !warnings.is_empty() || !summary.warnings.is_empty() {
                    BurstObservatoryPageState::ConfigurationContainsWarnings
                } else {
                    BurstObservatoryPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds a Burst Observatory page model.
pub fn build_burst_observatory_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> BurstObservatoryPageModel {
    let summary = config.burst_observatory().cloned();
    let mut warnings = Vec::new();
    if let Some(summary) = summary.as_ref() {
        warnings.extend(config.warnings().iter().cloned());
        warnings.extend(summary.warnings.iter().cloned());
    }
    BurstObservatoryPageModel {
        state: derive_burst_observatory_page_state(ssh, discovery, config),
        summary,
        warnings,
    }
}

/// Formatted general section values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstObservatoryGeneralDisplay {
    /// Number of usable subject selectors.
    pub subject_selector_count: String,
    /// Number of official singular ping configurations (zero or one).
    pub ping_configuration_count: String,
    /// Basename of the source file.
    pub source_file: String,
}

/// Formats general Burst Observatory values.
pub fn burst_observatory_general_display(
    summary: &BurstObservatorySummary,
) -> BurstObservatoryGeneralDisplay {
    BurstObservatoryGeneralDisplay {
        subject_selector_count: summary.subject_selectors.len().to_string(),
        ping_configuration_count: usize::from(summary.ping_config.is_some()).to_string(),
        source_file: display_source_file(&summary.source_file).to_owned(),
    }
}

/// Formatted supported ping configuration values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstPingConfigDisplay {
    /// Probe destination or `—`.
    pub destination: String,
    /// Connectivity-check URL or `—`.
    pub connectivity: String,
    /// Probe interval or `—`.
    pub interval: String,
    /// Probe timeout or `—`.
    pub timeout: String,
    /// Sampling count or `—`.
    pub sampling: String,
    /// HTTP method or `—`.
    pub http_method: String,
    /// Concise summary.
    pub summary: String,
}

/// Formats a ping configuration for table and detail views.
pub fn burst_ping_config_display(config: &BurstPingConfigSummary) -> BurstPingConfigDisplay {
    BurstPingConfigDisplay {
        destination: display_optional_str(config.destination.as_deref()),
        connectivity: display_optional_str(config.connectivity.as_deref()),
        interval: display_optional_str(config.interval.as_deref()),
        timeout: display_optional_str(config.timeout.as_deref()),
        sampling: config
            .sampling
            .map(|value| value.to_string())
            .unwrap_or_else(|| crate::app::MISSING_FIELD.to_owned()),
        http_method: display_optional_str(config.http_method.as_deref()),
        summary: config.summary.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{ConfigSource, InitSystemKind, XrayInstallation};

    fn ping() -> BurstPingConfigSummary {
        BurstPingConfigSummary {
            destination: Some("https://example.com/generate_204".to_owned()),
            connectivity: None,
            interval: Some("30s".to_owned()),
            sampling: Some(10),
            timeout: Some("5s".to_owned()),
            http_method: Some("HEAD".to_owned()),
            summary: "Example probe".to_owned(),
        }
    }

    fn summary(selectors: &[&str], ping_config: bool) -> BurstObservatorySummary {
        BurstObservatorySummary {
            subject_selectors: selectors.iter().map(|value| (*value).to_owned()).collect(),
            ping_config: ping_config.then(ping),
            source_file: "/etc/xray/08-burst-observatory.json".to_owned(),
            warnings: Vec::new(),
        }
    }

    fn loaded(summary: Option<BurstObservatorySummary>) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: summary,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable: None,
        }
    }

    fn succeeded() -> DiscoveryState {
        DiscoveryState::Succeeded(XrayInstallation {
            operating_system: "Linux".to_owned(),
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

    #[test]
    fn blocked_and_missing_states() {
        assert_eq!(
            derive_burst_observatory_page_state(
                SshStatus::Disconnected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            BurstObservatoryPageState::NoSshConnection
        );
        assert_eq!(
            derive_burst_observatory_page_state(
                SshStatus::Connected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            BurstObservatoryPageState::XrayNotDiscovered
        );
        assert_eq!(
            derive_burst_observatory_page_state(
                SshStatus::Connected,
                &succeeded(),
                &LoadedConfigSnapshot::NotLoaded,
            ),
            BurstObservatoryPageState::ConfigurationNotLoaded
        );
        assert_eq!(
            derive_burst_observatory_page_state(SshStatus::Connected, &succeeded(), &loaded(None),),
            BurstObservatoryPageState::BurstObservatorySectionMissing
        );
    }

    #[test]
    fn empty_content_states_are_primary_over_warnings() {
        let mut no_selectors = summary(&[], true);
        no_selectors.warnings.push("empty selectors".to_owned());
        assert_eq!(
            derive_burst_observatory_page_state(
                SshStatus::Connected,
                &succeeded(),
                &loaded(Some(no_selectors)),
            ),
            BurstObservatoryPageState::NoSubjectSelectors
        );
        assert_eq!(
            derive_burst_observatory_page_state(
                SshStatus::Connected,
                &succeeded(),
                &loaded(Some(summary(&["proxy"], false))),
            ),
            BurstObservatoryPageState::NoPingConfigurations
        );
    }

    #[test]
    fn loaded_and_warning_states() {
        let config = loaded(Some(summary(&["proxy"], true)));
        assert_eq!(
            derive_burst_observatory_page_state(SshStatus::Connected, &succeeded(), &config),
            BurstObservatoryPageState::ConfigurationLoaded
        );

        let mut warned = summary(&["proxy"], true);
        warned.warnings.push("unknown field preserved".to_owned());
        let model = build_burst_observatory_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(warned)),
        );
        assert_eq!(
            model.state,
            BurstObservatoryPageState::ConfigurationContainsWarnings
        );
        assert_eq!(model.warnings, ["unknown field preserved"]);
    }

    #[test]
    fn display_formats_counts_missing_fields_and_source_basename() {
        let summary = summary(&["proxy", "warp"], true);
        let general = burst_observatory_general_display(&summary);
        assert_eq!(general.subject_selector_count, "2");
        assert_eq!(general.ping_configuration_count, "1");
        assert_eq!(general.source_file, "08-burst-observatory.json");

        let missing = burst_ping_config_display(&BurstPingConfigSummary {
            destination: None,
            connectivity: None,
            interval: None,
            sampling: None,
            timeout: None,
            http_method: None,
            summary: "Ping configuration".to_owned(),
        });
        assert_eq!(missing.destination, "—");
        assert_eq!(missing.interval, "—");
        assert_eq!(missing.timeout, "—");
        assert_eq!(missing.sampling, "—");
    }
}
