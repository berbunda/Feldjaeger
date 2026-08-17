//! Read-only Observatory page view model for [`super::ApplicationService`].
//!
//! The GUI consumes supported summary fields only and never inspects JSON.

use crate::app::inbounds::{LoadedConfigSnapshot, display_optional_str, display_source_file};
use crate::app::status::SshStatus;
use crate::xray::{
    DiscoveryState, ObservatorySettings, ObservatorySummary, observatory_settings_change_summary,
};

/// High-level state shown by the Observatory page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservatoryPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded without an Observatory section.
    ObservatorySectionMissing,
    /// Observatory section present but no usable subject selectors.
    NoSubjectSelectors,
    /// Observatory configuration loaded without warnings.
    ConfigurationLoaded,
    /// Configuration loaded with non-fatal warnings.
    ConfigurationContainsWarnings,
    /// In-memory draft is being edited (Roadmap §2.1:50).
    EditMode,
    /// Draft failed local validation.
    ValidationError,
    /// Remote save is in progress.
    Saving,
    /// Last save succeeded (transient before returning to view).
    Saved,
    /// Last save failed (classified error shown separately).
    SaveFailed,
    /// Top-level `observatory` value is not a JSON object.
    MalformedObservatoryObject,
}

impl ObservatoryPageState {
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
            Self::ObservatorySectionMissing => "Observatory section is not configured.",
            Self::NoSubjectSelectors => "No subject selectors configured.",
            Self::ConfigurationLoaded => "Observatory configuration loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the details below."
            }
            Self::EditMode => {
                "Editing Observatory settings. Changes are not saved until you click Save."
            }
            Self::ValidationError => {
                "Observatory settings validation failed. Fix the highlighted fields."
            }
            Self::Saving => "Saving Observatory settings...",
            Self::Saved => "Observatory settings updated.",
            Self::SaveFailed => "Failed to save Observatory settings.",
            Self::MalformedObservatoryObject => {
                "Malformed observatory object in the remote configuration."
            }
        }
    }

    /// Returns whether Observatory details can be rendered.
    pub fn shows_observatory(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded
                | Self::ConfigurationContainsWarnings
                | Self::NoSubjectSelectors
        )
    }
}

/// View **and** edit model exposed to the Observatory page (Roadmap §2.1:50). Browsing uses
/// [`ObservatorySummary`] as before; editing uses the typed [`ObservatorySettings`] — the same
/// coexistence pattern already used by Routing/Policy (§52/§53).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryPageModel {
    /// Coarse page state.
    pub state: ObservatoryPageState,
    /// Supported Observatory data, when the section exists.
    pub summary: Option<ObservatorySummary>,
    /// Combined non-fatal warnings (config + Observatory-specific).
    pub warnings: Vec<String>,
    /// Settings currently displayed by the edit form (loaded or draft).
    pub observatory_settings: ObservatorySettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
}

/// Derives the Observatory page state from connection, discovery, and config state.
pub fn derive_observatory_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> ObservatoryPageState {
    if ssh != SshStatus::Connected {
        return ObservatoryPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => ObservatoryPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                ObservatoryPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                observatory,
                warnings,
                ..
            } => {
                let Some(summary) = observatory.as_ref() else {
                    return ObservatoryPageState::ObservatorySectionMissing;
                };
                // Empty / missing selectors stay primary so the mandatory empty-list
                // warning cannot hide this state; warnings are still shown in the model.
                if summary.subject_selectors.is_empty() {
                    ObservatoryPageState::NoSubjectSelectors
                } else if !warnings.is_empty() || !summary.warnings.is_empty() {
                    ObservatoryPageState::ConfigurationContainsWarnings
                } else {
                    ObservatoryPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the Observatory page model (browsing + edit, Roadmap §2.1:50).
///
/// `draft`/`saving`/`error_message`/`saved_flash` mirror [`super::dns::build_dns_page_model`]'s
/// parameters exactly; when `draft` is `None` the page behaves exactly as the read-only version
/// did — same precedence order as Routing/Policy (§52/§53): Saving > Saved > (error while editing
/// = ValidationError) > (error while not editing = SaveFailed) > Malformed > EditMode > the
/// browsing state already computed by [`derive_observatory_page_state`].
pub fn build_observatory_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&ObservatorySettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> ObservatoryPageModel {
    let mut state = derive_observatory_page_state(ssh, discovery, config);
    let summary = config.observatory().cloned();
    let mut warnings = Vec::new();
    if summary.is_some() {
        warnings.extend(config.warnings().iter().cloned());
        if let Some(summary) = summary.as_ref() {
            warnings.extend(summary.warnings.iter().cloned());
        }
    }

    let mut observatory_settings = ObservatorySettings::defaults();
    let mut editing = false;
    let mut change_summary = Vec::new();

    if let Some(editable) = config.editable() {
        let loaded = editable.observatory_settings();
        let malformed = loaded
            .warnings
            .iter()
            .any(|w| w.starts_with("Malformed observatory object"));

        editing = draft.is_some();
        observatory_settings = draft.cloned().unwrap_or_else(|| loaded.clone());
        change_summary = if let Some(draft) = draft {
            observatory_settings_change_summary(&loaded, draft)
        } else {
            Vec::new()
        };

        state = if saving {
            ObservatoryPageState::Saving
        } else if saved_flash {
            ObservatoryPageState::Saved
        } else if error_message.is_some() && editing {
            ObservatoryPageState::ValidationError
        } else if error_message.is_some() {
            ObservatoryPageState::SaveFailed
        } else if malformed {
            ObservatoryPageState::MalformedObservatoryObject
        } else if editing {
            ObservatoryPageState::EditMode
        } else {
            state
        };
    }

    ObservatoryPageModel {
        state,
        summary,
        warnings,
        observatory_settings,
        editing,
        change_summary,
        error_message,
    }
}

/// Formatted general Observatory fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryGeneralDisplay {
    /// Probe URL or `—`.
    pub probe_url: String,
    /// Probe interval or `—`.
    pub probe_interval: String,
    /// Number of subject selectors.
    pub subject_selector_count: String,
    /// Basename of the source file.
    pub source_file: String,
}

/// Formats general Observatory fields for display.
pub fn observatory_general_display(summary: &ObservatorySummary) -> ObservatoryGeneralDisplay {
    ObservatoryGeneralDisplay {
        probe_url: display_optional_str(summary.probe_url.as_deref()),
        probe_interval: display_optional_str(summary.probe_interval.as_deref()),
        subject_selector_count: summary.subject_selectors.len().to_string(),
        source_file: display_source_file(&summary.source_file).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{ConfigSource, InitSystemKind, XrayInstallation};

    fn summary(source_file: &str, selectors: &[&str], warnings: Vec<String>) -> ObservatorySummary {
        ObservatorySummary {
            probe_url: Some("https://www.google.com/generate_204".to_owned()),
            probe_interval: Some("10s".to_owned()),
            subject_selectors: selectors.iter().map(|text| (*text).to_owned()).collect(),
            source_file: source_file.to_owned(),
            warnings,
        }
    }

    fn loaded(
        observatory: Option<ObservatorySummary>,
        warnings: Vec<String>,
    ) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings,
            editable: None,
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

    #[test]
    fn no_ssh_connection_state() {
        let model = build_observatory_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, ObservatoryPageState::NoSshConnection);
    }

    #[test]
    fn xray_not_discovered_state() {
        let model = build_observatory_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, ObservatoryPageState::XrayNotDiscovered);
    }

    #[test]
    fn configuration_not_loaded_state() {
        let model = build_observatory_page_model(
            SshStatus::Connected,
            &succeeded(),
            &LoadedConfigSnapshot::NotLoaded,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, ObservatoryPageState::ConfigurationNotLoaded);
        assert!(model.state.message().contains("Configuration not loaded"));
    }

    #[test]
    fn missing_observatory_section_is_not_an_error() {
        let model = build_observatory_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(None, Vec::new()),
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, ObservatoryPageState::ObservatorySectionMissing);
        assert_eq!(
            model.state.message(),
            "Observatory section is not configured."
        );
        assert!(model.summary.is_none());
        assert!(model.warnings.is_empty());
    }

    #[test]
    fn empty_section_is_no_subject_selectors() {
        let model = build_observatory_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(
                Some(summary("/etc/xray/config.json", &[], Vec::new())),
                Vec::new(),
            ),
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, ObservatoryPageState::NoSubjectSelectors);
        assert!(model.state.shows_observatory());
    }

    #[test]
    fn one_and_several_selectors() {
        let one = build_observatory_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(
                Some(summary("/etc/xray/config.json", &["proxy"], Vec::new())),
                Vec::new(),
            ),
            None,
            false,
            None,
            false,
        );
        assert_eq!(one.state, ObservatoryPageState::ConfigurationLoaded);
        assert_eq!(one.summary.as_ref().unwrap().subject_selectors, ["proxy"]);

        let several = summary(
            "/etc/xray/07-observatory.json",
            &["proxy", "warp", "vpn", "hk", "jp"],
            Vec::new(),
        );
        let display = observatory_general_display(&several);
        assert_eq!(display.subject_selector_count, "5");
        assert_eq!(display.source_file, "07-observatory.json");
        assert_eq!(
            several.subject_selectors,
            ["proxy", "warp", "vpn", "hk", "jp"]
        );
    }

    #[test]
    fn missing_probe_fields_show_dash_and_warnings() {
        let summary = ObservatorySummary {
            probe_url: None,
            probe_interval: None,
            subject_selectors: vec!["proxy".to_owned()],
            source_file: "/etc/xray/config.json".to_owned(),
            warnings: vec![
                "`probeUrl` is missing.".to_owned(),
                "`probeInterval` is missing.".to_owned(),
            ],
        };
        let display = observatory_general_display(&summary);
        assert_eq!(display.probe_url, "—");
        assert_eq!(display.probe_interval, "—");

        let model = build_observatory_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary), Vec::new()),
            None,
            false,
            None,
            false,
        );
        assert_eq!(
            model.state,
            ObservatoryPageState::ConfigurationContainsWarnings
        );
        assert_eq!(model.warnings.len(), 2);
    }

    #[test]
    fn empty_selector_list_stays_primary_even_with_warning() {
        let model = build_observatory_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(
                Some(summary(
                    "config.json",
                    &[],
                    vec!["`subjectSelector` is empty.".to_owned()],
                )),
                Vec::new(),
            ),
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, ObservatoryPageState::NoSubjectSelectors);
        assert_eq!(model.warnings, ["`subjectSelector` is empty."]);
        assert!(model.state.shows_observatory());
    }
}
