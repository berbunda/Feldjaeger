//! Metrics Settings page view model for [`super::ApplicationService`] (Roadmap §2.1:53).
//!
//! Edits the Xray top-level `metrics` object (`tag` / `listen`) only — the exact same two fields
//! as `api.tag`/`api.listen` (`crate::app::api_settings`, Roadmap §2.1:54), minus `services[]`.
//! Live HTTP scraping of an already-configured endpoint is a separate concern — the Metrics page
//! (Roadmap §3:130, `crate::app::metrics_console`) — the same split this crate already draws
//! between API Settings and API Console, or Log Settings and Xray Logs.

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, MetricsSettings, metrics_settings_change_summary};

/// High-level state shown by the Metrics Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsSettingsPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Loaded settings are shown read-only.
    ViewMode,
    /// In-memory draft is being edited.
    EditMode,
    /// Draft failed local validation.
    ValidationError,
    /// Remote save is in progress.
    Saving,
    /// Last save succeeded (transient before returning to view).
    Saved,
    /// Last save failed (classified error shown separately).
    SaveFailed,
    /// Top-level `metrics` value is not a JSON object.
    MalformedMetricsObject,
}

impl MetricsSettingsPageState {
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
            Self::ViewMode => "Metrics settings loaded.",
            Self::EditMode => {
                "Editing metrics settings. Changes are not saved until you click Save."
            }
            Self::ValidationError => {
                "Metrics settings validation failed. Fix the highlighted fields."
            }
            Self::Saving => "Saving metrics settings...",
            Self::Saved => "Metrics settings updated.",
            Self::SaveFailed => "Failed to save metrics settings.",
            Self::MalformedMetricsObject => "Malformed metrics object in the remote configuration.",
        }
    }
}

/// Model exposed to the Metrics Settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSettingsPageModel {
    /// Coarse page state.
    pub state: MetricsSettingsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: MetricsSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the Metrics Settings page model.
pub fn build_metrics_settings_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&MetricsSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> MetricsSettingsPageModel {
    if ssh != SshStatus::Connected {
        return MetricsSettingsPageModel {
            state: MetricsSettingsPageState::NoSshConnection,
            settings: MetricsSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: Vec::new(),
        };
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => {
            return MetricsSettingsPageModel {
                state: MetricsSettingsPageState::XrayNotDiscovered,
                settings: MetricsSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return MetricsSettingsPageModel {
            state: MetricsSettingsPageState::ConfigurationNotLoaded,
            settings: MetricsSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.metrics_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed metrics object"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        metrics_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        MetricsSettingsPageState::Saving
    } else if saved_flash {
        MetricsSettingsPageState::Saved
    } else if error_message.is_some() && editing {
        MetricsSettingsPageState::ValidationError
    } else if error_message.is_some() {
        MetricsSettingsPageState::SaveFailed
    } else if malformed {
        MetricsSettingsPageState::MalformedMetricsObject
    } else if editing {
        MetricsSettingsPageState::EditMode
    } else {
        MetricsSettingsPageState::ViewMode
    };

    MetricsSettingsPageModel {
        state,
        settings,
        editing,
        change_summary,
        error_message,
        config_warnings: config.warnings().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::inbounds::LoadedConfigSnapshot;
    use crate::xray::DiscoveryState;

    #[test]
    fn no_ssh_state() {
        let model = build_metrics_settings_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, MetricsSettingsPageState::NoSshConnection);
    }

    #[test]
    fn not_discovered_state() {
        let model = build_metrics_settings_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, MetricsSettingsPageState::XrayNotDiscovered);
    }
}
