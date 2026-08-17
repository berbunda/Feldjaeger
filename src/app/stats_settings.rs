//! Stats Settings page view model for [`super::ApplicationService`] (Roadmap §2.1:52).
//!
//! Edits the Xray top-level `stats` object's *presence* only — `StatsObject` has no documented
//! fields (see `crate::xray::config::stats_settings` module docs), so "editing" this section
//! means enabling or disabling it. Live counter reads against an already-enabled module are a
//! separate concern — the Statistics page (`crate::app::stats_console`, Roadmap §3:129) — the
//! same split this crate already draws between Log Settings/API Settings and Xray Logs/API
//! Console.

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, StatsSettings, stats_settings_change_summary};

/// High-level state shown by the Stats Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsSettingsPageState {
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
    /// Top-level `stats` value is not a JSON object.
    MalformedStatsObject,
}

impl StatsSettingsPageState {
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
            Self::ViewMode => "Stats settings loaded.",
            Self::EditMode => {
                "Editing stats settings. Changes are not saved until you click Save."
            }
            Self::ValidationError => "Stats settings validation failed. Fix the highlighted fields.",
            Self::Saving => "Saving stats settings...",
            Self::Saved => "Stats settings updated.",
            Self::SaveFailed => "Failed to save stats settings.",
            Self::MalformedStatsObject => "Malformed stats object in the remote configuration.",
        }
    }
}

/// Model exposed to the Stats Settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSettingsPageModel {
    /// Coarse page state.
    pub state: StatsSettingsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: StatsSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the Stats Settings page model.
pub fn build_stats_settings_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&StatsSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> StatsSettingsPageModel {
    if ssh != SshStatus::Connected {
        return StatsSettingsPageModel {
            state: StatsSettingsPageState::NoSshConnection,
            settings: StatsSettings::defaults(),
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
            return StatsSettingsPageModel {
                state: StatsSettingsPageState::XrayNotDiscovered,
                settings: StatsSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return StatsSettingsPageModel {
            state: StatsSettingsPageState::ConfigurationNotLoaded,
            settings: StatsSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.stats_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed stats object"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        stats_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        StatsSettingsPageState::Saving
    } else if saved_flash {
        StatsSettingsPageState::Saved
    } else if error_message.is_some() && editing {
        StatsSettingsPageState::ValidationError
    } else if error_message.is_some() {
        StatsSettingsPageState::SaveFailed
    } else if malformed {
        StatsSettingsPageState::MalformedStatsObject
    } else if editing {
        StatsSettingsPageState::EditMode
    } else {
        StatsSettingsPageState::ViewMode
    };

    StatsSettingsPageModel {
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
        let model = build_stats_settings_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, StatsSettingsPageState::NoSshConnection);
    }

    #[test]
    fn not_discovered_state() {
        let model = build_stats_settings_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, StatsSettingsPageState::XrayNotDiscovered);
    }
}
