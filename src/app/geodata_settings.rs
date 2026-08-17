//! GeoData Settings page view model for [`super::ApplicationService`] (Roadmap §2.1:57).
//!
//! Edits the Xray top-level `geodata` object — `cron`/`outbound`/`assets[]` (see
//! `crate::xray::config::geodata_settings` module docs for the full field breakdown and the
//! deliberate boundary against the existing, unrelated GeoData page, Roadmap Tier 1, which
//! performs live SSH file operations rather than editing the configuration file). Like Env
//! Settings, this page is a single `ViewMode`/`EditMode` pair with a variable-length `assets`
//! table rather than a fixed field grid, since `assets` can hold any number of entries.

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, GeodataSettings, geodata_settings_change_summary};

/// High-level state shown by the GeoData Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeodataSettingsPageState {
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
    /// Top-level `geodata` value is not a JSON object.
    MalformedGeodataObject,
}

impl GeodataSettingsPageState {
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
            Self::ViewMode => "GeoData settings loaded.",
            Self::EditMode => {
                "Editing geodata settings. Changes are not saved until you click Save."
            }
            Self::ValidationError => {
                "GeoData settings validation failed. Fix the highlighted fields."
            }
            Self::Saving => "Saving geodata settings...",
            Self::Saved => "GeoData settings updated.",
            Self::SaveFailed => "Failed to save geodata settings.",
            Self::MalformedGeodataObject => "Malformed geodata object in the remote configuration.",
        }
    }
}

/// Model exposed to the GeoData Settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeodataSettingsPageModel {
    /// Coarse page state.
    pub state: GeodataSettingsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: GeodataSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the GeoData Settings page model.
pub fn build_geodata_settings_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&GeodataSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> GeodataSettingsPageModel {
    if ssh != SshStatus::Connected {
        return GeodataSettingsPageModel {
            state: GeodataSettingsPageState::NoSshConnection,
            settings: GeodataSettings::defaults(),
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
            return GeodataSettingsPageModel {
                state: GeodataSettingsPageState::XrayNotDiscovered,
                settings: GeodataSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return GeodataSettingsPageModel {
            state: GeodataSettingsPageState::ConfigurationNotLoaded,
            settings: GeodataSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.geodata_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed geodata object"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        geodata_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        GeodataSettingsPageState::Saving
    } else if saved_flash {
        GeodataSettingsPageState::Saved
    } else if error_message.is_some() && editing {
        GeodataSettingsPageState::ValidationError
    } else if error_message.is_some() {
        GeodataSettingsPageState::SaveFailed
    } else if malformed {
        GeodataSettingsPageState::MalformedGeodataObject
    } else if editing {
        GeodataSettingsPageState::EditMode
    } else {
        GeodataSettingsPageState::ViewMode
    };

    GeodataSettingsPageModel {
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
        let model = build_geodata_settings_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, GeodataSettingsPageState::NoSshConnection);
    }

    #[test]
    fn not_discovered_state() {
        let model = build_geodata_settings_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, GeodataSettingsPageState::XrayNotDiscovered);
    }
}
