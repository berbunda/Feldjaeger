//! Version Settings page view model for [`super::ApplicationService`] (Roadmap §2.1:56).
//!
//! Edits the Xray top-level `version` object — `{ min, max }` guard-rail version constraints for
//! the config file (see `crate::xray::config::version_settings` module docs). Like Env/Metrics/
//! API/Stats Settings, this is a single `ViewMode`/`EditMode` pair — `version` has no browsing
//! sub-state, just two flat optional string fields.

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, VersionSettings, version_settings_change_summary};

/// High-level state shown by the Version Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSettingsPageState {
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
    /// Top-level `version` value is not a JSON object.
    MalformedVersionObject,
}

impl VersionSettingsPageState {
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
            Self::ViewMode => "Version settings loaded.",
            Self::EditMode => {
                "Editing version settings. Changes are not saved until you click Save."
            }
            Self::ValidationError => {
                "Version settings validation failed. Fix the highlighted fields."
            }
            Self::Saving => "Saving version settings...",
            Self::Saved => "Version settings updated.",
            Self::SaveFailed => "Failed to save version settings.",
            Self::MalformedVersionObject => "Malformed version object in the remote configuration.",
        }
    }
}

/// Model exposed to the Version Settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSettingsPageModel {
    /// Coarse page state.
    pub state: VersionSettingsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: VersionSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the Version Settings page model.
pub fn build_version_settings_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&VersionSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> VersionSettingsPageModel {
    if ssh != SshStatus::Connected {
        return VersionSettingsPageModel {
            state: VersionSettingsPageState::NoSshConnection,
            settings: VersionSettings::defaults(),
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
            return VersionSettingsPageModel {
                state: VersionSettingsPageState::XrayNotDiscovered,
                settings: VersionSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return VersionSettingsPageModel {
            state: VersionSettingsPageState::ConfigurationNotLoaded,
            settings: VersionSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.version_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed version object"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        version_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        VersionSettingsPageState::Saving
    } else if saved_flash {
        VersionSettingsPageState::Saved
    } else if error_message.is_some() && editing {
        VersionSettingsPageState::ValidationError
    } else if error_message.is_some() {
        VersionSettingsPageState::SaveFailed
    } else if malformed {
        VersionSettingsPageState::MalformedVersionObject
    } else if editing {
        VersionSettingsPageState::EditMode
    } else {
        VersionSettingsPageState::ViewMode
    };

    VersionSettingsPageModel {
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
        let model = build_version_settings_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, VersionSettingsPageState::NoSshConnection);
    }

    #[test]
    fn not_discovered_state() {
        let model = build_version_settings_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, VersionSettingsPageState::XrayNotDiscovered);
    }
}
