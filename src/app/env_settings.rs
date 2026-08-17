//! Env Settings page view model for [`super::ApplicationService`] (Roadmap §2.1:55).
//!
//! Edits the Xray top-level `env` object — a free-form environment-variable name→string map, not
//! a fixed-field object (see `crate::xray::config::env_settings` module docs for the full
//! rationale, including why three documented variable names are deliberately excluded from the
//! preset list). This is the first root-section editor in the crate with no prior read-only page
//! to extend — `env` was not previously a recognized top-level section at all — so there is no
//! separate browsing state machine to preserve; like API/Stats/Metrics Settings, this page is a
//! single `ViewMode`/`EditMode` pair.

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, EnvSettings, env_settings_change_summary};

/// High-level state shown by the Env Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvSettingsPageState {
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
    /// Top-level `env` value is not a JSON object.
    MalformedEnvObject,
}

impl EnvSettingsPageState {
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
            Self::ViewMode => "Env settings loaded.",
            Self::EditMode => "Editing env settings. Changes are not saved until you click Save.",
            Self::ValidationError => "Env settings validation failed. Fix the highlighted fields.",
            Self::Saving => "Saving env settings...",
            Self::Saved => "Env settings updated.",
            Self::SaveFailed => "Failed to save env settings.",
            Self::MalformedEnvObject => "Malformed env object in the remote configuration.",
        }
    }
}

/// Model exposed to the Env Settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSettingsPageModel {
    /// Coarse page state.
    pub state: EnvSettingsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: EnvSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the Env Settings page model.
pub fn build_env_settings_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&EnvSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> EnvSettingsPageModel {
    if ssh != SshStatus::Connected {
        return EnvSettingsPageModel {
            state: EnvSettingsPageState::NoSshConnection,
            settings: EnvSettings::defaults(),
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
            return EnvSettingsPageModel {
                state: EnvSettingsPageState::XrayNotDiscovered,
                settings: EnvSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return EnvSettingsPageModel {
            state: EnvSettingsPageState::ConfigurationNotLoaded,
            settings: EnvSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.env_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed env object"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        env_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        EnvSettingsPageState::Saving
    } else if saved_flash {
        EnvSettingsPageState::Saved
    } else if error_message.is_some() && editing {
        EnvSettingsPageState::ValidationError
    } else if error_message.is_some() {
        EnvSettingsPageState::SaveFailed
    } else if malformed {
        EnvSettingsPageState::MalformedEnvObject
    } else if editing {
        EnvSettingsPageState::EditMode
    } else {
        EnvSettingsPageState::ViewMode
    };

    EnvSettingsPageModel {
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
        let model = build_env_settings_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, EnvSettingsPageState::NoSshConnection);
    }

    #[test]
    fn not_discovered_state() {
        let model = build_env_settings_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, EnvSettingsPageState::XrayNotDiscovered);
    }
}
