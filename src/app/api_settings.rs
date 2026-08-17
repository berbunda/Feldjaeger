//! API Settings page view model for [`super::ApplicationService`] (Roadmap §2.1:54).
//!
//! Edits the Xray top-level `api` object (`tag` / `listen` / `services`) only. Live gRPC calls
//! against an already-configured endpoint are a separate concern — the API Console page
//! (Roadmap §3:128, `crate::app::api_console`) — the same split as this crate already draws
//! between Log Settings (this module's sibling) and Xray Logs.

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{ApiSettings, DiscoveryState, api_settings_change_summary};

/// High-level state shown by the API Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiSettingsPageState {
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
    /// Top-level `api` value is not a JSON object.
    MalformedApiObject,
}

impl ApiSettingsPageState {
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
            Self::ViewMode => "API settings loaded.",
            Self::EditMode => "Editing API settings. Changes are not saved until you click Save.",
            Self::ValidationError => "API settings validation failed. Fix the highlighted fields.",
            Self::Saving => "Saving API settings...",
            Self::Saved => "API settings updated.",
            Self::SaveFailed => "Failed to save API settings.",
            Self::MalformedApiObject => "Malformed api object in the remote configuration.",
        }
    }
}

/// Model exposed to the API Settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiSettingsPageModel {
    /// Coarse page state.
    pub state: ApiSettingsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: ApiSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the API Settings page model.
pub fn build_api_settings_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&ApiSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> ApiSettingsPageModel {
    if ssh != SshStatus::Connected {
        return ApiSettingsPageModel {
            state: ApiSettingsPageState::NoSshConnection,
            settings: ApiSettings::defaults(),
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
            return ApiSettingsPageModel {
                state: ApiSettingsPageState::XrayNotDiscovered,
                settings: ApiSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return ApiSettingsPageModel {
            state: ApiSettingsPageState::ConfigurationNotLoaded,
            settings: ApiSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.api_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed api object"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        api_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        ApiSettingsPageState::Saving
    } else if saved_flash {
        ApiSettingsPageState::Saved
    } else if error_message.is_some() && editing {
        ApiSettingsPageState::ValidationError
    } else if error_message.is_some() {
        ApiSettingsPageState::SaveFailed
    } else if malformed {
        ApiSettingsPageState::MalformedApiObject
    } else if editing {
        ApiSettingsPageState::EditMode
    } else {
        ApiSettingsPageState::ViewMode
    };

    ApiSettingsPageModel {
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
        let model = build_api_settings_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, ApiSettingsPageState::NoSshConnection);
    }

    #[test]
    fn not_discovered_state() {
        let model = build_api_settings_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, ApiSettingsPageState::XrayNotDiscovered);
    }
}
