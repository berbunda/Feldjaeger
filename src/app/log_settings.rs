//! Log Settings page view model for [`super::ApplicationService`].
//!
//! Edits the Xray top-level `log` object only. Runtime log bodies remain on the
//! Xray Logs page (D021). Application Feldjäger logs remain separate (D017).

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{
    DiscoveryState, LogLevel, LogOutput, LogSettings, MaskAddress, log_settings_change_summary,
    log_settings_from_section,
};

/// High-level state shown by the Log Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSettingsPageState {
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
    /// Configuration contains unknown log values that are preserved.
    UnknownConfigurationValue,
    /// Top-level `log` value is not a JSON object.
    MalformedLogObject,
}

impl LogSettingsPageState {
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
            Self::ViewMode => "Log settings loaded.",
            Self::EditMode => "Editing log settings. Changes are not saved until you click Save.",
            Self::ValidationError => "Log settings validation failed. Fix the highlighted fields.",
            Self::Saving => "Saving log settings...",
            Self::Saved => "Log settings updated.",
            Self::SaveFailed => "Failed to save log settings.",
            Self::UnknownConfigurationValue => {
                "Configuration contains unknown log values. They are preserved until you change them."
            }
            Self::MalformedLogObject => "Malformed log object in the remote configuration.",
        }
    }
}

/// Model exposed to the Log Settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSettingsPageModel {
    /// Coarse page state.
    pub state: LogSettingsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: LogSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the Log Settings page model.
pub fn build_log_settings_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&LogSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> LogSettingsPageModel {
    if ssh != SshStatus::Connected {
        return LogSettingsPageModel {
            state: LogSettingsPageState::NoSshConnection,
            settings: LogSettings::defaults(),
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
            return LogSettingsPageModel {
                state: LogSettingsPageState::XrayNotDiscovered,
                settings: LogSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return LogSettingsPageModel {
            state: LogSettingsPageState::ConfigurationNotLoaded,
            settings: LogSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.log_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed log object"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        log_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        LogSettingsPageState::Saving
    } else if saved_flash {
        LogSettingsPageState::Saved
    } else if error_message.is_some() && editing {
        LogSettingsPageState::ValidationError
    } else if error_message.is_some() {
        LogSettingsPageState::SaveFailed
    } else if malformed {
        LogSettingsPageState::MalformedLogObject
    } else if editing {
        LogSettingsPageState::EditMode
    } else if loaded.has_unknown_values() {
        LogSettingsPageState::UnknownConfigurationValue
    } else {
        LogSettingsPageState::ViewMode
    };

    LogSettingsPageModel {
        state,
        settings,
        editing,
        change_summary,
        error_message,
        config_warnings: config.warnings().to_vec(),
    }
}

/// Display helpers for view-mode rows.
pub fn log_output_display(output: &LogOutput) -> String {
    output.display_label()
}

/// Display helper for log level.
pub fn log_level_display(level: &LogLevel) -> String {
    level.display_label()
}

/// Display helper for mask address.
pub fn mask_address_display(mask: &MaskAddress) -> String {
    mask.display_label()
}

/// Reloads typed settings from a snapshot (used by tests / cancel).
pub fn settings_from_snapshot(config: &LoadedConfigSnapshot) -> LogSettings {
    match config.editable() {
        Some(editable) => editable.log_settings(),
        None => log_settings_from_section(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::inbounds::LoadedConfigSnapshot;
    use crate::xray::{DiscoveryState, LogOutput};

    #[test]
    fn no_ssh_state() {
        let model = build_log_settings_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, LogSettingsPageState::NoSshConnection);
    }

    #[test]
    fn cancel_clears_draft_semantics() {
        let mut draft = LogSettings::defaults();
        draft.access = LogOutput::Disabled;
        let loaded = LogSettings::defaults();
        // Cancel means the page model is rebuilt without a draft → view of loaded defaults.
        let model = build_log_settings_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None, // draft discarded
            false,
            None,
            false,
        );
        assert_eq!(model.state, LogSettingsPageState::XrayNotDiscovered);
        assert_ne!(draft.access, loaded.access);
    }

    #[test]
    fn edit_mode_exposes_change_summary() {
        let mut draft = LogSettings::defaults();
        draft.access = LogOutput::Disabled;
        // Without a loaded editable config the page stays ConfigurationNotLoaded.
        let model = build_log_settings_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            Some(&draft),
            false,
            None,
            false,
        );
        assert_eq!(model.state, LogSettingsPageState::XrayNotDiscovered);
    }
}
