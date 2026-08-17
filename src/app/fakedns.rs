//! FakeDNS page view model for [`super::ApplicationService`] (Roadmap §2.1:47).
//!
//! View **and** edit — mirrors [`super::dns`]'s state machine exactly (this page has no separate
//! live/runtime counterpart to split away from). The GUI consumes [`crate::xray::FakeDnsSettings`]
//! and never inspects JSON.

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, FakeDnsSettings};

/// High-level state shown by the FakeDNS page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeDnsPageState {
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
    /// Top-level `fakedns` value is neither an object nor an array of objects.
    MalformedFakeDnsObject,
}

impl FakeDnsPageState {
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
            Self::ViewMode => "FakeDNS configuration loaded.",
            Self::EditMode => {
                "Editing FakeDNS settings. Changes are not saved until you click Save."
            }
            Self::ValidationError => {
                "FakeDNS settings validation failed. Fix the highlighted fields."
            }
            Self::Saving => "Saving FakeDNS settings...",
            Self::Saved => "FakeDNS settings updated.",
            Self::SaveFailed => "Failed to save FakeDNS settings.",
            Self::MalformedFakeDnsObject => "Malformed fakedns section in the remote configuration.",
        }
    }
}

/// Model exposed to the FakeDNS page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsPageModel {
    /// Coarse page state.
    pub state: FakeDnsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: FakeDnsSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the FakeDNS page model.
pub fn build_fakedns_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&FakeDnsSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> FakeDnsPageModel {
    if ssh != SshStatus::Connected {
        return FakeDnsPageModel {
            state: FakeDnsPageState::NoSshConnection,
            settings: FakeDnsSettings::defaults(),
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
            return FakeDnsPageModel {
                state: FakeDnsPageState::XrayNotDiscovered,
                settings: FakeDnsSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return FakeDnsPageModel {
            state: FakeDnsPageState::ConfigurationNotLoaded,
            settings: FakeDnsSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.fakedns_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed fakedns section"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        crate::xray::fakedns_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        FakeDnsPageState::Saving
    } else if saved_flash {
        FakeDnsPageState::Saved
    } else if error_message.is_some() && editing {
        FakeDnsPageState::ValidationError
    } else if error_message.is_some() {
        FakeDnsPageState::SaveFailed
    } else if malformed {
        FakeDnsPageState::MalformedFakeDnsObject
    } else if editing {
        FakeDnsPageState::EditMode
    } else {
        FakeDnsPageState::ViewMode
    };

    FakeDnsPageModel {
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

    #[test]
    fn no_ssh_state() {
        let model = build_fakedns_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, FakeDnsPageState::NoSshConnection);
    }

    #[test]
    fn not_discovered_state() {
        let model = build_fakedns_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, FakeDnsPageState::XrayNotDiscovered);
    }
}
