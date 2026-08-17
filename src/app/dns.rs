//! DNS page view model for [`super::ApplicationService`] (Roadmap §2.1:46).
//!
//! View **and** edit — mirrors [`super::api_settings`]'s state machine exactly (this page has no
//! separate live/runtime counterpart to split away from, unlike API Settings vs. the API
//! Console, so — unlike that pair — DNS keeps one page for both view and edit). The GUI consumes
//! [`crate::xray::DnsSettings`] and never inspects JSON.

use crate::app::inbounds::LoadedConfigSnapshot;
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, DnsSettings};

/// High-level state shown by the DNS page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPageState {
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
    /// Top-level `dns` value is not a JSON object.
    MalformedDnsObject,
}

impl DnsPageState {
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
            Self::ViewMode => "DNS configuration loaded.",
            Self::EditMode => "Editing DNS settings. Changes are not saved until you click Save.",
            Self::ValidationError => "DNS settings validation failed. Fix the highlighted fields.",
            Self::Saving => "Saving DNS settings...",
            Self::Saved => "DNS settings updated.",
            Self::SaveFailed => "Failed to save DNS settings.",
            Self::MalformedDnsObject => "Malformed dns object in the remote configuration.",
        }
    }
}

/// Model exposed to the DNS page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPageModel {
    /// Coarse page state.
    pub state: DnsPageState,
    /// Settings currently displayed (loaded or draft).
    pub settings: DnsSettings,
    /// Whether the UI is in edit mode with an in-memory draft.
    pub editing: bool,
    /// Change summary lines when editing (loaded → draft).
    pub change_summary: Vec<String>,
    /// Last classified save/validation error for the page.
    pub error_message: Option<String>,
    /// Non-fatal configuration warnings from discovery.
    pub config_warnings: Vec<String>,
}

/// Builds the DNS page model.
pub fn build_dns_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    draft: Option<&DnsSettings>,
    saving: bool,
    error_message: Option<String>,
    saved_flash: bool,
) -> DnsPageModel {
    if ssh != SshStatus::Connected {
        return DnsPageModel {
            state: DnsPageState::NoSshConnection,
            settings: DnsSettings::defaults(),
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
            return DnsPageModel {
                state: DnsPageState::XrayNotDiscovered,
                settings: DnsSettings::defaults(),
                editing: false,
                change_summary: Vec::new(),
                error_message: None,
                config_warnings: Vec::new(),
            };
        }
        DiscoveryState::Succeeded(_) => {}
    }

    let Some(editable) = config.editable() else {
        return DnsPageModel {
            state: DnsPageState::ConfigurationNotLoaded,
            settings: DnsSettings::defaults(),
            editing: false,
            change_summary: Vec::new(),
            error_message: None,
            config_warnings: config.warnings().to_vec(),
        };
    };

    let loaded = editable.dns_settings();
    let malformed = loaded
        .warnings
        .iter()
        .any(|w| w.starts_with("Malformed dns object"));

    let editing = draft.is_some();
    let settings = draft.cloned().unwrap_or_else(|| loaded.clone());
    let change_summary = if let Some(draft) = draft {
        crate::xray::dns_settings_change_summary(&loaded, draft)
    } else {
        Vec::new()
    };

    let state = if saving {
        DnsPageState::Saving
    } else if saved_flash {
        DnsPageState::Saved
    } else if error_message.is_some() && editing {
        DnsPageState::ValidationError
    } else if error_message.is_some() {
        DnsPageState::SaveFailed
    } else if malformed {
        DnsPageState::MalformedDnsObject
    } else if editing {
        DnsPageState::EditMode
    } else {
        DnsPageState::ViewMode
    };

    DnsPageModel {
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
        let model = build_dns_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, DnsPageState::NoSshConnection);
    }

    #[test]
    fn not_discovered_state() {
        let model = build_dns_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            false,
            None,
            false,
        );
        assert_eq!(model.state, DnsPageState::XrayNotDiscovered);
    }
}
