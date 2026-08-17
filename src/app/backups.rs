//! Read-only Backups page view model for [`super::ApplicationService`] (Roadmap §3:127 —
//! Rollback UI: list + restore previously created config backups).
//!
//! Every remote configuration write in Feldjäger already creates a timestamped backup next to
//! the original file (`{filename}.feldjaeger.bak.{timestamp}`, `BackupManager::create_backup`)
//! before overwriting it — but until this page nothing in the GUI ever listed or restored one;
//! only an automatic restore-on-failed-`xray run -test` existed. This page covers the Xray
//! configuration file(s) only (single file, or every confdir member) — not the systemd unit
//! file, which uses the same backup mechanism but is a deliberately separate concern (Roadmap
//! §3:126 already gives Edit unit a before/after diff; restoring it would also need a
//! `daemon-reload` that this flow doesn't run).

use crate::app::inbounds::{LoadedConfigSnapshot, display_source_file};
use crate::app::status::SshStatus;
use crate::xray::DiscoveryState;

/// High-level state shown by the Backups page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupsPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Config file list loaded without warnings.
    ConfigurationLoaded,
    /// Config file list loaded with non-fatal warnings.
    ConfigurationContainsWarnings,
}

impl BackupsPageState {
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
            Self::ConfigurationLoaded => "Configuration files loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the details below."
            }
        }
    }

    /// Returns whether the file list should be rendered.
    pub fn shows_files(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings
        )
    }
}

/// One row — a config source file eligible for backup listing/restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFileRow {
    /// Full remote source path.
    pub path: String,
    /// Basename for display.
    pub display_name: String,
}

/// Read-only model exposed to the Backups page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupsPageModel {
    /// Coarse page state.
    pub state: BackupsPageState,
    /// Files eligible for backup listing (sorted — `EditableXrayConfig::file_roots` is a
    /// `BTreeMap`; a single-file install has exactly one row).
    pub rows: Vec<BackupFileRow>,
    /// Non-fatal configuration warnings.
    pub warnings: Vec<String>,
}

/// Derives the Backups page state from connection, discovery, and config state.
pub fn derive_backups_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> BackupsPageState {
    if ssh != SshStatus::Connected {
        return BackupsPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => BackupsPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                BackupsPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                warnings, editable, ..
            } => {
                if editable.is_none() {
                    return BackupsPageState::ConfigurationNotLoaded;
                }
                if !warnings.is_empty() {
                    BackupsPageState::ConfigurationContainsWarnings
                } else {
                    BackupsPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the read-only Backups page model.
pub fn build_backups_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> BackupsPageModel {
    let state = derive_backups_page_state(ssh, discovery, config);
    let rows = if state.shows_files() {
        config
            .editable()
            .map(|editable| {
                editable
                    .file_roots()
                    .keys()
                    .map(|path| BackupFileRow {
                        path: path.clone(),
                        display_name: display_source_file(path).to_owned(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    BackupsPageModel {
        state,
        rows,
        warnings: config.warnings().to_vec(),
    }
}

/// Formats a backup's creation timestamp as `YYYY-MM-DD HH:MM:SS UTC` — full time-of-day
/// precision, unlike `format_unix_date` (date-only), since a busy host can create several
/// backups of the same file on the same day.
pub fn format_backup_timestamp(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| unix.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{ConfigSource, EditableXrayConfig, InitSystemKind, XrayConfigParser, XrayInstallation};

    fn succeeded(config_source: ConfigSource) -> DiscoveryState {
        DiscoveryState::Succeeded(XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: None,
            version: None,
            service_name: None,
            service_state: None,
            exec_start: None,
            config_source,
            config_readable: true,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        })
    }

    fn editable_from(path: &str, json: &str) -> EditableXrayConfig {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file(path, json);
        assert!(!outcome.has_fatal_errors(), "{:?}", outcome.errors());
        let root: serde_json::Value = serde_json::from_str(json).expect("json");
        EditableXrayConfig::from_single_file(path, root, outcome.into_sections())
    }

    fn loaded(editable: Option<EditableXrayConfig>) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings: Vec::new(),
            editable,
        }
    }

    #[test]
    fn single_file_config_lists_one_row() {
        let editable = editable_from("/etc/xray/config.json", r#"{}"#);
        let model = build_backups_page_model(
            SshStatus::Connected,
            &succeeded(ConfigSource::SingleFile(
                feldjaeger_ssh::RemotePath::new("/etc/xray/config.json").unwrap(),
            )),
            &loaded(Some(editable)),
        );
        assert_eq!(model.state, BackupsPageState::ConfigurationLoaded);
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].display_name, "config.json");
    }

    #[test]
    fn confdir_lists_every_member_file() {
        let editable = editable_from("/etc/xray/00-log.json", r#"{"policy":{}}"#);
        let model = build_backups_page_model(
            SshStatus::Connected,
            &succeeded(ConfigSource::ConfigDirectory(
                feldjaeger_ssh::RemotePath::new("/etc/xray").unwrap(),
            )),
            &loaded(Some(editable)),
        );
        assert_eq!(model.state, BackupsPageState::ConfigurationLoaded);
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].path, "/etc/xray/00-log.json");
    }

    #[test]
    fn not_connected_and_not_discovered_states() {
        assert_eq!(
            derive_backups_page_state(
                SshStatus::Disconnected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            BackupsPageState::NoSshConnection
        );
        assert_eq!(
            derive_backups_page_state(
                SshStatus::Connected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            BackupsPageState::XrayNotDiscovered
        );
    }

    #[test]
    fn configuration_not_loaded_state() {
        let model = build_backups_page_model(
            SshStatus::Connected,
            &succeeded(ConfigSource::SingleFile(
                feldjaeger_ssh::RemotePath::new("/etc/xray/config.json").unwrap(),
            )),
            &LoadedConfigSnapshot::NotLoaded,
        );
        assert_eq!(model.state, BackupsPageState::ConfigurationNotLoaded);
    }
}
