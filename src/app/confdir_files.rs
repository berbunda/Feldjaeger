//! Read-only Config Files page view model for [`super::ApplicationService`].
//!
//! Lets the user add an empty file to, or remove an empty file from, an existing Xray
//! confdir (Roadmap §2.5:107). Not applicable to single-file (`config.json`) installs — the
//! GUI consumes [`ConfdirFilesPageState::NotAConfdir`] to explain that instead of a mutation
//! entry point.

use crate::app::inbounds::{LoadedConfigSnapshot, MISSING_FIELD, display_source_file};
use crate::app::status::SshStatus;
use crate::xray::{ConfigSource, DiscoveryState, XrayConfigSections};

/// High-level state shown by the Config Files page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfdirFilesPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Discovered config is a single file, not a confdir — nothing to add/remove here.
    NotAConfdir,
    /// Confdir file list loaded without warnings.
    ConfigurationLoaded,
    /// Confdir file list loaded with non-fatal warnings.
    ConfigurationContainsWarnings,
}

impl ConfdirFilesPageState {
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
            Self::NotAConfdir => {
                "This Xray instance uses a single config.json file — file add/remove only \
                 applies to confdir installations."
            }
            Self::ConfigurationLoaded => "Confdir files loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the details below."
            }
        }
    }

    /// Returns whether the file table and mutation actions should be rendered.
    pub fn shows_files(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings
        )
    }
}

/// One row in the confdir files table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfdirFileRow {
    /// Full remote source path.
    pub path: String,
    /// Basename for display.
    pub display_name: String,
    /// `true` when no config section is currently sourced from this file.
    pub is_empty: bool,
    /// Human-readable contents summary (or `—` when empty).
    pub contents_summary: String,
}

/// Read-only model exposed to the Config Files page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfdirFilesPageModel {
    /// Coarse page state.
    pub state: ConfdirFilesPageState,
    /// Files to display (sorted by path — `EditableXrayConfig::file_roots` is a `BTreeMap`).
    pub rows: Vec<ConfdirFileRow>,
    /// Non-fatal configuration warnings.
    pub warnings: Vec<String>,
}

/// Derives the Config Files page state from connection, discovery, and config state.
pub fn derive_confdir_files_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> ConfdirFilesPageState {
    if ssh != SshStatus::Connected {
        return ConfdirFilesPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => ConfdirFilesPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(installation) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                ConfdirFilesPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                warnings, editable, ..
            } => {
                if !matches!(installation.config_source, ConfigSource::ConfigDirectory(_)) {
                    return ConfdirFilesPageState::NotAConfdir;
                }
                if editable.is_none() {
                    return ConfdirFilesPageState::ConfigurationNotLoaded;
                }
                if !warnings.is_empty() {
                    ConfdirFilesPageState::ConfigurationContainsWarnings
                } else {
                    ConfdirFilesPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the read-only Config Files page model.
pub fn build_confdir_files_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> ConfdirFilesPageModel {
    let state = derive_confdir_files_page_state(ssh, discovery, config);
    let rows = if state.shows_files() {
        config
            .editable()
            .map(|editable| {
                editable
                    .file_roots()
                    .keys()
                    .map(|path| confdir_file_row(editable.sections(), path))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    ConfdirFilesPageModel {
        state,
        rows,
        warnings: config.warnings().to_vec(),
    }
}

fn confdir_file_row(sections: &XrayConfigSections, path: &str) -> ConfdirFileRow {
    let contents = sections.sections_in_file(path);
    ConfdirFileRow {
        path: path.to_owned(),
        display_name: display_source_file(path).to_owned(),
        is_empty: contents.is_empty(),
        contents_summary: if contents.is_empty() {
            MISSING_FIELD.to_owned()
        } else {
            contents.join(", ")
        },
    }
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
    fn single_file_config_is_not_a_confdir() {
        let editable = editable_from("/etc/xray/config.json", r#"{}"#);
        let model = build_confdir_files_page_model(
            SshStatus::Connected,
            &succeeded(ConfigSource::SingleFile(
                feldjaeger_ssh::RemotePath::new("/etc/xray/config.json").unwrap(),
            )),
            &loaded(Some(editable)),
        );
        assert_eq!(model.state, ConfdirFilesPageState::NotAConfdir);
        assert!(model.rows.is_empty());
    }

    #[test]
    fn confdir_lists_files_with_contents_summary() {
        let editable = editable_from("/etc/xray/00-log.json", r#"{"policy":{}}"#);
        let model = build_confdir_files_page_model(
            SshStatus::Connected,
            &succeeded(ConfigSource::ConfigDirectory(
                feldjaeger_ssh::RemotePath::new("/etc/xray").unwrap(),
            )),
            &loaded(Some(editable)),
        );
        assert_eq!(model.state, ConfdirFilesPageState::ConfigurationLoaded);
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].display_name, "00-log.json");
        assert!(!model.rows[0].is_empty);
        assert_eq!(model.rows[0].contents_summary, "policy");
    }

    #[test]
    fn empty_confdir_file_reports_missing_field() {
        let editable = editable_from("/etc/xray/00-log.json", r#"{}"#);
        let model = build_confdir_files_page_model(
            SshStatus::Connected,
            &succeeded(ConfigSource::ConfigDirectory(
                feldjaeger_ssh::RemotePath::new("/etc/xray").unwrap(),
            )),
            &loaded(Some(editable)),
        );
        assert!(model.rows[0].is_empty);
        assert_eq!(model.rows[0].contents_summary, MISSING_FIELD);
    }

    #[test]
    fn not_connected_and_not_discovered_states() {
        assert_eq!(
            derive_confdir_files_page_state(
                SshStatus::Disconnected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            ConfdirFilesPageState::NoSshConnection
        );
        assert_eq!(
            derive_confdir_files_page_state(
                SshStatus::Connected,
                &DiscoveryState::Idle,
                &LoadedConfigSnapshot::None,
            ),
            ConfdirFilesPageState::XrayNotDiscovered
        );
    }

    #[test]
    fn configuration_not_loaded_state() {
        let model = build_confdir_files_page_model(
            SshStatus::Connected,
            &succeeded(ConfigSource::ConfigDirectory(
                feldjaeger_ssh::RemotePath::new("/etc/xray").unwrap(),
            )),
            &LoadedConfigSnapshot::NotLoaded,
        );
        assert_eq!(model.state, ConfdirFilesPageState::ConfigurationNotLoaded);
    }
}
