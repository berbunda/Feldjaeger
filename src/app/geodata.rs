//! GeoData page model and async refresh/update workers for [`super::ApplicationService`].

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::{error, info};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::app::status::SshStatus;
use crate::logging::redact::{sanitize_detail, user_message_see_log};
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    DiscoveryState, GeoDataDatabaseSummary, GeoDataError, GeoDataErrorKind, GeoDataManager,
    GeoDataResolveHints, GeoDataSummary,
};

/// Async GeoData operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoDataOperation {
    /// Refresh remote GeoData status (read-only).
    Refresh,
    /// Download and replace geoip.dat / geosite.dat.
    Update,
}

impl GeoDataOperation {
    /// Status Bar text while the operation runs.
    pub fn status_message(self) -> &'static str {
        match self {
            Self::Refresh => "Refreshing GeoData...",
            Self::Update => "Updating GeoData...",
        }
    }
}

/// GUI lifecycle for GeoData operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GeoDataUiState {
    /// Idle; last snapshot may still be present on the service.
    #[default]
    Idle,
    /// Refresh or update in flight.
    Busy(GeoDataOperation),
    /// Last operation failed with a classified kind.
    Failed {
        /// Error classification for GUI state labels.
        kind: GeoDataErrorKind,
        /// Safe user-facing detail.
        detail: String,
    },
}

impl GeoDataUiState {
    /// Returns `true` while a GeoData worker is running.
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Busy(_))
    }
}

/// Read-only row for the GeoData table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataRowDisplay {
    /// Database file name.
    pub name: String,
    /// `Installed` or `Not installed`.
    pub status: String,
    /// Version label (date) or `—`.
    pub version: String,
    /// Modified timestamp display or `—`.
    pub modified: String,
    /// Human size or `—`.
    pub size: String,
}

/// Page model consumed by the GeoData GUI page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataPageModel {
    /// High-level page state label for banners.
    pub page_state: GeoDataPageState,
    /// Resolved installation / asset path, or `—`.
    pub installation_path: String,
    /// Count of installed databases (0..=2).
    pub database_count: usize,
    /// Table rows for geoip / geosite.
    pub rows: Vec<GeoDataRowDisplay>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Show restart recommendation after a successful update.
    pub restart_recommended: bool,
    /// Current async UI state.
    pub ui_state: GeoDataUiState,
    /// Whether Refresh may be started.
    pub can_refresh: bool,
    /// Whether Update may be started.
    pub can_update: bool,
    /// Optional blocked reason when actions are disabled.
    pub blocked_reason: Option<String>,
}

/// Coarse page availability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoDataPageState {
    /// SSH not connected.
    NoSshConnection,
    /// Discovery not completed.
    DiscoveryRequired,
    /// Xray not found on host.
    XrayNotInstalled,
    /// Ready to show GeoData info / run ops.
    Ready,
    /// Last GeoData op failed (see ui_state).
    Error,
}

impl GeoDataPageState {
    /// Short label for diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            Self::NoSshConnection => "SSH connection failed",
            Self::DiscoveryRequired => "Run discovery first",
            Self::XrayNotInstalled => "Unsupported installation",
            Self::Ready => "Ready",
            Self::Error => "Error",
        }
    }
}

/// Outcome of a GeoData worker thread.
#[derive(Debug)]
pub struct GeoDataOutcome {
    /// Which operation ran.
    pub operation: GeoDataOperation,
    /// Result of discover/update.
    pub result: Result<GeoDataSummary, GeoDataError>,
}

/// Builds the GeoData page model from application state.
pub fn build_geodata_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    summary: Option<&GeoDataSummary>,
    ui_state: &GeoDataUiState,
    remote_busy: bool,
) -> GeoDataPageModel {
    let (page_state, blocked_reason) = match ssh {
        SshStatus::Connected => match discovery {
            DiscoveryState::Succeeded(installation) => {
                if installation.binary_path.is_none() {
                    (
                        GeoDataPageState::XrayNotInstalled,
                        Some("Xray binary not found. Unsupported installation.".to_owned()),
                    )
                } else if matches!(ui_state, GeoDataUiState::Failed { .. }) {
                    (GeoDataPageState::Error, None)
                } else {
                    (GeoDataPageState::Ready, None)
                }
            }
            DiscoveryState::NotFound { .. } => (
                GeoDataPageState::XrayNotInstalled,
                Some("Xray is not installed on this host.".to_owned()),
            ),
            DiscoveryState::Failed { .. } => (
                GeoDataPageState::DiscoveryRequired,
                Some("Discovery failed. Re-run discovery on the Connection page.".to_owned()),
            ),
            DiscoveryState::Idle | DiscoveryState::Discovering => (
                GeoDataPageState::DiscoveryRequired,
                Some("Run discovery on the Connection page first.".to_owned()),
            ),
        },
        _ => (
            GeoDataPageState::NoSshConnection,
            Some("Connect over SSH first.".to_owned()),
        ),
    };

    let can_act = page_state == GeoDataPageState::Ready
        || (page_state == GeoDataPageState::Error
            && matches!(discovery, DiscoveryState::Succeeded(_)));
    let can_refresh = can_act && !remote_busy && !ui_state.is_busy();
    let can_update = can_refresh;

    let (installation_path, database_count, rows, warnings, restart_recommended) = match summary {
        Some(summary) => {
            let path = summary
                .installation_path
                .as_ref()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_else(|| "—".to_owned());
            let count = summary.databases.iter().filter(|d| d.installed).count();
            let rows = summary.databases.iter().map(row_from_database).collect();
            (
                path,
                count,
                rows,
                summary.warnings.clone(),
                summary.restart_recommended,
            )
        }
        None => (
            "—".to_owned(),
            0,
            default_empty_rows(),
            Vec::new(),
            false,
        ),
    };

    GeoDataPageModel {
        page_state,
        installation_path,
        database_count,
        rows,
        warnings,
        restart_recommended,
        ui_state: ui_state.clone(),
        can_refresh,
        can_update,
        blocked_reason,
    }
}

fn default_empty_rows() -> Vec<GeoDataRowDisplay> {
    ["geoip.dat", "geosite.dat"]
        .into_iter()
        .map(|name| GeoDataRowDisplay {
            name: name.to_owned(),
            status: "Not installed".to_owned(),
            version: "—".to_owned(),
            modified: "—".to_owned(),
            size: "—".to_owned(),
        })
        .collect()
}

fn row_from_database(db: &GeoDataDatabaseSummary) -> GeoDataRowDisplay {
    if !db.installed {
        return GeoDataRowDisplay {
            name: db.name.clone(),
            status: "Not installed".to_owned(),
            version: "—".to_owned(),
            modified: "—".to_owned(),
            size: "—".to_owned(),
        };
    }

    GeoDataRowDisplay {
        name: db.name.clone(),
        status: "Installed".to_owned(),
        version: db.version.clone().unwrap_or_else(|| "—".to_owned()),
        modified: db
            .modified_unix
            .map(format_unix_date)
            .unwrap_or_else(|| "—".to_owned()),
        size: db
            .size_bytes
            .map(format_size)
            .unwrap_or_else(|| "—".to_owned()),
    }
}

/// Formats a Unix timestamp as `YYYY-MM-DD` (UTC).
pub fn format_unix_date(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| unix.to_string())
}

/// Formats byte size for the table (e.g. `3.4 MB`).
pub fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let n = bytes as f64;
    if n >= GB {
        format!("{:.1} GB", n / GB)
    } else if n >= MB {
        format!("{:.1} MB", n / MB)
    } else if n >= KB {
        format!("{:.1} KB", n / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Maps a GeoData error to a short Status Bar / UI message.
pub fn user_facing_geodata_error(error: &GeoDataError) -> String {
    let detail = sanitize_detail(error.detail());
    if detail.is_empty() {
        error.kind().label().to_owned()
    } else {
        format!("{}: {}", error.kind().label(), detail)
    }
}

/// Runs discover or update on a background worker connection.
pub async fn run_geodata_operation<B: SshBackend>(
    client: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    hints: GeoDataResolveHints,
    operation: GeoDataOperation,
) -> GeoDataOutcome
where
    B::Session: Sync,
{
    let request = build_connect_request(profile, secrets);
    let session = match client.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            let detail = sanitize_detail(error.message());
            error!(
                target: "app",
                operation = ?operation,
                detail = %detail,
                "GeoData SSH connect failed"
            );
            return GeoDataOutcome {
                operation,
                result: Err(GeoDataError::new(
                    GeoDataErrorKind::SshConnectionFailed,
                    user_message_see_log("Unable to connect to server."),
                )),
            };
        }
    };

    let manager = GeoDataManager::new();
    let result = match operation {
        GeoDataOperation::Refresh => {
            info!(target: "app", "GeoData refresh started");
            manager.discover(&session, &hints).await
        }
        GeoDataOperation::Update => manager.update(&session, &hints).await,
    };

    if let Err(error) = session.disconnect().await {
        error!(
            target: "app",
            detail = %sanitize_detail(error.message()),
            "GeoData session disconnect failed"
        );
    }

    GeoDataOutcome { operation, result }
}

/// Builds resolve hints from a successful discovery snapshot.
pub fn hints_from_discovery(discovery: &DiscoveryState) -> Option<GeoDataResolveHints> {
    let DiscoveryState::Succeeded(installation) = discovery else {
        return None;
    };
    Some(GeoDataResolveHints {
        binary_path: installation.binary_path.clone(),
        service_name: installation.service_name.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::GeoDataDatabaseSummary;
    use feldjaeger_ssh::RemotePath;

    fn sample_summary(both: bool) -> GeoDataSummary {
        GeoDataSummary {
            installation_path: Some(RemotePath::new("/usr/local/share/xray").unwrap()),
            databases: vec![
                GeoDataDatabaseSummary {
                    name: "geoip.dat".to_owned(),
                    installed: true,
                    version: Some("2026-05-12".to_owned()),
                    modified_unix: Some(1_778_544_000),
                    size_bytes: Some(3_563_520),
                },
                GeoDataDatabaseSummary {
                    name: "geosite.dat".to_owned(),
                    installed: both,
                    version: if both {
                        Some("2026-05-12".to_owned())
                    } else {
                        None
                    },
                    modified_unix: if both { Some(1_778_544_000) } else { None },
                    size_bytes: if both { Some(2_097_152) } else { None },
                },
            ],
            warnings: if both {
                Vec::new()
            } else {
                vec!["GeoData database missing: geosite.dat".to_owned()]
            },
            restart_recommended: false,
        }
    }

    #[test]
    fn formats_size_and_date() {
        assert_eq!(format_size(3_563_520), "3.4 MB");
        assert_eq!(format_unix_date(1_778_544_000), "2026-05-12");
    }

    #[test]
    fn page_model_shows_not_installed_rows() {
        let summary = sample_summary(false);
        let model = build_geodata_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            Some(&summary),
            &GeoDataUiState::Idle,
            false,
        );
        assert_eq!(model.page_state, GeoDataPageState::DiscoveryRequired);
        assert_eq!(model.rows[1].status, "Not installed");
    }

    #[test]
    fn page_model_ready_when_discovered() {
        use crate::init::ServiceState;
        use crate::xray::{ConfigSource, InitSystemKind, XrayInstallation};

        let installation = XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: Some(RemotePath::new("/usr/local/bin/xray").unwrap()),
            version: Some("25.7.1".to_owned()),
            service_name: Some("xray.service".to_owned()),
            service_state: Some(ServiceState::Running),
            exec_start: None,
            config_source: ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        };
        let discovery = DiscoveryState::Succeeded(installation);
        let summary = sample_summary(true);
        let model = build_geodata_page_model(
            SshStatus::Connected,
            &discovery,
            Some(&summary),
            &GeoDataUiState::Idle,
            false,
        );
        assert_eq!(model.page_state, GeoDataPageState::Ready);
        assert!(model.can_update);
        assert_eq!(model.database_count, 2);
        assert_eq!(model.rows[0].status, "Installed");
        assert_eq!(model.rows[0].size, "3.4 MB");
    }
}
