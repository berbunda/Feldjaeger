//! Remote Xray GeoIP / GeoSite database management over SSH.
//!
//! Manages exactly two official Xray-core GeoData databases (`geoip.dat`,
//! `geosite.dat`) on a Linux + systemd host. Downloads always come from the
//! same hardcoded source Xray-core CI uses (Loyalsoldier's `v2ray-rules-dat`
//! release assets) — there is no support for user-supplied URLs, custom
//! repositories, manual file edits, or scheduled updates.
//!
//! Never restarts Xray and never touches `config.json`; callers decide
//! whether/when to restart using [`GeoDataSummary::restart_recommended`].

use feldjaeger_ssh::{ExecResult, RemoteCommand, RemotePath, SshError, SshSession};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::init::ServiceName;
use crate::logging::redact::sanitize_detail;

/// Official download URL for `geoip.dat` (same source Xray-core CI uses).
const GEOIP_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";

/// Official download URL for `geosite.dat` (same source Xray-core CI uses).
const GEOSITE_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";

/// Managed GeoData database file names, in canonical (geoip, geosite) order.
const DATABASE_NAMES: [&str; 2] = ["geoip.dat", "geosite.dat"];

/// Suffix appended to a live database path for the pre-replace rollback copy.
const ROLLBACK_SUFFIX: &str = ".feldjaeger.prev";

/// Asset directory candidates probed (after systemd `Environment`) for an
/// existing `geoip.dat` / `geosite.dat`, in priority order.
const DEFAULT_ASSET_DIR_CANDIDATES: &[&str] = &["/usr/local/share/xray", "/usr/share/xray"];

/// Final fallback asset directory (Xray-core's own compiled-in default).
const DEFAULT_ASSET_DIR: &str = "/usr/local/share/xray";

/// Classifies a failed GeoData discovery/update operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoDataErrorKind {
    /// SSH connection could not be established or was lost.
    SshConnectionFailed,
    /// Downloading a database from the official source failed.
    DownloadFailed,
    /// Downloaded database failed verification (missing / unreadable / empty).
    VerificationFailed,
    /// Remote user lacks permission for a required read/write/exec.
    PermissionDenied,
    /// Backing up an existing live database before replace failed.
    BackupFailed,
    /// A required database file is missing on the remote host.
    DatabaseMissing,
    /// Host/installation is not a supported Xray-on-systemd installation.
    UnsupportedInstallation,
    /// No usable GeoData asset directory could be resolved.
    AssetDirectoryNotFound,
    /// Atomically replacing a live database with the downloaded one failed.
    ReplaceFailed,
    /// Restoring a live database from its rollback copy failed.
    RollbackFailed,
    /// Generic remote command failure.
    CommandFailed,
}

impl GeoDataErrorKind {
    /// Stable user-facing label (no secrets).
    pub fn label(self) -> &'static str {
        match self {
            Self::SshConnectionFailed => "SSH connection failed",
            Self::DownloadFailed => "Download failed",
            Self::VerificationFailed => "Verification failed",
            Self::PermissionDenied => "Permission denied",
            Self::BackupFailed => "Backup failed",
            Self::DatabaseMissing => "Database missing",
            Self::UnsupportedInstallation => "Unsupported installation",
            Self::AssetDirectoryNotFound => "Asset directory not found",
            Self::ReplaceFailed => "Replace failed",
            Self::RollbackFailed => "Rollback failed",
            Self::CommandFailed => "Command failed",
        }
    }
}

/// Error returned by [`GeoDataManager`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataError {
    kind: GeoDataErrorKind,
    detail: String,
}

impl GeoDataError {
    /// Creates an error with a classified kind and safe detail text.
    pub fn new(kind: GeoDataErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Error classification.
    pub fn kind(&self) -> GeoDataErrorKind {
        self.kind
    }

    /// Additional detail safe for UI (no passwords, keys, or secrets).
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Combined message: kind label plus optional detail.
    pub fn message(&self) -> String {
        if self.detail.is_empty() {
            self.kind.label().to_owned()
        } else {
            format!("{}: {}", self.kind.label(), self.detail)
        }
    }
}

impl std::fmt::Display for GeoDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for GeoDataError {}

/// Convenience alias for GeoData results.
pub type GeoDataResult<T> = Result<T, GeoDataError>;

/// Hints from discovery used to resolve the remote GeoData asset directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoDataResolveHints {
    /// Absolute path to the Xray binary, when known.
    pub binary_path: Option<RemotePath>,
    /// systemd unit name for Xray, when known.
    pub service_name: Option<String>,
}

/// Per-database status snapshot on the remote host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataDatabaseSummary {
    /// File name: `geoip.dat` or `geosite.dat`.
    pub name: String,
    /// Whether the file currently exists on the remote host.
    pub installed: bool,
    /// Display version derived from the file's mtime (`YYYY-MM-DD`), when known.
    pub version: Option<String>,
    /// Last-modified time as a Unix timestamp, when known.
    pub modified_unix: Option<u64>,
    /// File size in bytes, when known.
    pub size_bytes: Option<u64>,
}

/// Outcome of a discovery or update pass over the remote GeoData databases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDataSummary {
    /// Resolved asset directory, when it could be determined.
    pub installation_path: Option<RemotePath>,
    /// Status of each managed database, in `geoip.dat`, `geosite.dat` order.
    pub databases: Vec<GeoDataDatabaseSummary>,
    /// Non-fatal findings safe for UI display (no secrets).
    pub warnings: Vec<String>,
    /// `true` once an update has succeeded — callers may prompt for a restart.
    pub restart_recommended: bool,
}

/// Manages the two official Xray GeoData databases over an SSH session.
///
/// Only the hardcoded official download source is ever used; there are no
/// user-configurable URLs, custom repositories, or scheduled-update fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct GeoDataManager;

impl GeoDataManager {
    /// Creates a new manager.
    pub fn new() -> Self {
        Self
    }

    /// Reads current installed/missing status for both GeoData databases.
    ///
    /// Read-only: never writes, downloads, or restarts anything. A missing
    /// database is reported (not fatal) via `installed = false` plus a warning.
    pub async fn discover<S: SshSession + Sync>(
        &self,
        session: &S,
        hints: &GeoDataResolveHints,
    ) -> GeoDataResult<GeoDataSummary> {
        let asset_dir = self.resolve_asset_dir(session, hints).await?;

        let mut databases = Vec::with_capacity(DATABASE_NAMES.len());
        let mut warnings = Vec::new();

        for name in DATABASE_NAMES {
            let path = join_asset_path(&asset_dir, name)?;
            let probe = probe_database(session, &path).await?;

            if !probe.installed {
                warn!(target: "xray", database = name, "GeoData database missing");
                warnings.push(format!("GeoData database missing: {name}"));
            }

            databases.push(GeoDataDatabaseSummary {
                name: name.to_owned(),
                installed: probe.installed,
                version: probe.version,
                modified_unix: probe.modified_unix,
                size_bytes: probe.size_bytes,
            });
        }

        Ok(GeoDataSummary {
            installation_path: Some(asset_dir),
            databases,
            warnings,
            restart_recommended: false,
        })
    }

    /// Downloads both official GeoData databases and atomically replaces the
    /// live copies, backing each one up first.
    ///
    /// Never restarts Xray and never touches `config.json`. On any failure
    /// after a live file has been replaced, the previous content is restored
    /// from its `.feldjaeger.prev` rollback copy.
    pub async fn update<S: SshSession + Sync>(
        &self,
        session: &S,
        hints: &GeoDataResolveHints,
    ) -> GeoDataResult<GeoDataSummary> {
        info!(target: "xray", "GeoData update started");

        let asset_dir = self.resolve_asset_dir(session, hints).await?;

        match self.run_update(session, &asset_dir).await {
            Ok(()) => {
                info!(target: "xray", "GeoData updated successfully");
                let mut summary = self.discover(session, hints).await?;
                summary.restart_recommended = true;
                Ok(summary)
            }
            Err(error) => {
                error!(
                    target: "xray",
                    detail = %sanitize_detail(&error.detail),
                    "GeoData update failed"
                );
                Err(error)
            }
        }
    }

    async fn run_update<S: SshSession + Sync>(
        &self,
        session: &S,
        asset_dir: &RemotePath,
    ) -> GeoDataResult<()> {
        let mut plans: Vec<DatabasePlan> = Vec::with_capacity(DATABASE_NAMES.len());

        for name in DATABASE_NAMES {
            if let Err(error) = self.download_and_verify(session, asset_dir, name, &mut plans).await {
                cleanup_temp_files(session, &plans).await;
                return Err(error);
            }
        }

        for plan in plans.iter_mut() {
            if plan.had_existing {
                match backup_live_file(session, &plan.live_path, &plan.backup_path).await {
                    Ok(()) => plan.backed_up = true,
                    Err(error) => {
                        cleanup_temp_files(session, &plans).await;
                        return Err(error);
                    }
                }
            }
        }

        for index in 0..plans.len() {
            let write_result = session
                .write_file_atomic(&plans[index].live_path, &plans[index].downloaded)
                .await;

            match write_result {
                Ok(()) => plans[index].replaced = true,
                Err(error) => {
                    let rollback_outcome = rollback(session, &plans).await;
                    cleanup_temp_files(session, &plans).await;
                    rollback_outcome?;
                    return Err(GeoDataError::new(
                        GeoDataErrorKind::ReplaceFailed,
                        sanitize_detail(error.message()),
                    ));
                }
            }
        }

        cleanup_temp_files(session, &plans).await;
        Ok(())
    }

    async fn download_and_verify<S: SshSession + Sync>(
        &self,
        session: &S,
        asset_dir: &RemotePath,
        name: &'static str,
        plans: &mut Vec<DatabasePlan>,
    ) -> GeoDataResult<()> {
        let live_path = join_asset_path(asset_dir, name)?;
        let temp_path = join_asset_path(asset_dir, &format!("{name}.{}.tmp", Uuid::new_v4()))?;

        if let Err(error) = download_file(session, &temp_path, url_for(name)).await {
            let _ = session.remove_file(&temp_path).await;
            return Err(error);
        }

        let downloaded = match verify_download(session, &temp_path).await {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = session.remove_file(&temp_path).await;
                return Err(error);
            }
        };

        let had_existing = match remote_path_is_file(session, live_path.as_str()).await {
            Ok(value) => value,
            Err(error) => {
                let _ = session.remove_file(&temp_path).await;
                return Err(error);
            }
        };

        let backup_path = RemotePath::new(format!("{}{ROLLBACK_SUFFIX}", live_path.as_str()))
            .map_err(|error| GeoDataError::new(GeoDataErrorKind::CommandFailed, error.message()))?;

        plans.push(DatabasePlan {
            name,
            live_path,
            temp_path,
            downloaded,
            had_existing,
            backup_path,
            backed_up: false,
            replaced: false,
        });

        Ok(())
    }

    /// Resolves the remote GeoData asset directory using, in order:
    /// 1. systemd unit `Environment` (`XRAY_LOCATION_ASSET` / `xray.location.asset`)
    /// 2. A well-known directory that already contains one of the databases
    /// 3. The Xray binary's parent directory
    /// 4. The Xray-core compiled-in default (`/usr/local/share/xray`)
    async fn resolve_asset_dir<S: SshSession + Sync>(
        &self,
        session: &S,
        hints: &GeoDataResolveHints,
    ) -> GeoDataResult<RemotePath> {
        if hints.binary_path.is_none() && hints.service_name.is_none() {
            return Err(GeoDataError::new(
                GeoDataErrorKind::UnsupportedInstallation,
                "no Xray installation hints available (binary path or service name required)",
            ));
        }

        if let Some(service_name) = &hints.service_name
            && let Some(dir) = self.query_environment_asset_dir(session, service_name).await?
            && let Ok(path) = RemotePath::new(dir)
            && remote_path_is_dir(session, path.as_str()).await?
        {
            info!(
                target: "xray",
                asset_dir = %path.as_str(),
                "resolved GeoData asset directory from systemd Environment"
            );
            return Ok(path);
        }

        let mut candidates: Vec<String> = Vec::new();
        if let Some(binary) = &hints.binary_path
            && let Some(parent) = parent_dir_str(binary.as_str())
        {
            candidates.push(parent.to_owned());
        }
        for default in DEFAULT_ASSET_DIR_CANDIDATES {
            candidates.push((*default).to_owned());
        }

        for candidate in &candidates {
            let geoip = format!("{}/geoip.dat", candidate.trim_end_matches('/'));
            let geosite = format!("{}/geosite.dat", candidate.trim_end_matches('/'));
            if remote_path_is_file(session, &geoip).await? || remote_path_is_file(session, &geosite).await? {
                return RemotePath::new(candidate.clone()).map_err(|error| {
                    GeoDataError::new(GeoDataErrorKind::CommandFailed, error.message())
                });
            }
        }

        if let Some(binary) = &hints.binary_path
            && let Some(parent) = parent_dir_str(binary.as_str())
            && remote_path_is_dir(session, parent).await?
        {
            return RemotePath::new(parent.to_owned())
                .map_err(|error| GeoDataError::new(GeoDataErrorKind::CommandFailed, error.message()));
        }

        if remote_path_is_dir(session, DEFAULT_ASSET_DIR).await? {
            return RemotePath::new(DEFAULT_ASSET_DIR)
                .map_err(|error| GeoDataError::new(GeoDataErrorKind::CommandFailed, error.message()));
        }

        Err(GeoDataError::new(
            GeoDataErrorKind::AssetDirectoryNotFound,
            "could not resolve a GeoData asset directory on the remote host",
        ))
    }

    async fn query_environment_asset_dir<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> GeoDataResult<Option<String>> {
        let service = ServiceName::new(service_name)
            .map_err(|error| GeoDataError::new(GeoDataErrorKind::CommandFailed, error.message()))?;

        let result = run_remote(
            session,
            "systemctl",
            vec![
                "show".to_owned(),
                "--property=Environment".to_owned(),
                "--value".to_owned(),
                "--".to_owned(),
                service.as_str().to_owned(),
            ],
        )
        .await?;

        if result.exit_code != 0 {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&result.stdout);
        Ok(parse_asset_dir_from_environment(&stdout))
    }
}

struct DatabasePlan {
    name: &'static str,
    live_path: RemotePath,
    temp_path: RemotePath,
    downloaded: Vec<u8>,
    had_existing: bool,
    backup_path: RemotePath,
    backed_up: bool,
    replaced: bool,
}

struct DatabaseProbe {
    installed: bool,
    version: Option<String>,
    modified_unix: Option<u64>,
    size_bytes: Option<u64>,
}

async fn probe_database<S: SshSession + Sync>(
    session: &S,
    path: &RemotePath,
) -> GeoDataResult<DatabaseProbe> {
    if !remote_path_is_file(session, path.as_str()).await? {
        return Ok(DatabaseProbe {
            installed: false,
            version: None,
            modified_unix: None,
            size_bytes: None,
        });
    }

    let stat = stat_size_and_mtime(session, path.as_str()).await?;
    let (size_bytes, modified_unix) = match stat {
        Some((size, mtime)) => (Some(size), Some(mtime)),
        None => (None, None),
    };
    let version = modified_unix.and_then(format_mtime_date);

    Ok(DatabaseProbe {
        installed: true,
        version,
        modified_unix,
        size_bytes,
    })
}

async fn download_file<S: SshSession + Sync>(
    session: &S,
    temp_path: &RemotePath,
    url: &str,
) -> GeoDataResult<()> {
    let result = run_remote(
        session,
        "curl",
        vec![
            "-L".to_owned(),
            "-f".to_owned(),
            "-o".to_owned(),
            temp_path.as_str().to_owned(),
            url.to_owned(),
        ],
    )
    .await?;

    if result.exit_code != 0 {
        return Err(GeoDataError::new(
            GeoDataErrorKind::DownloadFailed,
            format!(
                "curl exited with code {}: {}",
                result.exit_code,
                sanitize_detail(&String::from_utf8_lossy(&result.stderr))
            ),
        ));
    }

    Ok(())
}

async fn verify_download<S: SshSession + Sync>(
    session: &S,
    temp_path: &RemotePath,
) -> GeoDataResult<Vec<u8>> {
    if !remote_path_is_file(session, temp_path.as_str()).await? {
        return Err(GeoDataError::new(
            GeoDataErrorKind::VerificationFailed,
            "downloaded GeoData database does not exist",
        ));
    }

    let bytes = session.read_file(temp_path).await.map_err(|error| {
        GeoDataError::new(GeoDataErrorKind::VerificationFailed, sanitize_detail(error.message()))
    })?;

    if bytes.is_empty() {
        return Err(GeoDataError::new(
            GeoDataErrorKind::VerificationFailed,
            "downloaded GeoData database is empty",
        ));
    }

    Ok(bytes)
}

async fn backup_live_file<S: SshSession + Sync>(
    session: &S,
    live_path: &RemotePath,
    backup_path: &RemotePath,
) -> GeoDataResult<()> {
    let contents = session.read_file(live_path).await.map_err(|error| {
        GeoDataError::new(GeoDataErrorKind::BackupFailed, sanitize_detail(error.message()))
    })?;

    session
        .write_file(backup_path, &contents)
        .await
        .map_err(|error| {
            GeoDataError::new(GeoDataErrorKind::BackupFailed, sanitize_detail(error.message()))
        })
}

async fn rollback<S: SshSession + Sync>(session: &S, plans: &[DatabasePlan]) -> GeoDataResult<()> {
    for plan in plans {
        if !plan.replaced {
            continue;
        }

        if plan.had_existing && plan.backed_up {
            let contents = session.read_file(&plan.backup_path).await.map_err(|error| {
                GeoDataError::new(GeoDataErrorKind::RollbackFailed, sanitize_detail(error.message()))
            })?;
            session
                .write_file_atomic(&plan.live_path, &contents)
                .await
                .map_err(|error| {
                    GeoDataError::new(GeoDataErrorKind::RollbackFailed, sanitize_detail(error.message()))
                })?;
        } else if !plan.had_existing {
            session.remove_file(&plan.live_path).await.map_err(|error| {
                GeoDataError::new(GeoDataErrorKind::RollbackFailed, sanitize_detail(error.message()))
            })?;
        }
    }

    Ok(())
}

async fn cleanup_temp_files<S: SshSession + Sync>(session: &S, plans: &[DatabasePlan]) {
    for plan in plans {
        if let Err(error) = session.remove_file(&plan.temp_path).await {
            warn!(
                target: "xray",
                database = plan.name,
                detail = %sanitize_detail(error.message()),
                "failed to remove temporary GeoData download"
            );
        }
    }
}

async fn remote_path_is_file<S: SshSession + Sync>(session: &S, path: &str) -> GeoDataResult<bool> {
    let result = run_remote(session, "test", vec!["-f".to_owned(), path.to_owned()]).await?;
    Ok(result.exit_code == 0)
}

async fn remote_path_is_dir<S: SshSession + Sync>(session: &S, path: &str) -> GeoDataResult<bool> {
    let result = run_remote(session, "test", vec!["-d".to_owned(), path.to_owned()]).await?;
    Ok(result.exit_code == 0)
}

async fn stat_size_and_mtime<S: SshSession + Sync>(
    session: &S,
    path: &str,
) -> GeoDataResult<Option<(u64, u64)>> {
    let result = run_remote(
        session,
        "stat",
        vec!["-c".to_owned(), "%s %Y".to_owned(), path.to_owned()],
    )
    .await?;

    if result.exit_code != 0 {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&result.stdout);
    let mut parts = stdout.split_whitespace();
    let size = parts.next().and_then(|value| value.parse::<u64>().ok());
    let mtime = parts.next().and_then(|value| value.parse::<u64>().ok());
    Ok(size.zip(mtime))
}

async fn run_remote<S: SshSession + Sync>(
    session: &S,
    program: &str,
    args: Vec<String>,
) -> GeoDataResult<ExecResult> {
    let command = RemoteCommand::new(program, args)
        .map_err(|error| GeoDataError::new(GeoDataErrorKind::CommandFailed, error.message()))?;

    session.exec(&command).await.map_err(classify_exec_error)
}

fn classify_exec_error(error: SshError) -> GeoDataError {
    let message = sanitize_detail(error.message());
    let lower = message.to_ascii_lowercase();
    let kind = if lower.contains("permission denied") || lower.contains("access denied") {
        GeoDataErrorKind::PermissionDenied
    } else if lower.contains("connection")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("broken pipe")
    {
        GeoDataErrorKind::SshConnectionFailed
    } else {
        GeoDataErrorKind::CommandFailed
    };
    GeoDataError::new(kind, message)
}

fn url_for(name: &str) -> &'static str {
    match name {
        "geoip.dat" => GEOIP_URL,
        "geosite.dat" => GEOSITE_URL,
        other => unreachable!("unknown GeoData database name: {other}"),
    }
}

fn join_asset_path(dir: &RemotePath, file_name: &str) -> GeoDataResult<RemotePath> {
    let dir_str = dir.as_str().trim_end_matches('/');
    let joined = format!("{dir_str}/{file_name}");
    RemotePath::new(joined).map_err(|error| GeoDataError::new(GeoDataErrorKind::CommandFailed, error.message()))
}

fn parent_dir_str(path: &str) -> Option<&str> {
    let (parent, file_name) = path.rsplit_once('/')?;
    if file_name.is_empty() {
        return None;
    }
    if parent.is_empty() {
        Some("/")
    } else {
        Some(parent)
    }
}

fn format_mtime_date(modified_unix: u64) -> Option<String> {
    let secs = i64::try_from(modified_unix).ok()?;
    let datetime = chrono::DateTime::from_timestamp(secs, 0)?;
    Some(datetime.format("%Y-%m-%d").to_string())
}

/// Parses a GeoData asset directory from `systemctl show --property=Environment`
/// output (with or without the leading `Environment=` prefix).
///
/// Recognizes `XRAY_LOCATION_ASSET` and `xray.location.asset` (case-insensitive).
pub fn parse_asset_dir_from_environment(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let line = line.strip_prefix("Environment=").unwrap_or(line);
        if let Some(value) = find_asset_dir_in_tokens(line) {
            return Some(value);
        }
    }
    None
}

fn find_asset_dir_in_tokens(line: &str) -> Option<String> {
    for token in split_whitespace_respecting_quotes(line) {
        let (key, value) = token.split_once('=')?;
        if key.eq_ignore_ascii_case("XRAY_LOCATION_ASSET") || key.eq_ignore_ascii_case("xray.location.asset") {
            let value = value.trim_matches('"');
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn split_whitespace_respecting_quotes(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use feldjaeger_ssh::{ConnectionProfile, ExecResult, SshResult};
    use std::collections::HashMap;
    use std::future;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockSession {
        profile: ConnectionProfile,
        exec_results: Arc<Mutex<HashMap<String, ExecResult>>>,
        exec_errors: Arc<Mutex<HashMap<String, String>>>,
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        dirs: Arc<Mutex<std::collections::HashSet<String>>>,
        mtimes: Arc<Mutex<HashMap<String, u64>>>,
        exec_calls: Arc<Mutex<Vec<RemoteCommand>>>,
        write_calls: Arc<Mutex<Vec<String>>>,
    }

    impl MockSession {
        fn new() -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "root"),
                exec_results: Arc::new(Mutex::new(HashMap::new())),
                exec_errors: Arc::new(Mutex::new(HashMap::new())),
                files: Arc::new(Mutex::new(HashMap::new())),
                dirs: Arc::new(Mutex::new(std::collections::HashSet::new())),
                mtimes: Arc::new(Mutex::new(HashMap::new())),
                exec_calls: Arc::new(Mutex::new(Vec::new())),
                write_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn with_exec(self, key: impl Into<String>, result: ExecResult) -> Self {
            self.exec_results.lock().unwrap().insert(key.into(), result);
            self
        }

        /// Registers an exec-level SSH failure. `key` may be an exact
        /// `"<program> <args...>"` string or just a bare program name (matches
        /// any invocation of that program, useful when arguments contain a
        /// randomly generated temp path).
        fn with_exec_error(self, key: impl Into<String>, message: impl Into<String>) -> Self {
            self.exec_errors.lock().unwrap().insert(key.into(), message.into());
            self
        }

        fn with_file(self, path: impl Into<String>, contents: Vec<u8>) -> Self {
            self.files.lock().unwrap().insert(path.into(), contents);
            self
        }

        fn with_dir(self, path: impl Into<String>) -> Self {
            self.dirs.lock().unwrap().insert(path.into());
            self
        }

        fn with_mtime(self, path: impl Into<String>, unix: u64) -> Self {
            self.mtimes.lock().unwrap().insert(path.into(), unix);
            self
        }

        fn write_calls(&self) -> Vec<String> {
            self.write_calls.lock().unwrap().clone()
        }

        fn file(&self, path: &str) -> Option<Vec<u8>> {
            self.files.lock().unwrap().get(path).cloned()
        }
    }

    fn exec_key(command: &RemoteCommand) -> String {
        let args = command.args().join(" ");
        format!("{} {args}", command.program())
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        fn read_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<Vec<u8>>> + Send {
            let contents = self.files.lock().unwrap().get(path.as_str()).cloned();
            future::ready(match contents {
                Some(bytes) => Ok(bytes),
                None => Err(SshError::new(format!("file not found: {}", path.as_str()))),
            })
        }

        fn write_file(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = SshResult<()>> + Send {
            self.write_calls.lock().unwrap().push(path.as_str().to_owned());
            self.files
                .lock()
                .unwrap()
                .insert(path.as_str().to_owned(), contents.to_vec());
            future::ready(Ok(()))
        }

        fn write_file_atomic(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = SshResult<()>> + Send {
            self.write_file(path, contents)
        }

        fn rename_file(
            &self,
            from: &RemotePath,
            to: &RemotePath,
        ) -> impl Future<Output = SshResult<()>> + Send {
            let mut files = self.files.lock().unwrap();
            let contents = files.remove(from.as_str());
            future::ready(match contents {
                Some(bytes) => {
                    files.insert(to.as_str().to_owned(), bytes);
                    Ok(())
                }
                None => Err(SshError::new(format!("file not found: {}", from.as_str()))),
            })
        }

        fn remove_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<()>> + Send {
            self.files.lock().unwrap().remove(path.as_str());
            future::ready(Ok(()))
        }

        fn path_is_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = SshResult<bool>> + Send {
            let is_file = self.files.lock().unwrap().contains_key(path.as_str());
            future::ready(Ok(is_file))
        }

        fn exec(
            &self,
            command: &RemoteCommand,
        ) -> impl Future<Output = SshResult<ExecResult>> + Send {
            self.exec_calls.lock().unwrap().push(command.clone());

            let key = exec_key(command);
            let error_message = {
                let errors = self.exec_errors.lock().unwrap();
                errors
                    .get(&key)
                    .or_else(|| errors.get(command.program()))
                    .cloned()
            };
            if let Some(message) = error_message {
                return future::ready(Err(SshError::new(message)));
            }

            // Explicit overrides take priority over generic filesystem simulation.
            let override_result = self.exec_results.lock().unwrap().get(&key).cloned();
            if let Some(result) = override_result {
                return future::ready(Ok(result));
            }

            let result = simulate(self, command);
            future::ready(Ok(result))
        }

    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
        let _ = stdin;
        self.exec(command)
    }

        fn disconnect(self) -> impl Future<Output = SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    fn simulate(session: &MockSession, command: &RemoteCommand) -> ExecResult {
        match command.program() {
            "test" => {
                let flag = command.args().first().map(String::as_str).unwrap_or("");
                let path = command.args().get(1).map(String::as_str).unwrap_or("");
                let exists = match flag {
                    "-f" => session.files.lock().unwrap().contains_key(path),
                    "-d" => session.dirs.lock().unwrap().contains(path),
                    _ => false,
                };
                ExecResult::new(Vec::new(), Vec::new(), if exists { 0 } else { 1 })
            }
            "stat" => {
                let path = command.args().get(2).map(String::as_str).unwrap_or("");
                let files = session.files.lock().unwrap();
                match files.get(path) {
                    Some(bytes) => {
                        let mtime = session.mtimes.lock().unwrap().get(path).copied().unwrap_or(0);
                        ExecResult::new(format!("{} {mtime}", bytes.len()).into_bytes(), Vec::new(), 0)
                    }
                    None => ExecResult::new(Vec::new(), b"no such file".to_vec(), 1),
                }
            }
            "curl" => {
                let url = command.args().last().map(String::as_str).unwrap_or("");
                let out_index = command.args().iter().position(|a| a == "-o");
                let out_path = out_index
                    .and_then(|idx| command.args().get(idx + 1))
                    .map(String::as_str)
                    .unwrap_or("");
                let payload = session
                    .files
                    .lock()
                    .unwrap()
                    .get(&format!("__download__:{url}"))
                    .cloned()
                    .unwrap_or_else(|| b"downloaded-bytes".to_vec());
                session
                    .files
                    .lock()
                    .unwrap()
                    .insert(out_path.to_owned(), payload);
                ExecResult::new(Vec::new(), Vec::new(), 0)
            }
            "systemctl" => ExecResult::new(Vec::new(), Vec::new(), 1),
            _ => ExecResult::new(Vec::new(), format!("no mock for {}", command.program()).into_bytes(), 1),
        }
    }

    trait DownloadFixture {
        fn with_download(self, url: &str, bytes: Vec<u8>) -> Self;
    }

    impl DownloadFixture for MockSession {
        fn with_download(self, url: &str, bytes: Vec<u8>) -> Self {
            self.with_file(format!("__download__:{url}"), bytes)
        }
    }

    fn hints_with_binary() -> GeoDataResolveHints {
        GeoDataResolveHints {
            binary_path: Some(RemotePath::new("/usr/local/bin/xray").unwrap()),
            service_name: Some("xray.service".to_owned()),
        }
    }

    // ---- discover -----------------------------------------------------

    #[tokio::test]
    async fn discover_neither_installed() {
        let session = MockSession::new().with_dir("/usr/local/bin");
        let manager = GeoDataManager::new();
        let summary = manager
            .discover(&session, &hints_with_binary())
            .await
            .expect("discover should succeed");

        assert_eq!(summary.databases.len(), 2);
        assert!(summary.databases.iter().all(|d| !d.installed));
        assert!(summary.databases.iter().all(|d| d.version.is_none()));
        assert_eq!(summary.warnings.len(), 2);
        assert!(!summary.restart_recommended);
    }

    #[tokio::test]
    async fn discover_only_geoip_installed() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_file("/usr/local/bin/geoip.dat", b"geoip-bytes".to_vec())
            .with_mtime("/usr/local/bin/geoip.dat", 1_700_000_000);
        let manager = GeoDataManager::new();
        let summary = manager
            .discover(&session, &hints_with_binary())
            .await
            .expect("discover should succeed");

        let geoip = summary.databases.iter().find(|d| d.name == "geoip.dat").unwrap();
        let geosite = summary.databases.iter().find(|d| d.name == "geosite.dat").unwrap();
        assert!(geoip.installed);
        assert_eq!(geoip.size_bytes, Some(11));
        assert_eq!(geoip.version.as_deref(), Some("2023-11-14"));
        assert!(!geosite.installed);
        assert_eq!(summary.warnings.len(), 1);
    }

    #[tokio::test]
    async fn discover_only_geosite_installed() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_file("/usr/local/bin/geosite.dat", b"geosite-bytes".to_vec())
            .with_mtime("/usr/local/bin/geosite.dat", 1_700_000_000);
        let manager = GeoDataManager::new();
        let summary = manager
            .discover(&session, &hints_with_binary())
            .await
            .expect("discover should succeed");

        let geoip = summary.databases.iter().find(|d| d.name == "geoip.dat").unwrap();
        let geosite = summary.databases.iter().find(|d| d.name == "geosite.dat").unwrap();
        assert!(!geoip.installed);
        assert!(geosite.installed);
        assert_eq!(geosite.size_bytes, Some(13));
    }

    #[tokio::test]
    async fn discover_both_installed() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_file("/usr/local/bin/geoip.dat", b"geoip-bytes".to_vec())
            .with_mtime("/usr/local/bin/geoip.dat", 1_700_000_000)
            .with_file("/usr/local/bin/geosite.dat", b"geosite-bytes-longer".to_vec())
            .with_mtime("/usr/local/bin/geosite.dat", 1_700_086_400);
        let manager = GeoDataManager::new();
        let summary = manager
            .discover(&session, &hints_with_binary())
            .await
            .expect("discover should succeed");

        assert!(summary.databases.iter().all(|d| d.installed));
        assert!(summary.warnings.is_empty());
        assert_eq!(summary.databases[0].name, "geoip.dat");
        assert_eq!(summary.databases[1].name, "geosite.dat");
        assert_eq!(
            summary.installation_path.as_ref().map(RemotePath::as_str),
            Some("/usr/local/bin")
        );
    }

    #[tokio::test]
    async fn discover_refresh_reflects_new_state() {
        let session = MockSession::new().with_dir("/usr/local/bin");
        let manager = GeoDataManager::new();

        let first = manager
            .discover(&session, &hints_with_binary())
            .await
            .expect("first discover should succeed");
        assert!(first.databases.iter().all(|d| !d.installed));

        session
            .files
            .lock()
            .unwrap()
            .insert("/usr/local/bin/geoip.dat".to_owned(), b"now-present".to_vec());

        let second = manager
            .discover(&session, &hints_with_binary())
            .await
            .expect("second discover should succeed");
        let geoip = second.databases.iter().find(|d| d.name == "geoip.dat").unwrap();
        assert!(geoip.installed);
    }

    // ---- asset directory resolution -----------------------------------

    #[tokio::test]
    async fn resolve_uses_systemd_environment_asset_dir() {
        let session = MockSession::new()
            .with_dir("/opt/xray-assets")
            .with_exec(
                "systemctl show --property=Environment --value -- xray.service",
                ExecResult::new(b"XRAY_LOCATION_ASSET=/opt/xray-assets\n".to_vec(), Vec::new(), 0),
            );
        let manager = GeoDataManager::new();
        let summary = manager
            .discover(&session, &hints_with_binary())
            .await
            .expect("discover should succeed");

        assert_eq!(
            summary.installation_path.as_ref().map(RemotePath::as_str),
            Some("/opt/xray-assets")
        );
    }

    #[tokio::test]
    async fn resolve_fails_without_any_hints() {
        let session = MockSession::new();
        let manager = GeoDataManager::new();
        let error = manager
            .discover(&session, &GeoDataResolveHints::default())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), GeoDataErrorKind::UnsupportedInstallation);
    }

    #[test]
    fn parse_asset_dir_from_environment_finds_xray_location_asset() {
        let dir = parse_asset_dir_from_environment("XRAY_LOCATION_ASSET=/usr/local/share/xray OTHER=1\n");
        assert_eq!(dir, Some("/usr/local/share/xray".to_owned()));
    }

    #[test]
    fn parse_asset_dir_from_environment_handles_property_prefix_and_dotted_key() {
        let dir = parse_asset_dir_from_environment("Environment=xray.location.asset=/srv/xray-geo\n");
        assert_eq!(dir, Some("/srv/xray-geo".to_owned()));
    }

    #[test]
    fn parse_asset_dir_from_environment_returns_none_when_absent() {
        assert_eq!(parse_asset_dir_from_environment("FOO=bar BAZ=qux\n"), None);
        assert_eq!(parse_asset_dir_from_environment(""), None);
    }

    // ---- update ---------------------------------------------------------

    #[tokio::test]
    async fn update_downloads_backs_up_and_replaces_both_files() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_file("/usr/local/bin/geoip.dat", b"old-geoip".to_vec())
            .with_file("/usr/local/bin/geosite.dat", b"old-geosite".to_vec())
            .with_download(GEOIP_URL, b"new-geoip-bytes".to_vec())
            .with_download(GEOSITE_URL, b"new-geosite-bytes".to_vec());
        let manager = GeoDataManager::new();

        let summary = manager
            .update(&session, &hints_with_binary())
            .await
            .expect("update should succeed");

        assert!(summary.restart_recommended);
        assert!(summary.databases.iter().all(|d| d.installed));

        assert_eq!(session.file("/usr/local/bin/geoip.dat"), Some(b"new-geoip-bytes".to_vec()));
        assert_eq!(
            session.file("/usr/local/bin/geosite.dat"),
            Some(b"new-geosite-bytes".to_vec())
        );
        assert_eq!(session.file("/usr/local/bin/geoip.dat.feldjaeger.prev"), Some(b"old-geoip".to_vec()));
        assert_eq!(
            session.file("/usr/local/bin/geosite.dat.feldjaeger.prev"),
            Some(b"old-geosite".to_vec())
        );

        // The only systemctl call allowed is the read-only Environment lookup —
        // no restart/start/stop/reload action is ever issued.
        for call in session.exec_calls.lock().unwrap().iter() {
            if call.program() == "systemctl" {
                assert_eq!(call.args().first().map(String::as_str), Some("show"));
            }
        }
    }

    #[tokio::test]
    async fn update_first_install_has_no_prior_backup() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_download(GEOIP_URL, b"new-geoip-bytes".to_vec())
            .with_download(GEOSITE_URL, b"new-geosite-bytes".to_vec());
        let manager = GeoDataManager::new();

        let summary = manager
            .update(&session, &hints_with_binary())
            .await
            .expect("update should succeed");

        assert!(summary.restart_recommended);
        assert!(session.file("/usr/local/bin/geoip.dat.feldjaeger.prev").is_none());
        assert!(session.file("/usr/local/bin/geosite.dat.feldjaeger.prev").is_none());
    }

    #[tokio::test]
    async fn update_aborts_when_backup_fails() {
        // The live geoip.dat exists (so `test -f` succeeds and a backup is
        // attempted) but reading it for the backup copy fails with a
        // permission error, forced via the `BackupFailSession` wrapper below.
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_file("/usr/local/bin/geoip.dat", b"old-geoip".to_vec())
            .with_download(GEOIP_URL, b"new-geoip-bytes".to_vec())
            .with_download(GEOSITE_URL, b"new-geosite-bytes".to_vec());
        let session = BackupFailSession { inner: session };

        let manager = GeoDataManager::new();
        let error = manager
            .update(&session, &hints_with_binary())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), GeoDataErrorKind::BackupFailed);
        // Nothing should have been replaced — the live file is unchanged.
        assert_eq!(
            session.inner.file("/usr/local/bin/geoip.dat"),
            Some(b"old-geoip".to_vec())
        );
        assert!(session.inner.file("/usr/local/bin/geosite.dat").is_none());
    }

    /// Wraps [`MockSession`] to force `read_file` failures for the live
    /// `geoip.dat` path only (simulating a permission/backup failure) while
    /// leaving every other operation delegated to the inner mock.
    #[derive(Clone)]
    struct BackupFailSession {
        inner: MockSession,
    }

    impl SshSession for BackupFailSession {
        fn profile(&self) -> &ConnectionProfile {
            self.inner.profile()
        }

        fn read_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<Vec<u8>>> + Send {
            if path.as_str() == "/usr/local/bin/geoip.dat" {
                return future::ready(Err(SshError::new("Permission denied")));
            }
            let contents = self.inner.files.lock().unwrap().get(path.as_str()).cloned();
            future::ready(match contents {
                Some(bytes) => Ok(bytes),
                None => Err(SshError::new(format!("file not found: {}", path.as_str()))),
            })
        }

        fn write_file(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = SshResult<()>> + Send {
            self.inner.write_file(path, contents)
        }

        fn write_file_atomic(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = SshResult<()>> + Send {
            self.inner.write_file_atomic(path, contents)
        }

        fn rename_file(
            &self,
            from: &RemotePath,
            to: &RemotePath,
        ) -> impl Future<Output = SshResult<()>> + Send {
            self.inner.rename_file(from, to)
        }

        fn remove_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<()>> + Send {
            self.inner.remove_file(path)
        }

        fn path_is_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = SshResult<bool>> + Send {
            self.inner.path_is_file(path)
        }

        fn exec(
            &self,
            command: &RemoteCommand,
        ) -> impl Future<Output = SshResult<ExecResult>> + Send {
            self.inner.exec(command)
        }


    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl std::future::Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
        let _ = stdin;
        self.exec(command)
    }

        fn disconnect(self) -> impl Future<Output = SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn update_fails_verification_on_empty_download() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_download(GEOIP_URL, Vec::new())
            .with_download(GEOSITE_URL, b"new-geosite-bytes".to_vec());
        let manager = GeoDataManager::new();

        let error = manager
            .update(&session, &hints_with_binary())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), GeoDataErrorKind::VerificationFailed);
        assert!(session.file("/usr/local/bin/geoip.dat").is_none());
        assert!(session.file("/usr/local/bin/geosite.dat").is_none());
    }

    #[tokio::test]
    async fn update_classifies_permission_denied() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_exec_error("curl", "Permission denied");
        let manager = GeoDataManager::new();

        let error = manager
            .update(&session, &hints_with_binary())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), GeoDataErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn update_classifies_ssh_connection_failure() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_exec_error("curl", "connection reset by peer");
        let manager = GeoDataManager::new();

        let error = manager
            .update(&session, &hints_with_binary())
            .await
            .unwrap_err();

        assert_eq!(error.kind(), GeoDataErrorKind::SshConnectionFailed);
    }

    #[tokio::test]
    async fn update_never_touches_config_json() {
        let session = MockSession::new()
            .with_dir("/usr/local/bin")
            .with_file("/usr/local/etc/xray/config.json", b"{}".to_vec())
            .with_download(GEOIP_URL, b"new-geoip-bytes".to_vec())
            .with_download(GEOSITE_URL, b"new-geosite-bytes".to_vec());
        let manager = GeoDataManager::new();

        manager
            .update(&session, &hints_with_binary())
            .await
            .expect("update should succeed");

        assert_eq!(
            session.file("/usr/local/etc/xray/config.json"),
            Some(b"{}".to_vec())
        );
        assert!(
            !session
                .write_calls()
                .iter()
                .any(|p| p.contains("config.json"))
        );
    }

    // ---- error/kind sanity ------------------------------------------

    #[test]
    fn error_message_includes_label_and_detail() {
        let error = GeoDataError::new(GeoDataErrorKind::DownloadFailed, "curl exited with code 22");
        assert_eq!(error.message(), "Download failed: curl exited with code 22");
    }
}
