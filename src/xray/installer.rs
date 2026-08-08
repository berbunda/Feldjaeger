//! Official Xray-install script orchestration over SSH.
//!
//! Downloads and runs the upstream `install-release.sh` as discrete
//! [`RemoteCommand`]s (no nested shell interpolation). Binary lifecycle
//! operations never modify Xray configuration contents.

use feldjaeger_ssh::{ExecResult, RemoteCommand, RemotePath, SshSession};
use tracing::{info, warn};

use crate::init::{InitSystemManager, ServiceName, ServiceState, SystemdManager};
use crate::logging::redact::sanitize_detail;
use crate::remote::BackupManager;
use crate::xray::installation::{InitSystemKind, XrayInstallation};

/// Official Xray-install script URL (raw GitHub).
const INSTALL_SCRIPT_URL: &str =
    "https://github.com/XTLS/Xray-install/raw/main/install-release.sh";

/// GitHub API endpoint for the latest Xray-core release.
const LATEST_RELEASE_API_URL: &str =
    "https://api.github.com/repos/XTLS/Xray-core/releases/latest";

/// GitHub API endpoint for the Xray-core releases list (first page).
const RELEASES_API_URL: &str = "https://api.github.com/repos/XTLS/Xray-core/releases";

/// Default unit name used after a fresh install when discovery has no unit yet.
const DEFAULT_UNIT_NAME: &str = "xray.service";

/// Release channel for official `install-release.sh` (Stable vs `--beta`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InstallChannel {
    /// Latest GitHub release (`releases/latest` / script without `--beta`).
    #[default]
    Stable,
    /// Script `--beta` / `PRE_RELEASE_LATEST` candidate.
    Beta,
}

impl InstallChannel {
    /// Short UI label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Stable => "Stable",
            Self::Beta => "Beta",
        }
    }
}

/// Dual-channel available tags from a Check versions probe (partial success).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AvailableVersions {
    /// Latest stable tag (no leading `v`), when the stable probe succeeded.
    pub stable: Option<String>,
    /// Beta/`--beta` candidate tag (no leading `v`), when found.
    pub beta: Option<String>,
    /// Safe error detail when the stable probe failed.
    pub stable_error: Option<String>,
    /// Safe error detail when the beta probe failed (or arch unsupported).
    pub beta_error: Option<String>,
}

impl AvailableVersions {
    /// Tag for the selected channel, if known.
    pub fn tag_for(&self, channel: InstallChannel) -> Option<&str> {
        match channel {
            InstallChannel::Stable => self.stable.as_deref(),
            InstallChannel::Beta => self.beta.as_deref(),
        }
    }
}

/// Classifies a failed Xray install/update/remove operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerErrorKind {
    /// SSH connection could not be established or was lost.
    SshConnectionFailed,
    /// Downloading the install script or release metadata failed.
    DownloadFailed,
    /// Downloaded script failed verification (empty / not a script).
    VerificationFailed,
    /// Remote user lacks permission to install or manage the service.
    PermissionDenied,
    /// systemd unit could not be created or enabled.
    ServiceCreationFailed,
    /// Service did not reach a running state after install/update.
    ServiceStartFailed,
    /// Mandatory backup before overwrite/remove failed.
    BackupFailed,
    /// Xray is already present; install refuses to overwrite.
    AlreadyInstalled,
    /// Host OS or init system is unsupported.
    UnsupportedSystem,
    /// Generic remote command failure.
    CommandFailed,
}

impl InstallerErrorKind {
    /// Stable user-facing label (no secrets).
    pub fn label(self) -> &'static str {
        match self {
            Self::SshConnectionFailed => "SSH connection failed",
            Self::DownloadFailed => "Download failed",
            Self::VerificationFailed => "Verification failed",
            Self::PermissionDenied => "Permission denied",
            Self::ServiceCreationFailed => "Service creation failed",
            Self::ServiceStartFailed => "Service start failed",
            Self::BackupFailed => "Backup failed",
            Self::AlreadyInstalled => "Installation already exists",
            Self::UnsupportedSystem => "Unsupported system",
            Self::CommandFailed => "Command failed",
        }
    }
}

/// Error returned by [`XrayInstaller`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerError {
    kind: InstallerErrorKind,
    detail: String,
}

impl InstallerError {
    /// Creates an error with a classified kind and safe detail text.
    pub fn new(kind: InstallerErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Error classification.
    pub fn kind(&self) -> InstallerErrorKind {
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

impl std::fmt::Display for InstallerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for InstallerError {}

/// Convenience alias for installer results.
pub type InstallerResult<T> = Result<T, InstallerError>;

/// Orchestrates official Xray install / update / remove over an SSH session.
#[derive(Debug, Clone, Default)]
pub struct XrayInstaller {
    backup: BackupManager,
    init: SystemdManager,
}

impl XrayInstaller {
    /// Creates an installer with default backup and systemd managers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an installer with an explicit backup manager (tests).
    pub fn with_backup(backup: BackupManager) -> Self {
        Self {
            backup,
            init: SystemdManager::new(),
        }
    }

    /// Installs Xray using the official install-release.sh script.
    ///
    /// Refuses when an existing installation is reported (`AlreadyInstalled`).
    /// Requires systemd. `InstallChannel::Beta` passes `--beta` to the script.
    pub async fn install<S: SshSession + Sync>(
        &self,
        session: &S,
        init_system: InitSystemKind,
        already_installed: bool,
        channel: InstallChannel,
    ) -> InstallerResult<()> {
        ensure_supported(init_system)?;
        if already_installed {
            return Err(InstallerError::new(
                InstallerErrorKind::AlreadyInstalled,
                "Xray is already installed.",
            ));
        }

        info!(target: "xray", channel = ?channel, "Starting Xray installation");
        self.run_official_script(session, &install_script_args(channel))
            .await?;
        self.verify_service_running(session, DEFAULT_UNIT_NAME)
            .await?;
        info!(target: "xray", "Xray installation completed");
        Ok(())
    }

    /// Updates an existing Xray installation (official script `install` upgrades in place).
    ///
    /// Backs up binary, unit file, and configuration files first. Does not modify
    /// configuration contents. `InstallChannel::Beta` passes `--beta` to the script.
    pub async fn update<S: SshSession + Sync>(
        &self,
        session: &S,
        installation: &XrayInstallation,
        channel: InstallChannel,
    ) -> InstallerResult<()> {
        ensure_supported(installation.init_system)?;
        if installation.binary_path.is_none() {
            return Err(InstallerError::new(
                InstallerErrorKind::CommandFailed,
                "Xray binary path is unknown; run discovery first.",
            ));
        }

        info!(target: "xray", channel = ?channel, "Starting Xray update");
        self.backup_for_update(session, installation).await?;
        self.run_official_script(session, &install_script_args(channel))
            .await?;

        let unit = installation
            .service_name
            .as_deref()
            .unwrap_or(DEFAULT_UNIT_NAME);
        self.verify_service_running(session, unit).await?;
        info!(target: "xray", "Xray version updated");
        Ok(())
    }

    /// Removes Xray via the official script (`remove`), preserving configuration.
    ///
    /// Backs up the unit file and configuration files first. Never deletes
    /// `/usr/local/etc/xray/` or other config paths.
    pub async fn remove<S: SshSession + Sync>(
        &self,
        session: &S,
        installation: &XrayInstallation,
    ) -> InstallerResult<()> {
        ensure_supported(installation.init_system)?;

        info!(target: "xray", "Starting Xray removal");
        self.backup_for_remove(session, installation).await?;
        self.run_official_script(session, &["remove".to_owned()])
            .await?;
        info!(target: "xray", "Xray removal completed");
        Ok(())
    }

    /// Queries stable and beta available tags via the GitHub API on the remote host.
    ///
    /// Always attempts both channels sequentially (stable → MACHINE → beta).
    /// Per-channel failures are recorded on [`AvailableVersions`]; this method
    /// does not fail the whole check when only one channel errors.
    pub async fn available_versions<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> AvailableVersions {
        let mut versions = AvailableVersions::default();

        match self.probe_stable_tag(session).await {
            Ok(tag) => versions.stable = Some(tag),
            Err(error) => {
                versions.stable_error = Some(sanitize_detail(&error.message()));
            }
        }

        match self.resolve_xray_machine(session).await {
            Ok(machine) => match self.probe_beta_tag(session, &machine).await {
                Ok(tag) => versions.beta = tag,
                Err(error) => {
                    versions.beta_error = Some(sanitize_detail(&error.message()));
                }
            },
            Err(error) => {
                versions.beta_error = Some(sanitize_detail(&error.message()));
            }
        }

        versions
    }

    async fn probe_stable_tag<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> InstallerResult<String> {
        let result = github_curl(session, LATEST_RELEASE_API_URL).await?;
        parse_latest_tag(&result.stdout)
    }

    async fn probe_beta_tag<S: SshSession + Sync>(
        &self,
        session: &S,
        machine: &str,
    ) -> InstallerResult<Option<String>> {
        let result = github_curl(session, RELEASES_API_URL).await?;
        parse_beta_tag(&result.stdout, machine)
    }

    /// Resolves script `MACHINE` from remote `uname -m` (+ side-checks).
    pub async fn resolve_xray_machine<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> InstallerResult<String> {
        let result = run_remote(session, "uname", vec!["-m".to_owned()]).await?;
        if result.exit_code != 0 {
            return Err(InstallerError::new(
                InstallerErrorKind::CommandFailed,
                format!(
                    "uname -m exited with code {}: {}",
                    result.exit_code,
                    sanitize_detail(&String::from_utf8_lossy(&result.stderr))
                ),
            ));
        }
        let uname_m = String::from_utf8_lossy(&result.stdout).trim().to_owned();
        map_uname_to_machine(session, &uname_m).await
    }

    async fn backup_for_update<S: SshSession + Sync>(
        &self,
        session: &S,
        installation: &XrayInstallation,
    ) -> InstallerResult<()> {
        if let Some(binary) = &installation.binary_path {
            self.backup_path(session, binary).await?;
        }
        if let Some(unit) = &installation.service_name
            && let Some(fragment) = self.resolve_fragment_path(session, unit).await?
        {
            self.backup_path(session, &fragment).await?;
        }
        for path in &installation.config_files {
            self.backup_path(session, path).await?;
        }
        Ok(())
    }

    async fn backup_for_remove<S: SshSession + Sync>(
        &self,
        session: &S,
        installation: &XrayInstallation,
    ) -> InstallerResult<()> {
        if let Some(unit) = &installation.service_name
            && let Some(fragment) = self.resolve_fragment_path(session, unit).await?
        {
            self.backup_path(session, &fragment).await?;
        }
        for path in &installation.config_files {
            self.backup_path(session, path).await?;
        }
        Ok(())
    }

    async fn backup_path<S: SshSession + Sync>(
        &self,
        session: &S,
        path: &RemotePath,
    ) -> InstallerResult<()> {
        self.backup
            .create_backup(session, path)
            .await
            .map_err(|error| {
                InstallerError::new(
                    InstallerErrorKind::BackupFailed,
                    sanitize_detail(error.message()),
                )
            })?;
        Ok(())
    }

    async fn resolve_fragment_path<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> InstallerResult<Option<RemotePath>> {
        let service = ServiceName::new(service_name).map_err(|error| {
            InstallerError::new(InstallerErrorKind::CommandFailed, error.message())
        })?;

        let result = run_remote(
            session,
            "systemctl",
            vec![
                "show".to_owned(),
                "-p".to_owned(),
                "FragmentPath".to_owned(),
                "--value".to_owned(),
                "--".to_owned(),
                service.as_str().to_owned(),
            ],
        )
        .await?;

        if result.exit_code != 0 {
            warn!(
                target: "xray",
                exit_code = result.exit_code,
                "systemctl FragmentPath query failed; skipping unit backup"
            );
            return Ok(None);
        }

        let path = String::from_utf8_lossy(&result.stdout).trim().to_owned();
        if path.is_empty() {
            return Ok(None);
        }

        match RemotePath::new(path) {
            Ok(path) => Ok(Some(path)),
            Err(error) => {
                warn!(
                    target: "xray",
                    detail = %sanitize_detail(error.message()),
                    "invalid FragmentPath; skipping unit backup"
                );
                Ok(None)
            }
        }
    }

    async fn run_official_script<S: SshSession + Sync>(
        &self,
        session: &S,
        script_args: &[String],
    ) -> InstallerResult<()> {
        let action = script_args
            .first()
            .map(String::as_str)
            .unwrap_or("install");
        let script_path = temp_script_path()?;
        let remote_path = RemotePath::new(script_path.clone()).map_err(|error| {
            InstallerError::new(InstallerErrorKind::CommandFailed, error.message())
        })?;

        // 1. Download
        let download = run_remote(
            session,
            "curl",
            vec![
                "-L".to_owned(),
                "-f".to_owned(),
                "-o".to_owned(),
                script_path.clone(),
                INSTALL_SCRIPT_URL.to_owned(),
            ],
        )
        .await
        .map_err(|error| {
            if error.kind() == InstallerErrorKind::PermissionDenied
                || error.kind() == InstallerErrorKind::SshConnectionFailed
            {
                error
            } else {
                InstallerError::new(
                    InstallerErrorKind::DownloadFailed,
                    sanitize_detail(error.detail()),
                )
            }
        })?;

        if download.exit_code != 0 {
            let _ = session.remove_file(&remote_path).await;
            return Err(InstallerError::new(
                InstallerErrorKind::DownloadFailed,
                format!(
                    "curl exited with code {}: {}",
                    download.exit_code,
                    sanitize_detail(&String::from_utf8_lossy(&download.stderr))
                ),
            ));
        }

        // 2. Verify
        let contents = session.read_file(&remote_path).await.map_err(|error| {
            InstallerError::new(
                InstallerErrorKind::VerificationFailed,
                sanitize_detail(error.message()),
            )
        })?;

        if contents.is_empty() || !contents.starts_with(b"#!") {
            let _ = session.remove_file(&remote_path).await;
            return Err(InstallerError::new(
                InstallerErrorKind::VerificationFailed,
                "downloaded install script is empty or missing shebang",
            ));
        }

        // 3. Run
        let mut bash_args = vec![script_path.clone()];
        bash_args.extend(script_args.iter().cloned());
        let run = run_remote(session, "bash", bash_args).await;

        // 4. Cleanup (best effort)
        if let Err(error) = session.remove_file(&remote_path).await {
            warn!(
                target: "xray",
                detail = %sanitize_detail(error.message()),
                "failed to remove temporary install script"
            );
        }

        let run = run?;
        if run.exit_code != 0 {
            return Err(classify_script_failure(action, &run));
        }

        Ok(())
    }

    async fn verify_service_running<S: SshSession + Sync>(
        &self,
        session: &S,
        service_name: &str,
    ) -> InstallerResult<()> {
        match self.init.service_state(session, service_name).await {
            Ok(ServiceState::Running) => Ok(()),
            Ok(state) => Err(InstallerError::new(
                InstallerErrorKind::ServiceStartFailed,
                format!(
                    "service {service_name} state after install is {}",
                    state.label()
                ),
            )),
            Err(error) => {
                let kind = match error.kind() {
                    crate::init::ServiceOperationErrorKind::PermissionDenied => {
                        InstallerErrorKind::PermissionDenied
                    }
                    crate::init::ServiceOperationErrorKind::ServiceNotFound => {
                        InstallerErrorKind::ServiceCreationFailed
                    }
                    crate::init::ServiceOperationErrorKind::SshConnectionFailed => {
                        InstallerErrorKind::SshConnectionFailed
                    }
                    _ => InstallerErrorKind::ServiceStartFailed,
                };
                Err(InstallerError::new(kind, sanitize_detail(error.detail())))
            }
        }
    }
}

fn install_script_args(channel: InstallChannel) -> Vec<String> {
    match channel {
        InstallChannel::Stable => vec!["install".to_owned()],
        InstallChannel::Beta => vec!["install".to_owned(), "--beta".to_owned()],
    }
}

fn ensure_supported(init_system: InitSystemKind) -> InstallerResult<()> {
    if init_system.supports_service_control() {
        Ok(())
    } else {
        Err(InstallerError::new(
            InstallerErrorKind::UnsupportedSystem,
            format!(
                "init system {} is not supported for Xray lifecycle management",
                init_system.label()
            ),
        ))
    }
}

fn temp_script_path() -> InstallerResult<String> {
    // Cryptographically random suffix — never derive the path from wall-clock
    // time alone (predictable /tmp names enable symlink races).
    Ok(format!(
        "/tmp/feldjaeger-xray-install-{}.sh",
        uuid::Uuid::new_v4()
    ))
}

async fn github_curl<S: SshSession + Sync>(
    session: &S,
    url: &str,
) -> InstallerResult<ExecResult> {
    let result = run_remote(
        session,
        "curl",
        vec![
            "-sL".to_owned(),
            "-f".to_owned(),
            "-A".to_owned(),
            "Feldjaeger".to_owned(),
            url.to_owned(),
        ],
    )
    .await
    .map_err(|error| {
        if error.kind() == InstallerErrorKind::PermissionDenied {
            error
        } else {
            InstallerError::new(
                InstallerErrorKind::DownloadFailed,
                sanitize_detail(error.detail()),
            )
        }
    })?;

    if result.exit_code != 0 {
        return Err(InstallerError::new(
            InstallerErrorKind::DownloadFailed,
            format!(
                "curl exited with code {}: {}",
                result.exit_code,
                sanitize_detail(&String::from_utf8_lossy(&result.stderr))
            ),
        ));
    }

    Ok(result)
}

async fn run_remote<S: SshSession + Sync>(
    session: &S,
    program: &str,
    args: Vec<String>,
) -> InstallerResult<ExecResult> {
    let command = RemoteCommand::new(program, args).map_err(|error| {
        InstallerError::new(InstallerErrorKind::CommandFailed, error.message())
    })?;

    session.exec(&command).await.map_err(|error| {
        let message = sanitize_detail(error.message());
        let lower = message.to_ascii_lowercase();
        let kind = if lower.contains("permission denied") || lower.contains("access denied") {
            InstallerErrorKind::PermissionDenied
        } else if lower.contains("connection")
            || lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("broken pipe")
        {
            InstallerErrorKind::SshConnectionFailed
        } else {
            InstallerErrorKind::CommandFailed
        };
        InstallerError::new(kind, message)
    })
}

fn classify_script_failure(action: &str, result: &ExecResult) -> InstallerError {
    let stderr = sanitize_detail(String::from_utf8_lossy(&result.stderr).trim());
    let lower = stderr.to_ascii_lowercase();

    let kind = if lower.contains("permission denied")
        || lower.contains("access denied")
        || lower.contains("must be run as root")
        || lower.contains("root privileges")
        || lower.contains("operation not permitted")
    {
        InstallerErrorKind::PermissionDenied
    } else if action == "install"
        && (lower.contains("systemd") && lower.contains("fail")
            || lower.contains("failed to enable")
            || lower.contains("failed to start"))
    {
        if lower.contains("enable") || lower.contains("unit") {
            InstallerErrorKind::ServiceCreationFailed
        } else {
            InstallerErrorKind::ServiceStartFailed
        }
    } else {
        InstallerErrorKind::CommandFailed
    };

    let detail = if stderr.is_empty() {
        format!("install-release.sh {action} failed with exit code {}", result.exit_code)
    } else {
        format!(
            "install-release.sh {action} failed with exit code {}: {stderr}",
            result.exit_code
        )
    };

    InstallerError::new(kind, detail)
}

/// Strips a leading `v` for comparison / display with Xray version output.
pub fn normalize_version_tag(tag: &str) -> &str {
    tag.trim().strip_prefix('v').unwrap_or(tag.trim())
}

/// Returns `true` when `candidate` is strictly newer than `current` (script `sort -V`).
pub fn version_gt(candidate: &str, current: &str) -> bool {
    compare_version_tags(candidate, current) == std::cmp::Ordering::Greater
}

fn compare_version_tags(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts = version_numeric_parts(normalize_version_tag(a));
    let b_parts = version_numeric_parts(normalize_version_tag(b));
    let len = a_parts.len().max(b_parts.len());
    for i in 0..len {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

fn version_numeric_parts(tag: &str) -> Vec<u64> {
    let mut parts = Vec::new();
    let mut current = String::new();
    for ch in tag.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            if let Ok(n) = current.parse::<u64>() {
                parts.push(n);
            }
            current.clear();
        }
    }
    if !current.is_empty()
        && let Ok(n) = current.parse::<u64>()
    {
        parts.push(n);
    }
    parts
}

/// Maps `uname -m` (+ side-checks) to install-release.sh `MACHINE`.
pub async fn map_uname_to_machine<S: SshSession + Sync>(
    session: &S,
    uname_m: &str,
) -> InstallerResult<String> {
    match uname_m {
        "i386" | "i686" => Ok("32".to_owned()),
        "amd64" | "x86_64" => Ok("64".to_owned()),
        "armv5tel" => Ok("arm32-v5".to_owned()),
        "armv6l" => {
            if cpuinfo_has_vfp(session).await? {
                Ok("arm32-v6".to_owned())
            } else {
                Ok("arm32-v5".to_owned())
            }
        }
        "armv7" | "armv7l" => {
            if cpuinfo_has_vfp(session).await? {
                Ok("arm32-v7a".to_owned())
            } else {
                Ok("arm32-v5".to_owned())
            }
        }
        "armv8" | "aarch64" => Ok("arm64-v8a".to_owned()),
        "mips" => Ok("mips32".to_owned()),
        "mipsle" => Ok("mips32le".to_owned()),
        "mips64" => {
            if lscpu_little_endian(session).await? {
                Ok("mips64le".to_owned())
            } else {
                Ok("mips64".to_owned())
            }
        }
        "mips64le" => Ok("mips64le".to_owned()),
        "ppc64" => Ok("ppc64".to_owned()),
        "ppc64le" => Ok("ppc64le".to_owned()),
        "riscv64" => Ok("riscv64".to_owned()),
        "s390x" => Ok("s390x".to_owned()),
        other => Err(InstallerError::new(
            InstallerErrorKind::UnsupportedSystem,
            format!("architecture is not supported: {other}"),
        )),
    }
}

async fn cpuinfo_has_vfp<S: SshSession + Sync>(session: &S) -> InstallerResult<bool> {
    let result = run_remote(
        session,
        "grep",
        vec!["Features".to_owned(), "/proc/cpuinfo".to_owned()],
    )
    .await?;
    if result.exit_code != 0 {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&result.stdout)
        .to_ascii_lowercase()
        .contains("vfp"))
}

async fn lscpu_little_endian<S: SshSession + Sync>(session: &S) -> InstallerResult<bool> {
    let result = run_remote(session, "lscpu", Vec::new()).await?;
    if result.exit_code != 0 {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&result.stdout).contains("Little Endian"))
}

/// Parses `tag_name` from a GitHub releases/latest JSON payload.
pub fn parse_latest_tag(stdout: &[u8]) -> InstallerResult<String> {
    let value: serde_json::Value = serde_json::from_slice(stdout).map_err(|error| {
        InstallerError::new(
            InstallerErrorKind::VerificationFailed,
            format!("invalid GitHub release JSON: {error}"),
        )
    })?;

    let tag = value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            InstallerError::new(
                InstallerErrorKind::VerificationFailed,
                "GitHub release JSON missing tag_name",
            )
        })?;

    Ok(normalize_version_tag(tag).to_owned())
}

/// Picks `PRE_RELEASE_LATEST` like install-release.sh: first release tag whose
/// `Xray-linux-{MACHINE}.zip` download URL appears in the releases JSON.
pub fn parse_beta_tag(stdout: &[u8], machine: &str) -> InstallerResult<Option<String>> {
    let value: serde_json::Value = serde_json::from_slice(stdout).map_err(|error| {
        InstallerError::new(
            InstallerErrorKind::VerificationFailed,
            format!("invalid GitHub releases JSON: {error}"),
        )
    })?;

    let releases = value.as_array().ok_or_else(|| {
        InstallerError::new(
            InstallerErrorKind::VerificationFailed,
            "GitHub releases JSON is not an array",
        )
    })?;

    let text = String::from_utf8_lossy(stdout);
    for release in releases {
        let Some(tag) = release
            .get("tag_name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let tag_v = format!("v{}", normalize_version_tag(tag));
        let url_zip = format!(
            "https://github.com/XTLS/Xray-core/releases/download/{tag_v}/Xray-linux-{machine}.zip"
        );
        if text.contains(&url_zip) {
            return Ok(Some(normalize_version_tag(tag).to_owned()));
        }
    }

    Ok(None)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::ConfigSource;
    use feldjaeger_ssh::{ConnectionProfile, SshError, SshResult};
    use std::collections::HashMap;
    use std::future;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockSession {
        profile: ConnectionProfile,
        exec_results: Arc<Mutex<HashMap<String, ExecResult>>>,
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        exec_calls: Arc<Mutex<Vec<RemoteCommand>>>,
        remove_calls: Arc<Mutex<Vec<String>>>,
        read_fail_paths: Arc<Mutex<HashMap<String, &'static str>>>,
    }

    impl MockSession {
        fn new() -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "root"),
                exec_results: Arc::new(Mutex::new(HashMap::new())),
                files: Arc::new(Mutex::new(HashMap::new())),
                exec_calls: Arc::new(Mutex::new(Vec::new())),
                remove_calls: Arc::new(Mutex::new(Vec::new())),
                read_fail_paths: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn with_exec(self, key: impl Into<String>, result: ExecResult) -> Self {
            self.exec_results.lock().unwrap().insert(key.into(), result);
            self
        }

        fn with_file(self, path: impl Into<String>, contents: Vec<u8>) -> Self {
            self.files.lock().unwrap().insert(path.into(), contents);
            self
        }

        fn with_read_fail(self, path: impl Into<String>, message: &'static str) -> Self {
            self.read_fail_paths
                .lock()
                .unwrap()
                .insert(path.into(), message);
            self
        }

        fn remove_calls(&self) -> Vec<String> {
            self.remove_calls.lock().unwrap().clone()
        }

        fn programs(&self) -> Vec<String> {
            self.exec_calls
                .lock()
                .unwrap()
                .iter()
                .map(|c| c.program().to_owned())
                .collect()
        }
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        fn read_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<Vec<u8>>> + Send {
            if let Some(message) = self.read_fail_paths.lock().unwrap().get(path.as_str()) {
                return future::ready(Err(SshError::new(*message)));
            }
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
            _from: &RemotePath,
            _to: &RemotePath,
        ) -> impl Future<Output = SshResult<()>> + Send {
            future::ready(Ok(()))
        }

        fn remove_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<()>> + Send {
            self.remove_calls
                .lock()
                .unwrap()
                .push(path.as_str().to_owned());
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
            let map = self.exec_results.lock().unwrap();
            let result = if command.program() == "curl"
                && command.args().iter().any(|a| a.contains("install-release.sh"))
            {
                map.get("curl download script")
                    .cloned()
                    .unwrap_or_else(|| ExecResult::new(Vec::new(), Vec::new(), 0))
            } else if command.program() == "bash"
                && command.args().get(1).map(String::as_str) == Some("install")
                && command.args().get(2).map(String::as_str) == Some("--beta")
            {
                map.get("bash install --beta")
                    .cloned()
                    .unwrap_or_else(|| ExecResult::new(Vec::new(), Vec::new(), 0))
            } else if command.program() == "bash"
                && command.args().get(1).map(String::as_str) == Some("install")
            {
                map.get("bash install")
                    .cloned()
                    .unwrap_or_else(|| ExecResult::new(Vec::new(), Vec::new(), 0))
            } else if command.program() == "bash"
                && command.args().get(1).map(String::as_str) == Some("remove")
            {
                map.get("bash remove")
                    .cloned()
                    .unwrap_or_else(|| ExecResult::new(Vec::new(), Vec::new(), 0))
            } else if command.program() == "systemctl"
                && command.args().first().map(String::as_str) == Some("is-active")
            {
                map.get("systemctl is-active")
                    .cloned()
                    .unwrap_or_else(|| ExecResult::new(b"active\n".to_vec(), Vec::new(), 0))
            } else if command.program() == "systemctl"
                && command.args().iter().any(|a| a == "FragmentPath")
            {
                map.get("systemctl fragment").cloned().unwrap_or_else(|| {
                    ExecResult::new(
                        b"/etc/systemd/system/xray.service\n".to_vec(),
                        Vec::new(),
                        0,
                    )
                })
            } else if command.program() == "uname" {
                map.get("uname -m").cloned().unwrap_or_else(|| {
                    ExecResult::new(b"x86_64\n".to_vec(), Vec::new(), 0)
                })
            } else if command.program() == "curl"
                && command.args().iter().any(|a| a.contains("/releases/latest"))
            {
                map.get("curl github api").cloned().unwrap_or_else(|| {
                    ExecResult::new(br#"{"tag_name":"v26.3.31"}"#.to_vec(), Vec::new(), 0)
                })
            } else if command.program() == "curl"
                && command
                    .args()
                    .iter()
                    .any(|a| a.contains("/releases") && !a.contains("/releases/latest"))
            {
                map.get("curl github releases").cloned().unwrap_or_else(|| {
                    ExecResult::new(
                        br#"[{"tag_name":"v26.4.0-pre","assets":[{"browser_download_url":"https://github.com/XTLS/Xray-core/releases/download/v26.4.0-pre/Xray-linux-64.zip"}]}]"#.to_vec(),
                        Vec::new(),
                        0,
                    )
                })
            } else {
                let key = {
                    let args = command
                        .args()
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("{} {args}", command.program())
                };
                map.get(&key).cloned().unwrap_or_else(|| {
                    ExecResult::new(Vec::new(), format!("no mock for {key}").into_bytes(), 1)
                })
            };
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

    #[derive(Clone)]
    struct ScriptSession {
        inner: MockSession,
        script_bytes: Vec<u8>,
    }

    impl ScriptSession {
        fn valid(inner: MockSession) -> Self {
            Self {
                inner,
                script_bytes: b"#!/bin/bash\necho ok\n".to_vec(),
            }
        }

        fn invalid(inner: MockSession) -> Self {
            Self {
                inner,
                script_bytes: b"not a script".to_vec(),
            }
        }
    }

    impl SshSession for ScriptSession {
        fn profile(&self) -> &ConnectionProfile {
            self.inner.profile()
        }
        fn read_file(&self, path: &RemotePath) -> impl Future<Output = SshResult<Vec<u8>>> + Send {
            if path.as_str().starts_with("/tmp/feldjaeger-xray-install-") {
                return future::ready(Ok(self.script_bytes.clone()));
            }
            if let Some(message) = self
                .inner
                .read_fail_paths
                .lock()
                .unwrap()
                .get(path.as_str())
            {
                return future::ready(Err(SshError::new(*message)));
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
            self.inner.disconnect()
        }
    }

    fn sample_installation() -> XrayInstallation {
        XrayInstallation {
            operating_system: "Linux".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: Some(RemotePath::new("/usr/local/bin/xray").unwrap()),
            version: Some("26.3.27".to_owned()),
            service_name: Some("xray.service".to_owned()),
            service_state: Some(ServiceState::Running),
            exec_start: None,
            config_source: ConfigSource::SingleFile(
                RemotePath::new("/usr/local/etc/xray/config.json").unwrap(),
            ),
            config_readable: true,
            config_files: vec![RemotePath::new("/usr/local/etc/xray/config.json").unwrap()],
            discovery_warnings: Vec::new(),
        }
    }

    #[test]
    fn parse_latest_tag_strips_v_prefix() {
        let tag = parse_latest_tag(br#"{"tag_name":"v26.3.31","name":"Xray"}"#).unwrap();
        assert_eq!(tag, "26.3.31");
    }

    #[test]
    fn parse_latest_tag_rejects_malformed_json() {
        let error = parse_latest_tag(b"not-json").unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::VerificationFailed);
    }

    #[test]
    fn ensure_supported_rejects_openrc() {
        let error = ensure_supported(InitSystemKind::OpenRC).unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::UnsupportedSystem);
    }

    #[tokio::test]
    async fn install_refuses_when_already_installed() {
        let session = MockSession::new();
        let installer = XrayInstaller::new();
        let error = installer
            .install(&session, InitSystemKind::Systemd, true, InstallChannel::Stable)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::AlreadyInstalled);
        assert!(session.programs().is_empty());
    }

    #[tokio::test]
    async fn install_refuses_unsupported_init() {
        let session = MockSession::new();
        let installer = XrayInstaller::new();
        let error = installer
            .install(&session, InitSystemKind::Runit, false, InstallChannel::Stable)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::UnsupportedSystem);
    }

    #[tokio::test]
    async fn install_downloads_verifies_and_runs_script() {
        let session = ScriptSession::valid(
            MockSession::new()
                .with_exec("curl download script", ExecResult::new(Vec::new(), Vec::new(), 0))
                .with_exec("bash install", ExecResult::new(Vec::new(), Vec::new(), 0)),
        );
        let installer = XrayInstaller::new();
        installer
            .install(&session, InitSystemKind::Systemd, false, InstallChannel::Stable)
            .await
            .expect("install should succeed");

        let programs = session.inner.programs();
        assert!(programs.iter().any(|p| p == "curl"));
        assert!(programs.iter().any(|p| p == "bash"));
        assert!(programs.iter().any(|p| p == "systemctl"));
        assert!(!session.inner.remove_calls().is_empty());
    }

    #[tokio::test]
    async fn install_fails_on_download_error() {
        let session = MockSession::new().with_exec(
            "curl download script",
            ExecResult::new(Vec::new(), b"curl: (22) HTTP 404\n".to_vec(), 22),
        );
        let installer = XrayInstaller::new();
        let error = installer
            .install(&session, InitSystemKind::Systemd, false, InstallChannel::Stable)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::DownloadFailed);
    }

    #[tokio::test]
    async fn install_fails_on_bad_script_content() {
        let session = ScriptSession::invalid(
            MockSession::new()
                .with_exec("curl download script", ExecResult::new(Vec::new(), Vec::new(), 0)),
        );
        let installer = XrayInstaller::new();
        let error = installer
            .install(&session, InitSystemKind::Systemd, false, InstallChannel::Stable)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::VerificationFailed);
        assert!(session.inner.programs().iter().all(|p| p != "bash"));
    }

    #[tokio::test]
    async fn install_fails_when_service_inactive() {
        let session = ScriptSession::valid(
            MockSession::new()
                .with_exec("curl download script", ExecResult::new(Vec::new(), Vec::new(), 0))
                .with_exec("bash install", ExecResult::new(Vec::new(), Vec::new(), 0))
                .with_exec(
                    "systemctl is-active",
                    ExecResult::new(b"inactive\n".to_vec(), Vec::new(), 3),
                ),
        );
        let installer = XrayInstaller::new();
        let error = installer
            .install(&session, InitSystemKind::Systemd, false, InstallChannel::Stable)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::ServiceStartFailed);
    }

    #[tokio::test]
    async fn install_classifies_permission_denied() {
        let session = ScriptSession::valid(
            MockSession::new()
                .with_exec("curl download script", ExecResult::new(Vec::new(), Vec::new(), 0))
                .with_exec(
                    "bash install",
                    ExecResult::new(
                        Vec::new(),
                        b"Error: You must be run as root\n".to_vec(),
                        1,
                    ),
                ),
        );
        let installer = XrayInstaller::new();
        let error = installer
            .install(&session, InitSystemKind::Systemd, false, InstallChannel::Stable)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn update_backs_up_before_script() {
        let session = ScriptSession::valid(
            MockSession::new()
                .with_file("/usr/local/bin/xray", b"binary".to_vec())
                .with_file("/etc/systemd/system/xray.service", b"[Unit]\n".to_vec())
                .with_file("/usr/local/etc/xray/config.json", b"{}".to_vec())
                .with_exec("curl download script", ExecResult::new(Vec::new(), Vec::new(), 0))
                .with_exec("bash install", ExecResult::new(Vec::new(), Vec::new(), 0)),
        );
        let installer = XrayInstaller::new();
        installer
            .update(&session, &sample_installation(), InstallChannel::Stable)
            .await
            .expect("update should succeed");

        let files = session.inner.files.lock().unwrap();
        let bak_count = files
            .keys()
            .filter(|k| k.contains(".feldjaeger.bak"))
            .count();
        assert!(bak_count >= 3, "expected backups for binary, unit, config");
    }

    #[tokio::test]
    async fn update_aborts_when_backup_fails() {
        let session = MockSession::new()
            .with_read_fail("/usr/local/bin/xray", "Permission denied")
            .with_exec("curl download script", ExecResult::new(Vec::new(), Vec::new(), 0));
        let installer = XrayInstaller::new();
        let error = installer
            .update(&session, &sample_installation(), InstallChannel::Stable)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), InstallerErrorKind::BackupFailed);
        assert!(!session.programs().iter().any(|p| p == "bash"));
    }

    #[tokio::test]
    async fn remove_preserves_config_files() {
        let session = ScriptSession::valid(
            MockSession::new()
                .with_file("/etc/systemd/system/xray.service", b"[Unit]\n".to_vec())
                .with_file("/usr/local/etc/xray/config.json", b"{}".to_vec())
                .with_exec("curl download script", ExecResult::new(Vec::new(), Vec::new(), 0))
                .with_exec("bash remove", ExecResult::new(Vec::new(), Vec::new(), 0)),
        );
        let installer = XrayInstaller::new();
        installer
            .remove(&session, &sample_installation())
            .await
            .expect("remove should succeed");

        let removes = session.inner.remove_calls();
        assert!(
            removes
                .iter()
                .all(|p| !p.contains("/usr/local/etc/xray/config.json")),
            "config must not be deleted: {removes:?}"
        );
        assert!(session.inner.programs().iter().any(|p| p == "bash"));
    }

    #[tokio::test]
    async fn available_versions_parses_stable_and_beta() {
        let session = MockSession::new();
        let installer = XrayInstaller::new();
        let versions = installer.available_versions(&session).await;
        assert_eq!(versions.stable.as_deref(), Some("26.3.31"));
        assert_eq!(versions.beta.as_deref(), Some("26.4.0-pre"));
        assert!(versions.stable_error.is_none());
        assert!(versions.beta_error.is_none());
    }

    #[tokio::test]
    async fn available_versions_partial_success_when_beta_fails() {
        let session = MockSession::new().with_exec(
            "curl github releases",
            ExecResult::new(Vec::new(), b"curl: (22) HTTP 403\n".to_vec(), 22),
        );
        let installer = XrayInstaller::new();
        let versions = installer.available_versions(&session).await;
        assert_eq!(versions.stable.as_deref(), Some("26.3.31"));
        assert!(versions.beta.is_none());
        assert!(versions.beta_error.is_some());
    }

    #[tokio::test]
    async fn install_beta_passes_beta_flag() {
        let session = ScriptSession::valid(
            MockSession::new()
                .with_exec("curl download script", ExecResult::new(Vec::new(), Vec::new(), 0))
                .with_exec(
                    "bash install --beta",
                    ExecResult::new(Vec::new(), Vec::new(), 0),
                ),
        );
        let installer = XrayInstaller::new();
        installer
            .install(
                &session,
                InitSystemKind::Systemd,
                false,
                InstallChannel::Beta,
            )
            .await
            .expect("beta install should succeed");

        let calls = session.inner.exec_calls.lock().unwrap();
        let beta_bash = calls.iter().find(|c| {
            c.program() == "bash"
                && c.args().iter().any(|a| a == "--beta")
                && c.args().iter().any(|a| a == "install")
        });
        assert!(beta_bash.is_some(), "expected bash … install --beta");
    }

    #[test]
    fn version_gt_compares_numeric_segments() {
        assert!(version_gt("25.7.1", "25.3.6"));
        assert!(version_gt("1.8.10", "1.8.9"));
        assert!(!version_gt("26.3.31", "26.3.31"));
        assert!(!version_gt("26.3.30", "26.3.31"));
        assert!(version_gt("v26.4.0", "26.3.31"));
    }

    #[test]
    fn parse_beta_tag_picks_first_with_machine_zip() {
        let json = br#"[
          {"tag_name":"v26.5.0","assets":[]},
          {"tag_name":"v26.4.0-pre","assets":[{"browser_download_url":"https://github.com/XTLS/Xray-core/releases/download/v26.4.0-pre/Xray-linux-64.zip"}]},
          {"tag_name":"v26.3.0","assets":[{"browser_download_url":"https://github.com/XTLS/Xray-core/releases/download/v26.3.0/Xray-linux-64.zip"}]}
        ]"#;
        let tag = parse_beta_tag(json, "64").unwrap();
        assert_eq!(tag.as_deref(), Some("26.4.0-pre"));
    }

    #[test]
    fn parse_beta_tag_empty_when_no_zip() {
        let json = br#"[{"tag_name":"v26.4.0","assets":[]}]"#;
        let tag = parse_beta_tag(json, "64").unwrap();
        assert!(tag.is_none());
    }

    #[tokio::test]
    async fn map_uname_common_arches() {
        let session = MockSession::new();
        assert_eq!(
            map_uname_to_machine(&session, "x86_64").await.unwrap(),
            "64"
        );
        assert_eq!(
            map_uname_to_machine(&session, "aarch64").await.unwrap(),
            "arm64-v8a"
        );
        assert_eq!(
            map_uname_to_machine(&session, "i686").await.unwrap(),
            "32"
        );
        let err = map_uname_to_machine(&session, "sparc").await.unwrap_err();
        assert_eq!(err.kind(), InstallerErrorKind::UnsupportedSystem);
    }

    #[test]
    fn temp_script_path_is_unpredictable_and_unique() {
        let a = temp_script_path().expect("path a");
        let b = temp_script_path().expect("path b");
        assert_ne!(a, b, "temp script path must not collide across rapid calls");
        assert!(a.starts_with("/tmp/feldjaeger-xray-install-"));
        assert!(a.ends_with(".sh"));
        // UUID v4 string is 36 chars — far more than a unix-seconds stamp.
        let suffix = a
            .trim_start_matches("/tmp/feldjaeger-xray-install-")
            .trim_end_matches(".sh");
        assert!(
            suffix.len() >= 32,
            "expected high-entropy suffix, got {suffix:?}"
        );
        assert!(!suffix.chars().all(|c| c.is_ascii_digit()), "must not be timestamp-only");
    }
}
