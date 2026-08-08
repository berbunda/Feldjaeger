//! Cloudflare WARP device registration (`wgcf-cli register`) lifecycle.
//!
//! Registration output (`wgcf.json`) contains a WireGuard private key and is
//! never logged; failures surface a sanitized helper stderr snippet alongside
//! the exit code.

use tracing::{info, warn};

use feldjaeger_ssh::{RemotePath, SshSession};

use super::error::{WarpError, WarpErrorKind, WarpResult};
use super::remote::{chmod, join_path, mkdir_p, remote_path_is_file};
use super::remote::run_remote;
use super::types::{MANAGED_WARP_DIR, REGISTRATION_FILE_NAME};
use crate::logging::redact::sanitize_detail;

/// Outcome of a [`WarpRegistrationService::register`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarpRegistrationOutcome {
    /// A `wgcf.json` registration already existed and was left untouched.
    AlreadyRegistered,
    /// A new registration was created (or an existing one overwritten with `force`).
    Registered,
}

/// Manages the remote WARP registration file under [`MANAGED_WARP_DIR`].
#[derive(Debug, Clone, Copy, Default)]
pub struct WarpRegistrationService;

impl WarpRegistrationService {
    /// Creates a new service.
    pub fn new() -> Self {
        Self
    }

    /// Path to the managed WARP registration file (`wgcf.json`).
    pub fn registration_path() -> WarpResult<RemotePath> {
        join_path(MANAGED_WARP_DIR, REGISTRATION_FILE_NAME)
    }

    /// Ensures the managed WARP directory exists and is mode `700`.
    pub async fn ensure_work_dir<S: SshSession + Sync>(&self, session: &S) -> WarpResult<RemotePath> {
        mkdir_p(session, MANAGED_WARP_DIR).await?;
        chmod(session, "700", MANAGED_WARP_DIR).await?;
        RemotePath::new(MANAGED_WARP_DIR)
            .map_err(|error| WarpError::new(WarpErrorKind::CommandFailed, error.message().to_owned()))
    }

    /// Returns `true` when a registration file already exists remotely.
    pub async fn registration_exists<S: SshSession + Sync>(&self, session: &S) -> WarpResult<bool> {
        let path = Self::registration_path()?;
        remote_path_is_file(session, path.as_str()).await
    }

    /// Registers a new WARP device unless a registration already exists.
    ///
    /// Pass `force = true` to overwrite an existing registration. Never logs
    /// raw helper stdout/stderr (registration secrets); on failure the error
    /// detail includes a sanitized stderr snippet.
    pub async fn register<S: SshSession + Sync>(
        &self,
        session: &S,
        helper_path: &RemotePath,
        force: bool,
    ) -> WarpResult<WarpRegistrationOutcome> {
        self.ensure_work_dir(session).await?;
        let reg_path = Self::registration_path()?;

        let exists = remote_path_is_file(session, reg_path.as_str()).await?;
        if exists && !force {
            info!(target: "xray", "WARP registration already present; skipping");
            return Ok(WarpRegistrationOutcome::AlreadyRegistered);
        }

        // wgcf-cli prompts interactively when the config file already exists and
        // exits 1 without a TTY/`y` answer. Force re-register must remove the
        // live file first (callers are expected to have backed it up).
        if exists && force {
            session.remove_file(&reg_path).await.map_err(|error| {
                WarpError::new(
                    WarpErrorKind::RemoteWriteFailed,
                    sanitize_detail(error.message()),
                )
            })?;
            info!(target: "xray", "removed existing WARP registration for forced re-register");
        }

        let result = run_remote(
            session,
            helper_path.as_str(),
            vec!["-c".to_owned(), reg_path.as_str().to_owned(), "register".to_owned()],
        )
        .await?;

        if result.exit_code != 0 {
            let stderr = sanitize_detail(String::from_utf8_lossy(&result.stderr).trim());
            warn!(
                target: "xray",
                exit_code = result.exit_code,
                detail = %stderr,
                "WARP registration command failed"
            );
            let detail = if stderr.is_empty() {
                format!("wgcf-cli register exited with code {}", result.exit_code)
            } else {
                format!(
                    "wgcf-cli register exited with code {}: {stderr}",
                    result.exit_code
                )
            };
            return Err(WarpError::new(
                WarpErrorKind::WarpRegistrationFailed,
                detail,
            ));
        }

        chmod(session, "600", reg_path.as_str()).await?;
        info!(target: "xray", "WARP registration completed");
        Ok(WarpRegistrationOutcome::Registered)
    }

    /// Copies the current registration to a timestamped `.feldjaeger.bak.<ts>`
    /// sibling. Returns `None` when there is no registration to back up.
    pub async fn backup_registration<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> WarpResult<Option<RemotePath>> {
        let reg_path = Self::registration_path()?;
        if !remote_path_is_file(session, reg_path.as_str()).await? {
            return Ok(None);
        }

        let contents = session.read_file(&reg_path).await.map_err(|error| {
            WarpError::new(WarpErrorKind::BackupFailed, sanitize_detail(error.message()))
        })?;

        let timestamp = current_unix_timestamp();
        let backup_path = join_path(
            MANAGED_WARP_DIR,
            &format!("{REGISTRATION_FILE_NAME}.feldjaeger.bak.{timestamp}"),
        )?;

        session
            .write_file(&backup_path, &contents)
            .await
            .map_err(|error| WarpError::new(WarpErrorKind::BackupFailed, sanitize_detail(error.message())))?;
        if let Err(error) = chmod(session, "600", backup_path.as_str()).await {
            warn!(
                target: "xray",
                detail = %sanitize_detail(error.detail()),
                "failed to restrict WARP registration backup permissions"
            );
        }

        info!(target: "xray", "WARP registration backed up");
        Ok(Some(backup_path))
    }

    /// Restores a registration backup produced by [`Self::backup_registration`].
    pub async fn restore_registration_backup<S: SshSession + Sync>(
        &self,
        session: &S,
        backup_path: &RemotePath,
    ) -> WarpResult<()> {
        let contents = session.read_file(backup_path).await.map_err(|error| {
            WarpError::new(WarpErrorKind::RollbackFailed, sanitize_detail(error.message()))
        })?;

        let reg_path = Self::registration_path()?;
        session
            .write_file_atomic(&reg_path, &contents)
            .await
            .map_err(|error| WarpError::new(WarpErrorKind::RollbackFailed, sanitize_detail(error.message())))?;
        if let Err(error) = chmod(session, "600", reg_path.as_str()).await {
            warn!(
                target: "xray",
                detail = %sanitize_detail(error.detail()),
                "failed to restrict WARP registration permissions after rollback"
            );
        }

        info!(target: "xray", "WARP registration restored from backup");
        Ok(())
    }
}

fn current_unix_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
