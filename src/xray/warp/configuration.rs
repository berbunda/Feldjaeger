//! Remote WARP credential file and ownership marker I/O.
//!
//! This module only reads/writes files under [`MANAGED_WARP_DIR`]. It never
//! modifies Xray's `config.json` — that pipeline belongs to the application
//! layer's configuration-modify service.

use tracing::{info, warn};

use feldjaeger_ssh::{RemotePath, SshSession};

use super::error::{WarpError, WarpErrorKind, WarpResult};
use super::parse::parse_generated_xray_outbound;
use super::registration::WarpRegistrationService;
use super::remote::{chmod, join_path, remote_path_is_file, run_remote};
use super::types::{
    WarpCredentials, WarpOwnershipRecord, GENERATED_XRAY_FILE_NAME, MANAGED_WARP_DIR,
    OWNERSHIP_FILE_NAME,
};
use crate::logging::redact::sanitize_detail;

/// Manages generated Xray outbound credentials and the ownership marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct WarpConfigurationService;

impl WarpConfigurationService {
    /// Creates a new service.
    pub fn new() -> Self {
        Self
    }

    /// Path to the generated Xray outbound file (`wgcf.xray.json`).
    pub fn generated_outbound_path() -> WarpResult<RemotePath> {
        join_path(MANAGED_WARP_DIR, GENERATED_XRAY_FILE_NAME)
    }

    /// Path to the non-secret ownership marker (`ownership.json`).
    pub fn ownership_path() -> WarpResult<RemotePath> {
        join_path(MANAGED_WARP_DIR, OWNERSHIP_FILE_NAME)
    }

    /// Runs `wgcf-cli generate --xray` and parses the resulting credentials.
    ///
    /// On failure the error detail includes a sanitized helper stderr snippet.
    /// Requires an existing registration file. Removes any prior generated
    /// outbound file first — `wgcf-cli` otherwise prompts interactively.
    pub async fn generate_xray_outbound<S: SshSession + Sync>(
        &self,
        session: &S,
        helper_path: &RemotePath,
    ) -> WarpResult<WarpCredentials> {
        let reg_path = WarpRegistrationService::registration_path()?;
        if !remote_path_is_file(session, reg_path.as_str()).await? {
            return Err(WarpError::new(
                WarpErrorKind::WarpRegistrationFailed,
                "WARP registration data not found; register before generating an outbound",
            ));
        }

        self.remove_generated_files(session).await?;

        let result = run_remote(
            session,
            helper_path.as_str(),
            vec![
                "-c".to_owned(),
                reg_path.as_str().to_owned(),
                "generate".to_owned(),
                "--xray".to_owned(),
            ],
        )
        .await?;

        if result.exit_code != 0 {
            let stderr = sanitize_detail(String::from_utf8_lossy(&result.stderr).trim());
            warn!(
                target: "xray",
                exit_code = result.exit_code,
                detail = %stderr,
                "WARP outbound generation command failed"
            );
            let detail = if stderr.is_empty() {
                format!("wgcf-cli generate --xray exited with code {}", result.exit_code)
            } else {
                format!(
                    "wgcf-cli generate --xray exited with code {}: {stderr}",
                    result.exit_code
                )
            };
            return Err(WarpError::new(WarpErrorKind::HelperExecutionFailed, detail));
        }

        let outbound_path = Self::generated_outbound_path()?;
        if !remote_path_is_file(session, outbound_path.as_str()).await? {
            return Err(WarpError::new(
                WarpErrorKind::GeneratedConfigurationMissing,
                "generated outbound file was not created",
            ));
        }

        let bytes = session.read_file(&outbound_path).await.map_err(|error| {
            WarpError::new(WarpErrorKind::GeneratedConfigurationMissing, sanitize_detail(error.message()))
        })?;
        let credentials = parse_generated_xray_outbound(&bytes)?;

        info!(target: "xray", "WARP Xray outbound generated");
        Ok(credentials)
    }

    /// Reads the ownership marker, when present.
    pub async fn read_ownership<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> WarpResult<Option<WarpOwnershipRecord>> {
        let path = Self::ownership_path()?;
        if !remote_path_is_file(session, path.as_str()).await? {
            return Ok(None);
        }

        let bytes = session.read_file(&path).await.map_err(|error| {
            WarpError::new(WarpErrorKind::RemoteWriteFailed, sanitize_detail(error.message()))
        })?;
        let record: WarpOwnershipRecord = serde_json::from_slice(&bytes).map_err(|_| {
            WarpError::new(
                WarpErrorKind::GeneratedConfigurationInvalid,
                "ownership marker is not valid JSON",
            )
        })?;
        Ok(Some(record))
    }

    /// Writes the (non-secret) ownership marker, mode `644`.
    pub async fn write_ownership<S: SshSession + Sync>(
        &self,
        session: &S,
        record: &WarpOwnershipRecord,
    ) -> WarpResult<()> {
        let path = Self::ownership_path()?;
        let bytes = serde_json::to_vec_pretty(record).map_err(|_| {
            WarpError::new(WarpErrorKind::RemoteWriteFailed, "failed to serialize ownership marker")
        })?;

        session.write_file_atomic(&path, &bytes).await.map_err(|error| {
            WarpError::new(WarpErrorKind::RemoteWriteFailed, sanitize_detail(error.message()))
        })?;
        if let Err(error) = chmod(session, "644", path.as_str()).await {
            warn!(
                target: "xray",
                detail = %sanitize_detail(error.detail()),
                "failed to set WARP ownership marker permissions"
            );
        }

        info!(target: "xray", "WARP ownership marker written");
        Ok(())
    }

    /// Removes the generated Xray outbound file only (`wgcf.xray.json`).
    ///
    /// Never touches the registration file or the ownership marker.
    pub async fn remove_generated_files<S: SshSession + Sync>(&self, session: &S) -> WarpResult<()> {
        let path = Self::generated_outbound_path()?;
        if remote_path_is_file(session, path.as_str()).await? {
            session.remove_file(&path).await.map_err(|error| {
                WarpError::new(WarpErrorKind::RemoteWriteFailed, sanitize_detail(error.message()))
            })?;
        }
        Ok(())
    }
}
