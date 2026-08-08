//! Managed `wgcf-cli` helper binary lifecycle (discover / install / remove).
//!
//! Only the pinned [`APPROVED_HELPER_VERSION`](super::types::APPROVED_HELPER_VERSION)
//! release is ever downloaded, and only from
//! [`HELPER_RELEASE_BASE_URL`](super::types::HELPER_RELEASE_BASE_URL). The
//! helper is never looked up on `PATH` — only the path under
//! [`MANAGED_TOOLS_DIR`] is trusted.

use feldjaeger_ssh::{RemotePath, SshSession};
use tracing::{info, warn};
use uuid::Uuid;

use super::error::{WarpError, WarpErrorKind, WarpResult};
use super::remote::{
    as_permission_error, chmod, download_file, join_path, mkdir_p, remote_path_is_file, run_remote,
};
use super::types::{
    helper_asset_stem_for_arch, HELPER_FILE_NAME, HELPER_RELEASE_BASE_URL, MANAGED_TOOLS_DIR,
};
use crate::logging::redact::sanitize_detail;

/// ELF magic bytes (`\x7fELF`) checked on the extracted helper binary.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Result of a helper discovery pass (managed tools directory only).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WarpHelperInfo {
    /// Whether the approved helper binary exists at the managed path.
    pub installed: bool,
    /// Version string reported by `wgcf-cli version`, when parseable.
    pub version: Option<String>,
    /// Managed path to the helper binary, when installed.
    pub path: Option<RemotePath>,
}

/// Manages the approved `wgcf-cli` helper binary under [`MANAGED_TOOLS_DIR`].
#[derive(Debug, Clone, Copy, Default)]
pub struct WarpHelperManager;

impl WarpHelperManager {
    /// Creates a new manager.
    pub fn new() -> Self {
        Self
    }

    /// Path to the helper binary under the managed tools directory.
    pub fn managed_helper_path() -> WarpResult<RemotePath> {
        join_path(MANAGED_TOOLS_DIR, HELPER_FILE_NAME)
    }

    /// Reads current helper installation state from the managed path only.
    ///
    /// Read-only: never installs, downloads, or removes anything. A missing
    /// helper is reported (not an error) via `installed = false`.
    pub async fn discover_helper<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> WarpResult<WarpHelperInfo> {
        let path = Self::managed_helper_path()?;
        if !remote_path_is_file(session, path.as_str()).await? {
            return Ok(WarpHelperInfo::default());
        }

        // Best-effort: a working binary but unparsable `version` output should
        // not turn a read-only discovery pass into a hard failure.
        let version = query_version(session, &path).await.unwrap_or(None);

        Ok(WarpHelperInfo {
            installed: true,
            version,
            path: Some(path),
        })
    }

    /// Downloads, verifies, and installs the pinned helper release.
    ///
    /// On any verification failure the partially downloaded/extracted files
    /// are removed and the managed binary is never executed.
    pub async fn install_helper<S: SshSession + Sync>(
        &self,
        session: &S,
    ) -> WarpResult<WarpHelperInfo> {
        info!(target: "xray", "WARP helper install started");
        match self.run_install(session).await {
            Ok(info) => {
                info!(
                    target: "xray",
                    version = info.version.as_deref().unwrap_or("unknown"),
                    "WARP helper installed"
                );
                Ok(info)
            }
            Err(error) => {
                warn!(
                    target: "xray",
                    detail = %sanitize_detail(error.detail()),
                    "WARP helper install failed"
                );
                Err(error)
            }
        }
    }

    async fn run_install<S: SshSession + Sync>(&self, session: &S) -> WarpResult<WarpHelperInfo> {
        let os_name = probe_uname(session, "-s").await?;
        if !os_name.eq_ignore_ascii_case("linux") {
            return Err(WarpError::new(
                WarpErrorKind::UnsupportedOperatingSystem,
                format!("remote OS reported as `{os_name}`"),
            ));
        }

        let arch_name = probe_uname(session, "-m").await?;
        let stem = helper_asset_stem_for_arch(&arch_name).ok_or_else(|| {
            WarpError::new(
                WarpErrorKind::UnsupportedArchitecture,
                format!("unsupported architecture: `{arch_name}`"),
            )
        })?;

        mkdir_p(session, MANAGED_TOOLS_DIR)
            .await
            .map_err(|error| as_permission_error(error, WarpErrorKind::NoPermissionToInstallHelper))?;

        let unique = Uuid::new_v4();
        let archive_path = join_path("/tmp", &format!("feldjaeger-wgcf-{unique}.tar.zstd"))?;
        let dgst_path = join_path("/tmp", &format!("feldjaeger-wgcf-{unique}.tar.zstd.dgst"))?;
        let extract_dir = join_path("/tmp", &format!("feldjaeger-wgcf-{unique}-extract"))?;

        let temps = [&archive_path, &dgst_path];

        let archive_url = format!("{HELPER_RELEASE_BASE_URL}/{stem}.tar.zstd");
        let dgst_url = format!("{HELPER_RELEASE_BASE_URL}/{stem}.tar.zstd.dgst");

        if let Err(error) = download_file(session, &archive_path, &archive_url).await {
            cleanup_temp(session, &temps, &extract_dir).await;
            return Err(error);
        }
        if let Err(error) = download_file(session, &dgst_path, &dgst_url).await {
            cleanup_temp(session, &temps, &extract_dir).await;
            return Err(error);
        }

        if let Err(error) = verify_download(session, &archive_path, &dgst_path).await {
            cleanup_temp(session, &temps, &extract_dir).await;
            return Err(error);
        }

        if let Err(error) = mkdir_p(session, extract_dir.as_str()).await {
            cleanup_temp(session, &temps, &extract_dir).await;
            return Err(error);
        }
        if let Err(error) = extract_archive(session, &archive_path, &extract_dir).await {
            cleanup_temp(session, &temps, &extract_dir).await;
            return Err(error);
        }

        let found = match find_binary(session, &extract_dir).await {
            Ok(path) => path,
            Err(error) => {
                cleanup_temp(session, &temps, &extract_dir).await;
                return Err(error);
            }
        };

        let bytes = match session.read_file(&found).await {
            Ok(bytes) => bytes,
            Err(error) => {
                cleanup_temp(session, &temps, &extract_dir).await;
                return Err(WarpError::new(
                    WarpErrorKind::HelperVerificationFailed,
                    sanitize_detail(error.message()),
                ));
            }
        };
        if bytes.len() < ELF_MAGIC.len() || bytes[..ELF_MAGIC.len()] != ELF_MAGIC {
            cleanup_temp(session, &temps, &extract_dir).await;
            return Err(WarpError::new(
                WarpErrorKind::HelperVerificationFailed,
                "extracted helper is not a recognized ELF binary",
            ));
        }

        let managed_path = Self::managed_helper_path()?;
        if let Err(error) = session.write_file_atomic(&managed_path, &bytes).await {
            cleanup_temp(session, &temps, &extract_dir).await;
            let error = WarpError::new(WarpErrorKind::RemoteWriteFailed, sanitize_detail(error.message()));
            return Err(as_permission_error(error, WarpErrorKind::NoPermissionToInstallHelper));
        }
        if let Err(error) = chmod(session, "755", managed_path.as_str()).await {
            cleanup_temp(session, &temps, &extract_dir).await;
            return Err(as_permission_error(error, WarpErrorKind::NoPermissionToInstallHelper));
        }

        let version = match query_version(session, &managed_path).await {
            Ok(version) => version,
            Err(error) => {
                cleanup_temp(session, &temps, &extract_dir).await;
                return Err(WarpError::new(WarpErrorKind::HelperExecutionFailed, error.detail().to_owned()));
            }
        };

        cleanup_temp(session, &temps, &extract_dir).await;

        Ok(WarpHelperInfo {
            installed: true,
            version,
            path: Some(managed_path),
        })
    }

    /// Removes only the managed helper binary (and the managed tools
    /// directory when it is left empty).
    ///
    /// Never touches a system-installed `wgcf`, Cloudflare WARP client, or
    /// any file outside [`MANAGED_TOOLS_DIR`].
    pub async fn remove_helper<S: SshSession + Sync>(&self, session: &S) -> WarpResult<()> {
        let path = Self::managed_helper_path()?;
        if remote_path_is_file(session, path.as_str()).await? {
            session.remove_file(&path).await.map_err(|error| {
                WarpError::new(WarpErrorKind::RemoteWriteFailed, sanitize_detail(error.message()))
            })?;
            info!(target: "xray", "WARP helper binary removed");
        }
        // Best-effort: `rmdir` only succeeds when the directory is empty, so
        // this never removes anything else left in the managed tools dir.
        let _ = run_remote(session, "rmdir", vec![MANAGED_TOOLS_DIR.to_owned()]).await;
        Ok(())
    }
}

async fn probe_uname<S: SshSession + Sync>(session: &S, flag: &str) -> WarpResult<String> {
    let result = run_remote(session, "uname", vec![flag.to_owned()]).await?;
    if result.exit_code != 0 {
        return Err(WarpError::new(
            WarpErrorKind::CommandFailed,
            format!("uname {flag} exited with code {}", result.exit_code),
        ));
    }
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
}

async fn query_version<S: SshSession + Sync>(
    session: &S,
    path: &RemotePath,
) -> WarpResult<Option<String>> {
    let result = run_remote(session, path.as_str(), vec!["version".to_owned()]).await?;
    if result.exit_code != 0 {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&result.stdout);
    let text = stdout.lines().next().unwrap_or("").trim();
    Ok(if text.is_empty() { None } else { Some(text.to_owned()) })
}

async fn verify_download<S: SshSession + Sync>(
    session: &S,
    archive_path: &RemotePath,
    dgst_path: &RemotePath,
) -> WarpResult<()> {
    let archive_bytes = session.read_file(archive_path).await.map_err(|error| {
        WarpError::new(WarpErrorKind::HelperVerificationFailed, sanitize_detail(error.message()))
    })?;
    if archive_bytes.is_empty() {
        return Err(WarpError::new(
            WarpErrorKind::HelperVerificationFailed,
            "downloaded helper archive is empty",
        ));
    }

    let dgst_bytes = session.read_file(dgst_path).await.map_err(|error| {
        WarpError::new(WarpErrorKind::HelperVerificationFailed, sanitize_detail(error.message()))
    })?;
    let dgst_text = String::from_utf8_lossy(&dgst_bytes);
    let expected_sha256 = extract_sha256_hex(&dgst_text).ok_or_else(|| {
        WarpError::new(
            WarpErrorKind::HelperVerificationFailed,
            "digest file does not contain a sha256 hash",
        )
    })?;

    let sha_result = run_remote(session, "sha256sum", vec![archive_path.as_str().to_owned()]).await?;
    if sha_result.exit_code != 0 {
        return Err(WarpError::new(
            WarpErrorKind::HelperVerificationFailed,
            "sha256sum failed on the downloaded archive",
        ));
    }
    let sha_stdout = String::from_utf8_lossy(&sha_result.stdout);
    let actual_sha256 = sha_stdout.split_whitespace().next().unwrap_or("");

    if actual_sha256.is_empty() || !actual_sha256.eq_ignore_ascii_case(&expected_sha256) {
        return Err(WarpError::new(
            WarpErrorKind::HelperVerificationFailed,
            "helper archive checksum does not match the published digest",
        ));
    }

    Ok(())
}

/// Extracts a SHA-256 hex digest from published helper checksum files.
///
/// Supports:
/// - OpenSSL digests (`.dgst` from ArchiveNetwork releases): `SHA2-256= <hex>`
/// - `sha256sum` output: `<hex>  <filename>`
fn extract_sha256_hex(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        let Some((label, value)) = line.split_once('=') else {
            continue;
        };
        let label = label.trim();
        if !label.eq_ignore_ascii_case("SHA2-256") && !label.eq_ignore_ascii_case("SHA256") {
            continue;
        }
        let hex = value.split_whitespace().next()?.trim();
        if is_sha256_hex(hex) {
            return Some(hex.to_owned());
        }
    }

    let first_token = text.split_whitespace().next()?.trim();
    if is_sha256_hex(first_token) {
        Some(first_token.to_owned())
    } else {
        None
    }
}

fn is_sha256_hex(hex: &str) -> bool {
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

async fn extract_archive<S: SshSession + Sync>(
    session: &S,
    archive_path: &RemotePath,
    extract_dir: &RemotePath,
) -> WarpResult<()> {
    let result = run_remote(
        session,
        "tar",
        vec![
            "-I".to_owned(),
            "zstd".to_owned(),
            "-xf".to_owned(),
            archive_path.as_str().to_owned(),
            "-C".to_owned(),
            extract_dir.as_str().to_owned(),
        ],
    )
    .await?;

    if result.exit_code != 0 {
        return Err(WarpError::new(
            WarpErrorKind::HelperVerificationFailed,
            format!("helper archive extraction failed (exit code {})", result.exit_code),
        ));
    }
    Ok(())
}

async fn find_binary<S: SshSession + Sync>(
    session: &S,
    extract_dir: &RemotePath,
) -> WarpResult<RemotePath> {
    let result = run_remote(
        session,
        "find",
        vec![
            extract_dir.as_str().to_owned(),
            "-type".to_owned(),
            "f".to_owned(),
            "-name".to_owned(),
            HELPER_FILE_NAME.to_owned(),
        ],
    )
    .await?;

    if result.exit_code != 0 {
        return Err(WarpError::new(
            WarpErrorKind::HelperVerificationFailed,
            "could not locate the extracted helper binary",
        ));
    }

    let stdout = String::from_utf8_lossy(&result.stdout);
    let first = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| {
            WarpError::new(
                WarpErrorKind::HelperVerificationFailed,
                "extracted archive did not contain the helper binary",
            )
        })?;

    RemotePath::new(first.to_owned())
        .map_err(|error| WarpError::new(WarpErrorKind::HelperVerificationFailed, error.message().to_owned()))
}

async fn cleanup_temp<S: SshSession + Sync>(
    session: &S,
    files: &[&RemotePath],
    extract_dir: &RemotePath,
) {
    for file in files {
        if let Err(error) = session.remove_file(file).await {
            warn!(
                target: "xray",
                detail = %sanitize_detail(error.message()),
                "failed to remove temporary WARP helper download"
            );
        }
    }
    if let Err(error) = run_remote(session, "rm", vec!["-rf".to_owned(), extract_dir.as_str().to_owned()]).await {
        warn!(
            target: "xray",
            detail = %sanitize_detail(error.detail()),
            "failed to remove temporary WARP helper extraction directory"
        );
    }
}

#[cfg(test)]
mod digest_parse_tests {
    use super::{extract_sha256_hex, is_sha256_hex};

    #[test]
    fn parses_openssl_dgst_sha2_256() {
        let text = "MD5= 8df8f90222fc781b2977927e4d343ab3\n\
                    SHA1= 033dac59cf1ccdf531995d64ca8f27ff8df08a6f\n\
                    SHA2-256= d5119d9c9832572c6fda7b3c973334c4d2a3bc9346944e06e4708bdb7e14a58d\n\
                    SHA2-512= d157c53e367c53a17f4e1741cef81bc478e04d7e380cae2a144aa133c9bee40d0490b559bc1078056ee412d56bc8aa5087cb51453abb22da440e96bcb5e7840a\n";
        assert_eq!(
            extract_sha256_hex(text).as_deref(),
            Some("d5119d9c9832572c6fda7b3c973334c4d2a3bc9346944e06e4708bdb7e14a58d")
        );
    }

    #[test]
    fn parses_sha256sum_format() {
        let hex = "a".repeat(64);
        let text = format!("{hex}  wgcf-cli-linux-64.tar.zstd\n");
        assert_eq!(extract_sha256_hex(&text).as_deref(), Some(hex.as_str()));
    }

    #[test]
    fn rejects_digest_without_sha256() {
        assert!(extract_sha256_hex("MD5= deadbeef\nSHA1= deadbeef\n").is_none());
        assert!(!is_sha256_hex("MD5="));
    }
}
