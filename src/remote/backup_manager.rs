//! Remote configuration backup manager.

use std::time::{SystemTime, UNIX_EPOCH};

use feldjaeger_ssh::{RemoteCommand, RemotePath, SshSession};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use super::ConfigBackup;
use crate::error::{AppError, AppResult};

const BACKUP_SUFFIX: &str = ".feldjaeger.bak";

/// Configuration for [`BackupManager`] path layout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupManagerOptions {
    /// Optional dedicated directory where backup files are stored.
    ///
    /// When set, backups include a digest of the full original path to separate equal basenames.
    /// When unset, backups are created next to the original file.
    pub backup_dir: Option<RemotePath>,
}

/// Creates and restores remote configuration backups over SSH.
///
/// Backups are created by reading the original file and writing the same bytes to a
/// new validated path. No shell commands are involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupManager {
    options: BackupManagerOptions,
}

impl BackupManager {
    /// Creates a manager with default options (backup next to the original file).
    pub fn new() -> Self {
        Self {
            options: BackupManagerOptions::default(),
        }
    }

    /// Creates a manager with the given options.
    pub fn with_options(options: BackupManagerOptions) -> Self {
        Self { options }
    }

    /// Returns the configured options.
    pub fn options(&self) -> &BackupManagerOptions {
        &self.options
    }

    /// Reads a remote configuration file and stores an timestamped backup copy.
    pub async fn create_backup<S: SshSession>(
        &self,
        session: &S,
        original_path: &RemotePath,
    ) -> AppResult<ConfigBackup> {
        info!(
            target: "remote",
            host = %session.profile().host,
            user = %session.profile().username,
            path = %original_path.as_str(),
            "creating remote config backup"
        );

        let contents = session
            .read_file(original_path)
            .await
            .map_err(app_error_from_ssh)?;

        let created_at_unix = current_unix_timestamp()?;
        let candidates = (0..8).map(|_| self.resolve_backup_path(original_path, created_at_unix));
        let backup_path = store_backup(session, &contents, candidates).await?;

        info!(
            target: "remote",
            host = %session.profile().host,
            user = %session.profile().username,
            original = %original_path.as_str(),
            backup = %backup_path.as_str(),
            bytes = contents.len(),
            "remote config backup stored"
        );

        Ok(ConfigBackup::new(
            original_path.clone(),
            backup_path,
            created_at_unix,
            contents.len(),
        ))
    }

    /// Restores the original configuration file from a previously created backup.
    pub async fn restore_backup<S: SshSession>(
        &self,
        session: &S,
        backup: &ConfigBackup,
    ) -> AppResult<()> {
        info!(
            target: "remote",
            host = %session.profile().host,
            user = %session.profile().username,
            original = %backup.original_path.as_str(),
            backup = %backup.backup_path.as_str(),
            "restoring remote config from backup"
        );

        let contents = session
            .read_file(&backup.backup_path)
            .await
            .map_err(app_error_from_ssh)?;

        if contents.len() != backup.size_bytes {
            warn!(
                target: "remote",
                expected = backup.size_bytes,
                actual = contents.len(),
                backup = %backup.backup_path.as_str(),
                "backup size mismatch during restore"
            );
            return Err(AppError::new(format!(
                "backup size mismatch for {}: expected {} bytes, found {}",
                backup.backup_path.as_str(),
                backup.size_bytes,
                contents.len()
            )));
        }

        session
            .write_file_atomic(&backup.original_path, &contents)
            .await
            .map_err(app_error_from_ssh)?;

        info!(
            target: "remote",
            host = %session.profile().host,
            user = %session.profile().username,
            path = %backup.original_path.as_str(),
            "remote config restored"
        );

        Ok(())
    }

    /// Lists previously created backups for `original_path`, newest first (Roadmap §3:127 —
    /// Rollback UI). Read-only: a single remote `find` in the resolved backup directory,
    /// matching both legacy timestamp names and path-scoped UUID names.
    /// Entries whose filename does not match a supported timestamp/identity format
    /// are silently skipped (defensive against a foreign file that happens to match
    /// the glob, or a `find` implementation without GNU `-printf` support).
    pub async fn list_backups<S: SshSession>(
        &self,
        session: &S,
        original_path: &RemotePath,
    ) -> AppResult<Vec<ConfigBackup>> {
        let file_name = remote_file_name(original_path)?;
        let dir = match &self.options.backup_dir {
            Some(backup_dir) => backup_dir.as_str().to_owned(),
            None => remote_parent_dir(original_path)?.to_owned(),
        };
        let prefix = format!("{file_name}{BACKUP_SUFFIX}.");
        let pattern = format!("{prefix}*");

        let command = RemoteCommand::new(
            "find",
            vec![
                dir.clone(),
                "-maxdepth".to_owned(),
                "1".to_owned(),
                "-type".to_owned(),
                "f".to_owned(),
                "-name".to_owned(),
                pattern,
                "-printf".to_owned(),
                "%s\t%f\n".to_owned(),
            ],
        )
        .map_err(app_error_from_ssh)?;

        info!(
            target: "remote",
            host = %session.profile().host,
            user = %session.profile().username,
            dir = %dir,
            original = %original_path.as_str(),
            "listing remote config backups"
        );

        let result = session.exec(&command).await.map_err(app_error_from_ssh)?;
        if result.exit_code != 0 {
            let detail = String::from_utf8_lossy(&result.stderr);
            return Err(AppError::new(format!(
                "failed to list backups in {dir}: {}",
                detail.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&result.stdout);
        let mut backups = Vec::new();
        for line in stdout.lines() {
            let Some((size_str, name)) = line.split_once('\t') else {
                continue;
            };
            let Ok(size_bytes) = size_str.parse::<usize>() else {
                continue;
            };
            let Some(timestamp_str) = name.strip_prefix(&prefix) else {
                continue;
            };
            let Some(created_at_unix) = parse_backup_timestamp(timestamp_str, original_path) else {
                continue;
            };
            let Ok(backup_path) = join_remote_path(&dir, name) else {
                continue;
            };
            backups.push(ConfigBackup::new(
                original_path.clone(),
                backup_path,
                created_at_unix,
                size_bytes,
            ));
        }
        backups.sort_by_key(|backup| std::cmp::Reverse(backup.created_at_unix));

        Ok(backups)
    }

    /// Generates a fresh backup path for an original file without performing remote I/O.
    pub fn resolve_backup_path(
        &self,
        original_path: &RemotePath,
        created_at_unix: u64,
    ) -> AppResult<RemotePath> {
        let file_name = remote_file_name(original_path)?;
        let backup_file_name = format!(
            "{file_name}{BACKUP_SUFFIX}.{created_at_unix}.{}.{}",
            path_digest(original_path),
            Uuid::new_v4().simple()
        );

        let backup_path = if let Some(backup_dir) = &self.options.backup_dir {
            join_remote_path(backup_dir.as_str(), &backup_file_name)?
        } else {
            let parent = remote_parent_dir(original_path)?;
            join_remote_path(parent, &backup_file_name)?
        };

        if backup_path.as_str() == original_path.as_str() {
            return Err(AppError::new(
                "backup path must differ from the original configuration path",
            ));
        }

        Ok(backup_path)
    }
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}

// Exclusive creation is the authority: a preflight existence check cannot prevent
// races with other clients. Retry occupied candidates, never remove or overwrite
// them; propagate other failures and bound retries even against a faulty server.
async fn store_backup<S: SshSession>(
    session: &S,
    contents: &[u8],
    candidates: impl Iterator<Item = AppResult<RemotePath>>,
) -> AppResult<RemotePath> {
    for candidate in candidates.take(8) {
        let path = candidate?;
        match session.write_file(&path, contents).await {
            Ok(()) => return Ok(path),
            Err(error) => {
                if !session.path_is_file(&path).await.unwrap_or(false) {
                    return Err(app_error_from_ssh(error));
                }
            }
        }
    }
    Err(AppError::new(
        "could not create a unique backup after 8 attempts",
    ))
}

fn path_digest(path: &RemotePath) -> String {
    Sha256::digest(path.as_str().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_backup_timestamp(suffix: &str, original: &RemotePath) -> Option<u64> {
    // Legacy names have no source identity. Keep them visible for recovery;
    // new names must match the full source path, especially in a shared directory.
    if let Ok(timestamp) = suffix.parse() {
        return Some(timestamp);
    }
    let mut parts = suffix.split('.');
    let timestamp = parts.next()?.parse().ok()?;
    let digest = parts.next()?;
    let id = parts.next()?;
    if parts.next().is_some()
        || digest != path_digest(original)
        || id.len() != 32
        || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(timestamp)
}

fn current_unix_timestamp() -> AppResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| AppError::new(format!("system clock is before unix epoch: {error}")))
}

fn remote_file_name(path: &RemotePath) -> AppResult<&str> {
    path.as_str()
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            AppError::new(format!(
                "remote path has no file name component: {}",
                path.as_str()
            ))
        })
}

fn remote_parent_dir(path: &RemotePath) -> AppResult<&str> {
    let value = path.as_str();
    let Some((parent, file_name)) = value.rsplit_once('/') else {
        return Err(AppError::new(format!(
            "remote path has no parent directory: {value}"
        )));
    };

    if file_name.is_empty() {
        return Err(AppError::new(format!(
            "remote path must point to a file, not a directory: {value}"
        )));
    }

    if parent.is_empty() {
        Ok("/")
    } else {
        Ok(parent)
    }
}

fn join_remote_path(dir: &str, file_name: &str) -> AppResult<RemotePath> {
    if file_name.is_empty() {
        return Err(AppError::new("backup file name must not be empty"));
    }

    if file_name.contains('/') {
        return Err(AppError::new(format!(
            "backup file name must not contain path separators: {file_name}"
        )));
    }

    let joined = if dir.ends_with('/') {
        format!("{dir}{file_name}")
    } else {
        format!("{dir}/{file_name}")
    };

    RemotePath::new(joined).map_err(app_error_from_ssh)
}

fn app_error_from_ssh(error: feldjaeger_ssh::SshError) -> AppError {
    AppError::new(error.message())
}

#[cfg(test)]
mod tests {
    use super::*;
    use feldjaeger_ssh::ConnectionProfile;
    use std::collections::HashMap;
    use std::future;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockSession {
        profile: ConnectionProfile,
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        exec_result: Arc<Mutex<Option<feldjaeger_ssh::ExecResult>>>,
    }

    impl MockSession {
        fn new(files: HashMap<String, Vec<u8>>) -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                files: Arc::new(Mutex::new(files)),
                exec_result: Arc::new(Mutex::new(None)),
            }
        }

        fn with_exec_stdout(self, stdout: &str) -> Self {
            *self.exec_result.lock().unwrap() = Some(feldjaeger_ssh::ExecResult {
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
            });
            self
        }
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        fn read_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<Vec<u8>>> + Send {
            let result = self
                .files
                .lock()
                .unwrap()
                .get(path.as_str())
                .cloned()
                .ok_or_else(|| {
                    feldjaeger_ssh::SshError::new(format!("file not found: {}", path.as_str()))
                });
            future::ready(result)
        }

        fn write_file(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            let mut files = self.files.lock().unwrap();
            if files.contains_key(path.as_str()) {
                return future::ready(Err(feldjaeger_ssh::SshError::new("file exists")));
            }
            files.insert(path.as_str().to_owned(), contents.to_vec());
            future::ready(Ok(()))
        }

        fn write_file_atomic(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.files
                .lock()
                .unwrap()
                .insert(path.as_str().to_owned(), contents.to_vec());
            future::ready(Ok(()))
        }

        fn rename_file(
            &self,
            from: &RemotePath,
            to: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            let mut files = self.files.lock().unwrap();
            let contents = match files.remove(from.as_str()) {
                Some(value) => value,
                None => {
                    return future::ready(Err(feldjaeger_ssh::SshError::new(format!(
                        "file not found: {}",
                        from.as_str()
                    ))));
                }
            };
            files.insert(to.as_str().to_owned(), contents);
            future::ready(Ok(()))
        }

        fn remove_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.files.lock().unwrap().remove(path.as_str());
            future::ready(Ok(()))
        }

        fn path_is_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<bool>> + Send {
            let is_file = self.files.lock().unwrap().contains_key(path.as_str());
            future::ready(Ok(is_file))
        }

        fn exec(
            &self,
            _command: &feldjaeger_ssh::RemoteCommand,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send
        {
            let result =
                self.exec_result.lock().unwrap().clone().ok_or_else(|| {
                    feldjaeger_ssh::SshError::new("exec not supported in mock session")
                });
            future::ready(result)
        }

        fn exec_with_stdin(
            &self,
            command: &feldjaeger_ssh::RemoteCommand,
            stdin: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send
        {
            let _ = stdin;
            self.exec(command)
        }

        fn disconnect(self) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    fn path(value: &str) -> RemotePath {
        RemotePath::new(value).expect("valid test path")
    }

    #[test]
    fn resolve_backup_path_next_to_original() {
        let manager = BackupManager::new();
        let original = path("/etc/xray/config.json");
        let backup = manager
            .resolve_backup_path(&original, 1_700_000_000)
            .expect("backup path should resolve");

        assert!(
            backup
                .as_str()
                .starts_with("/etc/xray/config.json.feldjaeger.bak.1700000000.")
        );
        assert_ne!(
            backup,
            manager
                .resolve_backup_path(&original, 1_700_000_000)
                .unwrap()
        );
    }

    #[test]
    fn resolve_backup_path_in_backup_dir() {
        let manager = BackupManager::with_options(BackupManagerOptions {
            backup_dir: Some(path("/var/backups/feldjaeger")),
        });
        let original = path("/etc/xray/config.json");
        let backup = manager
            .resolve_backup_path(&original, 1_700_000_000)
            .expect("backup path should resolve");

        assert!(
            backup
                .as_str()
                .starts_with("/var/backups/feldjaeger/config.json.feldjaeger.bak.1700000000.")
        );
    }

    #[tokio::test]
    async fn create_backup_copies_remote_file() {
        let original = path("/etc/xray/config.json");
        let mut files = HashMap::new();
        files.insert(original.as_str().to_owned(), b"{\"inbounds\":[]}".to_vec());

        let session = MockSession::new(files);
        let manager = BackupManager::new();
        let backup = manager
            .create_backup(&session, &original)
            .await
            .expect("backup should succeed");

        assert_eq!(backup.original_path, original);
        assert_eq!(backup.size_bytes, b"{\"inbounds\":[]}".len());
        assert!(backup.backup_path.as_str().contains(BACKUP_SUFFIX));

        let files = session.files.lock().unwrap();
        let stored = files
            .get(backup.backup_path.as_str())
            .expect("backup file should exist");
        assert_eq!(stored, b"{\"inbounds\":[]}");
    }

    #[tokio::test]
    async fn restore_backup_reverts_original_file() {
        let original = path("/etc/xray/config.json");
        let mut files = HashMap::new();
        files.insert(original.as_str().to_owned(), b"original".to_vec());

        let session = MockSession::new(files);
        let manager = BackupManager::new();
        let backup = manager
            .create_backup(&session, &original)
            .await
            .expect("backup should succeed");

        session
            .files
            .lock()
            .unwrap()
            .insert(original.as_str().to_owned(), b"modified".to_vec());

        manager
            .restore_backup(&session, &backup)
            .await
            .expect("restore should succeed");

        let files = session.files.lock().unwrap();
        let restored = files
            .get(original.as_str())
            .expect("original file should exist");
        assert_eq!(restored, b"original");
    }

    #[tokio::test]
    async fn create_backup_fails_when_original_missing() {
        let session = MockSession::new(HashMap::new());
        let manager = BackupManager::new();
        let error = manager
            .create_backup(&session, &path("/etc/xray/config.json"))
            .await
            .expect_err("missing original should fail");

        assert!(error.message().contains("file not found"));
    }

    #[tokio::test]
    async fn restore_backup_fails_on_size_mismatch() {
        let original = path("/etc/xray/config.json");
        let backup_path = path("/etc/xray/config.json.feldjaeger.bak.1700000000");
        let mut files = HashMap::new();
        files.insert(backup_path.as_str().to_owned(), b"changed".to_vec());

        let session = MockSession::new(files);
        let manager = BackupManager::new();
        let backup = ConfigBackup::new(original, backup_path, 1_700_000_000, 100);

        let error = manager
            .restore_backup(&session, &backup)
            .await
            .expect_err("size mismatch should fail");

        assert!(error.message().contains("backup size mismatch"));
    }

    #[tokio::test]
    async fn list_backups_parses_and_sorts_newest_first() {
        // Roadmap §3:127: Rollback UI needs a listing of previously created backups.
        let original = path("/etc/xray/config.json");
        let session = MockSession::new(HashMap::new()).with_exec_stdout(
            "15\tconfig.json.feldjaeger.bak.1700000000\n\
             20\tconfig.json.feldjaeger.bak.1700000100\n\
             not-a-number\tconfig.json.feldjaeger.bak.bogus\n\
             10\tunrelated.json.feldjaeger.bak.1700000050\n",
        );
        let manager = BackupManager::new();

        let backups = manager
            .list_backups(&session, &original)
            .await
            .expect("list should succeed");

        // The "unrelated.json" line matches a different original file's naming and the
        // "bogus" timestamp line is unparseable — both must be skipped, not just the target.
        assert_eq!(backups.len(), 2);
        assert_eq!(backups[0].created_at_unix, 1_700_000_100);
        assert_eq!(backups[0].size_bytes, 20);
        assert_eq!(
            backups[0].backup_path.as_str(),
            "/etc/xray/config.json.feldjaeger.bak.1700000100"
        );
        assert_eq!(backups[1].created_at_unix, 1_700_000_000);
        assert_eq!(backups[0].original_path, original);
    }

    #[tokio::test]
    async fn occupied_candidate_is_preserved_and_retried() {
        let occupied = path("/backup/occupied");
        let fresh = path("/backup/fresh");
        let session = MockSession::new(HashMap::from([(
            occupied.as_str().to_owned(),
            b"first version".to_vec(),
        )]));
        let stored = store_backup(
            &session,
            b"second version",
            vec![Ok(occupied.clone()), Ok(fresh.clone())].into_iter(),
        )
        .await
        .unwrap();
        assert_eq!(stored, fresh);
        let files = session.files.lock().unwrap();
        assert_eq!(files[occupied.as_str()], b"first version");
        assert_eq!(files[fresh.as_str()], b"second version");
    }

    #[tokio::test]
    async fn collisions_have_a_bounded_retry_budget() {
        let occupied = path("/backup/occupied");
        let session = MockSession::new(HashMap::from([(
            occupied.as_str().to_owned(),
            b"original".to_vec(),
        )]));
        let error = store_backup(&session, b"new", std::iter::repeat(Ok(occupied.clone())))
            .await
            .unwrap_err();
        assert!(error.message().contains("8 attempts"));
        assert_eq!(
            session.files.lock().unwrap()[occupied.as_str()],
            b"original"
        );
    }

    #[tokio::test]
    async fn concurrent_backups_in_shared_directory_remain_distinct() {
        let a = path("/a/config.json");
        let b = path("/b/config.json");
        let session = MockSession::new(HashMap::from([
            (a.as_str().to_owned(), b"version a".to_vec()),
            (b.as_str().to_owned(), b"version b".to_vec()),
        ]));
        let manager = BackupManager::with_options(BackupManagerOptions {
            backup_dir: Some(path("/backup")),
        });
        let (first, second, third) = tokio::join!(
            manager.create_backup(&session, &a),
            manager.create_backup(&session, &a),
            manager.create_backup(&session, &b),
        );
        let backups = [first.unwrap(), second.unwrap(), third.unwrap()];
        let files = session.files.lock().unwrap();
        for (index, backup) in backups.iter().enumerate() {
            assert_eq!(
                files[backup.backup_path.as_str()],
                if index == 2 {
                    b"version b"
                } else {
                    b"version a"
                }
            );
            for other in &backups[..index] {
                assert_ne!(backup.backup_path, other.backup_path);
            }
        }
    }

    #[tokio::test]
    async fn listing_filters_new_names_by_source_and_preserves_legacy() {
        let original = path("/a/config.json");
        let other = path("/b/config.json");
        let manager = BackupManager::with_options(BackupManagerOptions {
            backup_dir: Some(path("/backup")),
        });
        let own = manager.resolve_backup_path(&original, 200).unwrap();
        let foreign = manager.resolve_backup_path(&other, 300).unwrap();
        let stdout = format!(
            "10\t{}\n20\t{}\n30\tconfig.json.feldjaeger.bak.100\n40\tconfig.json.feldjaeger.bak.400.bad.invalid\n",
            remote_file_name(&own).unwrap(),
            remote_file_name(&foreign).unwrap()
        );
        let session = MockSession::new(HashMap::new()).with_exec_stdout(&stdout);
        let backups = manager.list_backups(&session, &original).await.unwrap();
        assert_eq!(backups.len(), 2);
        assert_eq!(backups[0].backup_path, own);
        assert_eq!(backups[1].created_at_unix, 100);
    }

    #[tokio::test]
    async fn list_backups_empty_when_none_found() {
        let session = MockSession::new(HashMap::new()).with_exec_stdout("");
        let manager = BackupManager::new();
        let backups = manager
            .list_backups(&session, &path("/etc/xray/config.json"))
            .await
            .expect("list should succeed");
        assert!(backups.is_empty());
    }
}
