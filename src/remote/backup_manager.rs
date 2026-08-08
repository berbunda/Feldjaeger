//! Remote configuration backup manager.

use std::time::{SystemTime, UNIX_EPOCH};

use feldjaeger_ssh::{RemotePath, SshSession};
use tracing::{info, warn};

use super::ConfigBackup;
use crate::error::{AppError, AppResult};

const BACKUP_SUFFIX: &str = ".feldjaeger.bak";

/// Configuration for [`BackupManager`] path layout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupManagerOptions {
    /// Optional dedicated directory where backup files are stored.
    ///
    /// When set, only the basename of the original file is appended to this directory.
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
        let backup_path = self.resolve_backup_path(original_path, created_at_unix)?;

        session
            .write_file(&backup_path, &contents)
            .await
            .map_err(app_error_from_ssh)?;

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

    /// Computes the backup path for an original file without performing I/O.
    pub fn resolve_backup_path(
        &self,
        original_path: &RemotePath,
        created_at_unix: u64,
    ) -> AppResult<RemotePath> {
        let file_name = remote_file_name(original_path)?;
        let backup_file_name = format!("{file_name}{BACKUP_SUFFIX}.{created_at_unix}");

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
    }

    impl MockSession {
        fn new(files: HashMap<String, Vec<u8>>) -> Self {
            Self {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                files: Arc::new(Mutex::new(files)),
            }
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
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.write_file(path, contents)
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
            future::ready(Err(feldjaeger_ssh::SshError::new(
                "exec not supported in mock session",
            )))
        }

    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
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

        assert_eq!(
            backup.as_str(),
            "/etc/xray/config.json.feldjaeger.bak.1700000000"
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

        assert_eq!(
            backup.as_str(),
            "/var/backups/feldjaeger/config.json.feldjaeger.bak.1700000000"
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
}
