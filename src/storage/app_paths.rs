//! Platform-specific application directories shared by config and logging.

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::error::{AppError, AppResult};

use super::config_manager::CONFIG_FILE_NAME;

/// Qualifier / organization / application identifiers for [`directories`].
pub(crate) const QUALIFIER: &str = "";
pub(crate) const ORGANIZATION: &str = "";
pub(crate) const APPLICATION: &str = "Feldjaeger";

/// File name of the application log.
pub const LOG_FILE_NAME: &str = "feldjaeger.log";

/// Subdirectory under the application data root that stores log files.
pub const LOG_DIR_NAME: &str = "logs";

/// Resolved platform paths for Feldjäger local state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    config_file: PathBuf,
    log_dir: PathBuf,
}

impl AppPaths {
    /// Resolves platform directories for the current user.
    pub fn resolve() -> AppResult<Self> {
        let dirs = project_dirs()?;
        Ok(Self::from_project_dirs(&dirs))
    }

    /// Builds paths from an already-resolved [`ProjectDirs`] instance.
    pub fn from_project_dirs(dirs: &ProjectDirs) -> Self {
        Self {
            config_file: dirs.config_dir().join(CONFIG_FILE_NAME),
            log_dir: log_dir_from_data_local(dirs.data_local_dir()),
        }
    }

    /// Creates paths pointing at an explicit application root (useful for tests).
    ///
    /// Layout:
    /// - `{root}/config/{CONFIG_FILE_NAME}`
    /// - `{root}/logs/{LOG_FILE_NAME}`
    pub fn for_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config_file: root.join("config").join(CONFIG_FILE_NAME),
            log_dir: root.join(LOG_DIR_NAME),
        }
    }

    /// Platform path of `config.json`.
    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    /// Platform directory that contains application log files.
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// Full path of the primary application log file.
    pub fn log_file(&self) -> PathBuf {
        self.log_dir.join(LOG_FILE_NAME)
    }
}

fn project_dirs() -> AppResult<ProjectDirs> {
    ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
        .ok_or_else(|| AppError::new("unable to determine application directories"))
}

/// Maps `directories` data-local directory onto the application log directory.
///
/// On Windows `data_local_dir` ends with a `data` component
/// (`%LOCALAPPDATA%\Feldjaeger\data`). Logs live next to that root:
/// `%LOCALAPPDATA%\Feldjaeger\logs`.
///
/// On Linux/macOS `data_local_dir` is already the application root
/// (`~/.local/share/feldjaeger` / `~/Library/Application Support/Feldjaeger`),
/// so logs are placed underneath it.
pub(crate) fn log_dir_from_data_local(data_local: &Path) -> PathBuf {
    let app_root = data_local
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.eq_ignore_ascii_case("data"))
        .and_then(|_| data_local.parent())
        .unwrap_or(data_local);
    app_root.join(LOG_DIR_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_dir_strips_windows_data_suffix() {
        let data_local = PathBuf::from(r"C:\Users\test\AppData\Local\Feldjaeger\data");
        assert_eq!(
            log_dir_from_data_local(&data_local),
            PathBuf::from(r"C:\Users\test\AppData\Local\Feldjaeger\logs")
        );
    }

    #[test]
    fn log_dir_under_linux_style_root() {
        let data_local = PathBuf::from("/home/user/.local/share/feldjaeger");
        assert_eq!(
            log_dir_from_data_local(&data_local),
            PathBuf::from("/home/user/.local/share/feldjaeger/logs")
        );
    }

    #[test]
    fn for_root_layout() {
        let paths = AppPaths::for_root(PathBuf::from("/tmp/feldjaeger-root"));
        assert_eq!(
            paths.config_file(),
            Path::new("/tmp/feldjaeger-root/config/config.json")
        );
        assert_eq!(
            paths.log_file(),
            PathBuf::from("/tmp/feldjaeger-root/logs/feldjaeger.log")
        );
    }

    #[test]
    fn resolve_returns_feldjaeger_named_paths() {
        let paths = AppPaths::resolve().expect("platform dirs");
        let config = paths.config_file().to_string_lossy().to_ascii_lowercase();
        let log_dir = paths.log_dir().to_string_lossy().to_ascii_lowercase();
        assert!(config.contains("feldjaeger"));
        assert!(config.ends_with("config.json"));
        assert!(log_dir.contains("feldjaeger"));
        assert!(
            log_dir.ends_with("logs") || log_dir.ends_with("logs/") || log_dir.ends_with("logs\\")
        );
        assert_eq!(
            paths.log_file().file_name().and_then(|n| n.to_str()),
            Some(LOG_FILE_NAME)
        );
    }
}
