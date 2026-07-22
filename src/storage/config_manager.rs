//! Load and save the local application configuration file.

use std::fs;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::error::{AppError, AppResult};

use super::app_config::AppConfig;
use super::app_paths::AppPaths;

/// File name of the application configuration.
pub const CONFIG_FILE_NAME: &str = "config.json";

/// Loads, validates, and persists [`AppConfig`].
///
/// The GUI must never read or write `config.json` directly; all access goes
/// through this type (typically via [`crate::app::ApplicationService`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigManager {
    path: PathBuf,
    config: AppConfig,
}

impl ConfigManager {
    /// Loads configuration from the platform config directory.
    ///
    /// If the file is missing, a default configuration is created and saved.
    /// If the file is malformed, it is renamed to `config.json.bak`, a default
    /// configuration is written, and the problem is logged.
    pub fn load() -> AppResult<Self> {
        let path = Self::default_config_path()?;
        Self::load_from(path)
    }

    /// Loads configuration from an explicit path (useful for tests).
    pub fn load_from(path: PathBuf) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::new(format!(
                    "failed to create config directory {}: {error}",
                    parent.display()
                ))
            })?;
        }

        if !path.exists() {
            info!(
                target: "config",
                path = %path.display(),
                "config file not found; creating default configuration"
            );
            let manager = Self::with_defaults(path);
            manager.save()?;
            return Ok(manager);
        }

        match Self::read_config(&path) {
            Ok(config) => Ok(Self { path, config }),
            Err(error) => {
                warn!(
                    target: "config",
                    path = %path.display(),
                    error = %crate::logging::redact::sanitize_detail(&error.to_string()),
                    "config file is malformed; backing up and recreating defaults"
                );
                Self::backup_malformed_config(&path)?;
                let manager = Self::with_defaults(path);
                manager.save()?;
                Ok(manager)
            }
        }
    }

    /// Creates an in-memory manager with default values for the given path.
    ///
    /// Does not write to disk until [`Self::save`] is called.
    pub fn with_defaults(path: PathBuf) -> Self {
        Self {
            path,
            config: AppConfig::default(),
        }
    }

    /// Writes the current configuration to disk.
    pub fn save(&self) -> AppResult<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::new(format!(
                    "failed to create config directory {}: {error}",
                    parent.display()
                ))
            })?;
        }

        let json = serde_json::to_string_pretty(&self.config).map_err(|error| {
            AppError::new(format!("failed to serialize application config: {error}"))
        })?;

        fs::write(&self.path, json).map_err(|error| {
            AppError::new(format!(
                "failed to write config file {}: {error}",
                self.path.display()
            ))
        })?;

        Ok(())
    }

    /// Returns the path of the configuration file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the loaded configuration.
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    ///
    /// Call [`Self::save`] after mutating to persist changes.
    pub fn config_mut(&mut self) -> &mut AppConfig {
        &mut self.config
    }

    /// Replaces the in-memory configuration and saves it.
    pub fn replace_and_save(&mut self, config: AppConfig) -> AppResult<()> {
        self.config = config;
        self.save()
    }

    /// Platform-specific path of `config.json`.
    pub fn default_config_path() -> AppResult<PathBuf> {
        Ok(AppPaths::resolve()?.config_file().to_path_buf())
    }

    fn read_config(path: &Path) -> AppResult<AppConfig> {
        let contents = fs::read_to_string(path).map_err(|error| {
            AppError::new(format!(
                "failed to read config file {}: {error}",
                path.display()
            ))
        })?;

        // Missing fields are filled via `#[serde(default)]` on AppConfig / UiConfig.
        serde_json::from_str(&contents).map_err(|error| {
            AppError::new(format!(
                "failed to parse config file {}: {error}",
                path.display()
            ))
        })
    }

    fn backup_malformed_config(path: &Path) -> AppResult<()> {
        let backup_path = path.with_extension("json.bak");
        if backup_path.exists() {
            let mut index = 1u32;
            loop {
                let candidate = path.with_extension(format!("json.bak.{index}"));
                if !candidate.exists() {
                    fs::rename(path, &candidate).map_err(|error| {
                        AppError::new(format!(
                            "failed to back up malformed config {} -> {}: {error}",
                            path.display(),
                            candidate.display()
                        ))
                    })?;
                    warn!(
                        target: "config",
                        path = %candidate.display(),
                        "malformed config backed up"
                    );
                    return Ok(());
                }
                index = index.saturating_add(1);
            }
        }

        fs::rename(path, &backup_path).map_err(|error| {
            AppError::new(format!(
                "failed to back up malformed config {} -> {}: {error}",
                path.display(),
                backup_path.display()
            ))
        })?;
        warn!(
            target: "config",
            path = %backup_path.display(),
            "malformed config backed up"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{ThemeMode, WindowSize};

    fn temp_config_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "feldjaeger-config-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir.join(CONFIG_FILE_NAME)
    }

    #[test]
    fn creates_default_when_missing() {
        let path = temp_config_path("missing");
        let manager = ConfigManager::load_from(path.clone()).expect("load");
        assert!(path.exists());
        assert_eq!(manager.config().ui.theme, ThemeMode::System);
        assert_eq!(manager.config().ui.last_page, "Dashboard");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn fills_missing_fields_with_defaults() {
        let path = temp_config_path("partial");
        fs::write(&path, r#"{"ui":{"sidebar_width":220.0}}"#).expect("write");
        let manager = ConfigManager::load_from(path.clone()).expect("load");
        assert!((manager.config().ui.sidebar_width - 220.0).abs() < f32::EPSILON);
        assert_eq!(manager.config().ui.window_size, WindowSize::default());
        assert_eq!(manager.config().ui.theme, ThemeMode::System);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn backs_up_malformed_config() {
        let path = temp_config_path("malformed");
        fs::write(&path, "{ not json").expect("write");
        let manager = ConfigManager::load_from(path.clone()).expect("load");
        assert_eq!(manager.config().ui.last_page, "Dashboard");
        assert!(path.exists());
        assert!(path.with_extension("json.bak").exists());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn round_trip_save_load() {
        let path = temp_config_path("roundtrip");
        let mut manager = ConfigManager::load_from(path.clone()).expect("load");
        manager.config_mut().ui.sidebar_width = 220.0;
        manager.config_mut().ui.last_page = "Users".to_owned();
        manager.save().expect("save");

        let reloaded = ConfigManager::load_from(path.clone()).expect("reload");
        assert!((reloaded.config().ui.sidebar_width - 220.0).abs() < f32::EPSILON);
        assert_eq!(reloaded.config().ui.last_page, "Users");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
