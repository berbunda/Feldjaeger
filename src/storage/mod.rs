//! Local non-secret application configuration storage.
//!
//! Secrets (passwords, passphrases, tokens) must never be stored here.
//! Use the platform credential store instead.

mod app_config;
mod app_paths;
mod config_manager;
mod connection_profile;

pub use app_config::{AppConfig, ThemeMode, UiConfig, WindowPosition, WindowSize};
pub use app_paths::{AppPaths, LOG_DIR_NAME, LOG_FILE_NAME};
pub use config_manager::{CONFIG_FILE_NAME, ConfigManager};
pub use connection_profile::{
    ConnectionDraft, ConnectionValidationErrors, DEFAULT_SSH_PORT, StoredConnectionProfile,
};
