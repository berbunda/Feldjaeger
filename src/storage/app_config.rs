//! Application configuration schema persisted in `config.json`.
//!
//! This file stores non-secret UI preferences and connection profile metadata only.
//! Passwords, passphrases, and tokens must never appear here.

use serde::{Deserialize, Serialize};

use super::connection_profile::StoredConnectionProfile;

/// Root application configuration written to `config.json`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AppConfig {
    /// User-interface preferences.
    #[serde(default)]
    pub ui: UiConfig,
    /// Non-secret SSH connection profile.
    #[serde(default)]
    pub connection: StoredConnectionProfile,
}

/// Persisted UI preferences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UiConfig {
    /// Width of the left sidebar in logical points.
    #[serde(default = "default_sidebar_width")]
    pub sidebar_width: f32,
    /// Last known inner window size.
    #[serde(default)]
    pub window_size: WindowSize,
    /// Last known outer window position, if known.
    #[serde(default)]
    pub window_position: Option<WindowPosition>,
    /// Last selected sidebar page (`Dashboard`, `Connection`, …).
    #[serde(default = "default_last_page", alias = "last_selected_page")]
    pub last_page: String,
    /// Preferred color theme. Only [`ThemeMode::System`] is applied in MVP.
    #[serde(default, alias = "theme_mode")]
    pub theme: ThemeMode,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            sidebar_width: default_sidebar_width(),
            window_size: WindowSize::default(),
            window_position: None,
            last_page: default_last_page(),
            theme: ThemeMode::System,
        }
    }
}

fn default_sidebar_width() -> f32 {
    180.0
}

fn default_last_page() -> String {
    "Dashboard".to_owned()
}

/// Inner window size in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WindowSize {
    /// Window width.
    pub width: f32,
    /// Window height.
    pub height: f32,
}

impl Default for WindowSize {
    fn default() -> Self {
        Self {
            width: 1100.0,
            height: 700.0,
        }
    }
}

/// Outer window position in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WindowPosition {
    /// Horizontal offset from the top-left of the screen.
    pub x: f32,
    /// Vertical offset from the top-left of the screen.
    pub y: f32,
}

/// Color theme preference.
///
/// MVP always renders with the system theme regardless of stored value.
/// `Light` and `Dark` are reserved for a future implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ThemeMode {
    /// Follow the operating-system theme.
    #[default]
    System,
    /// Force a light theme (not applied yet).
    Light,
    /// Force a dark theme (not applied yet).
    Dark,
}
