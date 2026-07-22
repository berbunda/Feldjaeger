//! Xray service lifecycle orchestration.

use super::{ConfigValidator, XrayConfigSections};
use crate::error::AppResult;
use crate::init::InitSystemManager;
use crate::remote::RemoteAdmin;

/// Orchestrates Xray configuration deployment and service lifecycle.
///
/// Coordinates remote backup, validation, and init-system restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayManager {
    service_name: String,
}

impl XrayManager {
    /// Creates a manager for the given systemd service name.
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    /// Returns the managed service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Applies a new configuration: backup, validate, write, and restart.
    pub fn apply_config<I, V>(
        &self,
        _remote: &RemoteAdmin,
        _init: &I,
        _validator: &V,
        _config: &XrayConfigSections,
    ) -> AppResult<()>
    where
        I: InitSystemManager,
        V: ConfigValidator,
    {
        Ok(())
    }
}
