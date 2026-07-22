//! Xray configuration validation.

use super::XrayConfigSections;
use crate::error::AppResult;

/// Validates Xray configuration before a service restart.
///
/// Validation must always run before applying changes and restarting the service.
pub trait ConfigValidator {
    /// Validates the given configuration and returns an error if it is invalid.
    fn validate(&self, config: &XrayConfigSections) -> AppResult<()>;
}

/// Default validator stub used until full validation is implemented.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultConfigValidator;

impl DefaultConfigValidator {
    /// Creates a new default validator.
    pub fn new() -> Self {
        Self
    }
}

impl ConfigValidator for DefaultConfigValidator {
    fn validate(&self, _config: &XrayConfigSections) -> AppResult<()> {
        Ok(())
    }
}
