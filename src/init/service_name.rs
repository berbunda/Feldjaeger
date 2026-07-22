//! systemd unit name validation.

use crate::error::{AppError, AppResult};

/// Validated systemd unit name safe for direct argument passing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceName {
    name: String,
}

impl ServiceName {
    /// Creates a service name after validation.
    pub fn new(name: impl Into<String>) -> AppResult<Self> {
        let name = name.into();
        validate_service_name(&name)?;
        Ok(Self { name })
    }

    /// Returns the validated service name.
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

/// Validates a systemd unit name before it is passed to init-system commands.
pub fn validate_service_name(name: &str) -> AppResult<()> {
    if name.is_empty() {
        return Err(AppError::new("service name must not be empty"));
    }

    if name.len() > 256 {
        return Err(AppError::new("service name is too long"));
    }

    if name.chars().any(char::is_whitespace) {
        return Err(AppError::new("service name must not contain whitespace"));
    }

    if name.contains('/') || name.contains('\\') {
        return Err(AppError::new(
            "service name must not contain path separators",
        ));
    }

    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(AppError::new("service name must not be empty"));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(AppError::new(
            "service name must start with an alphanumeric character",
        ));
    }

    if !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '@')) {
        return Err(AppError::new(
            "service name contains unsupported characters",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_service_names() {
        assert!(validate_service_name("xray").is_ok());
        assert!(validate_service_name("xray.service").is_ok());
        assert!(validate_service_name("xray@instance").is_ok());
    }

    #[test]
    fn rejects_unsafe_service_names() {
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name("xray; rm -rf /").is_err());
        assert!(validate_service_name("../xray").is_err());
        assert!(validate_service_name("x ray").is_err());
        assert!(validate_service_name("-Hroot@evil.example").is_err());
        assert!(validate_service_name("--help").is_err());
        assert!(validate_service_name("@instance").is_err());
    }
}
