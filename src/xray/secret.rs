//! Secret string wrapper shared across Xray features (WARP, inbound clients, …).
//!
//! Never log or `Debug`-print the inner value.

use std::fmt;

/// Secret string wrapper that redacts in [`Debug`].
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrows the secret for intentional use (never log / never show in GUI).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Consumes and returns the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = SecretString::new("super-secret");
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
        assert!(!format!("{secret:?}").contains("super-secret"));
    }
}
