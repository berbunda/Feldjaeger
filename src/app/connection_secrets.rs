//! In-memory connection secrets that must never be persisted.

use std::fmt;

/// Secret credential fields for the Connection page.
///
/// Values exist only in process memory. They are never written to `config.json`,
/// never included in Status Bar text, and are redacted in [`fmt::Debug`].
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ConnectionSecrets {
    /// Password for password authentication.
    password: String,
    /// Passphrase for an encrypted private key.
    passphrase: String,
}

impl ConnectionSecrets {
    /// Creates empty secrets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the password (may be empty).
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the private key passphrase (may be empty).
    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Sets the password.
    pub fn set_password(&mut self, password: impl Into<String>) {
        self.password = password.into();
    }

    /// Sets the private key passphrase.
    pub fn set_passphrase(&mut self, passphrase: impl Into<String>) {
        self.passphrase = passphrase.into();
    }

    /// Mutable access to the password field for UI binding.
    pub fn password_mut(&mut self) -> &mut String {
        &mut self.password
    }

    /// Mutable access to the passphrase field for UI binding.
    pub fn passphrase_mut(&mut self) -> &mut String {
        &mut self.passphrase
    }

    /// Clears all secret values from memory.
    pub fn clear(&mut self) {
        self.password.clear();
        self.passphrase.clear();
    }
}

impl fmt::Debug for ConnectionSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSecrets")
            .field("password", &"[REDACTED]")
            .field("passphrase", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secrets() {
        let mut secrets = ConnectionSecrets::new();
        secrets.set_password("super-secret-password");
        secrets.set_passphrase("super-secret-passphrase");
        let debug = format!("{secrets:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-password"));
        assert!(!debug.contains("super-secret-passphrase"));
    }
}
