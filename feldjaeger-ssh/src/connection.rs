//! SSH connection and authentication models.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Supported authentication methods for SSH connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AuthMethod {
    /// Password-based authentication.
    #[default]
    Password,
    /// Private key file authentication.
    PrivateKey,
}

impl AuthMethod {
    /// Human-readable label for UI controls.
    pub fn label(self) -> &'static str {
        match self {
            Self::Password => "Password",
            Self::PrivateKey => "Private key",
        }
    }
}

/// Non-secret connection parameters for a remote server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionProfile {
    /// Hostname or IP address of the remote server.
    pub host: String,
    /// SSH port (typically 22).
    pub port: u16,
    /// Remote username.
    pub username: String,
}

impl ConnectionProfile {
    /// Creates a new connection profile.
    pub fn new(host: impl Into<String>, port: u16, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
        }
    }
}

/// Secret credentials used to authenticate an SSH connection.
///
/// Values must never be written to logs. [`fmt::Debug`] redacts sensitive fields.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthCredentials {
    /// Password authentication.
    Password(String),
    /// Private key file, optionally protected by a passphrase.
    PrivateKey {
        /// Path to the private key file on the local machine.
        key_path: PathBuf,
        /// Optional passphrase for the private key.
        passphrase: Option<String>,
    },
}

impl fmt::Debug for AuthCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.debug_tuple("Password").field(&"[REDACTED]").finish(),
            Self::PrivateKey {
                key_path,
                passphrase,
            } => f
                .debug_struct("PrivateKey")
                .field("key_path", key_path)
                .field("passphrase", &passphrase.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

impl AuthCredentials {
    /// Returns the authentication method implied by these credentials.
    pub fn method(&self) -> AuthMethod {
        match self {
            Self::Password(_) => AuthMethod::Password,
            Self::PrivateKey { .. } => AuthMethod::PrivateKey,
        }
    }
}

/// Full connection request combining profile and credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    /// Non-secret connection parameters.
    pub profile: ConnectionProfile,
    /// Secret credentials for authentication.
    pub credentials: AuthCredentials,
}

impl ConnectRequest {
    /// Creates a new connection request.
    pub fn new(profile: ConnectionProfile, credentials: AuthCredentials) -> Self {
        Self {
            profile,
            credentials,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_credentials_debug_redacts_secrets() {
        let password = AuthCredentials::Password("super-secret-password".to_owned());
        let password_debug = format!("{password:?}");
        assert!(password_debug.contains("[REDACTED]"));
        assert!(!password_debug.contains("super-secret-password"));

        let key = AuthCredentials::PrivateKey {
            key_path: PathBuf::from("/tmp/id_ed25519"),
            passphrase: Some("super-secret-passphrase".to_owned()),
        };
        let key_debug = format!("{key:?}");
        assert!(key_debug.contains("[REDACTED]"));
        assert!(!key_debug.contains("super-secret-passphrase"));

        let request = ConnectRequest::new(
            ConnectionProfile::new("192.0.2.10", 22, "root"),
            AuthCredentials::Password("must-not-appear".to_owned()),
        );
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("must-not-appear"));
    }
}
