//! Persisted non-secret SSH connection profile.

use feldjaeger_ssh::{AuthMethod, ConnectionProfile};
use serde::{Deserialize, Serialize};

/// Default SSH port used when creating a new profile.
pub const DEFAULT_SSH_PORT: u16 = 22;

/// Non-secret connection profile stored in `config.json`.
///
/// Secrets (password, passphrase, private key contents) must never appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConnectionProfile {
    /// User-visible profile name.
    #[serde(default)]
    pub profile_name: String,
    /// Hostname or IP address.
    #[serde(default)]
    pub host: String,
    /// SSH port (`1..=65535`).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Remote username.
    #[serde(default)]
    pub username: String,
    /// Selected authentication method.
    #[serde(default)]
    pub auth_method: AuthMethod,
    /// Local path to the private key file (used when `auth_method` is PrivateKey).
    #[serde(default)]
    pub private_key_path: String,
}

impl Default for StoredConnectionProfile {
    fn default() -> Self {
        Self {
            profile_name: String::new(),
            host: String::new(),
            port: DEFAULT_SSH_PORT,
            username: String::new(),
            auth_method: AuthMethod::Password,
            private_key_path: String::new(),
        }
    }
}

fn default_port() -> u16 {
    DEFAULT_SSH_PORT
}

impl StoredConnectionProfile {
    /// Converts this stored profile into the SSH-layer connection profile.
    pub fn to_ssh_profile(&self) -> ConnectionProfile {
        ConnectionProfile::new(self.host.clone(), self.port, self.username.clone())
    }
}

/// Editable connection form state used by [`crate::app::ApplicationService`].
///
/// Port is kept as text so out-of-range values can be validated before parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDraft {
    /// User-visible profile name.
    pub profile_name: String,
    /// Hostname or IP address.
    pub host: String,
    /// SSH port as entered by the user.
    pub port: String,
    /// Remote username.
    pub username: String,
    /// Selected authentication method.
    pub auth_method: AuthMethod,
    /// Local path to the private key file.
    pub private_key_path: String,
}

impl Default for ConnectionDraft {
    fn default() -> Self {
        Self::from_stored(&StoredConnectionProfile::default())
    }
}

impl ConnectionDraft {
    /// Creates a draft from a persisted profile.
    pub fn from_stored(profile: &StoredConnectionProfile) -> Self {
        Self {
            profile_name: profile.profile_name.clone(),
            host: profile.host.clone(),
            port: profile.port.to_string(),
            username: profile.username.clone(),
            auth_method: profile.auth_method,
            private_key_path: profile.private_key_path.clone(),
        }
    }

    /// Returns `true` when non-secret fields differ from the saved profile.
    pub fn differs_from(&self, saved: &StoredConnectionProfile) -> bool {
        self != &Self::from_stored(saved)
    }

    /// Validates the draft and, on success, builds a [`StoredConnectionProfile`].
    #[allow(clippy::result_large_err)]
    pub fn validate(&self) -> Result<StoredConnectionProfile, ConnectionValidationErrors> {
        let mut errors = ConnectionValidationErrors::default();

        if self.profile_name.trim().is_empty() {
            errors.profile_name = Some("Profile name must not be empty.".to_owned());
        }
        if self.host.trim().is_empty() {
            errors.host = Some("Host / IP address must not be empty.".to_owned());
        }

        let port = match parse_port(&self.port) {
            Ok(port) => Some(port),
            Err(message) => {
                errors.port = Some(message);
                None
            }
        };

        if self.username.trim().is_empty() {
            errors.username = Some("Username must not be empty.".to_owned());
        }

        if self.auth_method == AuthMethod::PrivateKey && self.private_key_path.trim().is_empty() {
            errors.private_key_path =
                Some("Private key path is required for private key authentication.".to_owned());
        }

        if errors.has_errors() {
            return Err(errors);
        }

        let port = port.unwrap_or(DEFAULT_SSH_PORT);

        Ok(StoredConnectionProfile {
            profile_name: self.profile_name.trim().to_owned(),
            host: self.host.trim().to_owned(),
            port,
            username: self.username.trim().to_owned(),
            auth_method: self.auth_method,
            private_key_path: self.private_key_path.trim().to_owned(),
        })
    }
}

/// Field-level validation errors for the connection form.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionValidationErrors {
    /// Error for the profile name field.
    pub profile_name: Option<String>,
    /// Error for the host field.
    pub host: Option<String>,
    /// Error for the port field.
    pub port: Option<String>,
    /// Error for the username field.
    pub username: Option<String>,
    /// Error for the private key path field.
    pub private_key_path: Option<String>,
    /// Error for the password field (connection test only).
    pub password: Option<String>,
}

impl ConnectionValidationErrors {
    /// Returns `true` when at least one field has an error.
    pub fn has_errors(&self) -> bool {
        self.profile_name.is_some()
            || self.host.is_some()
            || self.port.is_some()
            || self.username.is_some()
            || self.private_key_path.is_some()
            || self.password.is_some()
    }
}

fn parse_port(raw: &str) -> Result<u16, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Port must not be empty.".to_owned());
    }
    let value = trimmed
        .parse::<u32>()
        .map_err(|_| "Port must be a number between 1 and 65535.".to_owned())?;
    if !(1..=65535).contains(&value) {
        return Err("Port must be in the range 1..=65535.".to_owned());
    }
    u16::try_from(value).map_err(|_| "Port must be in the range 1..=65535.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_draft() -> ConnectionDraft {
        ConnectionDraft {
            profile_name: "prod".to_owned(),
            host: "192.0.2.10".to_owned(),
            port: "22".to_owned(),
            username: "root".to_owned(),
            auth_method: AuthMethod::Password,
            private_key_path: String::new(),
        }
    }

    #[test]
    fn accepts_valid_password_profile() {
        let profile = valid_draft().validate().expect("valid");
        assert_eq!(profile.profile_name, "prod");
        assert_eq!(profile.host, "192.0.2.10");
        assert_eq!(profile.port, 22);
        assert_eq!(profile.username, "root");
        assert_eq!(profile.auth_method, AuthMethod::Password);
    }

    #[test]
    fn rejects_empty_profile_name() {
        let mut draft = valid_draft();
        draft.profile_name.clear();
        let errors = draft.validate().expect_err("empty name");
        assert!(errors.profile_name.is_some());
    }

    #[test]
    fn rejects_empty_host() {
        let mut draft = valid_draft();
        draft.host.clear();
        let errors = draft.validate().expect_err("empty host");
        assert!(errors.host.is_some());
    }

    #[test]
    fn rejects_port_zero() {
        let mut draft = valid_draft();
        draft.port = "0".to_owned();
        let errors = draft.validate().expect_err("port 0");
        assert!(errors.port.is_some());
    }

    #[test]
    fn rejects_port_above_65535() {
        let mut draft = valid_draft();
        draft.port = "65536".to_owned();
        let errors = draft.validate().expect_err("port too high");
        assert!(errors.port.is_some());
    }

    #[test]
    fn rejects_empty_username() {
        let mut draft = valid_draft();
        draft.username.clear();
        let errors = draft.validate().expect_err("empty username");
        assert!(errors.username.is_some());
    }

    #[test]
    fn rejects_missing_private_key_path() {
        let mut draft = valid_draft();
        draft.auth_method = AuthMethod::PrivateKey;
        draft.private_key_path.clear();
        let errors = draft.validate().expect_err("missing key path");
        assert!(errors.private_key_path.is_some());
    }

    #[test]
    fn accepts_private_key_profile_with_path() {
        let mut draft = valid_draft();
        draft.auth_method = AuthMethod::PrivateKey;
        draft.private_key_path = "/home/user/.ssh/id_ed25519".to_owned();
        let profile = draft.validate().expect("valid key profile");
        assert_eq!(profile.auth_method, AuthMethod::PrivateKey);
        assert_eq!(profile.private_key_path, "/home/user/.ssh/id_ed25519");
    }

    #[test]
    fn serialized_json_excludes_secrets() {
        let profile = StoredConnectionProfile {
            profile_name: "prod".to_owned(),
            host: "example.com".to_owned(),
            port: 22,
            username: "admin".to_owned(),
            auth_method: AuthMethod::Password,
            private_key_path: String::new(),
        };
        let json = serde_json::to_string(&profile).expect("serialize");
        assert!(!json.contains("password"));
        assert!(!json.contains("passphrase"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn to_ssh_profile_maps_non_secret_fields() {
        let stored = StoredConnectionProfile {
            profile_name: "ignored-by-ssh".to_owned(),
            host: "10.0.0.1".to_owned(),
            port: 2222,
            username: "deploy".to_owned(),
            auth_method: AuthMethod::PrivateKey,
            private_key_path: "/tmp/key".to_owned(),
        };
        let ssh = stored.to_ssh_profile();
        assert_eq!(ssh.host, "10.0.0.1");
        assert_eq!(ssh.port, 2222);
        assert_eq!(ssh.username, "deploy");
    }
}
