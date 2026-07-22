//! SSH host key verification policy.

use std::path::PathBuf;

/// Policy for verifying remote SSH host keys.
///
/// [`HostKeyPolicy::KnownHostsFile`] uses OpenSSH `known_hosts` semantics via
/// `russh::keys::known_hosts`, including non-standard ports (`[host]:port`) and
/// hashed host entries. The file is never modified by Feldjaeger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Accept any host key.
    ///
    /// Intended for development and testing only.
    AcceptAny,
    /// Verify host keys against an OpenSSH `known_hosts` file (read-only).
    KnownHostsFile(PathBuf),
}

impl Default for HostKeyPolicy {
    fn default() -> Self {
        Self::KnownHostsFile(default_known_hosts_path())
    }
}

impl HostKeyPolicy {
    /// Returns the default known-hosts path for the current platform.
    pub fn default_known_hosts_path() -> PathBuf {
        default_known_hosts_path()
    }
}

fn default_known_hosts_path() -> PathBuf {
    if let Some(home) = home_dir() {
        home.join(".ssh").join("known_hosts")
    } else {
        PathBuf::from(".ssh/known_hosts")
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}
