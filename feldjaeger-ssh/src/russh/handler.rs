//! Russh client event handler and host-key verification.

use russh::client;
use russh::keys::PublicKey;
use russh::keys::known_hosts::check_known_hosts_path;
use tracing::warn;

use super::host_key::HostKeyPolicy;
use crate::error::{SshError, SshResult};

/// Internal russh handler that applies [`HostKeyPolicy`].
pub struct ClientHandler {
    host_key_policy: HostKeyPolicy,
    /// Remote hostname from [`crate::connection::ConnectionProfile`].
    expected_host: String,
    /// Remote TCP port from [`crate::connection::ConnectionProfile`].
    ///
    /// Must not be defaulted to 22 when the profile uses another port; OpenSSH
    /// records non-standard ports as `[hostname]:port` in `known_hosts`.
    expected_port: u16,
}

impl ClientHandler {
    /// Creates a handler for the given host key policy and connection endpoint.
    pub fn new(host_key_policy: HostKeyPolicy, expected_host: String, expected_port: u16) -> Self {
        Self {
            host_key_policy,
            expected_host,
            expected_port,
        }
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.host_key_policy {
            HostKeyPolicy::AcceptAny => {
                warn!(
                    target: "ssh",
                    host = %self.expected_host,
                    port = self.expected_port,
                    "accepting SSH host key without verification"
                );
                Ok(true)
            }
            HostKeyPolicy::KnownHostsFile(path) => verify_known_hosts_key(
                path,
                &self.expected_host,
                self.expected_port,
                server_public_key,
            )
            .map_err(host_key_error_to_russh),
        }
    }
}

/// Verifies `server_public_key` against an OpenSSH `known_hosts` file.
///
/// Uses [`check_known_hosts_path`], which understands standard port 22 entries,
/// `[host]:port` non-standard-port entries, and hashed (`|1|…`) hostnames.
/// Never writes or updates the file.
pub(crate) fn verify_known_hosts_key(
    path: &std::path::Path,
    host: &str,
    port: u16,
    server_public_key: &PublicKey,
) -> SshResult<bool> {
    match check_known_hosts_path(host, port, server_public_key, path) {
        Ok(true) => Ok(true),
        Ok(false) => Err(SshError::new(format!(
            "unknown SSH host key for {host}:{port}; add the key to {}",
            path.display()
        ))),
        Err(russh::keys::Error::KeyChanged { line }) => Err(SshError::new(format!(
            "SSH host key mismatch for {host}:{port} (known_hosts line {line}); check {}",
            path.display()
        ))),
        Err(error) => Err(SshError::new(format!(
            "SSH host key verification failed for {host}:{port}: {error}"
        ))),
    }
}

fn host_key_error_to_russh(error: SshError) -> russh::Error {
    let message = error.message();
    if message.contains("mismatch") {
        russh::Error::KeyChanged { line: 0 }
    } else {
        russh::Error::UnknownKey
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::parse_public_key_base64;
    use std::fs;
    use std::path::PathBuf;

    /// Well-formed ed25519 public key material used only in unit tests.
    const KEY_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const KEY_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";
    /// Hashed known_hosts entry for `example.com` (port 22) with KEY_HASHED.
    /// Taken from russh's own known_hosts tests.
    const HASHED_EXAMPLE_COM: &str = "|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak=";
    const KEY_HASHED: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF";

    fn temp_known_hosts(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "feldjaeger-known-hosts-{}-{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("known_hosts");
        fs::write(&path, contents).expect("write known_hosts");
        path
    }

    fn cleanup(path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    fn key(base64: &str) -> PublicKey {
        parse_public_key_base64(base64).expect("test public key")
    }

    #[test]
    fn accepts_known_host_on_port_22() {
        let path = temp_known_hosts("port22", &format!("example.com ssh-ed25519 {KEY_A}\n"));
        let result = verify_known_hosts_key(&path, "example.com", 22, &key(KEY_A));
        cleanup(&path);
        assert!(result.expect("port 22 known host should match"));
    }

    #[test]
    fn accepts_known_host_on_nonstandard_port() {
        let path = temp_known_hosts(
            "port666",
            &format!("[ntz.odmen.org]:666 ssh-ed25519 {KEY_A}\n"),
        );
        let result = verify_known_hosts_key(&path, "ntz.odmen.org", 666, &key(KEY_A));
        cleanup(&path);
        assert!(result.expect("[host]:666 known host should match"));
    }

    #[test]
    fn same_hostname_different_port_is_different_endpoint() {
        let path = temp_known_hosts(
            "port-isolation",
            &format!("[ntz.odmen.org]:666 ssh-ed25519 {KEY_A}\n"),
        );

        // Correct key on the recorded non-standard port succeeds.
        assert!(
            verify_known_hosts_key(&path, "ntz.odmen.org", 666, &key(KEY_A))
                .expect("recorded endpoint should match")
        );

        // Same hostname + key on port 22 is a different OpenSSH endpoint.
        let other_port = verify_known_hosts_key(&path, "ntz.odmen.org", 22, &key(KEY_A));
        cleanup(&path);
        let error = other_port.expect_err("port 22 must not match [host]:666");
        assert!(
            error.message().contains("unknown SSH host key"),
            "expected unknown host key, got: {}",
            error.message()
        );
    }

    #[test]
    fn accepts_hashed_known_hosts_entry() {
        let path = temp_known_hosts(
            "hashed",
            &format!("{HASHED_EXAMPLE_COM} ssh-ed25519 {KEY_HASHED}\n"),
        );
        let result = verify_known_hosts_key(&path, "example.com", 22, &key(KEY_HASHED));
        cleanup(&path);
        assert!(result.expect("hashed known_hosts entry should match"));
    }

    #[test]
    fn rejects_unknown_host() {
        let path = temp_known_hosts("unknown", &format!("other.example ssh-ed25519 {KEY_A}\n"));
        let error = verify_known_hosts_key(&path, "ntz.odmen.org", 666, &key(KEY_A))
            .expect_err("unknown host should fail");
        cleanup(&path);
        assert!(error.message().contains("unknown SSH host key"));
        assert!(error.message().contains("ntz.odmen.org:666"));
    }

    #[test]
    fn rejects_mismatched_key() {
        let path = temp_known_hosts(
            "mismatch",
            &format!("[ntz.odmen.org]:666 ssh-ed25519 {KEY_A}\n"),
        );
        let error = verify_known_hosts_key(&path, "ntz.odmen.org", 666, &key(KEY_B))
            .expect_err("key mismatch should fail");
        cleanup(&path);
        assert!(
            error.message().contains("mismatch"),
            "expected mismatch, got: {}",
            error.message()
        );
    }

    #[test]
    fn does_not_create_or_modify_known_hosts_file() {
        let path = temp_known_hosts("readonly", "");
        let before = fs::metadata(&path)
            .expect("meta")
            .modified()
            .expect("mtime");

        let _ = verify_known_hosts_key(&path, "example.com", 22, &key(KEY_A));

        let after = fs::metadata(&path)
            .expect("meta")
            .modified()
            .expect("mtime");
        let contents = fs::read_to_string(&path).expect("read");
        cleanup(&path);

        assert_eq!(before, after);
        assert!(contents.is_empty());
    }
}
