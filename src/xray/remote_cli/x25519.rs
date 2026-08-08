//! `xray x25519` parse + remote invoke.

use feldjaeger_ssh::{RemoteCommand, SshSession};
use tracing::debug;

use super::error::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult};
use super::exec::classify_exec_error;

/// Key pair from `xray x25519` (public is never written to inbound JSON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519KeyPair {
    /// Server `realitySettings.privateKey`.
    pub private_key: String,
    /// Client share public key (`Password (PublicKey):` in CLI output).
    pub public_key: String,
    /// Optional Hash32 line (ignored by Reality wire today).
    pub hash32: Option<String>,
}

/// Parses stdout from `xray x25519` (fixture-compatible).
///
/// Expected labels:
/// - `PrivateKey:`
/// - `Password (PublicKey):`
/// - optional `Hash32:`
pub fn parse_x25519_stdout(stdout: &str) -> RemoteCliResult<X25519KeyPair> {
    let mut private_key = None;
    let mut public_key = None;
    let mut hash32 = None;

    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("PrivateKey:") {
            private_key = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("Password (PublicKey):") {
            public_key = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("Hash32:") {
            let value = rest.trim();
            if !value.is_empty() {
                hash32 = Some(value.to_owned());
            }
        }
    }

    let private_key = private_key.filter(|s| !s.is_empty()).ok_or_else(|| {
        RemoteCliError::new(
            RemoteCliErrorKind::ParseFailed,
            "missing PrivateKey".to_owned(),
        )
    })?;
    let public_key = public_key.filter(|s| !s.is_empty()).ok_or_else(|| {
        RemoteCliError::new(
            RemoteCliErrorKind::ParseFailed,
            "missing Password (PublicKey)".to_owned(),
        )
    })?;

    Ok(X25519KeyPair {
        private_key,
        public_key,
        hash32,
    })
}

/// Runs `xray x25519` on the remote host via SSH.
pub async fn run_x25519<S: SshSession + Sync>(
    session: &S,
    binary_path: &str,
) -> RemoteCliResult<X25519KeyPair> {
    let binary = binary_path.trim();
    if binary.is_empty() {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::CommandFailed,
            "Xray binary path is empty".to_owned(),
        ));
    }

    let command = RemoteCommand::new(binary, vec!["x25519".to_owned()]).map_err(|error| {
        RemoteCliError::new(RemoteCliErrorKind::CommandFailed, error.message().to_owned())
    })?;

    let result = session
        .exec(&command)
        .await
        .map_err(classify_exec_error)?;

    if result.exit_code != 0 {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::NonZeroExit,
            format!("exit code {}", result.exit_code),
        ));
    }

    let stdout = String::from_utf8_lossy(&result.stdout);
    // Never log key material — only lengths.
    debug!(
        stdout_len = stdout.len(),
        "parsed remote xray x25519 stdout"
    );
    parse_x25519_stdout(&stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_stdout() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("xray")
            .join("cli")
            .join("x25519.stdout.txt");
        std::fs::read_to_string(path).expect("x25519 fixture")
    }

    #[test]
    fn parses_fixture() {
        let pair = parse_x25519_stdout(&fixture_stdout()).expect("parse");
        assert_eq!(
            pair.private_key,
            "0EiEonMUwJyuyI4Q8tdGIRvjV_aaOfeFC7TSsohh5mk"
        );
        assert_eq!(
            pair.public_key,
            "RGhjWSrEM-rYV-nrfeDNswssqctjn8GFalDEuEcII1c"
        );
        assert_eq!(
            pair.hash32.as_deref(),
            Some("iBeAGVh21xjDUWuCpkhQbJxV3eVMX-ck0_X4omgBa-o")
        );
    }

    #[test]
    fn rejects_missing_public() {
        let err = parse_x25519_stdout("PrivateKey: abc\n").unwrap_err();
        assert_eq!(err.kind(), RemoteCliErrorKind::ParseFailed);
    }
}
