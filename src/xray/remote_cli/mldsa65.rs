//! `xray mldsa65` parse + remote invoke (IB-L4 Reality).

use feldjaeger_ssh::{RemoteCommand, SshSession};
use tracing::debug;

use super::error::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult};
use super::exec::classify_exec_error;

/// Seed / verify pair from `xray mldsa65`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mldsa65KeyPair {
    /// Server `realitySettings.mldsa65Seed`.
    pub seed: String,
    /// Client verify string (ephemeral UI only).
    pub verify: String,
}

/// Parses stdout from `xray mldsa65`.
pub fn parse_mldsa65_stdout(stdout: &str) -> RemoteCliResult<Mldsa65KeyPair> {
    let mut seed = None;
    let mut verify = None;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Seed:") {
            seed = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("Verify:") {
            verify = Some(rest.trim().to_owned());
        }
    }
    let seed = seed.filter(|s| !s.is_empty()).ok_or_else(|| {
        RemoteCliError::new(RemoteCliErrorKind::ParseFailed, "missing Seed".to_owned())
    })?;
    let verify = verify.filter(|s| !s.is_empty()).ok_or_else(|| {
        RemoteCliError::new(RemoteCliErrorKind::ParseFailed, "missing Verify".to_owned())
    })?;
    Ok(Mldsa65KeyPair { seed, verify })
}

/// Runs `xray mldsa65` on the remote host.
pub async fn run_mldsa65<S: SshSession + Sync>(
    session: &S,
    binary_path: &str,
) -> RemoteCliResult<Mldsa65KeyPair> {
    let binary = binary_path.trim();
    if binary.is_empty() {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::CommandFailed,
            "Xray binary path is empty".to_owned(),
        ));
    }
    let command = RemoteCommand::new(binary, vec!["mldsa65".to_owned()]).map_err(|error| {
        RemoteCliError::new(RemoteCliErrorKind::CommandFailed, error.message().to_owned())
    })?;
    let result = session.exec(&command).await.map_err(classify_exec_error)?;
    if result.exit_code != 0 {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::NonZeroExit,
            format!("exit code {}", result.exit_code),
        ));
    }
    let stdout = String::from_utf8_lossy(&result.stdout);
    debug!(stdout_len = stdout.len(), "parsed remote xray mldsa65 stdout");
    parse_mldsa65_stdout(&stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_fixture() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/xray/cli/mldsa65.stdout.txt");
        let stdout = std::fs::read_to_string(path).unwrap();
        let pair = parse_mldsa65_stdout(&stdout).unwrap();
        assert_eq!(pair.seed, "P9RyqiJHEImAn03AhiVio4mNzxECpqmSgcpqyR5DhAs");
        assert!(pair.verify.len() > 100);
    }
}
