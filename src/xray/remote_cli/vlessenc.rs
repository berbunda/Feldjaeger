//! `xray vlessenc` parse + remote invoke.

use feldjaeger_ssh::{RemoteCommand, SshSession};
use tracing::debug;

use super::error::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult};
use super::exec::classify_exec_error;

/// Which authentication block from `vlessenc` to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VlessEncAuthKind {
    /// `Authentication: X25519, not Post-Quantum`
    #[default]
    X25519,
    /// `Authentication: ML-KEM-768, Post-Quantum`
    MlKem768,
}

impl VlessEncAuthKind {
    /// Short UI label.
    pub fn label(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::MlKem768 => "ML-KEM-768",
        }
    }
}

/// One decryption/encryption pair from a single auth block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessEncPair {
    /// Server `settings.decryption` value.
    pub decryption: String,
    /// Client `encryption` (ephemeral UI / future share URI only).
    pub encryption: String,
}

/// Full `vlessenc` stdout: both auth blocks (do not mix halves across blocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessEncOutput {
    /// X25519 authentication pair.
    pub x25519: VlessEncPair,
    /// ML-KEM-768 authentication pair.
    pub mlkem768: VlessEncPair,
}

impl VlessEncOutput {
    /// Selects one auth block.
    pub fn pair_for(&self, kind: VlessEncAuthKind) -> &VlessEncPair {
        match kind {
            VlessEncAuthKind::X25519 => &self.x25519,
            VlessEncAuthKind::MlKem768 => &self.mlkem768,
        }
    }
}

/// Parses stdout from `xray vlessenc` (fixture-compatible).
pub fn parse_vlessenc_stdout(stdout: &str) -> RemoteCliResult<VlessEncOutput> {
    #[derive(Clone, Copy)]
    enum Block {
        X25519,
        MlKem768,
    }

    let mut current = None;
    let mut x25519_dec = None;
    let mut x25519_enc = None;
    let mut mlkem_dec = None;
    let mut mlkem_enc = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Authentication:") {
            let lower = trimmed.to_ascii_lowercase();
            if lower.contains("ml-kem") || lower.contains("mlkem") {
                current = Some(Block::MlKem768);
            } else if lower.contains("x25519") {
                current = Some(Block::X25519);
            }
            continue;
        }

        let Some(block) = current else {
            continue;
        };

        if let Some(value) = parse_quoted_field(trimmed, "decryption") {
            match block {
                Block::X25519 => x25519_dec = Some(value),
                Block::MlKem768 => mlkem_dec = Some(value),
            }
        } else if let Some(value) = parse_quoted_field(trimmed, "encryption") {
            match block {
                Block::X25519 => x25519_enc = Some(value),
                Block::MlKem768 => mlkem_enc = Some(value),
            }
        }
    }

    let x25519 = VlessEncPair {
        decryption: require_field(x25519_dec, "X25519 decryption")?,
        encryption: require_field(x25519_enc, "X25519 encryption")?,
    };
    let mlkem768 = VlessEncPair {
        decryption: require_field(mlkem_dec, "ML-KEM-768 decryption")?,
        encryption: require_field(mlkem_enc, "ML-KEM-768 encryption")?,
    };

    Ok(VlessEncOutput { x25519, mlkem768 })
}

fn parse_quoted_field(line: &str, key: &str) -> Option<String> {
    // "decryption": "value"  or  "encryption": "value"
    let prefix = format!("\"{key}\"");
    let rest = line.trim().strip_prefix(&prefix)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.rfind('"')?;
    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn require_field(value: Option<String>, label: &str) -> RemoteCliResult<String> {
    value.filter(|s| !s.is_empty()).ok_or_else(|| {
        RemoteCliError::new(
            RemoteCliErrorKind::ParseFailed,
            format!("missing {label}"),
        )
    })
}

/// Runs `xray vlessenc` on the remote host via SSH.
pub async fn run_vlessenc<S: SshSession + Sync>(
    session: &S,
    binary_path: &str,
) -> RemoteCliResult<VlessEncOutput> {
    let binary = binary_path.trim();
    if binary.is_empty() {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::CommandFailed,
            "Xray binary path is empty".to_owned(),
        ));
    }

    let command = RemoteCommand::new(binary, vec!["vlessenc".to_owned()]).map_err(|error| {
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
    debug!(stdout_len = stdout.len(), "parsed remote xray vlessenc stdout");
    parse_vlessenc_stdout(&stdout)
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
            .join("vlessenc.stdout.txt");
        std::fs::read_to_string(path).expect("vlessenc fixture")
    }

    #[test]
    fn parses_fixture_both_blocks() {
        let out = parse_vlessenc_stdout(&fixture_stdout()).expect("parse");
        assert!(out.x25519.decryption.starts_with("mlkem768x25519plus.native.600s."));
        assert!(out.x25519.encryption.starts_with("mlkem768x25519plus.native.0rtt."));
        assert!(out.mlkem768.decryption.len() > out.x25519.decryption.len());
        assert!(out.mlkem768.encryption.len() > out.x25519.encryption.len());
        assert_ne!(out.x25519.decryption, out.mlkem768.decryption);
    }

    #[test]
    fn pair_for_selects_block() {
        let out = parse_vlessenc_stdout(&fixture_stdout()).unwrap();
        assert_eq!(
            out.pair_for(VlessEncAuthKind::X25519).decryption,
            out.x25519.decryption
        );
        assert_eq!(
            out.pair_for(VlessEncAuthKind::MlKem768).encryption,
            out.mlkem768.encryption
        );
    }

    #[test]
    fn rejects_incomplete() {
        let err = parse_vlessenc_stdout(
            "Authentication: X25519, not Post-Quantum\n\"decryption\": \"only\"\n",
        )
        .unwrap_err();
        assert_eq!(err.kind(), RemoteCliErrorKind::ParseFailed);
    }
}
