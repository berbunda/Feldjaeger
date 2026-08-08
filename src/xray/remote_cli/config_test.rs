//! Remote `xray run … -test` after configuration writes (IB-L6).

use feldjaeger_ssh::{RemoteCommand, SshSession};
use tracing::{debug, info};

use super::error::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult};
use super::exec::classify_exec_error;

/// How to invoke `xray run -test` against the remote installation layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigTestTarget {
    /// Single-file install: `xray run -c <path> -test`.
    ConfigFile(String),
    /// Multi-file install: `xray run -confdir <dir> -test`.
    ConfDir(String),
}

impl ConfigTestTarget {
    /// Builds a target from discovery layout, falling back to the written file path.
    pub fn from_source_or_file(
        config_source: &crate::xray::ConfigSource,
        written_file: &str,
    ) -> Self {
        match config_source {
            crate::xray::ConfigSource::ConfigDirectory(path) => {
                Self::ConfDir(path.as_str().to_owned())
            }
            crate::xray::ConfigSource::SingleFile(path) => {
                Self::ConfigFile(path.as_str().to_owned())
            }
            crate::xray::ConfigSource::NotFound | crate::xray::ConfigSource::Unknown => {
                Self::ConfigFile(written_file.to_owned())
            }
        }
    }
}

/// Runs `xray run -c … -test` or `xray run -confdir … -test` on the remote host.
///
/// On non-zero exit, detail includes a truncated, sanitized stderr/stdout snippet
/// (never raw secrets beyond what `sanitize_detail` already strips).
pub async fn run_config_test<S: SshSession + Sync>(
    session: &S,
    binary_path: &str,
    target: &ConfigTestTarget,
) -> RemoteCliResult<()> {
    let binary = binary_path.trim();
    if binary.is_empty() {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::CommandFailed,
            "Xray binary path is empty".to_owned(),
        ));
    }

    let args = match target {
        ConfigTestTarget::ConfigFile(path) => {
            vec![
                "run".to_owned(),
                "-c".to_owned(),
                path.clone(),
                "-test".to_owned(),
            ]
        }
        ConfigTestTarget::ConfDir(path) => {
            vec![
                "run".to_owned(),
                "-confdir".to_owned(),
                path.clone(),
                "-test".to_owned(),
            ]
        }
    };

    let command = RemoteCommand::new(binary, args).map_err(|error| {
        RemoteCliError::new(RemoteCliErrorKind::CommandFailed, error.message().to_owned())
    })?;

    info!(
        target: "xray",
        binary,
        target = ?target,
        "running remote xray config test"
    );

    let result = session.exec(&command).await.map_err(classify_exec_error)?;

    if result.exit_code != 0 {
        let detail = format_test_failure(result.exit_code, &result.stdout, &result.stderr);
        debug!(
            exit_code = result.exit_code,
            detail_len = detail.len(),
            "remote xray config test failed"
        );
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::NonZeroExit,
            detail,
        ));
    }

    debug!(exit_code = result.exit_code, "remote xray config test ok");
    Ok(())
}

fn format_test_failure(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> String {
    let stderr_text = String::from_utf8_lossy(stderr);
    let stdout_text = String::from_utf8_lossy(stdout);
    let combined = if !stderr_text.trim().is_empty() {
        stderr_text.as_ref()
    } else {
        stdout_text.as_ref()
    };
    // Prefer the actual failure line(s); Xray banners eat the first N lines.
    let snippet = extract_xray_failure_snippet(combined.trim());
    let sanitized = crate::logging::redact::sanitize_detail(&snippet);
    if sanitized.is_empty() {
        format!("xray run -test failed (exit {exit_code})")
    } else {
        format!("xray run -test failed (exit {exit_code}): {sanitized}")
    }
}

fn extract_xray_failure_snippet(input: &str) -> String {
    let interesting: Vec<&str> = input
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("failed")
                || lower.contains("error")
                || lower.contains("invalid")
                || lower.contains("cannot")
                || lower.contains("shadowsocks")
                || lower.contains("password")
                || lower.contains("method")
        })
        .take(8)
        .collect();
    if !interesting.is_empty() {
        return truncate_lines(&interesting.join("\n"), 8, 900);
    }
    truncate_lines(input, 12, 800)
}

fn truncate_lines(input: &str, max_lines: usize, max_chars: usize) -> String {
    let mut out = String::new();
    for (i, line) in input.lines().take(max_lines).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line);
        if out.len() >= max_chars {
            out.truncate(max_chars);
            out.push('…');
            return out;
        }
    }
    if input.lines().count() > max_lines || input.len() > out.len() {
        if !out.is_empty() {
            out.push('…');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::ConfigSource;
    use feldjaeger_ssh::RemotePath;

    #[test]
    fn target_prefers_confdir() {
        let dir = RemotePath::new("/usr/local/etc/xray").unwrap();
        let target = ConfigTestTarget::from_source_or_file(
            &ConfigSource::ConfigDirectory(dir),
            "/usr/local/etc/xray/01.json",
        );
        assert_eq!(
            target,
            ConfigTestTarget::ConfDir("/usr/local/etc/xray".to_owned())
        );
    }

    #[test]
    fn target_single_file() {
        let file = RemotePath::new("/etc/xray/config.json").unwrap();
        let target = ConfigTestTarget::from_source_or_file(
            &ConfigSource::SingleFile(file),
            "/etc/xray/config.json",
        );
        assert_eq!(
            target,
            ConfigTestTarget::ConfigFile("/etc/xray/config.json".to_owned())
        );
    }

    #[test]
    fn target_falls_back_to_written_file() {
        let target =
            ConfigTestTarget::from_source_or_file(&ConfigSource::NotFound, "/tmp/written.json");
        assert_eq!(
            target,
            ConfigTestTarget::ConfigFile("/tmp/written.json".to_owned())
        );
    }

    #[test]
    fn truncate_limits_output() {
        let long = "line1\nline2\nline3\nline4\nline5";
        let out = truncate_lines(long, 3, 800);
        assert!(out.starts_with("line1"));
        assert!(out.contains('…'));
        assert!(!out.contains("line4"));
    }
}
