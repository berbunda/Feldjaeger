//! Generic `xray api` (gRPC HandlerService / RoutingService / LoggerService) CLI wrapper
//! (Roadmap §3:128 — live operations panel).
//!
//! Every `xray api <subcommand>` in upstream Xray-core
//! (`main/commands/all/api/` in XTLS/Xray-core) shares the same shape: `-s <server>` (the
//! `api.listen` address), optional flags, optional positional args, and — for the handful of
//! subcommands that take a JSON body (`adi`/`ado`/`adu`/`adrules`) — a literal `stdin:`
//! positional argument that makes the upstream CLI read the body from process stdin instead of
//! a file (`shared.go::loadArg`). That lets all ~17 subcommands go through this single executor
//! instead of one hand-rolled wrapper per subcommand.
//!
//! Unlike [`super::x25519`]/[`super::mldsa65`], output is **not** parsed into a typed struct:
//! shape varies per subcommand, and several (`lsi`/`lso`/`bi`) have no stable machine-readable
//! form upstream (`-json` is still a documented TODO for some of them). The raw trimmed stdout
//! is returned as-is for the GUI to display verbatim — the same treatment already given to Xray
//! runtime log bodies.
//!
//! These calls only affect the **running** Xray process via gRPC into `api.listen` — nothing is
//! written to the configuration file, backed up, or validated. Callers must make that
//! unmistakable in the UI (`rules.md`: every other configuration change goes through
//! backup → validate → write; this path deliberately does not).

use feldjaeger_ssh::{RemoteCommand, SshSession};
use tracing::debug;

use super::error::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult};
use super::exec::classify_exec_error;

/// Runs `xray api <subcommand> -s <server_addr> [extra_args...]` on the remote host.
///
/// `stdin_body`, when present, is written to the process's stdin after the command starts
/// ([`SshSession::exec_with_stdin`]) — pass it together with a literal `"stdin:".to_owned()` in
/// `extra_args` at the position the target subcommand expects its JSON body/file argument.
///
/// Returns trimmed stdout on success (`exit_code == 0`). Never logs argument values or output
/// content — output may contain emails, IPs, or (for `inbounduser`) client identifiers
/// (`rules.md`: no VLESS UUIDs / raw remote command output in logs) — only the subcommand name
/// and output length.
pub async fn run_xray_api<S: SshSession + Sync>(
    session: &S,
    binary_path: &str,
    server_addr: &str,
    subcommand: &str,
    extra_args: Vec<String>,
    stdin_body: Option<Vec<u8>>,
) -> RemoteCliResult<String> {
    let binary = binary_path.trim();
    if binary.is_empty() {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::CommandFailed,
            "Xray binary path is empty".to_owned(),
        ));
    }
    let server_addr = server_addr.trim();
    if server_addr.is_empty() {
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::CommandFailed,
            "API server address is empty (configure `api.listen`)".to_owned(),
        ));
    }

    let mut args = vec![
        "api".to_owned(),
        subcommand.to_owned(),
        "-s".to_owned(),
        server_addr.to_owned(),
    ];
    args.extend(extra_args);

    let command = RemoteCommand::new(binary, args).map_err(|error| {
        RemoteCliError::new(RemoteCliErrorKind::CommandFailed, error.message().to_owned())
    })?;

    debug!(
        target: "xray",
        subcommand,
        has_stdin = stdin_body.is_some(),
        "running remote xray api call"
    );

    let result = match &stdin_body {
        Some(body) => session.exec_with_stdin(&command, body).await,
        None => session.exec(&command).await,
    }
    .map_err(classify_exec_error)?;

    let stdout = String::from_utf8_lossy(&result.stdout).trim().to_owned();

    if result.exit_code != 0 {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let detail_source = if !stderr.trim().is_empty() {
            stderr.as_ref()
        } else {
            stdout.as_str()
        };
        let detail = crate::logging::redact::sanitize_detail(&truncate(detail_source, 900));
        debug!(
            target: "xray",
            subcommand,
            exit_code = result.exit_code,
            "remote xray api call failed"
        );
        return Err(RemoteCliError::new(
            RemoteCliErrorKind::NonZeroExit,
            if detail.is_empty() {
                format!("xray api {subcommand} exited with code {}", result.exit_code)
            } else {
                detail
            },
        ));
    }

    debug!(
        target: "xray",
        subcommand,
        stdout_len = stdout.len(),
        "remote xray api call ok"
    );
    Ok(stdout)
}

fn truncate(input: &str, max_chars: usize) -> String {
    let trimmed = input.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_owned()
    } else {
        let mut out: String = trimmed.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_short_input() {
        assert_eq!(truncate("short", 900), "short");
    }

    #[test]
    fn truncate_caps_long_input() {
        let long = "a".repeat(1000);
        let out = truncate(&long, 10);
        assert_eq!(out.chars().count(), 11); // 10 chars + ellipsis
        assert!(out.ends_with('…'));
    }
}
