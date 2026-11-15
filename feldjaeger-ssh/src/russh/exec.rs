//! Remote command execution helpers.

use crate::command::RemoteCommand;
use crate::error::{SshError, SshResult};
use crate::exec::ExecResult;

/// Builds the SSH exec payload from a validated remote command.
///
/// SSH `exec` requests are commonly interpreted by a remote login shell, so
/// every program and argument is POSIX single-quoted. Callers must still pass
/// structured argv (never a hand-built shell script).
pub fn build_exec_payload(command: &RemoteCommand) -> SshResult<String> {
    validate_exec_token(command.program(), "program")?;
    for arg in command.args() {
        validate_exec_token(arg, "argument")?;
    }

    let mut payload = shell_quote(command.program());
    for arg in command.args() {
        payload.push(' ');
        payload.push_str(&shell_quote(arg));
    }

    Ok(payload)
}

fn validate_exec_token(token: &str, label: &str) -> SshResult<()> {
    if token.is_empty() {
        return Err(SshError::new(format!(
            "remote command {label} must not be empty"
        )));
    }

    if token.contains('\0') {
        return Err(SshError::new(format!(
            "remote command {label} must not contain null bytes"
        )));
    }

    Ok(())
}

/// POSIX single-quote escaping: `'foo'\''bar'` for `foo'bar`.
fn shell_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Reads stdout, stderr, and exit status from an SSH exec channel.
///
/// Does **not** stop at [`ChannelMsg::Eof`]: some servers deliver
/// `exit-status` after EOF. Stopping early leaves `exit_code == -1`, which
/// makes successful commands (including `test -x` and `command -v`) look like
/// failures to callers that check `exit_code == 0`.
pub async fn collect_exec_output(
    channel: &mut russh::Channel<russh::client::Msg>,
) -> SshResult<ExecResult> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = -1;

    while let Some(message) =
        tokio::time::timeout(std::time::Duration::from_secs(30), channel.wait())
            .await
            .map_err(|_| SshError::new("SSH response idle timeout"))?
    {
        match message {
            russh::ChannelMsg::Data { data } => {
                append_bounded(&mut stdout, &data, 16 * 1024 * 1024)?
            }
            russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                append_bounded(&mut stderr, &data, 4 * 1024 * 1024)?
            }
            russh::ChannelMsg::ExitStatus { exit_status } => {
                exit_code = exit_status as i32;
            }
            russh::ChannelMsg::ExitSignal { .. } => {
                return Err(SshError::new(
                    "remote command terminated by signal before returning exit status",
                ));
            }
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => {
                // Keep waiting until the channel is fully closed (`wait` → None)
                // so a late ExitStatus is not dropped.
            }
            _ => {}
        }
    }

    Ok(ExecResult::new(stdout, stderr, exit_code))
}

pub(super) fn append_bounded(buffer: &mut Vec<u8>, data: &[u8], limit: usize) -> SshResult<()> {
    if data.len() > limit.saturating_sub(buffer.len()) {
        return Err(SshError::new("remote response exceeds byte limit"));
    }
    buffer.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_overflow_before_appending() {
        let mut bytes = vec![1, 2];
        append_bounded(&mut bytes, &[3, 4], 4).unwrap();
        assert!(append_bounded(&mut bytes, &[5], 4).is_err());
        assert_eq!(bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn builds_quoted_exec_payload() {
        let command = RemoteCommand::new(
            "systemctl",
            vec!["restart".to_owned(), "xray.service".to_owned()],
        )
        .expect("command should construct");

        let payload = build_exec_payload(&command).expect("payload should build");
        assert_eq!(payload, "'systemctl' 'restart' 'xray.service'");
    }

    #[test]
    fn quotes_metacharacters_and_whitespace() {
        let command = RemoteCommand::new(
            "cat",
            vec!["file > /tmp/evil".to_owned(), "*.json".to_owned()],
        )
        .expect("command should construct");

        let payload = build_exec_payload(&command).expect("payload should build");
        assert_eq!(payload, "'cat' 'file > /tmp/evil' '*.json'");
    }

    #[test]
    fn quotes_embedded_single_quotes() {
        let command = RemoteCommand::new("echo", vec!["it's".to_owned()]).expect("ok");
        let payload = build_exec_payload(&command).expect("payload");
        assert_eq!(payload, r"'echo' 'it'\''s'");
    }

    #[test]
    fn rejects_null_bytes_in_arguments() {
        let command =
            RemoteCommand::new("cat", vec!["a\0b".to_owned()]).expect("command should construct");
        let error = build_exec_payload(&command).expect_err("null should fail");
        assert!(error.message().contains("null"));
    }

    #[test]
    fn rejects_empty_argument() {
        let command =
            RemoteCommand::new("cat", vec![String::new()]).expect("command should construct");
        let error = build_exec_payload(&command).expect_err("empty should fail");
        assert!(error.message().contains("empty"));
    }

    #[test]
    fn builds_command_v_xray_payload() {
        let command = RemoteCommand::new("command", vec!["-v".to_owned(), "xray".to_owned()])
            .expect("command should construct");

        let payload = build_exec_payload(&command).expect("payload should build");
        assert_eq!(payload, "'command' '-v' 'xray'");
    }
}
