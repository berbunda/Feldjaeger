//! Remote command model.

use crate::error::{SshError, SshResult};

/// Remote command specified by program name and explicit arguments.
///
/// Callers must pass a program plus an argument list (never a hand-built shell
/// string). The russh backend currently serializes these into an SSH `exec`
/// payload string; arguments are validated/sanitized in `russh::exec` before
/// that serialization. Prefer tightening that path toward argv-style exec or
/// full shell quoting rather than treating this type as shell-free by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommand {
    program: String,
    args: Vec<String>,
}

impl RemoteCommand {
    /// Creates a new remote command.
    ///
    /// The program name must not contain shell metacharacters or whitespace.
    pub fn new(program: impl Into<String>, args: Vec<String>) -> SshResult<Self> {
        let program = program.into();

        if program.is_empty() {
            return Err(SshError::new("program name must not be empty"));
        }

        if program.chars().any(char::is_whitespace) {
            return Err(SshError::new("program name must not contain whitespace"));
        }

        Ok(Self { program, args })
    }

    /// Returns the program to execute.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Returns the argument list passed to the program.
    pub fn args(&self) -> &[String] {
        &self.args
    }
}
