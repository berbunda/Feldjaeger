//! Remote command execution result model.

/// Output of a remote command executed through [`super::SshSession::exec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// Bytes captured from standard output.
    pub stdout: Vec<u8>,
    /// Bytes captured from standard error.
    pub stderr: Vec<u8>,
    /// Process exit code reported by the remote host.
    pub exit_code: i32,
}

impl ExecResult {
    /// Creates a new execution result.
    pub fn new(stdout: Vec<u8>, stderr: Vec<u8>, exit_code: i32) -> Self {
        Self {
            stdout,
            stderr,
            exit_code,
        }
    }
}
