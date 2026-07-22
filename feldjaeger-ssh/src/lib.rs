//! Backend-agnostic SSH transport library.
//!
//! This crate is independent of Xray, GUI, and init-system logic.
//! Callers depend on [`SshBackend`] and [`SshSession`], not on a concrete SSH library.
//!
//! # Backends
//!
//! MVP provides [`RusshClient`]. An OpenSSH CLI backend may be added later for Unix-like
//! systems.

mod backend;
mod command;
mod connection;
mod error;
mod exec;
mod path;
mod russh;
mod session;

pub use backend::{SshBackend, SshSession};
pub use command::RemoteCommand;
pub use connection::{AuthCredentials, AuthMethod, ConnectRequest, ConnectionProfile};
pub use error::{SshError, SshResult};
pub use exec::ExecResult;
pub use path::RemotePath;
pub use russh::{HostKeyPolicy, RusshClient, RusshClientOptions, RusshSession};
pub use session::{SessionInfo, SessionState};
