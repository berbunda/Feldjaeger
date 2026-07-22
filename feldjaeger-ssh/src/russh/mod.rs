//! Russh-based SSH client backend (MVP).

mod client;
mod exec;
mod handler;
mod host_key;
mod session;
mod sftp;

pub use client::{RusshClient, RusshClientOptions};
pub use host_key::HostKeyPolicy;
pub use session::RusshSession;
