//! Feldjaeger library — remote Xray administration over SSH.
//!
//! The crate is organized in layers:
//! - [`feldjaeger_ssh`] — independent SSH transport library
//! - [`error`] — application-wide error type
//! - [`init`] — init-system abstraction for service control
//! - [`remote`] — remote file and session operations
//! - [`xray`] — Xray configuration and lifecycle
//! - [`storage`] — local non-secret application configuration
//! - [`app`] — application facade for callers
//! - [`gui`] — desktop UI shell

pub mod app;
pub mod error;
pub mod gui;
pub mod init;
pub mod logging;
pub mod remote;
pub mod storage;
pub mod xray;

pub use feldjaeger_ssh;
