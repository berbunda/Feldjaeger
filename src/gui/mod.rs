//! Desktop GUI shell.
//!
//! The GUI must not execute raw SSH commands or contain init-system-specific logic.
//! All operations go through [`crate::app::ApplicationService`].

mod app;
mod navigation;
mod pages;
mod sidebar;
mod status_bar;

pub use app::{FeldjaegerApp, run};
