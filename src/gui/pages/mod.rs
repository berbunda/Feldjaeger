//! Content pages for the main window.

use egui::Ui;

pub mod burst_observatory;
pub mod connection;
pub mod dashboard;
pub mod dns;
pub mod fakedns;
pub mod geodata;
pub mod inbounds;
pub mod logs;
pub mod observatory;
pub mod outbounds;
pub mod policy;
pub mod routing;
pub mod service;
pub mod settings;
pub mod users;
pub mod warp;
pub mod xray_management;

/// Renders a placeholder page with a title and a not-implemented message.
pub(crate) fn placeholder(ui: &mut Ui, title: &str) {
    ui.heading(title);
    ui.add_space(8.0);
    ui.label("This page is not implemented yet.");
}
