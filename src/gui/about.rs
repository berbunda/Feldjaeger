//! About dialog: app name, version, license, repository link, and credits.

use egui::{RichText, Ui};

fn about_open_id() -> egui::Id {
    egui::Id::new("about_dialog_open")
}

/// Status-bar entry that opens the About dialog.
pub fn trigger(ui: &mut Ui) {
    if ui.link("About Feldjäger").clicked() {
        ui.ctx().data_mut(|d| d.insert_temp(about_open_id(), true));
    }
}

/// Renders the About dialog if open. Call once per frame.
pub fn show(ui: &mut Ui) {
    let is_open = ui
        .ctx()
        .data(|d| d.get_temp(about_open_id()))
        .unwrap_or(false);
    if !is_open {
        return;
    }

    let mut open = true;
    let mut close_clicked = false;
    egui::Window::new("About Feldjäger")
        .collapsible(false)
        .resizable(false)
        .default_width(360.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.heading("Feldjäger");
            ui.add_space(4.0);
            ui.label(env!("CARGO_PKG_DESCRIPTION"));
            ui.separator();

            ui.label(format!("Version: {}", env!("CARGO_PKG_VERSION")));
            ui.label(format!("License: {}", env!("CARGO_PKG_LICENSE")));
            ui.label(format!(
                "Platform: {} / {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ));
            ui.separator();

            ui.label(RichText::new("Repository").strong());
            if ui.button("Open Repository").clicked() {
                ui.ctx()
                    .open_url(egui::OpenUrl::same_tab(env!("CARGO_PKG_REPOSITORY")));
            }
            ui.separator();

            ui.label(RichText::new("Technologies").strong());
            ui.label("Rust, egui + eframe");
            ui.separator();

            ui.label(RichText::new("AI-assisted development").strong());
            ui.label("Developed with the help of Claude Code.");
            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("Copy Version Info").clicked() {
                    let text = format!(
                        "Feldjäger {}\nLicense: {}\nPlatform: {} / {}",
                        env!("CARGO_PKG_VERSION"),
                        env!("CARGO_PKG_LICENSE"),
                        std::env::consts::OS,
                        std::env::consts::ARCH,
                    );
                    ui.ctx().copy_text(text);
                }
                if ui.button("Close").clicked() {
                    close_clicked = true;
                }
            });
        });

    if !open || close_clicked {
        ui.ctx().data_mut(|d| d.remove::<bool>(about_open_id()));
    }
}
