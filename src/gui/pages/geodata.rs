//! GeoData page — refresh / update via ApplicationService.
//!
//! The GUI never executes shell commands, downloads files, or accesses
//! remote paths. All work goes through [`ApplicationService`].

use egui::{Color32, RichText, Ui};

use crate::app::{ApplicationService, GeoDataPageModel, GeoDataUiState};
use crate::xray::GeoDataErrorKind;

/// Renders the GeoData management page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("GeoData");
    ui.add_space(8.0);

    let model = service.geodata_page_model();
    show_summary(ui, &model);
    ui.add_space(12.0);

    if let Some(reason) = &model.blocked_reason {
        ui.label(
            RichText::new(reason.clone())
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        ui.add_space(8.0);
    }

    if let GeoDataUiState::Failed { kind, detail } = &model.ui_state {
        ui.label(
            RichText::new(gui_state_label(*kind))
                .size(14.0)
                .color(Color32::from_rgb(200, 60, 60)),
        );
        ui.label(
            RichText::new(detail.clone())
                .size(14.0)
                .color(Color32::from_rgb(200, 60, 60)),
        );
        ui.add_space(8.0);
    }

    if model.restart_recommended {
        ui.label(
            RichText::new("Restart Xray recommended so it reloads GeoData.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        ui.add_space(8.0);
    }

    for warning in &model.warnings {
        ui.label(
            RichText::new(warning.clone())
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
    if !model.warnings.is_empty() {
        ui.add_space(8.0);
    }

    show_table(ui, &model);
    ui.add_space(12.0);
    show_actions(ui, service, &model);
}

fn show_summary(ui: &mut Ui, model: &GeoDataPageModel) {
    ui.strong("General");
    ui.add_space(4.0);
    egui::Grid::new("geodata_summary")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Installation path").strong());
            ui.label(&model.installation_path);
            ui.end_row();
            ui.label(RichText::new("Database count").strong());
            ui.label(model.database_count.to_string());
            ui.end_row();
        });
}

fn show_table(ui: &mut Ui, model: &GeoDataPageModel) {
    ui.strong("Databases");
    ui.add_space(4.0);

    egui::Grid::new("geodata_table")
        .num_columns(5)
        .striped(true)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            for header in ["Database", "Status", "Version", "Modified", "Size"] {
                ui.label(RichText::new(header).strong());
            }
            ui.end_row();

            for row in &model.rows {
                ui.label(&row.name);
                ui.label(RichText::new(&row.status).color(status_color(&row.status)));
                ui.label(&row.version);
                ui.label(&row.modified);
                ui.label(&row.size);
                ui.end_row();
            }
        });
}

fn show_actions(ui: &mut Ui, service: &mut ApplicationService, model: &GeoDataPageModel) {
    ui.horizontal(|ui| {
        if ui
            .add_enabled(model.can_refresh, egui::Button::new("Refresh information"))
            .clicked()
            && let Err(message) = service.start_geodata_refresh()
        {
            service.show_status_message(message);
        }

        if ui
            .add_enabled(model.can_update, egui::Button::new("Update GeoData"))
            .clicked()
            && let Err(message) = service.start_geodata_update()
        {
            service.show_status_message(message);
        }

        if model.ui_state.is_busy() {
            ui.spinner();
            ui.label("Working...");
        }
    });
}

fn status_color(status: &str) -> Color32 {
    if status == "Installed" {
        Color32::from_rgb(40, 160, 70)
    } else {
        Color32::from_rgb(140, 140, 140)
    }
}

fn gui_state_label(kind: GeoDataErrorKind) -> &'static str {
    match kind {
        GeoDataErrorKind::SshConnectionFailed => "SSH connection failed",
        GeoDataErrorKind::DownloadFailed => "Download failed",
        GeoDataErrorKind::VerificationFailed => "Verification failed",
        GeoDataErrorKind::PermissionDenied => "Permission denied",
        GeoDataErrorKind::BackupFailed => "Backup failed",
        GeoDataErrorKind::DatabaseMissing => "Database missing",
        GeoDataErrorKind::UnsupportedInstallation => "Unsupported installation",
        GeoDataErrorKind::AssetDirectoryNotFound => "Unsupported installation",
        GeoDataErrorKind::ReplaceFailed => "Verification failed",
        GeoDataErrorKind::RollbackFailed => "Backup failed",
        GeoDataErrorKind::CommandFailed => "Download failed",
    }
}
