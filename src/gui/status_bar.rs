//! Persistent Status Bar at the bottom of the main window.

use egui::{Color32, ProgressBar, RichText, Spinner, Ui};

use crate::app::{
    CurrentOperation, OperationProgress, SshStatus, StatusSeverity, StatusSnapshot, XrayStatus,
};

use super::about;

/// Fixed height of the Status Bar in logical points.
pub const STATUS_BAR_HEIGHT: f32 = 28.0;

/// Renders the always-visible Status Bar from a [`StatusSnapshot`].
///
/// Layout: `Current Operation` | `Xray Status` | `SSH Status`.
/// Long-running operations show a progress bar or spinner next to the label.
pub fn show(ui: &mut Ui, status: &StatusSnapshot) {
    ui.horizontal_centered(|ui| {
        ui.set_min_height(STATUS_BAR_HEIGHT);

        about::trigger(ui);
        ui.separator();
        show_current_operation(ui, &status.operation);

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            show_ssh_status(ui, status.ssh);
            ui.separator();
            show_xray_status(ui, &status.xray);
            ui.separator();
        });
    });
}

fn show_current_operation(ui: &mut Ui, operation: &CurrentOperation) {
    ui.label(RichText::new(operation.label()).color(operation_color(operation)));

    match operation.progress() {
        OperationProgress::None => {}
        OperationProgress::Determinate(fraction) => {
            ui.add(
                ProgressBar::new(fraction)
                    .desired_width(120.0)
                    .desired_height(12.0)
                    .show_percentage(),
            );
        }
        OperationProgress::Indeterminate => {
            ui.add(Spinner::new().size(14.0));
        }
    }
}

fn show_xray_status(ui: &mut Ui, status: &XrayStatus) {
    ui.label(RichText::new(status.message()).color(severity_color(status.severity())));
}

fn show_ssh_status(ui: &mut Ui, status: SshStatus) {
    let text = format!("SSH: {}", status.label());
    ui.label(RichText::new(text).color(severity_color(status.severity())));
}

fn operation_color(operation: &CurrentOperation) -> Color32 {
    match operation {
        CurrentOperation::Message { .. } => severity_color(StatusSeverity::Healthy),
        other if other.is_busy() => severity_color(StatusSeverity::Warning),
        _ => severity_color(StatusSeverity::Unknown),
    }
}

fn severity_color(severity: StatusSeverity) -> Color32 {
    match severity {
        StatusSeverity::Healthy => Color32::from_rgb(46, 160, 67),
        StatusSeverity::Warning => Color32::from_rgb(210, 170, 40),
        StatusSeverity::Error => Color32::from_rgb(200, 60, 60),
        StatusSeverity::Unknown => Color32::from_rgb(140, 140, 140),
    }
}
