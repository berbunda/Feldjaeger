//! Observatory page — read-only view of the discovered Xray Observatory section.
//!
//! Data flows exclusively through [`ApplicationService`] and Observatory summaries.
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, MISSING_FIELD, ObservatoryPageState, observatory_general_display,
};
use crate::xray::ObservatorySummary;

/// Renders the Observatory page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_observatory_page_status();

    ui.heading("Observatory");
    ui.add_space(8.0);

    let model = service.observatory_page_model();
    match model.state {
        ObservatoryPageState::NoSshConnection
        | ObservatoryPageState::XrayNotDiscovered
        | ObservatoryPageState::ConfigurationNotLoaded
        | ObservatoryPageState::ObservatorySectionMissing => {
            show_state_message(ui, model.state);
            return;
        }
        ObservatoryPageState::NoSubjectSelectors => {
            show_state_message(ui, model.state);
            show_warnings(ui, &model.warnings);
            ui.add_space(8.0);
        }
        ObservatoryPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            show_warnings(ui, &model.warnings);
            ui.add_space(8.0);
        }
        ObservatoryPageState::ConfigurationLoaded => {}
    }

    let Some(summary) = model.summary.as_ref() else {
        show_state_message(ui, ObservatoryPageState::ObservatorySectionMissing);
        return;
    };

    show_info_note(ui);
    ui.add_space(12.0);
    show_general(ui, summary);
    ui.add_space(12.0);
    show_subjects(ui, summary);
}

fn show_state_message(ui: &mut Ui, state: ObservatoryPageState) {
    let color = match state {
        ObservatoryPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        ObservatoryPageState::ObservatorySectionMissing
        | ObservatoryPageState::NoSubjectSelectors
        | ObservatoryPageState::ConfigurationLoaded => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_warnings(ui: &mut Ui, warnings: &[String]) {
    for warning in warnings {
        ui.label(
            RichText::new(warning.clone())
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
}

fn show_info_note(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "Runtime latency and availability require the Tier 3 Xray API and are not available yet.",
        )
        .size(14.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn show_general(ui: &mut Ui, summary: &ObservatorySummary) {
    let display = observatory_general_display(summary);
    ui.strong("General");
    ui.add_space(4.0);
    egui::Grid::new("observatory_general")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("Probe URL");
            let response = ui.add(egui::Label::new(&display.probe_url).sense(Sense::click()));
            response.context_menu(|ui| {
                if ui.button("Copy Probe URL").clicked() {
                    ui.ctx().copy_text(
                        summary
                            .probe_url
                            .clone()
                            .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    );
                    ui.close();
                }
                disabled_actions(ui);
            });
            ui.end_row();

            general_row(ui, "Probe Interval", &display.probe_interval);
            general_row(
                ui,
                "Subject Selector count",
                &display.subject_selector_count,
            );
            general_row(ui, "Source file", &display.source_file);
        });
}

fn general_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn show_subjects(ui: &mut Ui, summary: &ObservatorySummary) {
    ui.strong("Subjects");
    ui.add_space(4.0);
    if summary.subject_selectors.is_empty() {
        ui.label(
            RichText::new("No subject selectors configured.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    egui::Grid::new("observatory_subjects_table")
        .num_columns(2)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(40.0)
        .show(ui, |ui| {
            ui.strong("#");
            ui.strong("Selector");
            ui.end_row();

            for (index, selector) in summary.subject_selectors.iter().enumerate() {
                ui.label((index + 1).to_string());
                let response = ui.add(egui::Label::new(selector).sense(Sense::click()));
                response.context_menu(|ui| {
                    if ui.button("Copy Selector").clicked() {
                        ui.ctx().copy_text(selector.clone());
                        ui.close();
                    }
                    disabled_actions(ui);
                });
                ui.end_row();
            }
        });
}

fn disabled_actions(ui: &mut Ui) {
    ui.separator();
    ui.add_enabled(false, egui::Button::new("Edit"))
        .on_disabled_hover_text("Not implemented yet");
    ui.add_enabled(false, egui::Button::new("Delete"))
        .on_disabled_hover_text("Not implemented yet");
    ui.add_enabled(false, egui::Button::new("Duplicate"))
        .on_disabled_hover_text("Not implemented yet");
}
