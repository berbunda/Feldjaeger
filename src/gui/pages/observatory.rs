//! Observatory page — read-only view of the discovered Xray Observatory section.
//!
//! Data flows exclusively through [`ApplicationService`] and Observatory summaries.
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, TextEdit, Ui};

use crate::app::{
    ApplicationService, MISSING_FIELD, ObservatoryPageState, observatory_general_display,
};
use crate::xray::ObservatorySummary;

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);

/// Renders the Observatory page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_observatory_page_status();

    ui.heading("Observatory");
    ui.add_space(8.0);

    let model = service.observatory_page_model();

    match model.state {
        ObservatoryPageState::NoSshConnection
        | ObservatoryPageState::XrayNotDiscovered
        | ObservatoryPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        ObservatoryPageState::MalformedObservatoryObject => {
            show_state_message(ui, model.state);
            for warning in &model.observatory_settings.warnings {
                ui.label(RichText::new(warning.clone()).size(14.0).color(ERROR_COLOR));
            }
            return;
        }
        _ => {}
    }

    show_state_message(ui, model.state);
    show_warnings(ui, &model.warnings);
    if let Some(error) = &model.error_message {
        ui.label(RichText::new(error.clone()).size(14.0).color(ERROR_COLOR));
    }
    ui.add_space(8.0);

    show_actions(ui, service, model.editing, model.state);
    ui.add_space(12.0);

    if model.editing {
        if !model.change_summary.is_empty() {
            ui.strong("Change summary");
            ui.add_space(4.0);
            for line in &model.change_summary {
                for part in line.lines() {
                    ui.label(RichText::new(part.to_owned()).size(13.0));
                }
                ui.add_space(4.0);
            }
            ui.add_space(8.0);
        }
        if let Some(entries) = service.observatory_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        egui::ScrollArea::vertical()
            .id_salt("observatory_edit_scroll")
            .show(ui, |ui| show_edit_form(ui, service));
        return;
    }

    if model.state == ObservatoryPageState::ObservatorySectionMissing {
        return;
    }

    let Some(summary) = model.summary.as_ref() else {
        return;
    };

    show_info_note(ui);
    ui.add_space(12.0);
    show_general(ui, summary);
    ui.add_space(12.0);
    show_subjects(ui, summary);
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: ObservatoryPageState,
) {
    let busy = matches!(state, ObservatoryPageState::Saving | ObservatoryPageState::SaveFailed)
        && service.is_observatory_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_observatory_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_observatory_settings();
            }
            if ui
                .add_enabled(
                    !service.is_observatory_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_observatory_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_observatory_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_observatory_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_observatory_settings();
        }
    });
}

fn show_state_message(ui: &mut Ui, state: ObservatoryPageState) {
    let color = match state {
        ObservatoryPageState::ConfigurationContainsWarnings
        | ObservatoryPageState::ValidationError
        | ObservatoryPageState::Saved => WARN_COLOR,
        ObservatoryPageState::ObservatorySectionMissing
        | ObservatoryPageState::NoSubjectSelectors
        | ObservatoryPageState::ConfigurationLoaded
        | ObservatoryPageState::EditMode => MUTED_COLOR,
        ObservatoryPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => ERROR_COLOR,
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
                });
                ui.end_row();
            }
        });
}

// ─── Edit mode ──────────────────────────────────────────────────────────────

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(draft) = service.observatory_settings_draft_mut() else {
        return;
    };

    ui.strong("General");
    ui.add_space(4.0);

    optional_text_row(ui, "probeUrl", &mut draft.probe_url, "https://www.google.com/generate_204");
    optional_text_row(ui, "probeInterval", &mut draft.probe_interval, "10s");
    ui.checkbox(&mut draft.enable_concurrency, "enableConcurrency");
    ui.label(
        RichText::new(
            "enableConcurrency: probe all matching outbounds at once instead of one at a time \
             (default: off).",
        )
        .size(12.0)
        .color(MUTED_COLOR),
    );

    ui.add_space(16.0);
    ui.separator();
    ui.strong(format!("Subject selectors ({})", draft.subject_selectors.len()));
    ui.add_space(4.0);
    let mut text = draft.subject_selectors.join("\n");
    if ui
        .add(TextEdit::multiline(&mut text).desired_rows(4).hint_text("one outbound tag prefix per line"))
        .changed()
    {
        draft.subject_selectors = text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
    }
}

fn optional_text_row(ui: &mut Ui, label: &str, value: &mut Option<String>, hint: &str) {
    let mut text = value.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label(label);
        if ui
            .add(TextEdit::singleline(&mut text).desired_width(280.0).hint_text(hint))
            .changed()
        {
            let trimmed = text.trim();
            *value = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
}
