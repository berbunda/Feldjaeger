//! Burst Observatory page — read-only Xray configuration view.
//!
//! Data comes exclusively from [`ApplicationService`]; this module performs no
//! JSON parsing, SSH operations, serialization, or configuration mutation.

use egui::{Color32, RichText, Sense, TextEdit, Ui};

use crate::app::{
    ApplicationService, BurstObservatoryPageState, MISSING_FIELD,
    burst_observatory_general_display, burst_ping_config_display,
};
use crate::xray::{BurstObservatorySummary, BurstPingConfigEntry, BurstPingConfigSummary};

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);

/// Documented `PingConfigObject.httpMethod` examples, offered as a preset combo; the field
/// itself accepts any HTTP method string.
const HTTP_METHOD_PRESETS: &[&str] = &["HEAD", "GET"];

/// Renders the Burst Observatory page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_burst_observatory_page_status();

    ui.heading("BurstObservatory");
    ui.add_space(8.0);

    let model = service.burst_observatory_page_model();

    match model.state {
        BurstObservatoryPageState::NoSshConnection
        | BurstObservatoryPageState::XrayNotDiscovered
        | BurstObservatoryPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        BurstObservatoryPageState::MalformedBurstObservatoryObject => {
            show_state_message(ui, model.state);
            for warning in &model.burst_observatory_settings.warnings {
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
        if let Some(entries) = service.burst_observatory_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        egui::ScrollArea::vertical()
            .id_salt("burst_observatory_edit_scroll")
            .show(ui, |ui| show_edit_form(ui, service));
        return;
    }

    if model.state == BurstObservatoryPageState::BurstObservatorySectionMissing {
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
    ui.add_space(12.0);
    show_ping_configurations(ui, summary);
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: BurstObservatoryPageState,
) {
    let busy = matches!(
        state,
        BurstObservatoryPageState::Saving | BurstObservatoryPageState::SaveFailed
    ) && service.is_burst_observatory_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_burst_observatory_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_burst_observatory_settings();
            }
            if ui
                .add_enabled(
                    !service.is_burst_observatory_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_burst_observatory_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_burst_observatory_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_burst_observatory_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_burst_observatory_settings();
        }
    });
}

fn show_state_message(ui: &mut Ui, state: BurstObservatoryPageState) {
    let color = match state {
        BurstObservatoryPageState::ConfigurationContainsWarnings
        | BurstObservatoryPageState::ValidationError
        | BurstObservatoryPageState::Saved => WARN_COLOR,
        BurstObservatoryPageState::BurstObservatorySectionMissing
        | BurstObservatoryPageState::NoSubjectSelectors
        | BurstObservatoryPageState::NoPingConfigurations
        | BurstObservatoryPageState::ConfigurationLoaded
        | BurstObservatoryPageState::EditMode => MUTED_COLOR,
        BurstObservatoryPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_warnings(ui: &mut Ui, warnings: &[String]) {
    for warning in warnings {
        ui.label(
            RichText::new(warning)
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
}

fn show_info_note(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "BurstObservatory configuration is displayed only.\n\
             Live probe execution and statistics are not available in read-only mode.\n\
             Runtime information will be available after Xray API support is implemented.",
        )
        .size(14.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn show_general(ui: &mut Ui, summary: &BurstObservatorySummary) {
    let display = burst_observatory_general_display(summary);
    ui.strong("General");
    ui.add_space(4.0);
    egui::Grid::new("burst_observatory_general")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            detail_row(
                ui,
                "Subject selector count",
                &display.subject_selector_count,
            );
            detail_row(
                ui,
                "Ping configuration count",
                &display.ping_configuration_count,
            );
            detail_row(ui, "Source file", &display.source_file);
        });
}

fn show_subjects(ui: &mut Ui, summary: &BurstObservatorySummary) {
    ui.strong("Subject selectors");
    ui.add_space(4.0);
    if summary.subject_selectors.is_empty() {
        muted(ui, "No subject selectors configured.");
        return;
    }

    egui::Grid::new("burst_observatory_subjects")
        .num_columns(2)
        .striped(true)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.strong("#");
            ui.strong("Selector");
            ui.end_row();

            for (index, selector) in summary.subject_selectors.iter().enumerate() {
                ui.label((index + 1).to_string());
                let response = ui.add(egui::Label::new(selector).sense(Sense::click()));
                response.context_menu(|ui| {
                    if ui.button("Copy selector").clicked() {
                        ui.ctx().copy_text(selector.clone());
                        ui.close();
                    }
                });
                ui.end_row();
            }
        });
}

fn show_ping_configurations(ui: &mut Ui, summary: &BurstObservatorySummary) {
    ui.strong("Ping configurations");
    ui.add_space(4.0);
    let Some(config) = summary.ping_config.as_ref() else {
        muted(ui, "No ping configurations configured.");
        return;
    };

    let selected = selected_ping_config(ui);
    let display = burst_ping_config_display(config);
    egui::ScrollArea::horizontal()
        .id_salt("burst_observatory_ping_scroll")
        .show(ui, |ui| {
            egui::Grid::new("burst_observatory_ping_table")
                .num_columns(6)
                .striped(true)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("#");
                    ui.strong("Destination");
                    ui.strong("Interval");
                    ui.strong("Timeout");
                    ui.strong("Sampling");
                    ui.strong("Summary");
                    ui.end_row();

                    let index = if selected { "› 1" } else { "1" };
                    ping_cell(ui, config, index);
                    ping_cell(ui, config, &display.destination);
                    ping_cell(ui, config, &display.interval);
                    ping_cell(ui, config, &display.timeout);
                    ping_cell(ui, config, &display.sampling);
                    ping_cell(ui, config, &display.summary);
                    ui.end_row();
                });
        });

    if selected_ping_config(ui) {
        show_ping_details(ui, summary, config);
    } else {
        ui.add_space(12.0);
        muted(ui, "Select the ping configuration to view details.");
    }
}

fn ping_cell(ui: &mut Ui, config: &BurstPingConfigSummary, text: &str) {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    if response.clicked() || response.secondary_clicked() {
        set_selected_ping_config(ui, true);
    }
    response.context_menu(|ui| {
        if ui.button("Copy destination").clicked() {
            ui.ctx().copy_text(
                config
                    .destination
                    .clone()
                    .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.close();
        }
        if ui.button("Copy interval").clicked() {
            ui.ctx().copy_text(
                config
                    .interval
                    .clone()
                    .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.close();
        }
    });
}

fn show_ping_details(
    ui: &mut Ui,
    summary: &BurstObservatorySummary,
    config: &BurstPingConfigSummary,
) {
    let display = burst_ping_config_display(config);
    ui.add_space(12.0);
    ui.strong("Ping configuration details");

    detail_group(ui, "General", &[("Summary", &display.summary)]);
    detail_group(
        ui,
        "Destination",
        &[
            ("Destination", &display.destination),
            ("Connectivity", &display.connectivity),
            ("HTTP method", &display.http_method),
        ],
    );
    detail_group(
        ui,
        "Timing",
        &[
            ("Interval", &display.interval),
            ("Timeout", &display.timeout),
        ],
    );
    detail_group(ui, "Sampling", &[("Sampling", &display.sampling)]);
    detail_group(
        ui,
        "Source",
        &[(
            "Source file",
            crate::app::display_source_file(&summary.source_file),
        )],
    );
    muted(ui, "Unknown fields remain preserved internally.");
}

fn detail_group(ui: &mut Ui, title: &str, rows: &[(&str, &str)]) {
    ui.add_space(8.0);
    ui.label(RichText::new(title).strong());
    egui::Grid::new(format!("burst_observatory_detail_{title}"))
        .num_columns(2)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            for (label, value) in rows {
                detail_row(ui, label, value);
            }
        });
}

fn detail_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn muted(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn selected_ping_config(ui: &Ui) -> bool {
    ui.ctx()
        .data(|data| data.get_temp(egui::Id::new("burst_observatory_selected_ping")))
        .unwrap_or(false)
}

fn set_selected_ping_config(ui: &Ui, selected: bool) {
    ui.ctx().data_mut(|data| {
        data.insert_temp(egui::Id::new("burst_observatory_selected_ping"), selected);
    });
}

// ─── Edit mode ──────────────────────────────────────────────────────────────

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(draft) = service.burst_observatory_settings_draft_mut() else {
        return;
    };

    ui.strong(format!("Subject selectors ({})", draft.subject_selectors.len()));
    ui.add_space(4.0);
    let mut text = draft.subject_selectors.join("\n");
    if ui
        .add(
            TextEdit::multiline(&mut text)
                .desired_rows(4)
                .hint_text("one outbound tag prefix per line"),
        )
        .changed()
    {
        draft.subject_selectors = text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
    }

    ui.add_space(16.0);
    ui.separator();

    let mut enabled = draft.ping_config.is_some();
    if ui.checkbox(&mut enabled, "pingConfig").changed() {
        draft.ping_config = if enabled {
            Some(draft.ping_config.take().unwrap_or_else(BurstPingConfigEntry::blank))
        } else {
            None
        };
    }
    let Some(ping_config) = draft.ping_config.as_mut() else {
        return;
    };

    egui::CollapsingHeader::new("Ping configuration settings")
        .default_open(true)
        .show(ui, |ui| {
            optional_text_row(
                ui,
                "destination",
                &mut ping_config.destination,
                "https://connectivitycheck.gstatic.com/generate_204 (default)",
            );
            optional_text_row(
                ui,
                "connectivity",
                &mut ping_config.connectivity,
                "(default: no check)",
            );
            optional_text_row(ui, "interval", &mut ping_config.interval, "1m (default, min 10s)");
            optional_u64_row(ui, "sampling", &mut ping_config.sampling, 10, "burst_ping_sampling");
            optional_text_row(ui, "timeout", &mut ping_config.timeout, "5s (default)");

            ui.horizontal(|ui| {
                ui.label("httpMethod");
                http_method_combo(ui, "burst_ping_http_method", &mut ping_config.http_method);
            });
        });
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

fn optional_u64_row(
    ui: &mut Ui,
    label: &str,
    value: &mut Option<u64>,
    default: u64,
    id: impl std::hash::Hash + std::fmt::Debug,
) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(default);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut enabled, format!("{label} (default {default})"));
            ui.add_enabled(enabled, egui::DragValue::new(&mut number));
        });
    });
    *value = if enabled { Some(number) } else { None };
}

fn http_method_combo(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, value: &mut Option<String>) {
    let selected_text = value.clone().unwrap_or_else(|| "(default: HEAD)".to_owned());
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt(id)
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                if ui.selectable_label(value.is_none(), "(default: HEAD)").clicked() {
                    *value = None;
                }
                for preset in HTTP_METHOD_PRESETS {
                    if ui
                        .selectable_label(value.as_deref() == Some(*preset), *preset)
                        .clicked()
                    {
                        *value = Some((*preset).to_owned());
                    }
                }
            });
        let mut text = value.clone().unwrap_or_default();
        if ui
            .add(TextEdit::singleline(&mut text).desired_width(100.0).hint_text("custom"))
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
