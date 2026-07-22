//! Burst Observatory page — read-only Xray configuration view.
//!
//! Data comes exclusively from [`ApplicationService`]; this module performs no
//! JSON parsing, SSH operations, serialization, or configuration mutation.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, BurstObservatoryPageState, MISSING_FIELD,
    burst_observatory_general_display, burst_ping_config_display,
};
use crate::xray::{BurstObservatorySummary, BurstPingConfigSummary};

/// Renders the Burst Observatory page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_burst_observatory_page_status();

    ui.heading("BurstObservatory");
    ui.add_space(8.0);

    let model = service.burst_observatory_page_model();
    match model.state {
        BurstObservatoryPageState::NoSshConnection
        | BurstObservatoryPageState::XrayNotDiscovered
        | BurstObservatoryPageState::ConfigurationNotLoaded
        | BurstObservatoryPageState::BurstObservatorySectionMissing => {
            show_state_message(ui, model.state);
            return;
        }
        BurstObservatoryPageState::NoSubjectSelectors
        | BurstObservatoryPageState::NoPingConfigurations
        | BurstObservatoryPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            show_warnings(ui, &model.warnings);
            ui.add_space(8.0);
        }
        BurstObservatoryPageState::ConfigurationLoaded => {}
    }

    let Some(summary) = model.summary.as_ref() else {
        show_state_message(
            ui,
            BurstObservatoryPageState::BurstObservatorySectionMissing,
        );
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

fn show_state_message(ui: &mut Ui, state: BurstObservatoryPageState) {
    let color = match state {
        BurstObservatoryPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        BurstObservatoryPageState::BurstObservatorySectionMissing
        | BurstObservatoryPageState::NoSubjectSelectors
        | BurstObservatoryPageState::NoPingConfigurations
        | BurstObservatoryPageState::ConfigurationLoaded => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
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
                    disabled_actions(ui);
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
        disabled_actions(ui);
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

fn disabled_actions(ui: &mut Ui) {
    ui.separator();
    ui.add_enabled(false, egui::Button::new("Edit"))
        .on_disabled_hover_text("Not implemented yet");
    ui.add_enabled(false, egui::Button::new("Delete"))
        .on_disabled_hover_text("Not implemented yet");
    ui.add_enabled(false, egui::Button::new("Duplicate"))
        .on_disabled_hover_text("Not implemented yet");
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
