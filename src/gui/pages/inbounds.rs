//! Inbounds page — read-only table of discovered inbound summaries.
//!
//! Data flows exclusively through [`ApplicationService`] → [`InboundSummary`].
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, InboundsPageState, InboundsSortColumn, MISSING_FIELD, inbound_row_display,
};
use crate::xray::InboundSummary;

/// Renders the Inbounds page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Inbounds");
    ui.add_space(8.0);

    let model = service.inbounds_page_model();

    match model.state {
        InboundsPageState::NoSshConnection
        | InboundsPageState::NoXrayInstallation
        | InboundsPageState::DiscoveryNotCompleted
        | InboundsPageState::ConfigurationNotLoaded
        | InboundsPageState::NoInbounds => {
            show_state_message(ui, model.state);
            return;
        }
        InboundsPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            for warning in &model.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(8.0);
            if model.rows.is_empty() {
                ui.label(RichText::new("No inbounds").size(14.0));
                return;
            }
        }
        InboundsPageState::ConfigurationLoaded => {}
    }

    show_table(ui, service, &model.rows);
}

fn show_state_message(ui: &mut Ui, state: InboundsPageState) {
    let color = match state {
        InboundsPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        InboundsPageState::NoInbounds => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[InboundSummary]) {
    let sort = service.inbounds_sort();

    egui::Grid::new("inbounds_table")
        .num_columns(6)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(72.0)
        .show(ui, |ui| {
            sortable_header(ui, service, "Tag", InboundsSortColumn::Tag, sort.column);
            sortable_header(
                ui,
                service,
                "Protocol",
                InboundsSortColumn::Protocol,
                sort.column,
            );
            ui.strong("Listen");
            sortable_header(ui, service, "Port", InboundsSortColumn::Port, sort.column);
            ui.strong("Clients");
            ui.strong("Source file");
            ui.end_row();

            for row in rows {
                let display = inbound_row_display(row);
                cell_with_menu(ui, row, &display.tag);
                cell_with_menu(ui, row, &display.protocol);
                cell_with_menu(ui, row, &display.listen);
                cell_with_menu(ui, row, &display.port);
                cell_with_menu(ui, row, &display.clients);
                cell_with_menu(ui, row, display.source_file);
                ui.end_row();
            }
        });
}

fn sortable_header(
    ui: &mut Ui,
    service: &mut ApplicationService,
    label: &str,
    column: InboundsSortColumn,
    active: InboundsSortColumn,
) {
    let sort = service.inbounds_sort();
    let marker = if active == column {
        if sort.ascending { " ▲" } else { " ▼" }
    } else {
        ""
    };
    let text = format!("{label}{marker}");
    if ui
        .add(egui::Label::new(RichText::new(text).strong()).sense(Sense::click()))
        .clicked()
    {
        service.set_inbounds_sort_column(column);
    }
}

fn cell_with_menu(ui: &mut Ui, row: &InboundSummary, text: &str) {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    show_inbound_context_menu(&response, row);
}

fn show_inbound_context_menu(response: &egui::Response, row: &InboundSummary) {
    response.context_menu(|ui| {
        if ui.button("Copy tag").clicked() {
            let text = row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }
        if ui.button("Copy port").clicked() {
            let text = row
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }
        if ui.button("Copy protocol").clicked() {
            let text = row
                .protocol
                .clone()
                .unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }

        ui.separator();

        ui.add_enabled(false, egui::Button::new("Edit"))
            .on_disabled_hover_text("Not implemented yet");
        ui.add_enabled(false, egui::Button::new("Delete"))
            .on_disabled_hover_text("Not implemented yet");
        ui.add_enabled(false, egui::Button::new("Duplicate"))
            .on_disabled_hover_text("Not implemented yet");
    });
}
