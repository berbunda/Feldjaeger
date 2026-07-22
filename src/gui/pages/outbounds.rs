//! Outbounds page — read-only table of discovered outbound summaries.
//!
//! Data flows exclusively through [`ApplicationService`] → [`OutboundSummary`].
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, MISSING_FIELD, OutboundsPageState, OutboundsSortColumn,
    outbound_row_display,
};
use crate::xray::OutboundSummary;

/// Renders the Outbounds page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_outbounds_page_status();

    ui.heading("Outbounds");
    ui.add_space(8.0);

    let model = service.outbounds_page_model();

    match model.state {
        OutboundsPageState::NoSshConnection
        | OutboundsPageState::XrayNotDiscovered
        | OutboundsPageState::ConfigurationNotLoaded
        | OutboundsPageState::NoOutbounds => {
            show_state_message(ui, model.state);
            return;
        }
        OutboundsPageState::ConfigurationContainsWarnings => {
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
                ui.label(RichText::new("No outbounds").size(14.0));
                return;
            }
        }
        OutboundsPageState::ConfigurationLoaded => {}
    }

    show_table(ui, service, &model.rows);
}

fn show_state_message(ui: &mut Ui, state: OutboundsPageState) {
    let color = match state {
        OutboundsPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        OutboundsPageState::NoOutbounds => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[OutboundSummary]) {
    let sort = service.outbounds_sort();

    egui::Grid::new("outbounds_table")
        .num_columns(5)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(72.0)
        .show(ui, |ui| {
            sortable_header(ui, service, "Tag", OutboundsSortColumn::Tag, sort.column);
            sortable_header(
                ui,
                service,
                "Protocol",
                OutboundsSortColumn::Protocol,
                sort.column,
            );
            ui.strong("Send Through");
            ui.strong("Summary");
            ui.strong("Source file");
            ui.end_row();

            for row in rows {
                let display = outbound_row_display(row);
                cell_with_menu(ui, row, &display.tag);
                cell_with_menu(ui, row, &display.protocol);
                cell_with_menu(ui, row, &display.send_through);
                cell_with_menu(ui, row, &display.summary);
                cell_with_menu(ui, row, display.source_file);
                ui.end_row();
            }
        });
}

fn sortable_header(
    ui: &mut Ui,
    service: &mut ApplicationService,
    label: &str,
    column: OutboundsSortColumn,
    active: OutboundsSortColumn,
) {
    let sort = service.outbounds_sort();
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
        service.set_outbounds_sort_column(column);
    }
}

fn cell_with_menu(ui: &mut Ui, row: &OutboundSummary, text: &str) {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    show_outbound_context_menu(&response, row);
}

fn show_outbound_context_menu(response: &egui::Response, row: &OutboundSummary) {
    response.context_menu(|ui| {
        if ui.button("Copy tag").clicked() {
            let text = row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned());
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
