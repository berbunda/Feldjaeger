//! Outbounds page — table of discovered outbound summaries + Delete.
//!
//! Data flows exclusively through [`ApplicationService`] → [`OutboundSummary`].
//! This page never reads JSON or opens SSH directly.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, MISSING_FIELD, OutboundsPageState, OutboundsSortColumn,
    outbound_row_display,
};
use crate::xray::OutboundSummary;

/// Renders the Outbounds page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_outbounds_page_status();
    show_delete_outbound_dialog(ui, service);

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
                cell_with_menu(ui, service, row, &display.tag);
                cell_with_menu(ui, service, row, &display.protocol);
                cell_with_menu(ui, service, row, &display.send_through);
                cell_with_menu(ui, service, row, &display.summary);
                cell_with_menu(ui, service, row, display.source_file);
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
        if sort.ascending {
            " ▲"
        } else {
            " ▼"
        }
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

fn cell_with_menu(ui: &mut Ui, service: &mut ApplicationService, row: &OutboundSummary, text: &str) {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    show_outbound_context_menu(&response, service, row);
}

fn show_outbound_context_menu(
    response: &egui::Response,
    service: &mut ApplicationService,
    row: &OutboundSummary,
) {
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

        let busy = service.is_outbound_mutation_busy();
        if ui
            .add_enabled(!busy, egui::Button::new("Delete"))
            .on_disabled_hover_text("Delete requires an idle connection")
            .clicked()
        {
            set_pending_outbound_delete(
                ui,
                PendingOutboundDelete {
                    index: row.index,
                    tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    protocol: row
                        .protocol
                        .clone()
                        .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    error: None,
                },
            );
            ui.close();
        }

        ui.add_enabled(false, egui::Button::new("Duplicate"))
            .on_disabled_hover_text("Not implemented yet");
    });
}

#[derive(Clone)]
struct PendingOutboundDelete {
    index: usize,
    tag: String,
    protocol: String,
    error: Option<String>,
}

fn pending_outbound_delete_id() -> egui::Id {
    egui::Id::new("outbounds_pending_delete")
}

fn pending_outbound_delete(ui: &Ui) -> Option<PendingOutboundDelete> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingOutboundDelete>(pending_outbound_delete_id()))
}

fn set_pending_outbound_delete(ui: &Ui, pending: PendingOutboundDelete) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_outbound_delete_id(), pending));
}

fn clear_pending_outbound_delete(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingOutboundDelete>(pending_outbound_delete_id()));
}

fn show_delete_outbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(pending) = pending_outbound_delete(ui) else {
        return;
    };
    let mut open = true;
    egui::Window::new("Delete outbound")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(format!(
                    "Delete outbound «{}» ({})? This removes it from the remote configuration.",
                    pending.tag, pending.protocol
                ))
                .size(14.0),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Outbound shell edit is not available yet. Deletion cannot be undone from the UI (restore from backup if needed).",
                )
                .size(13.0)
                .color(Color32::from_rgb(160, 120, 40)),
            );
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_outbound_mutation_busy();
                if ui
                    .add_enabled(!busy, egui::Button::new("Delete"))
                    .clicked()
                {
                    match service.start_delete_outbound(pending.index) {
                        Ok(()) => clear_pending_outbound_delete(ui),
                        Err(message) => {
                            set_pending_outbound_delete(
                                ui,
                                PendingOutboundDelete {
                                    error: Some(message),
                                    ..pending.clone()
                                },
                            );
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    clear_pending_outbound_delete(ui);
                }
            });
        });

    if !open {
        clear_pending_outbound_delete(ui);
    }
}
