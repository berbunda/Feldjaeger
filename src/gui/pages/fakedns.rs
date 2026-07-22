//! FakeDNS page — read-only view of the discovered Xray FakeDNS configuration.
//!
//! Data flows exclusively through [`ApplicationService`] and FakeDNS summaries.
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{ApplicationService, FakeDnsPageState, MISSING_FIELD, fakedns_pool_display};
use crate::xray::{FakeDnsPoolSummary, FakeDnsSummary};

/// Renders the FakeDNS page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_fakedns_page_status();

    ui.heading("FakeDNS");
    ui.add_space(8.0);

    let model = service.fakedns_page_model();
    match model.state {
        FakeDnsPageState::NoSshConnection
        | FakeDnsPageState::XrayNotDiscovered
        | FakeDnsPageState::ConfigurationNotLoaded
        | FakeDnsPageState::FakeDnsSectionMissing => {
            show_state_message(ui, model.state);
            return;
        }
        FakeDnsPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            for warning in &model.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(8.0);
        }
        FakeDnsPageState::ConfigurationLoaded => {}
    }

    let Some(summary) = model.summary.as_ref() else {
        show_state_message(ui, FakeDnsPageState::FakeDnsSectionMissing);
        return;
    };

    show_info_note(ui);
    ui.add_space(12.0);

    if summary.pools.is_empty() {
        ui.label(
            RichText::new("No FakeDNS pools configured.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    for (index, pool) in summary.pools.iter().enumerate() {
        if summary.pools.len() > 1 {
            ui.strong(format!("Pool {}", index + 1));
            ui.add_space(4.0);
        }
        show_pool(ui, summary, pool, index);
        ui.add_space(12.0);
    }
}

fn show_state_message(ui: &mut Ui, state: FakeDnsPageState) {
    let color = match state {
        FakeDnsPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        FakeDnsPageState::FakeDnsSectionMissing | FakeDnsPageState::ConfigurationLoaded => {
            Color32::from_rgb(140, 140, 140)
        }
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_info_note(ui: &mut Ui) {
    ui.label(
        RichText::new("FakeDNS requires corresponding DNS and routing configuration.")
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn show_pool(ui: &mut Ui, summary: &FakeDnsSummary, pool: &FakeDnsPoolSummary, index: usize) {
    let display = fakedns_pool_display(summary, pool);
    egui::Grid::new(format!("fakedns_pool_{index}"))
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            pool_row(ui, summary, pool, "IP pool", &display.ip_pool);
            pool_row(ui, summary, pool, "Pool size", &display.pool_size);
            pool_row(ui, summary, pool, "Address family", &display.address_family);
            pool_row(ui, summary, pool, "Source file", &display.source_file);
            pool_row(ui, summary, pool, "CIDR prefix", &display.cidr_prefix);
            pool_row(
                ui,
                summary,
                pool,
                "Total address capacity",
                &display.total_address_capacity,
            );
            pool_row(
                ui,
                summary,
                pool,
                "Configured pool size",
                &display.configured_pool_size,
            );
        });
}

fn pool_row(
    ui: &mut Ui,
    summary: &FakeDnsSummary,
    pool: &FakeDnsPoolSummary,
    label: &str,
    value: &str,
) {
    ui.label(label);
    let response = ui.add(egui::Label::new(value).sense(Sense::click()));
    response.context_menu(|ui| {
        if ui.button("Copy IP pool").clicked() {
            ui.ctx().copy_text(
                pool.ip_pool
                    .clone()
                    .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.close();
        }
        if ui.button("Copy pool size").clicked() {
            ui.ctx().copy_text(
                pool.pool_size
                    .map(|size| size.to_string())
                    .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.close();
        }
        if ui.button("Copy source file").clicked() {
            ui.ctx()
                .copy_text(crate::app::display_source_file(&summary.source_file).to_owned());
            ui.close();
        }
        disabled_actions(ui);
    });
    ui.end_row();
}

fn disabled_actions(ui: &mut Ui) {
    ui.separator();
    ui.add_enabled(false, egui::Button::new("Edit"))
        .on_disabled_hover_text("Not implemented yet");
    ui.add_enabled(false, egui::Button::new("Delete"))
        .on_disabled_hover_text("Not implemented yet");
}
