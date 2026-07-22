//! Policy page — read-only view of the discovered Xray policy configuration.
//!
//! Data flows exclusively through [`ApplicationService`] and policy summaries.
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, MISSING_FIELD, PolicyPageState, PolicySortColumn, display_enabled_flag,
    format_timeout_values, policy_general_display, system_policy_display, user_policy_row_display,
};
use crate::xray::{PolicySummary, SystemPolicySummary, UserPolicySummary};

/// Renders the Policy page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_policy_page_status();

    ui.heading("Policy");
    ui.add_space(8.0);

    let model = service.policy_page_model();
    match model.state {
        PolicyPageState::NoSshConnection
        | PolicyPageState::XrayNotDiscovered
        | PolicyPageState::ConfigurationNotLoaded
        | PolicyPageState::PolicySectionMissing => {
            show_state_message(ui, model.state);
            return;
        }
        PolicyPageState::NoUserPolicies => {
            show_state_message(ui, model.state);
            if let Some(summary) = model.summary.as_ref() {
                ui.add_space(8.0);
                show_general_information(ui, summary);
                ui.add_space(12.0);
                show_system_policy_panel(ui, summary.system_policy.as_ref());
            }
            return;
        }
        PolicyPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            for warning in &model.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(8.0);
            let Some(summary) = model.summary.as_ref() else {
                show_state_message(ui, PolicyPageState::PolicySectionMissing);
                return;
            };
            show_loaded_content(ui, service, summary, &model.rows);
            return;
        }
        PolicyPageState::ConfigurationLoaded => {}
    }

    let Some(summary) = model.summary.as_ref() else {
        show_state_message(ui, PolicyPageState::PolicySectionMissing);
        return;
    };
    show_loaded_content(ui, service, summary, &model.rows);
}

fn show_loaded_content(
    ui: &mut Ui,
    service: &mut ApplicationService,
    summary: &PolicySummary,
    rows: &[UserPolicySummary],
) {
    show_general_information(ui, summary);
    ui.add_space(12.0);
    show_system_policy_panel(ui, summary.system_policy.as_ref());
    ui.add_space(12.0);

    if rows.is_empty() {
        show_state_message(ui, PolicyPageState::NoUserPolicies);
        return;
    }

    show_levels_table(ui, service, rows);
    show_selected_level_details(ui, rows);
}

fn show_state_message(ui: &mut Ui, state: PolicyPageState) {
    let color = match state {
        PolicyPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        PolicyPageState::PolicySectionMissing
        | PolicyPageState::NoUserPolicies
        | PolicyPageState::ConfigurationLoaded => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_general_information(ui: &mut Ui, summary: &PolicySummary) {
    let display = policy_general_display(summary);
    ui.strong("General information");
    ui.add_space(4.0);
    egui::Grid::new("policy_general_information")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            general_row(ui, "User policy count", &display.user_policy_count);
            general_row(
                ui,
                "System policy configured",
                &display.system_policy_configured,
            );
        });
}

fn general_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn show_system_policy_panel(ui: &mut Ui, system: Option<&SystemPolicySummary>) {
    ui.strong("System policy");
    ui.add_space(4.0);
    let Some(system) = system else {
        ui.label(
            RichText::new("System policy is not configured.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    };

    let display = system_policy_display(system);
    egui::Grid::new("policy_system_panel")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            general_row(ui, "Stats inbound uplink", &display.stats_inbound_uplink);
            general_row(
                ui,
                "Stats inbound downlink",
                &display.stats_inbound_downlink,
            );
            general_row(ui, "Stats outbound uplink", &display.stats_outbound_uplink);
            general_row(
                ui,
                "Stats outbound downlink",
                &display.stats_outbound_downlink,
            );
        });
}

fn show_levels_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[UserPolicySummary]) {
    ui.strong("User policies");
    ui.add_space(4.0);

    let sort = service.policy_sort();
    let selected = selected_level(ui);

    egui::ScrollArea::horizontal()
        .id_salt("policy_levels_scroll")
        .show(ui, |ui| {
            egui::Grid::new("policy_levels_table")
                .num_columns(6)
                .striped(true)
                .spacing([16.0, 6.0])
                .min_col_width(72.0)
                .show(ui, |ui| {
                    sortable_header(ui, service, "Level", PolicySortColumn::Level, sort.column);
                    ui.strong("Handshake");
                    ui.strong("Connection Idle");
                    ui.strong("Uplink Only");
                    ui.strong("Downlink Only");
                    ui.strong("Stats");
                    ui.end_row();

                    for row in rows {
                        let display = user_policy_row_display(row);
                        let is_selected = selected.as_deref() == Some(row.level.as_str());
                        let level_text = if is_selected {
                            format!("› {}", display.level)
                        } else {
                            display.level.clone()
                        };
                        if cell_with_menu(ui, row, &level_text) {
                            set_selected_level(ui, &row.level);
                        }
                        cell_with_menu(ui, row, &display.handshake);
                        cell_with_menu(ui, row, &display.conn_idle);
                        cell_with_menu(ui, row, &display.uplink_only);
                        cell_with_menu(ui, row, &display.downlink_only);
                        cell_with_menu(ui, row, &display.stats);
                        ui.end_row();
                    }
                });
        });
}

fn sortable_header(
    ui: &mut Ui,
    service: &mut ApplicationService,
    label: &str,
    column: PolicySortColumn,
    active: PolicySortColumn,
) {
    let sort = service.policy_sort();
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
        service.set_policy_sort_column(column);
    }
}

fn cell_with_menu(ui: &mut Ui, row: &UserPolicySummary, text: &str) -> bool {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    let clicked = response.clicked();
    if clicked {
        set_selected_level(ui, &row.level);
    }
    show_level_context_menu(&response, row);
    clicked
}

fn show_level_context_menu(response: &egui::Response, row: &UserPolicySummary) {
    response.context_menu(|ui| {
        if ui.button("Copy level").clicked() {
            ui.ctx().copy_text(row.level.clone());
            ui.close();
        }
        if ui.button("Copy timeout values").clicked() {
            ui.ctx().copy_text(format_timeout_values(row));
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

fn show_selected_level_details(ui: &mut Ui, rows: &[UserPolicySummary]) {
    let Some(level) = selected_level(ui) else {
        ui.add_space(12.0);
        ui.label(
            RichText::new("Select a policy level to view details.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    };
    let Some(row) = rows.iter().find(|entry| entry.level == level) else {
        return;
    };

    ui.add_space(12.0);
    ui.strong("Policy details");
    ui.add_space(4.0);

    ui.label(RichText::new("General").strong());
    egui::Grid::new("policy_details_general")
        .num_columns(2)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            detail_row(ui, "Level", &row.level);
            detail_row(
                ui,
                "Source file",
                crate::app::display_source_file(&row.source_file),
            );
        });

    ui.add_space(8.0);
    ui.label(RichText::new("Timeouts").strong());
    egui::Grid::new("policy_details_timeouts")
        .num_columns(2)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            detail_row(ui, "Handshake (s)", &display_optional_u64(row.handshake));
            detail_row(
                ui,
                "Connection Idle (s)",
                &display_optional_u64(row.conn_idle),
            );
            detail_row(
                ui,
                "Uplink Only (s)",
                &display_optional_u64(row.uplink_only),
            );
            detail_row(
                ui,
                "Downlink Only (s)",
                &display_optional_u64(row.downlink_only),
            );
        });

    ui.add_space(8.0);
    ui.label(RichText::new("Buffer").strong());
    egui::Grid::new("policy_details_buffer")
        .num_columns(2)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            detail_row(
                ui,
                "Buffer size (KB)",
                &display_optional_u64(row.buffer_size),
            );
        });

    ui.add_space(8.0);
    ui.label(RichText::new("Statistics").strong());
    egui::Grid::new("policy_details_stats")
        .num_columns(2)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            detail_row(
                ui,
                "Stats user uplink",
                &display_enabled_flag(row.stats_user_uplink),
            );
            detail_row(
                ui,
                "Stats user downlink",
                &display_enabled_flag(row.stats_user_downlink),
            );
            detail_row(
                ui,
                "Stats user online",
                &display_enabled_flag(row.stats_user_online),
            );
        });
}

fn detail_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn display_optional_u64(value: Option<u64>) -> String {
    value
        .map(|number| number.to_string())
        .unwrap_or_else(|| MISSING_FIELD.to_owned())
}

fn selected_level_id() -> egui::Id {
    egui::Id::new("policy_page_selected_level")
}

fn selected_level(ui: &Ui) -> Option<String> {
    ui.ctx()
        .data(|data| data.get_temp::<String>(selected_level_id()))
}

fn set_selected_level(ui: &Ui, level: &str) {
    ui.ctx()
        .data_mut(|data| data.insert_temp(selected_level_id(), level.to_owned()));
}
