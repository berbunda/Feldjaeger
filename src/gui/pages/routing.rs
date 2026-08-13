//! Routing page — read-only view of the discovered Xray routing configuration.
//!
//! Data flows exclusively through [`ApplicationService`] and routing summaries.
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, MISSING_FIELD, RoutingPageState, RoutingSortColumn, display_routing_list,
    routing_general_display, routing_rule_row_display,
};
use crate::xray::{RoutingRuleSummary, RoutingSummary};

/// Renders the Routing page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_routing_page_status();

    ui.heading("Routing");
    ui.add_space(8.0);

    let model = service.routing_page_model();
    show_wiring_warnings(ui, &model.wiring_warnings);
    match model.state {
        RoutingPageState::NoSshConnection
        | RoutingPageState::XrayNotDiscovered
        | RoutingPageState::ConfigurationNotLoaded
        | RoutingPageState::RoutingSectionMissing => {
            show_state_message(ui, model.state);
            return;
        }
        RoutingPageState::NoRoutingRules => {
            show_state_message(ui, model.state);
            if let Some(summary) = model.summary.as_ref() {
                ui.add_space(8.0);
                show_general_information(ui, summary);
            }
            return;
        }
        RoutingPageState::ConfigurationContainsWarnings => {
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
                show_state_message(ui, RoutingPageState::RoutingSectionMissing);
                return;
            };
            show_general_information(ui, summary);
            ui.add_space(12.0);
            if model.rows.is_empty() {
                show_state_message(ui, RoutingPageState::NoRoutingRules);
                return;
            }
            show_rules_table(ui, service, &model.rows);
            show_selected_rule_details(ui, &model.rows);
            return;
        }
        RoutingPageState::ConfigurationLoaded => {}
    }

    let Some(summary) = model.summary.as_ref() else {
        show_state_message(ui, RoutingPageState::RoutingSectionMissing);
        return;
    };

    show_general_information(ui, summary);
    ui.add_space(12.0);

    if model.rows.is_empty() {
        show_state_message(ui, RoutingPageState::NoRoutingRules);
        return;
    }

    show_rules_table(ui, service, &model.rows);
    show_selected_rule_details(ui, &model.rows);
}

/// Non-fatal `routing`/`balancers`/`outbounds`/`observatory` wiring warnings
/// (Roadmap §2.5:108).
///
/// Independent of the page state machine — shown whenever present, same placement rationale
/// as the Policy page's stats/policy/api/metrics wiring block.
fn show_wiring_warnings(ui: &mut Ui, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    ui.strong("Wiring consistency (routing ↔ balancers ↔ outbounds ↔ observatory)");
    ui.add_space(4.0);
    for warning in warnings {
        ui.label(
            RichText::new(warning.clone())
                .size(13.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
    ui.add_space(12.0);
}

fn show_state_message(ui: &mut Ui, state: RoutingPageState) {
    let color = match state {
        RoutingPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        RoutingPageState::RoutingSectionMissing
        | RoutingPageState::NoRoutingRules
        | RoutingPageState::ConfigurationLoaded => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_general_information(ui: &mut Ui, summary: &RoutingSummary) {
    let display = routing_general_display(summary);
    ui.strong("General information");
    ui.add_space(4.0);
    egui::Grid::new("routing_general_information")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            general_row(ui, "Domain strategy", &display.domain_strategy);
            general_row(ui, "Domain matcher", &display.domain_matcher);
            general_row(ui, "Rule count", &display.rule_count);
        });
}

fn general_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn show_rules_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[RoutingRuleSummary]) {
    ui.strong("Routing rules");
    ui.add_space(4.0);

    let sort = service.routing_sort();
    let selected = selected_rule_index(ui);

    egui::ScrollArea::horizontal()
        .id_salt("routing_rules_scroll")
        .show(ui, |ui| {
            egui::Grid::new("routing_rules_table")
                .num_columns(5)
                .striped(true)
                .spacing([16.0, 6.0])
                .min_col_width(72.0)
                .show(ui, |ui| {
                    sortable_header(ui, service, "#", RoutingSortColumn::Index, sort.column);
                    sortable_header(
                        ui,
                        service,
                        "Target",
                        RoutingSortColumn::Target,
                        sort.column,
                    );
                    ui.strong("Criteria");
                    ui.strong("Summary");
                    ui.strong("Source file");
                    ui.end_row();

                    for row in rows {
                        let display = routing_rule_row_display(row);
                        let is_selected = selected == Some(row.index);
                        let index_text = if is_selected {
                            format!("› {}", display.index)
                        } else {
                            display.index.clone()
                        };
                        if cell_with_menu(ui, row, &index_text) {
                            set_selected_rule_index(ui, row.index);
                        }
                        cell_with_menu(ui, row, &display.target);
                        cell_with_menu(ui, row, &display.criteria);
                        cell_with_menu(ui, row, &display.summary);
                        cell_with_menu(ui, row, &display.source_file);
                        ui.end_row();
                    }
                });
        });
}

fn sortable_header(
    ui: &mut Ui,
    service: &mut ApplicationService,
    label: &str,
    column: RoutingSortColumn,
    active: RoutingSortColumn,
) {
    let sort = service.routing_sort();
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
        service.set_routing_sort_column(column);
    }
}

fn cell_with_menu(ui: &mut Ui, row: &RoutingRuleSummary, text: &str) -> bool {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    let clicked = response.clicked();
    if clicked {
        set_selected_rule_index(ui, row.index);
    }
    show_rule_context_menu(&response, row);
    clicked
}

fn show_rule_context_menu(response: &egui::Response, row: &RoutingRuleSummary) {
    response.context_menu(|ui| {
        if ui.button("Copy outbound tag").clicked() {
            let text = row
                .outbound_tag
                .clone()
                .or_else(|| row.target.clone())
                .unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }
        if ui.button("Copy summary").clicked() {
            ui.ctx().copy_text(row.summary.clone());
            ui.close();
        }

        ui.separator();

        ui.add_enabled(false, egui::Button::new("Edit"))
            .on_disabled_hover_text("Not implemented yet");
        ui.add_enabled(false, egui::Button::new("Delete"))
            .on_disabled_hover_text("Not implemented yet");
        ui.add_enabled(false, egui::Button::new("Duplicate"))
            .on_disabled_hover_text("Not implemented yet");
        ui.add_enabled(false, egui::Button::new("Move up"))
            .on_disabled_hover_text("Not implemented yet");
        ui.add_enabled(false, egui::Button::new("Move down"))
            .on_disabled_hover_text("Not implemented yet");
    });
}

fn show_selected_rule_details(ui: &mut Ui, rows: &[RoutingRuleSummary]) {
    let Some(index) = selected_rule_index(ui) else {
        ui.add_space(12.0);
        ui.label(
            RichText::new("Select a rule to view details.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    };
    let Some(rule) = rows.iter().find(|row| row.index == index) else {
        return;
    };

    ui.add_space(12.0);
    ui.strong("Rule details");
    ui.add_space(4.0);

    ui.label(RichText::new("General").strong());
    egui::Grid::new("routing_rule_details_general")
        .num_columns(2)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            detail_row(ui, "Index", &(rule.index + 1).to_string());
            detail_row(ui, "Rule tag", &display_optional(&rule.rule_tag));
            detail_row(ui, "Type", &display_optional(&rule.rule_type));
            detail_row(
                ui,
                "Source file",
                crate::app::display_source_file(&rule.source_file),
            );
        });

    ui.add_space(8.0);
    ui.label(RichText::new("Matching Conditions").strong());
    egui::Grid::new("routing_rule_details_match")
        .num_columns(2)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            detail_row(ui, "Domain", &display_routing_list(&rule.domain));
            detail_row(ui, "IP", &display_routing_list(&rule.ip));
            detail_row(ui, "Port", &display_optional(&rule.port));
            detail_row(ui, "Source Port", &display_optional(&rule.source_port));
            detail_row(ui, "Local Port", &display_optional(&rule.local_port));
            detail_row(ui, "Network", &display_optional(&rule.network));
            detail_row(ui, "Source IP", &display_routing_list(&rule.source_ip));
            detail_row(ui, "Local IP", &display_routing_list(&rule.local_ip));
            detail_row(ui, "User", &display_routing_list(&rule.user));
            detail_row(ui, "VLESS Route", &display_optional(&rule.vless_route));
            detail_row(ui, "Inbound", &display_routing_list(&rule.inbound_tag));
            detail_row(ui, "Protocol", &display_routing_list(&rule.protocol));
            detail_row(ui, "Attribute", &display_optional(&rule.attrs_summary));
            detail_row(ui, "Process", &display_routing_list(&rule.process));
        });

    ui.add_space(8.0);
    ui.label(RichText::new("Target").strong());
    egui::Grid::new("routing_rule_details_target")
        .num_columns(2)
        .spacing([20.0, 4.0])
        .show(ui, |ui| {
            detail_row(ui, "Outbound tag", &display_optional(&rule.outbound_tag));
            detail_row(ui, "Balancer tag", &display_optional(&rule.balancer_tag));
        });
}

fn detail_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn display_optional(value: &Option<String>) -> String {
    value
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| MISSING_FIELD.to_owned())
}

fn selected_rule_id() -> egui::Id {
    egui::Id::new("routing_page_selected_rule")
}

fn selected_rule_index(ui: &Ui) -> Option<usize> {
    ui.ctx()
        .data(|data| data.get_temp::<usize>(selected_rule_id()))
}

fn set_selected_rule_index(ui: &Ui, index: usize) {
    ui.ctx()
        .data_mut(|data| data.insert_temp(selected_rule_id(), index));
}
