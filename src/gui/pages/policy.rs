//! Policy page — browse the discovered Xray policy configuration and edit it (Roadmap §2.1:49).
//!
//! Browsing (table, sort, selection, per-level detail panel) uses [`PolicySummary`]/
//! [`UserPolicySummary`] exactly as the original read-only page did. Editing uses the typed
//! [`PolicySettings`] draft — mirrors the View/Edit/Save/Cancel/Preview changes chrome already
//! established by DNS/FakeDNS/API/Routing (`gui/pages/dns.rs`, `gui/pages/routing.rs`).
//!
//! Data flows exclusively through [`ApplicationService`]. This page never reads raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, MISSING_FIELD, PolicyPageState, PolicySortColumn, display_enabled_flag,
    format_timeout_values, policy_general_display, system_policy_display, user_policy_row_display,
};
use crate::xray::{
    PolicyLevelEntry, PolicySummary, SystemPolicyEntry, SystemPolicySummary, UserPolicySummary,
};

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);

/// Renders the Policy page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_policy_page_status();

    ui.heading("Policy");
    ui.add_space(8.0);

    let model = service.policy_page_model();
    show_wiring_warnings(ui, &model.wiring_warnings);

    match model.state {
        PolicyPageState::NoSshConnection
        | PolicyPageState::XrayNotDiscovered
        | PolicyPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        PolicyPageState::MalformedPolicyObject => {
            show_state_message(ui, model.state);
            for warning in &model.policy_settings.warnings {
                ui.label(RichText::new(warning.clone()).size(14.0).color(ERROR_COLOR));
            }
            return;
        }
        _ => {}
    }

    show_state_message(ui, model.state);
    for warning in &model.warnings {
        ui.label(RichText::new(warning.clone()).size(14.0).color(WARN_COLOR));
    }
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
        if let Some(entries) = service.policy_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        egui::ScrollArea::vertical()
            .id_salt("policy_edit_scroll")
            .show(ui, |ui| show_edit_form(ui, service));
        return;
    }

    match model.state {
        PolicyPageState::PolicySectionMissing => {}
        PolicyPageState::NoUserPolicies => {
            if let Some(summary) = model.summary.as_ref() {
                ui.add_space(8.0);
                show_general_information(ui, summary);
                ui.add_space(12.0);
                show_system_policy_panel(ui, summary.system_policy.as_ref());
            }
        }
        PolicyPageState::ConfigurationContainsWarnings | PolicyPageState::ConfigurationLoaded => {
            let Some(summary) = model.summary.as_ref() else {
                return;
            };
            show_general_information(ui, summary);
            ui.add_space(12.0);
            show_system_policy_panel(ui, summary.system_policy.as_ref());
            ui.add_space(12.0);
            if !model.rows.is_empty() {
                show_levels_table(ui, service, &model.rows);
                show_selected_level_details(ui, &model.rows);
            }
        }
        _ => {}
    }
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: PolicyPageState,
) {
    let busy = matches!(state, PolicyPageState::Saving | PolicyPageState::SaveFailed)
        && service.is_policy_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_policy_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_policy_settings();
            }
            if ui
                .add_enabled(
                    !service.is_policy_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_policy_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_policy_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_policy_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_policy_settings();
        }
    });
}

/// Non-fatal `stats`/`policy`/`api`/`metrics` wiring warnings (Roadmap §2.5:106).
///
/// Independent of the page state machine — shown whenever present, even in states that
/// otherwise short-circuit (e.g. `PolicySectionMissing`, since `stats`/`api`/`metrics` can be
/// misconfigured without a `policy` section existing at all).
fn show_wiring_warnings(ui: &mut Ui, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    ui.strong("Wiring consistency (stats ↔ policy ↔ api ↔ metrics)");
    ui.add_space(4.0);
    for warning in warnings {
        ui.label(RichText::new(warning.clone()).size(13.0).color(WARN_COLOR));
    }
    ui.add_space(12.0);
}

fn show_state_message(ui: &mut Ui, state: PolicyPageState) {
    let color = match state {
        PolicyPageState::ConfigurationContainsWarnings
        | PolicyPageState::ValidationError
        | PolicyPageState::Saved => WARN_COLOR,
        PolicyPageState::PolicySectionMissing
        | PolicyPageState::NoUserPolicies
        | PolicyPageState::ConfigurationLoaded
        | PolicyPageState::EditMode => MUTED_COLOR,
        PolicyPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

// ─── View mode (browsing) ───────────────────────────────────────────────────

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
                .color(MUTED_COLOR),
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
    });
}

fn show_selected_level_details(ui: &mut Ui, rows: &[UserPolicySummary]) {
    let Some(level) = selected_level(ui) else {
        ui.add_space(12.0);
        ui.label(
            RichText::new("Select a policy level to view details.")
                .size(14.0)
                .color(MUTED_COLOR),
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

// ─── Edit mode ──────────────────────────────────────────────────────────────

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(draft) = service.policy_settings_draft_mut() else {
        return;
    };

    ui.strong(format!("User policy levels ({})", draft.levels.len()));
    ui.add_space(4.0);

    let mut remove_level: Option<usize> = None;
    for index in 0..draft.levels.len() {
        show_level_edit_form(ui, draft, index, &mut remove_level);
        ui.add_space(6.0);
    }
    if let Some(index) = remove_level {
        draft.levels.remove(index);
    }
    if ui.button("Add level").clicked() {
        draft.levels.push(PolicyLevelEntry::blank());
    }

    ui.add_space(16.0);
    ui.separator();
    show_system_policy_edit(ui, draft);
}

fn level_title(level: &PolicyLevelEntry) -> String {
    if level.level.is_empty() {
        "(no level set)".to_owned()
    } else {
        format!("Level {}", level.level)
    }
}

fn show_level_edit_form(
    ui: &mut Ui,
    draft: &mut crate::xray::PolicySettings,
    index: usize,
    remove: &mut Option<usize>,
) {
    let level = &mut draft.levels[index];
    ui.horizontal(|ui| {
        ui.label(format!("Level entry {}", index + 1));
        if ui.small_button("Remove").clicked() {
            *remove = Some(index);
        }
    });

    egui::CollapsingHeader::new(level_title(level))
        .id_salt(("policy_level_edit", index))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("level");
                ui.add(
                    egui::TextEdit::singleline(&mut level.level)
                        .desired_width(80.0)
                        .hint_text("0"),
                );
            });

            ui.add_space(4.0);
            ui.label(RichText::new("Timeouts").strong());
            optional_u64_row(
                ui,
                "handshake (s, default 4)",
                &mut level.handshake,
                ("policy_level_handshake", index),
            );
            optional_u64_row(
                ui,
                "connIdle (s, default 300)",
                &mut level.conn_idle,
                ("policy_level_conn_idle", index),
            );
            optional_u64_row(
                ui,
                "uplinkOnly (s, default 2)",
                &mut level.uplink_only,
                ("policy_level_uplink_only", index),
            );
            optional_u64_row(
                ui,
                "downlinkOnly (s, default 5)",
                &mut level.downlink_only,
                ("policy_level_downlink_only", index),
            );

            ui.add_space(4.0);
            ui.label(RichText::new("Buffer").strong());
            optional_u64_row(
                ui,
                "bufferSize (KB, platform default)",
                &mut level.buffer_size,
                ("policy_level_buffer_size", index),
            );

            ui.add_space(4.0);
            ui.label(RichText::new("Statistics").strong());
            ui.checkbox(&mut level.stats_user_uplink, "statsUserUplink");
            ui.checkbox(&mut level.stats_user_downlink, "statsUserDownlink");
            ui.checkbox(&mut level.stats_user_online, "statsUserOnline");
        });
}

fn show_system_policy_edit(ui: &mut Ui, draft: &mut crate::xray::PolicySettings) {
    let mut enabled = draft.system.is_some();
    if ui.checkbox(&mut enabled, "system policy").changed() {
        draft.system = if enabled {
            Some(draft.system.take().unwrap_or_else(SystemPolicyEntry::blank))
        } else {
            None
        };
    }
    let Some(system) = draft.system.as_mut() else {
        return;
    };
    egui::CollapsingHeader::new("System policy settings")
        .default_open(true)
        .show(ui, |ui| {
            ui.checkbox(&mut system.stats_inbound_uplink, "statsInboundUplink");
            ui.checkbox(&mut system.stats_inbound_downlink, "statsInboundDownlink");
            ui.checkbox(&mut system.stats_outbound_uplink, "statsOutboundUplink");
            ui.checkbox(&mut system.stats_outbound_downlink, "statsOutboundDownlink");
        });
}

fn optional_u64_row(
    ui: &mut Ui,
    label: &str,
    value: &mut Option<u64>,
    id: impl std::hash::Hash + std::fmt::Debug,
) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(0);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut enabled, label);
            ui.add_enabled(enabled, egui::DragValue::new(&mut number));
        });
    });
    *value = if enabled { Some(number) } else { None };
}
