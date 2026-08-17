//! Routing page — browse the discovered Xray routing configuration and edit it (Roadmap
//! §2.1:48).
//!
//! Browsing (table, sort, selection, per-rule detail panel) uses [`RoutingSummary`]/
//! [`RoutingRuleSummary`] exactly as the original read-only page did. Editing uses the typed
//! [`RoutingSettings`] draft — mirrors the View/Edit/Save/Cancel/Preview changes chrome already
//! established by DNS/FakeDNS/API Settings (`gui/pages/dns.rs`).
//!
//! Data flows exclusively through [`ApplicationService`]. This page never reads raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, Sense, TextEdit, Ui};

use crate::app::{
    ApplicationService, MISSING_FIELD, RoutingPageState, RoutingSortColumn, display_routing_list,
    routing_general_display, routing_rule_row_display,
};
use crate::xray::{
    BalancerEntry, BalancerStrategyType, CostEntry, DomainStrategy, NetworkKind, RoutingRuleEntry,
    RoutingRuleSummary, RoutingSummary, StrategyEntry, WebhookEntry,
};

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);

/// Documented `RuleObject.protocol` values, offered as checkboxes; any other value already on a
/// rule is preserved and editable through the free-text "custom" field beside them (same
/// checkboxes-plus-textarea idiom as `api_settings.rs`'s `KNOWN_API_SERVICES`).
const KNOWN_PROTOCOLS: &[&str] = &["http", "tls", "quic", "bittorrent"];

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
        | RoutingPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        RoutingPageState::MalformedRoutingObject => {
            show_state_message(ui, model.state);
            for warning in &model.routing_settings.warnings {
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
        if let Some(entries) = service.routing_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        egui::ScrollArea::vertical()
            .id_salt("routing_edit_scroll")
            .show(ui, |ui| show_edit_form(ui, service));
        return;
    }

    match model.state {
        RoutingPageState::RoutingSectionMissing => {}
        RoutingPageState::NoRoutingRules => {
            if let Some(summary) = model.summary.as_ref() {
                ui.add_space(8.0);
                show_general_information(ui, summary);
            }
        }
        RoutingPageState::ConfigurationContainsWarnings | RoutingPageState::ConfigurationLoaded => {
            let Some(summary) = model.summary.as_ref() else {
                return;
            };
            show_general_information(ui, summary);
            ui.add_space(12.0);
            if !model.rows.is_empty() {
                show_rules_table(ui, service, &model.rows);
                show_selected_rule_details(ui, &model.rows);
            }
        }
        _ => {}
    }
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: RoutingPageState,
) {
    let busy = matches!(state, RoutingPageState::Saving | RoutingPageState::SaveFailed)
        && service.is_routing_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_routing_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_routing_settings();
            }
            if ui
                .add_enabled(
                    !service.is_routing_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_routing_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_routing_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_routing_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_routing_settings();
        }
    });
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
        ui.label(RichText::new(warning.clone()).size(13.0).color(WARN_COLOR));
    }
    ui.add_space(12.0);
}

fn show_state_message(ui: &mut Ui, state: RoutingPageState) {
    let color = match state {
        RoutingPageState::ConfigurationContainsWarnings
        | RoutingPageState::ValidationError
        | RoutingPageState::Saved => WARN_COLOR,
        RoutingPageState::RoutingSectionMissing
        | RoutingPageState::NoRoutingRules
        | RoutingPageState::ConfigurationLoaded
        | RoutingPageState::EditMode => MUTED_COLOR,
        RoutingPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

// ─── View mode (browsing) ───────────────────────────────────────────────────

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
    });
}

fn show_selected_rule_details(ui: &mut Ui, rows: &[RoutingRuleSummary]) {
    let Some(index) = selected_rule_index(ui) else {
        ui.add_space(12.0);
        ui.label(
            RichText::new("Select a rule to view details.")
                .size(14.0)
                .color(MUTED_COLOR),
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

// ─── Edit mode ──────────────────────────────────────────────────────────────

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(draft) = service.routing_settings_draft_mut() else {
        return;
    };

    ui.strong("General information");
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("domainStrategy");
        domain_strategy_combo(ui, "routing_domain_strategy", &mut draft.domain_strategy);
    });
    ui.label(
        RichText::new("domainMatcher is preserved but not editable here — see View mode.")
            .size(12.0)
            .color(MUTED_COLOR),
    );

    ui.add_space(16.0);
    ui.separator();
    ui.strong(format!("Routing rules ({})", draft.rules.len()));
    ui.label(
        RichText::new("Order matters — the first matching rule wins.")
            .size(12.0)
            .color(MUTED_COLOR),
    );
    ui.add_space(4.0);

    let rule_count = draft.rules.len();
    let mut remove_rule: Option<usize> = None;
    let mut move_up: Option<usize> = None;
    let mut move_down: Option<usize> = None;
    for index in 0..rule_count {
        show_rule_edit_form(ui, draft, index, rule_count, &mut remove_rule, &mut move_up, &mut move_down);
        ui.add_space(6.0);
    }
    if let Some(index) = remove_rule {
        draft.rules.remove(index);
    }
    if let Some(index) = move_up
        && index > 0
    {
        draft.rules.swap(index, index - 1);
    }
    if let Some(index) = move_down
        && index + 1 < draft.rules.len()
    {
        draft.rules.swap(index, index + 1);
    }
    if ui.button("Add rule").clicked() {
        draft.rules.push(RoutingRuleEntry::blank());
    }

    ui.add_space(16.0);
    ui.separator();
    ui.strong(format!("Balancers ({})", draft.balancers.len()));
    ui.add_space(4.0);

    let mut remove_balancer: Option<usize> = None;
    for index in 0..draft.balancers.len() {
        show_balancer_edit_form(ui, draft, index, &mut remove_balancer);
        ui.add_space(6.0);
    }
    if let Some(index) = remove_balancer {
        draft.balancers.remove(index);
    }
    if ui.button("Add balancer").clicked() {
        draft.balancers.push(BalancerEntry::blank());
    }
}

fn rule_title(rule: &RoutingRuleEntry) -> String {
    let target = rule.outbound_tag.clone().or_else(|| rule.balancer_tag.clone());
    match target {
        Some(target) => format!("→ {target}"),
        None => "(no target set)".to_owned(),
    }
}

fn show_rule_edit_form(
    ui: &mut Ui,
    draft: &mut crate::xray::RoutingSettings,
    index: usize,
    rule_count: usize,
    remove: &mut Option<usize>,
    move_up: &mut Option<usize>,
    move_down: &mut Option<usize>,
) {
    let rule = &mut draft.rules[index];
    ui.horizontal(|ui| {
        ui.label(format!("Rule {}", index + 1));
        if ui
            .add_enabled(index > 0, egui::Button::new("▲"))
            .on_hover_text("Move up")
            .clicked()
        {
            *move_up = Some(index);
        }
        if ui
            .add_enabled(index + 1 < rule_count, egui::Button::new("▼"))
            .on_hover_text("Move down")
            .clicked()
        {
            *move_down = Some(index);
        }
        if ui.small_button("Remove").clicked() {
            *remove = Some(index);
        }
    });

    egui::CollapsingHeader::new(rule_title(rule))
        .id_salt(("routing_rule_edit", index))
        .show(ui, |ui| {
            optional_text_row(ui, "ruleTag", &mut rule.rule_tag, "my-rule");

            ui.add_space(6.0);
            ui.label(RichText::new("Matching Conditions").strong());
            multiline_list_row(ui, "domain (one per line)", &mut rule.domain, ("routing_rule_domain", index));
            multiline_list_row(ui, "ip (one per line)", &mut rule.ip, ("routing_rule_ip", index));
            optional_text_row(ui, "port", &mut rule.port, "443 or 1000-2000");
            optional_text_row(ui, "sourcePort", &mut rule.source_port, "1000-2000");
            optional_text_row(ui, "localPort", &mut rule.local_port, "1000-2000");
            ui.horizontal(|ui| {
                ui.label("network");
                optional_network_combo(ui, ("routing_rule_network", index), &mut rule.network);
            });
            multiline_list_row(ui, "sourceIP (one per line)", &mut rule.source_ip, ("routing_rule_source_ip", index));
            multiline_list_row(ui, "localIP (one per line)", &mut rule.local_ip, ("routing_rule_local_ip", index));
            multiline_list_row(ui, "user (one per line)", &mut rule.user, ("routing_rule_user", index));
            optional_text_row(ui, "vlessRoute", &mut rule.vless_route, "0-1");
            multiline_list_row(
                ui,
                "inboundTag (one per line)",
                &mut rule.inbound_tag,
                ("routing_rule_inbound_tag", index),
            );

            ui.add_space(4.0);
            ui.label("protocol");
            protocol_checkboxes(ui, index, &mut rule.protocol);

            ui.add_space(4.0);
            ui.label("attrs (HTTP header match)");
            ui.push_id(("routing_rule_attrs", index), |ui| {
                pairs_editor(ui, &mut rule.attrs);
            });

            multiline_list_row(
                ui,
                "process (one per line)",
                &mut rule.process,
                ("routing_rule_process", index),
            );

            ui.add_space(8.0);
            ui.label(RichText::new("Target").strong());
            optional_text_row(ui, "outboundTag", &mut rule.outbound_tag, "proxy");
            optional_text_row(ui, "balancerTag", &mut rule.balancer_tag, "lb");

            ui.add_space(8.0);
            show_webhook_edit(ui, rule, index);
        });
}

fn show_webhook_edit(ui: &mut Ui, rule: &mut RoutingRuleEntry, index: usize) {
    ui.push_id(("routing_rule_webhook", index), |ui| {
        let mut enabled = rule.webhook.is_some();
        if ui.checkbox(&mut enabled, "webhook").changed() {
            rule.webhook = if enabled {
                Some(rule.webhook.take().unwrap_or_else(WebhookEntry::blank))
            } else {
                None
            };
        }
        let Some(webhook) = rule.webhook.as_mut() else {
            return;
        };
        egui::CollapsingHeader::new("Webhook settings")
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("url");
                    ui.add(
                        TextEdit::singleline(&mut webhook.url)
                            .desired_width(260.0)
                            .hint_text("https://example.com/hook"),
                    );
                });
                optional_u64_row(ui, "deduplication (seconds)", &mut webhook.deduplication, "routing_webhook_dedup");
                ui.label("headers");
                pairs_editor(ui, &mut webhook.headers);
            });
    });
}

fn show_balancer_edit_form(
    ui: &mut Ui,
    draft: &mut crate::xray::RoutingSettings,
    index: usize,
    remove: &mut Option<usize>,
) {
    let balancer = &mut draft.balancers[index];
    ui.horizontal(|ui| {
        ui.label(format!("Balancer {}", index + 1));
        if ui.small_button("Remove").clicked() {
            *remove = Some(index);
        }
    });

    let title = if balancer.tag.is_empty() {
        "(no tag set)".to_owned()
    } else {
        balancer.tag.clone()
    };
    egui::CollapsingHeader::new(title)
        .id_salt(("routing_balancer_edit", index))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("tag");
                ui.add(
                    TextEdit::singleline(&mut balancer.tag)
                        .desired_width(180.0)
                        .hint_text("lb"),
                );
            });
            multiline_list_row(
                ui,
                "selector (one prefix per line)",
                &mut balancer.selector,
                ("routing_balancer_selector", index),
            );
            optional_text_row(ui, "fallbackTag", &mut balancer.fallback_tag, "direct");

            ui.add_space(6.0);
            show_strategy_edit(ui, balancer, index);
        });
}

fn show_strategy_edit(ui: &mut Ui, balancer: &mut BalancerEntry, index: usize) {
    ui.push_id(("routing_balancer_strategy", index), |ui| {
        let mut enabled = balancer.strategy.is_some();
        if ui.checkbox(&mut enabled, "strategy (default: random)").changed() {
            balancer.strategy = if enabled {
                Some(balancer.strategy.take().unwrap_or_else(StrategyEntry::blank))
            } else {
                None
            };
        }
        let Some(strategy) = balancer.strategy.as_mut() else {
            return;
        };
        egui::CollapsingHeader::new("Strategy settings")
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("type");
                    strategy_type_combo(ui, "routing_balancer_strategy_type", &mut strategy.strategy_type);
                });

                let mut settings_enabled = strategy.settings.is_some();
                if ui
                    .checkbox(&mut settings_enabled, "settings (used by leastLoad)")
                    .changed()
                {
                    strategy.settings = if settings_enabled {
                        Some(strategy.settings.take().unwrap_or_default())
                    } else {
                        None
                    };
                }
                let Some(settings) = strategy.settings.as_mut() else {
                    return;
                };
                egui::CollapsingHeader::new("leastLoad settings")
                    .default_open(true)
                    .show(ui, |ui| {
                        optional_i64_row(ui, "expected", &mut settings.expected, "routing_strategy_expected");
                        optional_text_row(ui, "maxRTT", &mut settings.max_rtt, "1s");
                        optional_f64_row(ui, "tolerance", &mut settings.tolerance, "routing_strategy_tolerance");
                        multiline_list_row(
                            ui,
                            "baselines (one duration per line)",
                            &mut settings.baselines,
                            "routing_strategy_baselines",
                        );

                        ui.add_space(4.0);
                        ui.label("costs");
                        let mut remove_cost: Option<usize> = None;
                        for (cost_index, cost) in settings.costs.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut cost.regexp, "regexp");
                                ui.add(
                                    TextEdit::singleline(&mut cost.match_value)
                                        .desired_width(140.0)
                                        .hint_text("outbound tag or pattern"),
                                );
                                ui.add(egui::DragValue::new(&mut cost.value).speed(0.1));
                                if ui.small_button("Remove").clicked() {
                                    remove_cost = Some(cost_index);
                                }
                            });
                        }
                        if let Some(cost_index) = remove_cost {
                            settings.costs.remove(cost_index);
                        }
                        if ui.button("Add cost").clicked() {
                            settings.costs.push(CostEntry::blank());
                        }
                    });
            });
    });
}

// ─── Small editing widgets ──────────────────────────────────────────────────

fn protocol_checkboxes(ui: &mut Ui, index: usize, values: &mut Vec<String>) {
    ui.push_id(("routing_rule_protocol", index), |ui| {
        ui.horizontal_wrapped(|ui| {
            for known in KNOWN_PROTOCOLS {
                let mut checked = values.iter().any(|v| v.eq_ignore_ascii_case(known));
                if ui.checkbox(&mut checked, *known).changed() {
                    if checked {
                        if !values.iter().any(|v| v.eq_ignore_ascii_case(known)) {
                            values.push((*known).to_owned());
                        }
                    } else {
                        values.retain(|v| !v.eq_ignore_ascii_case(known));
                    }
                }
            }
        });

        let mut extra_text = values
            .iter()
            .filter(|v| !KNOWN_PROTOCOLS.iter().any(|known| v.eq_ignore_ascii_case(known)))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        ui.label(RichText::new("custom protocol values (one per line)").size(12.0));
        if ui.add(TextEdit::multiline(&mut extra_text).desired_rows(1)).changed() {
            let mut merged: Vec<String> = values
                .iter()
                .filter(|v| KNOWN_PROTOCOLS.iter().any(|known| v.eq_ignore_ascii_case(known)))
                .cloned()
                .collect();
            merged.extend(lines_to_vec(&extra_text));
            *values = merged;
        }
    });
}

fn pairs_editor(ui: &mut Ui, pairs: &mut Vec<(String, String)>) {
    let mut remove_index: Option<usize> = None;
    egui::Grid::new("routing_pairs_editor_grid")
        .num_columns(3)
        .spacing([8.0, 4.0])
        .show(ui, |ui| {
            for (i, (key, value)) in pairs.iter_mut().enumerate() {
                ui.add(TextEdit::singleline(key).desired_width(140.0).hint_text("key"));
                ui.add(TextEdit::singleline(value).desired_width(180.0).hint_text("value"));
                if ui.small_button("Remove").clicked() {
                    remove_index = Some(i);
                }
                ui.end_row();
            }
        });
    if let Some(i) = remove_index {
        pairs.remove(i);
    }
    if ui.button("Add entry").clicked() {
        pairs.push((String::new(), String::new()));
    }
}

fn optional_text_row(ui: &mut Ui, label: &str, value: &mut Option<String>, hint: &str) {
    let mut text = value.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label(label);
        if ui
            .add(TextEdit::singleline(&mut text).desired_width(220.0).hint_text(hint))
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

fn multiline_list_row(
    ui: &mut Ui,
    label: &str,
    values: &mut Vec<String>,
    id: impl std::hash::Hash + std::fmt::Debug,
) {
    ui.push_id(id, |ui| {
        ui.label(label);
        let mut text = values.join("\n");
        if ui.add(TextEdit::multiline(&mut text).desired_rows(2)).changed() {
            *values = lines_to_vec(&text);
        }
    });
}

fn optional_i64_row(ui: &mut Ui, label: &str, value: &mut Option<i64>, id: impl std::hash::Hash + std::fmt::Debug) {
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

fn optional_u64_row(ui: &mut Ui, label: &str, value: &mut Option<u64>, id: impl std::hash::Hash + std::fmt::Debug) {
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

fn optional_f64_row(ui: &mut Ui, label: &str, value: &mut Option<f64>, id: impl std::hash::Hash + std::fmt::Debug) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(0.0);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut enabled, label);
            ui.add_enabled(enabled, egui::DragValue::new(&mut number).speed(0.01));
        });
    });
    *value = if enabled { Some(number) } else { None };
}

fn domain_strategy_combo(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, value: &mut DomainStrategy) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.display_label())
        .show_ui(ui, |ui| {
            for preset in [
                DomainStrategy::AsIs,
                DomainStrategy::IpIfNonMatch,
                DomainStrategy::IpOnDemand,
            ] {
                let label = preset.display_label();
                ui.selectable_value(value, preset, label);
            }
        });
}

fn optional_network_combo(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, value: &mut Option<NetworkKind>) {
    let selected_text = value
        .as_ref()
        .map(NetworkKind::display_label)
        .unwrap_or_else(|| "(any)".to_owned());
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected_text)
        .show_ui(ui, |ui| {
            ui.selectable_value(value, None, "(any)");
            for preset in [NetworkKind::Tcp, NetworkKind::Udp, NetworkKind::TcpUdp] {
                let label = preset.display_label();
                ui.selectable_value(value, Some(preset), label);
            }
        });
}

fn strategy_type_combo(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, value: &mut BalancerStrategyType) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.display_label())
        .show_ui(ui, |ui| {
            for preset in [
                BalancerStrategyType::Random,
                BalancerStrategyType::RoundRobin,
                BalancerStrategyType::LeastPing,
                BalancerStrategyType::LeastLoad,
            ] {
                let label = preset.display_label();
                ui.selectable_value(value, preset, label);
            }
        });
}

fn lines_to_vec(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
