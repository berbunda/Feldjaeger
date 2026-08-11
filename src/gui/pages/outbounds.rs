//! Outbounds page — table of discovered outbound summaries + Delete.
//!
//! Data flows exclusively through [`ApplicationService`] → [`OutboundSummary`].
//! This page never reads JSON or opens SSH directly.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, BLACKHOLE_RESPONSE_TYPES, DOMAIN_STRATEGIES, FREEDOM_NOISE_TYPES,
    FragmentDraft, MISSING_FIELD, NoiseDraft, OutboundKind, OutboundSettingsDraft,
    OutboundsPageState, OutboundsSortColumn, outbound_row_display,
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

    // Table header with Add button (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
    ui.horizontal(|ui| {
        ui.strong("Outbounds");
        ui.add_space(12.0);
        let busy = service.is_outbound_mutation_busy();
        let adding = service.outbound_editor_session().is_some_and(|s| s.is_add);
        ui.add_enabled_ui(!adding && !busy, |ui| {
            ui.menu_button("Add Outbound", |ui| {
                if ui.button("Freedom").clicked() {
                    if let Err(e) = service.begin_add_outbound_freedom() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui.button("Blackhole").clicked() {
                    if let Err(e) = service.begin_add_outbound_blackhole() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
            });
        });
    });
    ui.add_space(4.0);

    show_table(ui, service, &model.rows);
    ui.add_space(12.0);

    if service.outbound_editor_session().is_some() {
        show_outbound_editor_pane(ui, service);
    }
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

        let busy = service.is_outbound_mutation_busy();
        let edit_ok = matches!(row.kind(), OutboundKind::Freedom | OutboundKind::Blackhole);
        if ui
            .add_enabled(edit_ok && !busy, egui::Button::new("Edit"))
            .on_disabled_hover_text("Shell editing is available for Freedom and Blackhole outbounds only")
            .clicked()
        {
            if let Err(e) = service.begin_edit_outbound_shell(row.index) {
                service.show_status_message(e);
            }
            ui.close();
        }

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
                    "Deletion cannot be undone from the UI (restore from backup if needed).",
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

// ─── Outbound Shell editor (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95) ────

fn outbound_protocol_label(settings: &OutboundSettingsDraft) -> &'static str {
    match settings {
        OutboundSettingsDraft::Freedom { .. } => "Freedom",
        OutboundSettingsDraft::Blackhole { .. } => "Blackhole",
    }
}

fn show_outbound_editor_pane(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session() else {
        return;
    };
    let is_add = session.is_add;
    let protocol_label = outbound_protocol_label(&session.settings);

    ui.separator();
    ui.add_space(4.0);
    ui.strong(format!(
        "{} Outbound ({protocol_label})",
        if is_add { "Add" } else { "Edit" }
    ));
    ui.add_space(4.0);

    show_outbound_general_edit(ui, service, is_add);
    ui.add_space(6.0);
    ui.strong(format!("Protocol ({protocol_label})"));
    match service.outbound_editor_session().map(|s| &s.settings) {
        Some(OutboundSettingsDraft::Freedom { .. }) => show_freedom_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Blackhole { .. }) => show_blackhole_settings_edit(ui, service),
        None => {}
    }
    ui.add_space(8.0);

    let busy = service.is_outbound_mutation_busy();
    ui.horizontal(|ui| {
        let save_label = if is_add { "Add Outbound" } else { "Save" };
        if ui
            .add_enabled(!busy, egui::Button::new(save_label))
            .clicked()
        {
            let result = if is_add {
                service.start_add_outbound_shell()
            } else {
                service.start_save_outbound_shell()
            };
            if let Err(e) = result {
                service.show_status_message(e);
            }
        }
        if ui.button("Cancel").clicked() {
            service.cancel_outbound_editor_session();
        }
    });
}

fn show_outbound_general_edit(ui: &mut Ui, service: &mut ApplicationService, is_add: bool) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let general = &mut session.general;
    let mut tag = general.tag.clone().unwrap_or_default();
    let mut send_through = general.send_through.clone().unwrap_or_default();

    egui::Grid::new("outbound_general_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("tag");
            if is_add {
                ui.text_edit_singleline(&mut tag);
            } else {
                ui.label(if tag.is_empty() { MISSING_FIELD } else { &tag })
                    .on_hover_text("Rename is not supported yet (Roadmap §2.4:99)");
            }
            ui.end_row();

            ui.label("sendThrough");
            ui.text_edit_singleline(&mut send_through)
                .on_hover_text("Bind address; empty = system default");
            ui.end_row();
        });

    general.tag = Some(tag);
    general.send_through = Some(send_through);
}

fn show_freedom_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Freedom {
        domain_strategy,
        redirect,
        user_level,
        fragment,
        noises,
    } = &mut session.settings
    else {
        return;
    };

    let mut strategy = domain_strategy.clone();
    let mut redirect_text = redirect.clone();
    let mut level = *user_level as i64;

    egui::Grid::new("freedom_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("domainStrategy");
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("freedom_domain_strategy")
                    .selected_text(if strategy.is_empty() {
                        "(unset — AsIs)"
                    } else {
                        strategy.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in DOMAIN_STRATEGIES {
                            ui.selectable_value(&mut strategy, preset.to_owned(), preset);
                        }
                    });
                ui.text_edit_singleline(&mut strategy);
            });
            ui.end_row();

            ui.label("redirect");
            ui.text_edit_singleline(&mut redirect_text)
                .on_hover_text("host:port or :port; empty = disabled");
            ui.end_row();

            ui.label("userLevel");
            ui.add(egui::DragValue::new(&mut level).range(0..=u32::MAX as i64));
            ui.end_row();
        });

    *domain_strategy = strategy;
    *redirect = redirect_text;
    *user_level = level.max(0) as u64;

    ui.add_space(6.0);
    let mut fragment_enabled = fragment.is_some();
    if ui
        .checkbox(&mut fragment_enabled, "fragment")
        .on_hover_text("Packet fragmentation for DPI evasion")
        .changed()
    {
        *fragment = if fragment_enabled {
            Some(FragmentDraft::default())
        } else {
            None
        };
    }
    if let Some(fragment) = fragment {
        egui::Grid::new("freedom_fragment_edit_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label("packets");
                ui.text_edit_singleline(&mut fragment.packets)
                    .on_hover_text("e.g. tlshello or 1-3");
                ui.end_row();
                ui.label("length");
                ui.text_edit_singleline(&mut fragment.length)
                    .on_hover_text("e.g. 100-200");
                ui.end_row();
                ui.label("interval");
                ui.text_edit_singleline(&mut fragment.interval)
                    .on_hover_text("ms, e.g. 10-20");
                ui.end_row();
            });
    }

    ui.add_space(8.0);
    ui.strong("noises");
    show_freedom_noises_edit(ui, noises);
}

fn show_freedom_noises_edit(ui: &mut Ui, noises: &mut Vec<NoiseDraft>) {
    let mut remove_idx: Option<usize> = None;
    egui::Grid::new("freedom_noises_edit_grid")
        .num_columns(4)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label(RichText::new("type").strong());
            ui.label(RichText::new("packet").strong());
            ui.label(RichText::new("delay").strong());
            ui.label("");
            ui.end_row();

            for (idx, noise) in noises.iter_mut().enumerate() {
                egui::ComboBox::from_id_salt(("freedom_noise_type", idx))
                    .selected_text(if noise.kind.is_empty() {
                        "(unset)"
                    } else {
                        noise.kind.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in FREEDOM_NOISE_TYPES {
                            ui.selectable_value(&mut noise.kind, preset.to_owned(), preset);
                        }
                    });
                ui.text_edit_singleline(&mut noise.packet);
                ui.text_edit_singleline(&mut noise.delay);
                if ui.small_button("Del").clicked() {
                    remove_idx = Some(idx);
                }
                ui.end_row();
            }
        });
    if let Some(idx) = remove_idx {
        noises.remove(idx);
    }

    if ui.button("Add noise").clicked() {
        noises.push(NoiseDraft {
            kind: "rand".to_owned(),
            packet: String::new(),
            delay: String::new(),
            extras: Default::default(),
        });
    }
}

fn show_blackhole_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Blackhole { response_type, .. } = &mut session.settings else {
        return;
    };

    let mut kind = response_type.clone();
    egui::Grid::new("blackhole_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("response.type")
                .on_hover_text("none = close immediately; http = send a fake HTTP 403 then close");
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("blackhole_response_type")
                    .selected_text(if kind.is_empty() {
                        "(unset — none)"
                    } else {
                        kind.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in BLACKHOLE_RESPONSE_TYPES {
                            ui.selectable_value(&mut kind, preset.to_owned(), preset);
                        }
                    });
                ui.text_edit_singleline(&mut kind);
            });
            ui.end_row();
        });
    *response_type = kind;
}
