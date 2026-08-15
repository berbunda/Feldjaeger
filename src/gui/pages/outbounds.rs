//! Outbounds page — table of discovered outbound summaries + Delete.
//!
//! Data flows exclusively through [`ApplicationService`] → [`OutboundSummary`].
//! This page never reads JSON or opens SSH directly.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, BLACKHOLE_RESPONSE_TYPES, DNS_REWRITE_NETWORKS, DNS_RULE_ACTIONS,
    DOMAIN_STRATEGIES, DnsRuleDraft, FREEDOM_NOISE_TYPES, FragmentDraft, MISSING_FIELD, NoiseDraft,
    OutboundKind, OutboundSettingsDraft, OutboundsPageState, OutboundsSortColumn,
    outbound_row_display,
};
use crate::xray::OutboundSummary;

/// Renders the Outbounds page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_outbounds_page_status();
    show_delete_outbound_dialog(ui, service);
    show_rename_outbound_dialog(ui, service);
    show_raw_json_outbound_dialog(ui, service);

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
                if ui.button("DNS").clicked() {
                    if let Err(e) = service.begin_add_outbound_dns() {
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
        let edit_ok = matches!(
            row.kind(),
            OutboundKind::Freedom | OutboundKind::Blackhole | OutboundKind::Dns
        );
        if ui
            .add_enabled(edit_ok && !busy, egui::Button::new("Edit"))
            .on_disabled_hover_text("Shell editing is available for Freedom, Blackhole, and DNS outbounds only")
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

        let duplicate_ok = matches!(
            row.kind(),
            OutboundKind::Freedom | OutboundKind::Blackhole | OutboundKind::Dns
        );
        if ui
            .add_enabled(duplicate_ok && !busy, egui::Button::new("Duplicate"))
            .on_disabled_hover_text(
                "Duplicate is available for Freedom, Blackhole, and DNS outbounds only",
            )
            .clicked()
        {
            if let Err(error) = service.start_duplicate_outbound(row.index) {
                service.show_status_message(error);
            }
            ui.close();
        }

        if ui
            .add_enabled(!busy, egui::Button::new("Rename"))
            .on_disabled_hover_text("Rename requires an idle connection")
            .clicked()
        {
            let current_tag = row.tag.clone().unwrap_or_default();
            set_pending_outbound_rename(
                ui,
                PendingOutboundRename {
                    index: row.index,
                    current_tag: current_tag.clone(),
                    draft: current_tag,
                    references: service.outbound_tag_reference_preview(row.index),
                    error: None,
                },
            );
            ui.close();
        }

        // Raw JSON escape hatch (Roadmap §3:125) — any protocol, incl. ones with no Edit above.
        if ui
            .add_enabled(!busy, egui::Button::new("Raw JSON"))
            .on_disabled_hover_text("Raw JSON requires an idle connection")
            .clicked()
        {
            if let Some((text, expected_fingerprint)) = service.outbound_raw_json_view(row.index) {
                set_raw_json_outbound_state(
                    ui,
                    RawJsonOutboundEditState {
                        index: row.index,
                        tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                        text,
                        expected_fingerprint,
                        error: None,
                    },
                );
            }
            ui.close();
        }
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

#[derive(Clone)]
struct PendingOutboundRename {
    index: usize,
    current_tag: String,
    draft: String,
    references: Vec<String>,
    error: Option<String>,
}

fn pending_outbound_rename_id() -> egui::Id {
    egui::Id::new("outbounds_pending_rename")
}

fn pending_outbound_rename(ui: &Ui) -> Option<PendingOutboundRename> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingOutboundRename>(pending_outbound_rename_id()))
}

fn set_pending_outbound_rename(ui: &Ui, pending: PendingOutboundRename) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_outbound_rename_id(), pending));
}

fn clear_pending_outbound_rename(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingOutboundRename>(pending_outbound_rename_id()));
}

fn show_rename_outbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_outbound_rename(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Rename outbound")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(RichText::new(format!("Current tag: «{}»", pending.current_tag)).size(14.0));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("New tag:");
                ui.text_edit_singleline(&mut pending.draft);
            });
            if !pending.references.is_empty() {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "Still referenced in routing (will not be updated automatically): {}",
                        pending.references.join("; ")
                    ))
                    .size(13.0)
                    .color(Color32::from_rgb(210, 170, 40)),
                );
            }
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
                let can_submit = !busy && !pending.draft.trim().is_empty();
                if ui
                    .add_enabled(can_submit, egui::Button::new("Rename"))
                    .clicked()
                {
                    match service
                        .start_rename_outbound_tag(pending.index, pending.draft.trim().to_owned())
                    {
                        Ok(()) => closed = true,
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui.button("Cancel").clicked() {
                    closed = true;
                }
            });
        });

    if closed || !open {
        clear_pending_outbound_rename(ui);
    } else {
        set_pending_outbound_rename(ui, pending);
    }
}

// ─── Raw JSON escape hatch (Roadmap §3:125) ──────────────────────────────────

/// Standalone dialog state — deliberately kept out of `OutboundEditorSession` (which only
/// covers Freedom/Blackhole/DNS); Raw JSON is available for **any** outbound protocol.
#[derive(Clone)]
struct RawJsonOutboundEditState {
    index: usize,
    tag: String,
    text: String,
    expected_fingerprint: String,
    error: Option<String>,
}

fn raw_json_outbound_id() -> egui::Id {
    egui::Id::new("outbounds_raw_json_edit")
}

fn raw_json_outbound_state(ui: &Ui) -> Option<RawJsonOutboundEditState> {
    ui.ctx()
        .data(|d| d.get_temp::<RawJsonOutboundEditState>(raw_json_outbound_id()))
}

fn set_raw_json_outbound_state(ui: &Ui, state: RawJsonOutboundEditState) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(raw_json_outbound_id(), state));
}

fn clear_raw_json_outbound_state(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<RawJsonOutboundEditState>(raw_json_outbound_id()));
}

fn show_raw_json_outbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut state) = raw_json_outbound_state(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new(format!("Raw JSON — {}", state.tag))
        .collapsible(false)
        .resizable(true)
        .default_width(560.0)
        .default_height(480.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(
                    "Escape hatch: edits the entire outbound object as raw JSON — for fields \
                     the structured editor doesn't cover, or for protocols with no structured \
                     editor at all. Save replaces the whole object; invalid JSON or a stale \
                     fingerprint (config changed underneath) is rejected before anything is \
                     written.",
                )
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
            );
            ui.add_space(6.0);
            if let Some(error) = &state.error {
                ui.label(
                    RichText::new(error.clone())
                        .size(13.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
                ui.add_space(4.0);
            }
            egui::ScrollArea::vertical()
                .max_height(360.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut state.text)
                            .desired_rows(20)
                            .desired_width(f32::INFINITY)
                            .code_editor(),
                    );
                });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let busy = service.is_outbound_mutation_busy();
                if ui.add_enabled(!busy, egui::Button::new("Save")).clicked() {
                    match service.start_replace_outbound_raw_json(
                        state.index,
                        &state.text,
                        state.expected_fingerprint.clone(),
                    ) {
                        Ok(()) => closed = true,
                        Err(message) => state.error = Some(message),
                    }
                }
                if ui.button("Cancel").clicked() {
                    closed = true;
                }
            });
        });

    if closed || !open {
        clear_raw_json_outbound_state(ui);
    } else {
        set_raw_json_outbound_state(ui, state);
    }
}

// ─── Outbound Shell editor (Freedom, Blackhole, DNS; Roadmap §2.4:94, §2.4:95, §2.4:96) ────

fn outbound_protocol_label(settings: &OutboundSettingsDraft) -> &'static str {
    match settings {
        OutboundSettingsDraft::Freedom { .. } => "Freedom",
        OutboundSettingsDraft::Blackhole { .. } => "Blackhole",
        OutboundSettingsDraft::Dns { .. } => "DNS",
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
        Some(OutboundSettingsDraft::Dns { .. }) => show_dns_settings_edit(ui, service),
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

fn show_dns_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Dns {
        rewrite_network,
        rewrite_address,
        rewrite_port,
        user_level,
        rules,
    } = &mut session.settings
    else {
        return;
    };

    let mut network = rewrite_network.clone();
    let mut address = rewrite_address.clone();
    let mut port = rewrite_port.clone();
    let mut level = *user_level as i64;

    egui::Grid::new("dns_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("rewriteNetwork");
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("dns_rewrite_network")
                    .selected_text(if network.is_empty() {
                        "(unset — unchanged)"
                    } else {
                        network.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in DNS_REWRITE_NETWORKS {
                            ui.selectable_value(&mut network, preset.to_owned(), preset);
                        }
                    });
                ui.text_edit_singleline(&mut network);
            });
            ui.end_row();

            ui.label("rewriteAddress");
            ui.text_edit_singleline(&mut address)
                .on_hover_text("Target DNS server address; empty = unchanged");
            ui.end_row();

            ui.label("rewritePort");
            ui.text_edit_singleline(&mut port)
                .on_hover_text("1-65535; empty = unchanged");
            ui.end_row();

            ui.label("userLevel");
            ui.add(egui::DragValue::new(&mut level).range(0..=u32::MAX as i64));
            ui.end_row();
        });

    *rewrite_network = network;
    *rewrite_address = address;
    *rewrite_port = port;
    *user_level = level.max(0) as u64;

    ui.add_space(8.0);
    ui.strong("rules").on_hover_text(
        "Evaluated in order — first match wins. No matching rule: A/AAAA go to the internal DNS module, other types get an empty RCODE 0 response.",
    );
    show_dns_rules_edit(ui, rules);
}

/// Ordered `settings.rules[]` editor (Add/Remove/Move up/down; order is meaningful — mirrors the
/// FinalMask layer-list editor convention).
fn show_dns_rules_edit(ui: &mut Ui, rules: &mut Vec<DnsRuleDraft>) {
    let mut remove_idx: Option<usize> = None;
    let mut move_up_idx: Option<usize> = None;
    let mut move_down_idx: Option<usize> = None;
    let count = rules.len();

    for (idx, rule) in rules.iter_mut().enumerate() {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(format!("rule[{idx}]"));
                if ui.small_button("Up").on_hover_text("Move up").clicked() && idx > 0 {
                    move_up_idx = Some(idx);
                }
                if ui.small_button("Down").on_hover_text("Move down").clicked() && idx + 1 < count {
                    move_down_idx = Some(idx);
                }
                if ui.button("Remove").clicked() {
                    remove_idx = Some(idx);
                }
            });

            egui::Grid::new(("dns_rule_edit_grid", idx))
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.label("action");
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_id_salt(("dns_rule_action", idx))
                            .selected_text(if rule.action.is_empty() {
                                "(unset)"
                            } else {
                                rule.action.as_str()
                            })
                            .show_ui(ui, |ui| {
                                for &preset in DNS_RULE_ACTIONS {
                                    ui.selectable_value(&mut rule.action, preset.to_owned(), preset);
                                }
                            });
                        ui.text_edit_singleline(&mut rule.action);
                    });
                    ui.end_row();

                    ui.label("qType");
                    ui.text_edit_singleline(&mut rule.q_type).on_hover_text(
                        "Integer (e.g. 1, 28, 65), or range/comma-list (e.g. 11,13,15-17); empty = any",
                    );
                    ui.end_row();

                    ui.label("rCode").on_hover_text("Relevant only when action = return");
                    let mut r_code = rule.r_code;
                    ui.add(egui::DragValue::new(&mut r_code).range(0..=65535));
                    rule.r_code = r_code;
                    ui.end_row();
                });

            ui.label("domain (one per line; empty = matches all queries)");
            let mut domain_text = rule.domain.join("\n");
            if ui
                .add(egui::TextEdit::multiline(&mut domain_text).desired_rows(2))
                .changed()
            {
                rule.domain = domain_text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
        });
    }

    if let Some(idx) = remove_idx {
        rules.remove(idx);
    } else if let Some(idx) = move_up_idx {
        rules.swap(idx, idx - 1);
    } else if let Some(idx) = move_down_idx {
        rules.swap(idx, idx + 1);
    }

    ui.add_space(4.0);
    if ui.button("Add rule").clicked() {
        rules.push(DnsRuleDraft {
            action: "direct".to_owned(),
            q_type: String::new(),
            r_code: 0,
            domain: Vec::new(),
            extras: Default::default(),
        });
    }
}
