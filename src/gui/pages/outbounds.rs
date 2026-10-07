//! Outbounds page — table of discovered outbound summaries + Delete.
//!
//! Data flows exclusively through [`ApplicationService`] → [`OutboundSummary`].
//! This page never reads JSON or opens SSH directly.

use egui::{Color32, RichText, Sense, Ui};

use super::optional_string_combo;

use crate::app::{
    ApplicationService, BLACKHOLE_RESPONSE_TYPES, DNS_REWRITE_NETWORKS, DNS_RULE_ACTIONS,
    DnsRuleDraft, FREEDOM_DEFAULT_BLOCK_DELAY, FREEDOM_FINAL_RULE_ACTIONS,
    FREEDOM_FINAL_RULE_NETWORKS, FREEDOM_NOISE_TYPES, FREEDOM_PROXY_PROTOCOL_VERSIONS,
    FragmentDraft, FreedomFinalRuleDraft, MISSING_FIELD, NoiseDraft,
    OutboundKind, OutboundSettingsDraft, OutboundsPageState, OutboundsSortColumn,
    outbound_row_display,
};
use crate::xray::{
    CompatibilityWarning, CompatibilityWarningId, OutboundSummary, outbound_protocol_has_transport,
    LoopbackRouting, outbound_protocol_uses_sockopt, validate_send_through,
};

/// Renders the Outbounds page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_outbounds_page_status();
    show_delete_outbound_dialog(ui, service);
    show_duplicate_outbound_dialog(ui, service);
    show_rename_outbound_dialog(ui, service);
    show_raw_json_outbound_dialog(ui, service);

    ui.heading("Outbounds");
    ui.add_space(8.0);

    let model = service.outbounds_page_model();

    match model.state {
        OutboundsPageState::NoSshConnection
        | OutboundsPageState::XrayNotDiscovered
        | OutboundsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        OutboundsPageState::NoOutbounds => {
            // Configuration is loaded — the outbound list is just empty (e.g. a freshly
            // created config). Show the hint but fall through so the "Add Outbound" menu
            // below stays reachable.
            show_state_message(ui, model.state);
            ui.add_space(8.0);
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
                // Still fall through to the Add menu — an empty list plus warnings must
                // not lock the user out of creating the first outbound.
                ui.label(RichText::new("No outbounds").size(14.0));
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
                if ui
                    .button("Loopback")
                    .on_hover_text(
                        "Sends traffic back into routing as if it came from an inbound with the \
                         chosen tag — https://xtls.github.io/en/config/outbounds/loopback.html",
                    )
                    .clicked()
                {
                    if let Err(e) = service.begin_add_outbound_loopback() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui
                    .button("VLESS")
                    .on_hover_text(
                        "Bridge side of VLESS-native reverse proxy, or a plain forward outbound \
                         — https://xtls.github.io/en/document/level-2/vless_reverse.html",
                    )
                    .clicked()
                {
                    if let Err(e) = service.begin_add_outbound_vless() {
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
            OutboundKind::Freedom
                | OutboundKind::Blackhole
                | OutboundKind::Dns
                | OutboundKind::Vless
                | OutboundKind::Loopback
        );
        if ui
            .add_enabled(edit_ok && !busy, egui::Button::new("Edit"))
            .on_disabled_hover_text(
                "Shell editing is available for Freedom, Blackhole, DNS, Loopback, and VLESS \
                 outbounds only — a legacy VLESS vnext[] outbound opens only when it has one \
                 server with one user (Save converts it to the flat form); any other must be \
                 edited via Raw JSON",
            )
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
            OutboundKind::Freedom
                | OutboundKind::Blackhole
                | OutboundKind::Dns
                | OutboundKind::Vless
                | OutboundKind::Loopback
        );
        if ui
            .add_enabled(duplicate_ok && !busy, egui::Button::new("Duplicate"))
            .on_disabled_hover_text(
                "Duplicate is available for Freedom, Blackhole, DNS, Loopback, and VLESS outbounds only",
            )
            .clicked()
        {
            set_pending_outbound_duplicate(
                ui,
                PendingOutboundDuplicate {
                    index: row.index,
                    tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    error: None,
                    diff_preview: None,
                },
            );
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
                    diff_preview: None,
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
                        diff_preview: None,
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
struct PendingOutboundDuplicate {
    index: usize,
    tag: String,
    error: Option<String>,
    /// Last redacted structural diff preview (Roadmap §3:126); stale until re-clicked.
    diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
}

fn pending_outbound_duplicate_id() -> egui::Id {
    egui::Id::new("outbounds_pending_duplicate")
}

fn pending_outbound_duplicate(ui: &Ui) -> Option<PendingOutboundDuplicate> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingOutboundDuplicate>(pending_outbound_duplicate_id()))
}

fn set_pending_outbound_duplicate(ui: &Ui, pending: PendingOutboundDuplicate) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_outbound_duplicate_id(), pending));
}

fn clear_pending_outbound_duplicate(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingOutboundDuplicate>(pending_outbound_duplicate_id()));
}

fn show_duplicate_outbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_outbound_duplicate(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Duplicate outbound")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(format!(
                    "Duplicate outbound «{}»? A copy with a unique tag is added to the same source file.",
                    pending.tag
                ))
                .size(14.0),
            );
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            if let Some(entries) = pending.diff_preview.clone() {
                ui.add_space(8.0);
                super::json_diff_preview(ui, &entries);
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_outbound_mutation_busy();
                if ui
                    .add_enabled(!busy, egui::Button::new("Duplicate"))
                    .clicked()
                {
                    match service.start_duplicate_outbound(pending.index) {
                        Ok(()) => closed = true,
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("Preview changes"))
                    .clicked()
                {
                    match service.preview_duplicate_outbound_diff(pending.index) {
                        Ok(entries) => {
                            pending.diff_preview = Some(entries);
                            pending.error = None;
                        }
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui.button("Cancel").clicked() {
                    closed = true;
                }
            });
        });

    if closed || !open {
        clear_pending_outbound_duplicate(ui);
    } else {
        set_pending_outbound_duplicate(ui, pending);
    }
}

#[derive(Clone)]
struct PendingOutboundRename {
    index: usize,
    current_tag: String,
    draft: String,
    references: Vec<String>,
    error: Option<String>,
    /// Last redacted structural diff preview (Roadmap §3:126); stale until re-clicked.
    diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
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
            if let Some(entries) = pending.diff_preview.clone() {
                ui.add_space(8.0);
                super::json_diff_preview(ui, &entries);
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
                if ui
                    .add_enabled(can_submit, egui::Button::new("Preview changes"))
                    .clicked()
                {
                    match service
                        .preview_rename_outbound_tag_diff(pending.index, pending.draft.trim())
                    {
                        Ok(entries) => {
                            pending.diff_preview = Some(entries);
                            pending.error = None;
                        }
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
    /// Last redacted structural diff preview (Roadmap §3:126); stale until re-clicked.
    diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
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
            if let Some(entries) = state.diff_preview.clone() {
                super::json_diff_preview(ui, &entries);
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
                if ui
                    .add_enabled(!busy, egui::Button::new("Preview changes"))
                    .clicked()
                {
                    match service.preview_replace_outbound_raw_json_diff(
                        state.index,
                        &state.text,
                        state.expected_fingerprint.clone(),
                    ) {
                        Ok(entries) => {
                            state.diff_preview = Some(entries);
                            state.error = None;
                        }
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
        OutboundSettingsDraft::Freedom(_) => "Freedom",
        OutboundSettingsDraft::Blackhole { .. } => "Blackhole",
        OutboundSettingsDraft::Dns { .. } => "DNS",
        OutboundSettingsDraft::Vless(_) => "VLESS",
        OutboundSettingsDraft::Loopback(_) => "Loopback",
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
        Some(OutboundSettingsDraft::Freedom(_)) => show_freedom_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Blackhole { .. }) => show_blackhole_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Dns { .. }) => show_dns_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Vless(_)) => show_vless_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Loopback(_)) => show_loopback_settings_edit(ui, service),
        None => {}
    }
    // Stream / Security for protocols that dial through a transport (Roadmap §4.2).
    let protocol = service
        .outbound_editor_session()
        .map(|s| s.settings.protocol_name())
        .unwrap_or_default();
    if outbound_protocol_has_transport(protocol) {
        ui.add_space(8.0);
        ui.separator();
        super::outbound_stream::show_outbound_stream_edit(ui, service, protocol);
    }
    // Socket options for every protocol that dials (Roadmap §4.2).
    if outbound_protocol_uses_sockopt(protocol) {
        ui.add_space(8.0);
        ui.separator();
        super::outbound_stream::show_outbound_sockopt_edit(ui, service);
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
        if ui
            .add_enabled(!busy, egui::Button::new("Preview changes"))
            .clicked()
        {
            if let Err(e) = service.preview_outbound_shell_diff() {
                service.show_status_message(e);
            }
        }
        if ui.button("Cancel").clicked() {
            service.cancel_outbound_editor_session();
        }
    });
    show_outbound_diff_preview(ui, service);
}

fn show_outbound_diff_preview(ui: &mut Ui, service: &ApplicationService) {
    let Some(entries) = service
        .outbound_editor_session()
        .and_then(|s| s.diff_preview.clone())
    else {
        return;
    };
    super::json_diff_preview(ui, &entries);
}

fn show_outbound_general_edit(ui: &mut Ui, service: &mut ApplicationService, is_add: bool) {
    // Computing warnings borrows the service immutably, so before the mutable session borrow.
    let proxy_settings_warnings: Vec<_> = service
        .outbound_editor_warnings()
        .into_iter()
        .filter(|warning| warning.id == CompatibilityWarningId::OutboundProxySettingsRemoved)
        .collect();
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
            ui.text_edit_singleline(&mut send_through).on_hover_text(
                "Local address outgoing connections are sent from: an IP; IP/prefix — a random \
                 address of that range per connection; origin — the local address the client \
                 reached the inbound on; srcip — the client's own address. Empty = system default.",
            );
            ui.end_row();
        });
    // Checked live with the same rule as Save (Roadmap §4.2), plus the core's precedence:
    // `SetOutboundGateway` skips sendThrough while sockopt.dialerProxy is set.
    if let Err(message) = validate_send_through(&send_through) {
        ui.label(RichText::new(message).size(12.0).color(Color32::from_rgb(220, 80, 80)));
    } else if !send_through.trim().is_empty() && !session.stream.sockopt.dialer_proxy.trim().is_empty() {
        ui.label(
            RichText::new("sendThrough is not used while Socket options → dialerProxy is set.")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    }

    general.tag = Some(tag);
    general.send_through = Some(send_through);

    // `proxySettings` is never written: it is a removed feature (XTLS/Xray-core#6058). An
    // existing one is shown read-only with an explicit migration (Roadmap §4.2).
    let Some(legacy) = general.legacy_proxy_settings.clone() else {
        return;
    };
    let pending = general.migrate_proxy_settings;
    ui.add_space(6.0);
    let tag = if legacy.tag.is_empty() { MISSING_FIELD } else { legacy.tag.as_str() };
    ui.label(format!(
        "proxySettings (on disk): tag {tag}{}",
        if legacy.transport_layer { ", transportLayer" } else { "" }
    ));
    show_outbound_compatibility_warnings(ui, &proxy_settings_warnings);
    if pending {
        ui.label(
            RichText::new("Migration pending — proxySettings is removed on Save (see the preview).")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }
    if ui
        .button("Migrate to sockopt.dialerProxy")
        .on_hover_text(
            "Removes proxySettings and moves its tag into streamSettings.sockopt.dialerProxy (an \
             existing dialerProxy wins) and shows the diff; nothing is written until Save",
        )
        .clicked()
    {
        match service.migrate_outbound_proxy_settings() {
            Ok(message) | Err(message) => service.show_status_message(message),
        }
    }
}

fn show_freedom_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    // Warnings first: computing them borrows the service immutably.
    let warnings = outbound_editor_warnings_below_general(service);
    let can_migrate = matches!(
        service.outbound_editor_session().map(|s| &s.settings),
        Some(OutboundSettingsDraft::Freedom(draft))
            if draft.legacy_domain_strategy.is_some() && !draft.remove_legacy_domain_strategy
    );
    show_outbound_compatibility_warnings(ui, &warnings);
    if can_migrate {
        if ui
            .button("Migrate to sockopt")
            .on_hover_text(
                "Moves settings.domainStrategy into streamSettings.sockopt.domainStrategy (an \
                 existing sockopt value wins) and shows the diff; nothing is written until Save",
            )
            .clicked()
        {
            match service.migrate_outbound_legacy_domain_strategy() {
                Ok(message) | Err(message) => service.show_status_message(message),
            }
        }
        ui.add_space(6.0);
    }
    // The warning is computed on the draft and only for cores that refuse the key (gate G14), so
    // the button disappears once the removal is scheduled.
    let address_port_strategy_rejected = warnings
        .iter()
        .any(|warning| warning.id == CompatibilityWarningId::FreedomAddressPortStrategyRejected);
    if address_port_strategy_rejected {
        if ui
            .button("Remove addressPortStrategy")
            .on_hover_text(
                "Removes streamSettings.sockopt.addressPortStrategy (Freedom cannot use it; Save is \
                 blocked while it is there) and shows the diff; nothing is written until Save",
            )
            .clicked()
        {
            match service.remove_outbound_freedom_address_port_strategy() {
                Ok(message) | Err(message) => service.show_status_message(message),
            }
        }
        ui.add_space(6.0);
    }

    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Freedom(draft) = &mut session.settings else {
        return;
    };

    let mut redirect_text = draft.redirect.clone();
    let mut level = draft.user_level as i64;
    let mut proxy_protocol = draft.proxy_protocol;

    egui::Grid::new("freedom_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("redirect");
            ui.text_edit_singleline(&mut redirect_text)
                .on_hover_text("host:port or :port; empty = disabled");
            ui.end_row();

            ui.label("userLevel");
            ui.add(egui::DragValue::new(&mut level).range(0..=u32::MAX as i64));
            ui.end_row();

            ui.label("proxyProtocol").on_hover_text(
                "Send a PROXY protocol header to the target; the target must expect it, or the \
                 connection breaks",
            );
            egui::ComboBox::from_id_salt("freedom_proxy_protocol")
                .selected_text(proxy_protocol_label(proxy_protocol))
                .show_ui(ui, |ui| {
                    for &version in FREEDOM_PROXY_PROTOCOL_VERSIONS {
                        ui.selectable_value(&mut proxy_protocol, version, proxy_protocol_label(version));
                    }
                });
            ui.end_row();
        });

    draft.redirect = redirect_text;
    draft.user_level = level.max(0) as u64;
    draft.proxy_protocol = proxy_protocol;

    ui.add_space(6.0);
    let mut fragment_enabled = draft.fragment.is_some();
    if ui
        .checkbox(&mut fragment_enabled, "fragment")
        .on_hover_text("Packet fragmentation for DPI evasion")
        .changed()
    {
        draft.fragment = if fragment_enabled {
            Some(FragmentDraft::default())
        } else {
            None
        };
    }
    if let Some(fragment) = &mut draft.fragment {
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
    show_freedom_noises_edit(ui, &mut draft.noises);

    ui.add_space(8.0);
    ui.strong("finalRules").on_hover_text(
        "Checked in order before and after dialing; the first matching rule decides. Domain \
         targets are resolved with sockopt.domainStrategy first. Not applied when \
         sockopt.dialerProxy is set.",
    );
    if draft.final_rules_foreign {
        ui.label(
            RichText::new(
                "finalRules has a shape this editor cannot represent without changing it — it is \
                 kept as is; edit it with Raw JSON.",
            )
            .size(12.0)
            .color(Color32::from_rgb(210, 170, 40)),
        );
    } else {
        show_freedom_final_rules_edit(ui, &mut draft.final_rules);
    }
}

fn proxy_protocol_label(version: u64) -> String {
    match version {
        0 => "0 — disabled".to_owned(),
        1 | 2 => format!("v{version}"),
        other => format!("{other} (not supported by Xray-core)"),
    }
}

/// The editor's warnings without the ones the General section shows next to its fix
/// (`proxySettings`).
pub(super) fn outbound_editor_warnings_below_general(service: &ApplicationService) -> Vec<CompatibilityWarning> {
    let mut warnings = service.outbound_editor_warnings();
    warnings.retain(|warning| warning.id != CompatibilityWarningId::OutboundProxySettingsRemoved);
    warnings
}

/// Yellow `"<location>: <message>"` lines for non-blocking outbound warnings, danger ones in red
/// behind road sign 1.33 (mirrors the inbound Stream tab).
pub(super) fn show_outbound_compatibility_warnings(ui: &mut Ui, warnings: &[CompatibilityWarning]) {
    for warning in warnings {
        if warning.id.severity() == crate::xray::WarningSeverity::Danger {
            super::danger_warning(ui, &warning.text());
            continue;
        }
        ui.label(
            RichText::new(warning.text())
                .size(12.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
    if !warnings.is_empty() {
        ui.add_space(4.0);
    }
}

/// Ordered `settings.finalRules[]` editor (Add/Remove/Move up/down; mirrors the DNS `rules[]`
/// editor).
fn show_freedom_final_rules_edit(ui: &mut Ui, rules: &mut Vec<FreedomFinalRuleDraft>) {
    let mut remove_idx: Option<usize> = None;
    let mut move_up_idx: Option<usize> = None;
    let mut move_down_idx: Option<usize> = None;
    let count = rules.len();

    for (idx, rule) in rules.iter_mut().enumerate() {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(format!("finalRules[{idx}]"));
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

            egui::Grid::new(("freedom_final_rule_edit_grid", idx))
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.label("action");
                    egui::ComboBox::from_id_salt(("freedom_final_rule_action", idx))
                        .selected_text(if rule.action.is_empty() {
                            "(unset)"
                        } else {
                            rule.action.as_str()
                        })
                        .show_ui(ui, |ui| {
                            for &preset in FREEDOM_FINAL_RULE_ACTIONS {
                                ui.selectable_value(&mut rule.action, preset.to_owned(), preset);
                            }
                        });
                    ui.end_row();

                    ui.label("network");
                    egui::ComboBox::from_id_salt(("freedom_final_rule_network", idx))
                        .selected_text(if rule.network.is_empty() {
                            "(any)"
                        } else {
                            rule.network.as_str()
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut rule.network, String::new(), "(any)");
                            for &preset in FREEDOM_FINAL_RULE_NETWORKS {
                                ui.selectable_value(&mut rule.network, preset.to_owned(), preset);
                            }
                        });
                    ui.end_row();

                    ui.label("port");
                    ui.text_edit_singleline(&mut rule.port.text)
                        .on_hover_text("e.g. 25 or 1000-2000,443; empty = any port");
                    ui.end_row();

                    ui.label("blockDelay");
                    ui.text_edit_singleline(&mut rule.block_delay.text).on_hover_text(format!(
                        "Seconds a blocked connection is held open, e.g. 30 or 30-90; empty = \
                         {FREEDOM_DEFAULT_BLOCK_DELAY}"
                    ));
                    ui.end_row();
                });

            ui.label("ip (one CIDR per line, e.g. 10.0.0.0/8 or geoip:private; empty = any)");
            super::persistent_list_text_edit(ui, ("freedom_final_rule_ip", idx), &mut rule.ip, |ui, text| {
                ui.add(egui::TextEdit::multiline(text).desired_rows(2))
            });
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
    if ui.button("Add final rule").clicked() {
        rules.push(FreedomFinalRuleDraft::new("block"));
    }
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
    let OutboundSettingsDraft::Blackhole {
        response_type,
        custom_response_data,
        ..
    } = &mut session.settings
    else {
        return;
    };

    let mut kind = response_type.clone();
    let mut custom_data = custom_response_data.clone();
    egui::Grid::new("blackhole_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("response.type")
                .on_hover_text("none = close immediately; http = send a fake HTTP 403 then close; custom = send customResponseData then close");
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

            if kind.trim().eq_ignore_ascii_case("custom") {
                ui.label("response.customResponseData")
                    .on_hover_text("Base64-encoded raw bytes sent before close");
                ui.text_edit_singleline(&mut custom_data);
                ui.end_row();
            }
        });
    *response_type = kind;
    *custom_response_data = custom_data;
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

/// Loopback Protocol section (Roadmap §4.2): `inboundTag` (routing's `inboundTag` names + free
/// text) with a hint on where routing sends the traffic, and `sniffing` (shared editor).
fn show_loopback_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    // Computed before the mutable session borrow (a frame behind the typing, which is fine).
    let candidates = service.routing_inbound_tag_candidates();
    let routing = service.outbound_loopback_routing();
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Loopback(draft) = &mut session.settings else {
        return;
    };
    let grey = Color32::from_rgb(140, 140, 140);
    let amber = Color32::from_rgb(210, 170, 40);

    let presets: Vec<&str> = candidates.iter().map(String::as_str).collect();
    egui::Grid::new("loopback_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("inboundTag").on_hover_text(
                "The inbound tag the traffic re-enters routing with: rules whose inboundTag \
                 lists it decide where it goes next. Matched exactly (case and spaces count); \
                 it does not have to be the tag of a real inbound.",
            );
            ui.horizontal(|ui| {
                optional_string_combo(ui, "loopback_inbound_tag", &mut draft.inbound_tag, &presets);
            });
            ui.end_row();
        });
    if draft.inbound_tag_foreign && draft.inbound_tag.is_empty() {
        ui.label(
            RichText::new("inboundTag on disk is not a string (Xray-core refuses it); it is kept until a tag is typed here.")
                .size(12.0)
                .color(amber),
        );
    }
    let hint = match routing {
        Some(LoopbackRouting::NoTag) => Some((
            "No inboundTag: routing rules with an inboundTag condition never match this traffic; \
             the other rules decide."
                .to_owned(),
            amber,
        )),
        Some(LoopbackRouting::NoRule) => Some((
            "No routing rule lists this inboundTag — the other rules decide, and may send the \
             traffic back into this outbound."
                .to_owned(),
            amber,
        )),
        Some(LoopbackRouting::Rules(rules)) => Some((
            format!(
                "Routing rules for this tag: {}.",
                rules.iter().map(|index| format!("#{}", index + 1)).collect::<Vec<_>>().join(", ")
            ),
            grey,
        )),
        Some(LoopbackRouting::LoopsBack { rule }) => Some((
            format!(
                "Routing rule #{} sends this inboundTag back into this outbound — the traffic \
                 would loop.",
                rule + 1
            ),
            Color32::from_rgb(220, 80, 80),
        )),
        None => None,
    };
    if let Some((text, color)) = hint {
        ui.label(RichText::new(text).size(12.0).color(color));
    }

    ui.add_space(8.0);
    ui.strong("sniffing").on_hover_text(
        "settings.sniffing — sniff the re-injected traffic again (e.g. TLS SNI after a \
         decrypting outbound); runs only when enabled.",
    );
    if draft.sniffing_foreign {
        ui.label(
            RichText::new("settings.sniffing is not a JSON object; it is preserved — fix it on the Raw JSON tab to edit.")
                .size(12.0)
                .color(grey),
        );
        return;
    }
    super::inbounds::show_sniffing_fields(ui, &mut draft.sniffing);
    if !draft.sniffing.extras.is_empty() {
        ui.label(
            RichText::new(format!(
                "Preserved sniffing keys: {}",
                draft.sniffing.extras.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
            .size(12.0)
            .color(grey),
        );
    }
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
            super::persistent_list_text_edit(ui, ("dns_rule_domain", idx), &mut rule.domain, |ui, text| {
                ui.add(egui::TextEdit::multiline(text).desired_rows(2))
            });
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

/// VLESS outbound Protocol tab — bridge side of VLESS-native reverse proxy, or a plain forward
/// outbound (Roadmap §2.1:58). Writes the flat `settings` form (`address`/`port`/`id`/
/// `encryption`/`flow`/`level`/`email`/`reverse`); a draft read from a single-server legacy
/// `vnext[]` gets a notice that Save converts it (Roadmap §4.2).
fn show_vless_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let crate::app::OutboundSettingsDraft::Vless(settings) = &mut session.settings else {
        return;
    };
    let mut reverse = super::ReverseDraftFields::from_reverse(settings.reverse.as_ref());

    if settings.legacy_vnext {
        ui.label(
            egui::RichText::new(
                "This outbound uses the legacy vnext[] form. Save rewrites it into the flat \
                 settings form — same server and user for Xray-core. \"Preview changes\" shows \
                 the rewrite.",
            )
            .italics(),
        );
        ui.add_space(6.0);
    }

    egui::Grid::new("vless_outbound_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("address");
            ui.text_edit_singleline(&mut settings.address)
                .on_hover_text("Server this outbound dials (required)");
            ui.end_row();

            ui.label("port");
            ui.text_edit_singleline(&mut settings.port)
                .on_hover_text("1-65535 (required)");
            ui.end_row();

            ui.label("id");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut settings.id).desired_width(300.0))
                    .on_hover_text("UUID matching a clients[] entry on the far end (required)");
                if ui.button("Generate").clicked() {
                    settings.id = crate::app::generate_client_uuid();
                }
            });
            ui.end_row();

            ui.label("flow");
            ui.text_edit_singleline(&mut settings.flow)
                .on_hover_text("e.g. xtls-rprx-vision; empty = key absent");
            ui.end_row();

            ui.label("encryption");
            ui.text_edit_singleline(&mut settings.encryption)
                .on_hover_text(
                    "VLESS post-quantum encryption string (matches the inbound's decryption); \
                     empty = key absent",
                );
            ui.end_row();

            ui.label("level");
            ui.text_edit_singleline(&mut settings.level).on_hover_text(
                "User level: index into policy.levels (timeouts, buffer size); empty = key absent \
                 (level 0)",
            );
            ui.end_row();

            ui.label("email");
            ui.text_edit_singleline(&mut settings.email)
                .on_hover_text("User label in logs and statistics; empty = key absent");
            ui.end_row();
        });

    ui.add_space(6.0);
    super::reverse_fields_edit(ui, "vless_outbound_reverse_sniffing", &mut reverse);
    settings.reverse = reverse.to_reverse();
}
