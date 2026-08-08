//! Inbounds page — inbound table with 6-tab detail pane (IB-L1 + IB-L3 Stream).
//!
//! Tabs: General | Protocol | Stream | Security | Sniffing | Users
//! Data flows exclusively through [`ApplicationService`] → [`InboundSummary`].

use egui::{Color32, ComboBox, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, InboundClientProtocol, InboundEditorSession, InboundGeneral,
    InboundProtocolDraft, InboundShareMaterial, InboundsPageState, InboundsSortColumn,
    InboundSecurityMode, KNOWN_DEST_OVERRIDE, MISSING_FIELD,
    SniffingSettings, StreamMethod, allowed_security_modes,
    coerce_display_stream_method, coerce_security_mode_for_transport,
    selectable_stream_methods,
    inbound_row_display, parse_inbound_stream,
};
use crate::gui::pages::users;
use crate::xray::{
    ALPN_PRESETS, CERT_USAGE_PRESETS, CURVE_PRESETS, FINGERPRINT_PRESETS, FallbackDest,
    FallbackDestKind, FallbackObject, FinalMaskLayerDraft, InboundSummary, KCP_MTU_MAX,
    KCP_MTU_MIN, KCP_TTI_MAX,
    KCP_TTI_MIN, KcpStreamSettings, TCP_FINALMASK_TYPES, TLS_VERSION_PRESETS, TUNNEL_NETWORKS,
    UDP_FINALMASK_TYPES, CertificateDraft,
    TlsSettingsDraft, XHTTP_DOWNLOAD_SECURITIES, XHTTP_MODES, XHTTP_MODE_DEFAULT, XHTTP_PADDING_METHODS,
    XHTTP_PATH_DEFAULT, XHTTP_PLACEMENTS, XHTTP_SESSION_ID_TABLES, XHTTP_UPLINK_METHODS,
    XhttpCoreSettings, XhttpDownloadDraft, XhttpRange, XhttpStreamSettings,
    fallbacks_transport_compatible, parse_inbound_protocol, validate_port_map_target,
};

// ─── Tab enum ────────────────────────────────────────────────────────────────

/// Detail pane tab under a selected inbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum InboundDetailTab {
    #[default]
    General,
    Protocol,
    /// Stream settings editor (IB-L3).
    Stream,
    Security,
    Sniffing,
    Users,
}

// ─── Protocol picker for Add mode ────────────────────────────────────────────

/// Allowed XHTTP `mode` values (Stream tab) — re-exported constants from xray.
const XHTTP_MODE_AUTO: &str = XHTTP_MODE_DEFAULT;

fn protocol_picker_id() -> egui::Id {
    egui::Id::new("inbounds_add_protocol_picker")
}

fn protocol_picker(ui: &Ui) -> InboundClientProtocol {
    ui.ctx()
        .data(|d| d.get_temp::<InboundClientProtocol>(protocol_picker_id()))
        .unwrap_or(InboundClientProtocol::Vless)
}

fn set_protocol_picker(ui: &Ui, protocol: InboundClientProtocol) {
    ui.ctx().data_mut(|d| d.insert_temp(protocol_picker_id(), protocol));
}

// ─── Page entry point ────────────────────────────────────────────────────────

/// Renders the Inbounds page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Inbounds");
    ui.add_space(8.0);

    let model = service.inbounds_page_model();

    match model.state {
        InboundsPageState::NoSshConnection
        | InboundsPageState::NoXrayInstallation
        | InboundsPageState::DiscoveryNotCompleted
        | InboundsPageState::ConfigurationNotLoaded
        | InboundsPageState::NoInbounds => {
            show_state_message(ui, model.state);
            return;
        }
        InboundsPageState::ConfigurationContainsWarnings => {
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
                ui.label(RichText::new("No inbounds").size(14.0));
                return;
            }
        }
        InboundsPageState::ConfigurationLoaded => {}
    }

    // Table header with Add button.
    ui.horizontal(|ui| {
        ui.strong("Inbounds");
        ui.add_space(12.0);
        let busy = service.is_inbound_shell_mutation_busy();
        let adding = service
            .inbound_editor_session()
            .is_some_and(|s| s.is_add);
        if !adding
            && ui
                .add_enabled(!busy, egui::Button::new("Add Inbound"))
                .clicked()
        {
            let proto = protocol_picker(ui);
            if let Err(e) = service.begin_add_inbound(proto) {
                service.show_status_message(e);
            }
        }
    });
    ui.add_space(4.0);

    show_table(ui, service, &model.rows);
    ui.add_space(12.0);

    // If we are in Add mode, show the Add form regardless of selection.
    if service
        .inbound_editor_session()
        .is_some_and(|s| s.is_add)
    {
        show_add_pane(ui, service);
    } else {
        show_detail_pane(ui, service, &model.rows);
    }

    show_delete_inbound_dialog(ui, service);
}

fn show_state_message(ui: &mut Ui, state: InboundsPageState) {
    let color = match state {
        InboundsPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        InboundsPageState::NoInbounds => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

// ─── Inbound table ───────────────────────────────────────────────────────────

fn show_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[InboundSummary]) {
    let sort = service.inbounds_sort();
    let selected = service.selected_users_inbound();

    egui::Grid::new("inbounds_table")
        .num_columns(6)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(72.0)
        .show(ui, |ui| {
            sortable_header(ui, service, "Tag", InboundsSortColumn::Tag, sort.column);
            sortable_header(
                ui,
                service,
                "Protocol",
                InboundsSortColumn::Protocol,
                sort.column,
            );
            ui.strong("Listen");
            sortable_header(ui, service, "Port", InboundsSortColumn::Port, sort.column);
            ui.strong("Clients");
            ui.strong("Source file");
            ui.end_row();

            for row in rows {
                let display = inbound_row_display(row);
                let is_selected = selected == Some(row.index);
                let tag_text = if is_selected {
                    format!("› {}", display.tag)
                } else {
                    display.tag.clone()
                };
                if cell_with_menu(ui, service, row, &tag_text) {
                    service.set_selected_users_inbound(row.index);
                }
                cell_with_menu(ui, service, row, &display.protocol);
                cell_with_menu(ui, service, row, &display.listen);
                cell_with_menu(ui, service, row, &display.port);
                cell_with_menu(ui, service, row, &display.clients);
                cell_with_menu(ui, service, row, display.source_file);
                ui.end_row();
            }
        });
}

// ─── Add pane ────────────────────────────────────────────────────────────────

fn show_add_pane(ui: &mut Ui, service: &mut ApplicationService) {
    ui.separator();
    ui.add_space(4.0);
    ui.strong("Add New Inbound");
    ui.add_space(4.0);

    // Protocol picker at the top.
    let mut picker = protocol_picker(ui);
    ui.horizontal(|ui| {
        ui.label("Protocol:");
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Vless, "VLESS")
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Vless);
            let _ = service.begin_add_inbound(InboundClientProtocol::Vless);
        }
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Trojan, "Trojan")
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Trojan);
            let _ = service.begin_add_inbound(InboundClientProtocol::Trojan);
        }
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Hysteria, "Hysteria")
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Hysteria);
            let _ = service.begin_add_inbound(InboundClientProtocol::Hysteria);
        }
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Tunnel, "Tunnel")
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Tunnel);
            let _ = service.begin_add_inbound(InboundClientProtocol::Tunnel);
        }
    });
    ui.add_space(6.0);

    let busy = service.is_inbound_shell_mutation_busy();
    let is_tunnel = service
        .inbound_editor_session()
        .is_some_and(|s| matches!(s.protocol, InboundProtocolDraft::Tunnel { .. }));

    // General fields.
    show_add_general(ui, service);
    ui.add_space(6.0);

    // Protocol tab (VLESS only, Trojan has no extra fields).
    if let Some(session) = service.inbound_editor_session() {
        match &session.protocol {
            crate::app::InboundProtocolDraft::Vless { .. } => {
                ui.strong("Protocol");
                show_protocol_edit(ui, service);
                ui.add_space(6.0);
            }
            crate::app::InboundProtocolDraft::Trojan { .. } => {
                ui.strong("Protocol");
                show_protocol_edit(ui, service);
                ui.add_space(6.0);
            }
            crate::app::InboundProtocolDraft::Hysteria { version } => {
                ui.strong("Protocol");
                ui.label(format!("Hysteria version: {version} (fixed)"));
                ui.add_space(6.0);
            }
            crate::app::InboundProtocolDraft::Tunnel { .. } => {
                ui.strong("Protocol");
                show_protocol_edit(ui, service);
                ui.add_space(6.0);
            }
        }
    }

    // Stream (IB-L3) — not used for Tunnel.
    if !is_tunnel {
        ui.strong("Stream");
        show_stream_edit(ui, service);
        ui.add_space(6.0);
    }

    // Security (VLESS: none|reality; Trojan: Reality required).
    if service
        .inbound_editor_session()
        .is_some_and(|s| s.security.is_some())
    {
        ui.strong("Security");
        ui.horizontal(|ui| {
            show_security_keygen_actions(ui, service, busy);
        });
        show_security_edit(ui, service);
        ui.add_space(6.0);
    }

    // Sniffing.
    ui.strong("Sniffing");
    show_sniffing_edit_session(ui, service);
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui
            .add_enabled(!busy, egui::Button::new("Add Inbound"))
            .clicked()
        {
            if let Err(e) = service.start_add_inbound() {
                service.show_status_message(e);
            }
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Preview changes"))
            .clicked()
        {
            if let Err(e) = service.preview_inbound_shell_diff() {
                service.show_status_message(e);
            }
        }
        if ui.button("Cancel").clicked() {
            service.cancel_inbound_editor_session();
        }
    });
    show_json_diff_preview(ui, service);
}

fn show_add_general(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    let general = &mut session.general;

    let mut tag = general.tag.clone().unwrap_or_default();
    let mut listen = general.listen.clone().unwrap_or_default();
    let mut port_text = general.port.map(|p| p.to_string()).unwrap_or_default();

    egui::Grid::new("add_general_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("Tag (required)");
            if ui.text_edit_singleline(&mut tag).changed() {
                general.tag = if tag.trim().is_empty() { None } else { Some(tag) };
                session.dirty = true;
            }
            ui.end_row();
            ui.label("Listen");
            if ui.text_edit_singleline(&mut listen).changed() {
                general.listen = if listen.trim().is_empty() { None } else { Some(listen) };
                session.dirty = true;
            }
            ui.end_row();
            ui.label("Port");
            if ui.text_edit_singleline(&mut port_text).changed() {
                if port_text.trim().is_empty() {
                    general.port = None;
                } else if let Ok(p) = port_text.trim().parse::<u64>() {
                    general.port = Some(p);
                }
                session.dirty = true;
            }
            ui.end_row();
        });
}

// ─── 6-tab detail pane ───────────────────────────────────────────────────────

fn show_detail_pane(ui: &mut Ui, service: &mut ApplicationService, rows: &[InboundSummary]) {
    let Some(selected_index) = service.selected_users_inbound() else {
        ui.label(
            RichText::new(
                "Select an inbound to view General | Protocol | Stream | Security | Sniffing | Users.",
            )
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    };
    let Some(row) = rows.iter().find(|r| r.index == selected_index) else {
        ui.label(
            RichText::new("Selected inbound is no longer in the loaded configuration.")
                .size(14.0)
                .color(Color32::from_rgb(200, 60, 60)),
        );
        return;
    };

    let protocol = row
        .protocol
        .as_deref()
        .and_then(InboundClientProtocol::from_wire);

    if take_focus_general(ui) {
        set_detail_tab(ui, InboundDetailTab::General);
    }

    let mut tab = detail_tab(ui);
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let is_tunnel = matches!(protocol, Some(InboundClientProtocol::Tunnel));
    let users_ok = protocol.is_some_and(|p| p.mutate_enabled());
    let is_security_proto = matches!(
        protocol,
        Some(
            InboundClientProtocol::Vless
                | InboundClientProtocol::Trojan
                | InboundClientProtocol::Hysteria
        )
    );

    ui.horizontal(|ui| {
        ui.selectable_value(&mut tab, InboundDetailTab::General, "General");
        ui.selectable_value(&mut tab, InboundDetailTab::Protocol, "Protocol");

        // Stream tab: shell-editable protocols except Tunnel (tcp/none fixed).
        let stream_enabled = shell_ok && !is_tunnel;
        let stream_disabled_hint = if is_tunnel {
            "Stream is not used for Tunnel (tcp / none)"
        } else {
            "Stream editing requires a shell-editable inbound"
        };
        if ui
            .add_enabled(
                stream_enabled,
                egui::Button::selectable(tab == InboundDetailTab::Stream, "Stream"),
            )
            .on_disabled_hover_text(stream_disabled_hint)
            .clicked()
            && stream_enabled
        {
            tab = InboundDetailTab::Stream;
        }

        // Security tab enabled for VLESS / Trojan / Hysteria when shell-editable.
        let security_enabled = is_security_proto && shell_ok;
        let security_disabled_hint = if is_tunnel {
            "Security is not used for Tunnel"
        } else if !shell_ok {
            "Security editing requires a shell-editable inbound"
        } else {
            "Security tab available for VLESS, Trojan, and Hysteria inbounds only"
        };
        if ui
            .add_enabled(
                security_enabled,
                egui::Button::selectable(tab == InboundDetailTab::Security, "Security"),
            )
            .on_disabled_hover_text(security_disabled_hint)
            .clicked()
            && security_enabled
        {
            tab = InboundDetailTab::Security;
        }

        ui.selectable_value(&mut tab, InboundDetailTab::Sniffing, "Sniffing");
        if ui
            .add_enabled(
                users_ok,
                egui::Button::selectable(tab == InboundDetailTab::Users, "Users"),
            )
            .on_disabled_hover_text("Users are not available for Tunnel inbounds")
            .clicked()
            && users_ok
        {
            tab = InboundDetailTab::Users;
        } else if !users_ok && tab == InboundDetailTab::Users {
            tab = InboundDetailTab::General;
        }
        if is_tunnel && matches!(tab, InboundDetailTab::Stream | InboundDetailTab::Security) {
            tab = InboundDetailTab::Protocol;
        }
    });
    set_detail_tab(ui, tab);
    ui.add_space(8.0);

    match tab {
        InboundDetailTab::General => show_general(ui, service, row),
        InboundDetailTab::Protocol => show_protocol_tab(ui, service, row),
        InboundDetailTab::Stream => show_stream_tab(ui, service, row),
        InboundDetailTab::Security => show_security_tab(ui, service, row),
        InboundDetailTab::Sniffing => show_sniffing_tab(ui, service, row),
        InboundDetailTab::Users => {
            if let Some(reason) = service.users_blocked_by_dirty_shell() {
                ui.label(
                    RichText::new(reason)
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            } else {
                users::show(ui, service);
            }
        }
    }

    if service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index)
    {
        ui.add_space(8.0);
        let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
        if ui
            .add_enabled(!busy, egui::Button::new("Preview changes"))
            .clicked()
        {
            if let Err(e) = service.preview_inbound_shell_diff() {
                service.show_status_message(e);
            }
        }
        show_json_diff_preview(ui, service);
    }
}

// ─── General tab ─────────────────────────────────────────────────────────────

fn show_general(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    let protocol = row
        .protocol
        .clone()
        .unwrap_or_else(|| MISSING_FIELD.to_owned());

    if !shell_ok {
        ui.label(
            RichText::new(
                "Shell editing is available for VLESS, Trojan, Hysteria, and Tunnel only.",
            )
            .size(14.0)
            .color(Color32::from_rgb(210, 170, 40)),
        );
        ui.add_space(6.0);
        show_general_readonly(ui, service, row, &protocol);
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!busy, egui::Button::new("Save"))
                .clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
        } else {
            if ui
                .add_enabled(!busy, egui::Button::new("Edit"))
                .clicked()
                && let Err(e) = service.begin_edit_inbound_shell(row.index)
            {
                service.show_status_message(e);
            }
        }
    });
    ui.add_space(8.0);

    if editing {
        show_general_edit_session(ui, service, row, &protocol);
    } else {
        show_general_readonly(ui, service, row, &protocol);
    }
}

fn show_general_readonly(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
    protocol: &str,
) {
    let general = service
        .inbound_general_view(row.index)
        .unwrap_or_else(|| InboundGeneral {
            tag: row.tag.clone(),
            listen: row.listen.clone(),
            port: row.port,
        });
    let display = inbound_row_display(row);
    egui::Grid::new("inbound_general_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("Tag");
            ui.label(general.tag.as_deref().unwrap_or(MISSING_FIELD));
            ui.end_row();
            ui.label("Protocol");
            ui.label(protocol);
            ui.end_row();
            ui.label("Listen");
            ui.label(general.listen.as_deref().unwrap_or(MISSING_FIELD));
            ui.end_row();
            ui.label("Port");
            ui.label(
                general
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.end_row();
            ui.label("Clients");
            ui.label(&display.clients);
            ui.end_row();
            ui.label("Source file");
            ui.label(display.source_file);
            ui.end_row();
        });
}

fn show_general_edit_session(
    ui: &mut Ui,
    service: &mut ApplicationService,
    row: &InboundSummary,
    protocol: &str,
) {
    let port_ok = service.inbound_port_shell_editable(row.index);
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    let general = &mut session.general;

    let mut tag = general.tag.clone().unwrap_or_default();
    let mut listen = general.listen.clone().unwrap_or_default();
    let mut port_text = general.port.map(|p| p.to_string()).unwrap_or_default();

    egui::Grid::new("inbound_general_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("Tag");
            if ui.text_edit_singleline(&mut tag).changed() {
                general.tag = if tag.trim().is_empty() { None } else { Some(tag) };
                session.dirty = true;
            }
            ui.end_row();

            ui.label("Protocol");
            ui.label(protocol);
            ui.end_row();

            ui.label("Listen");
            if ui.text_edit_singleline(&mut listen).changed() {
                general.listen = if listen.trim().is_empty() { None } else { Some(listen) };
                session.dirty = true;
            }
            ui.end_row();

            ui.label("Port");
            if port_ok {
                if ui.text_edit_singleline(&mut port_text).changed() {
                    if port_text.trim().is_empty() {
                        general.port = None;
                    } else if let Ok(p) = port_text.trim().parse::<u64>() {
                        general.port = Some(p);
                    }
                    session.dirty = true;
                }
            } else {
                ui.label(
                    RichText::new("Port shape is not editable (scalar only)")
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.end_row();

            ui.label("Source file");
            ui.label(row.source_file.as_str());
            ui.end_row();
        });
}

// ─── Protocol tab ────────────────────────────────────────────────────────────

// ─── Client-side crypto display (VLESS pairs) ────────────────────────────────

const CLIENT_FIELD_HINT: Color32 = Color32::from_rgb(140, 140, 140);

fn resolved_client_value(
    service: &ApplicationService,
    row: Option<&InboundSummary>,
    session_field: impl Fn(&InboundEditorSession) -> Option<String>,
    material_field: impl Fn(&InboundShareMaterial) -> Option<String>,
) -> Option<String> {
    if let Some(session) = service.inbound_editor_session() {
        let matches_row = row.is_none_or(|r| !session.is_add && session.inbound_index == r.index);
        if matches_row {
            if let Some(value) = session_field(session).filter(|s| !s.trim().is_empty()) {
                return Some(value);
            }
        }
    }
    row.and_then(|r| {
        service
            .inbound_share_material(r.tag.as_deref(), r.index)
            .and_then(material_field)
            .filter(|s| !s.trim().is_empty())
    })
}

fn show_client_field_value(ui: &mut Ui, value: Option<impl AsRef<str>>, generate_hint: &str) {
    if let Some(value) = value.filter(|s| !s.as_ref().trim().is_empty()) {
        ui.label(RichText::new(value.as_ref()).monospace());
    } else {
        ui.vertical(|ui| {
            ui.label(RichText::new(MISSING_FIELD).color(CLIENT_FIELD_HINT));
            ui.label(
                RichText::new(format!("Generate {generate_hint}"))
                    .size(13.0)
                    .color(CLIENT_FIELD_HINT),
            );
        });
    }
}

fn show_protocol_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    if !shell_ok {
        ui.label(
            RichText::new("Shell editing is not enabled for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!busy, egui::Button::new("Save"))
                .clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
            && let Err(e) = service.begin_edit_inbound_shell(row.index)
        {
            service.show_status_message(e);
        }
    });
    ui.add_space(8.0);

    if editing {
        show_protocol_edit(ui, service);
    } else {
        show_protocol_readonly(ui, service, row);
    }
}

fn show_protocol_readonly(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
) {
    let protocol = row.protocol.as_deref().unwrap_or(MISSING_FIELD);
    match protocol.to_ascii_lowercase().as_str() {
        "vless" => {
            // Show current decryption from loaded config.
            let decryption = service
                .loaded_config()
                .editable()
                .and_then(|e| e.sections().inbounds().get(row.index))
                .and_then(|inbound| inbound.value().get("settings"))
                .and_then(|s| s.get("decryption"))
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            let encryption = resolved_client_value(
                service,
                Some(row),
                |s| s.ephemeral_client_encryption.clone(),
                |m| m.client_encryption.clone(),
            );
            egui::Grid::new("protocol_view_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.label("decryption");
                    ui.label(decryption);
                    ui.end_row();
                    ui.label("encryption");
                    show_client_field_value(ui, encryption, "vlessenc");
                    ui.end_row();
                });
            show_fallbacks_readonly_from_row(ui, service, row);
        }
        "trojan" => {
            show_fallbacks_readonly_from_row(ui, service, row);
        }
        "tunnel" => show_tunnel_protocol_readonly(ui, service, row),
        _ => {
            ui.label(
                RichText::new("Protocol tab not available for this inbound type.")
                    .size(14.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
        }
    }
}

fn show_fallbacks_readonly_from_row(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
) {
    let fallbacks = service
        .loaded_config()
        .editable()
        .and_then(|e| e.sections().inbounds().get(row.index))
        .and_then(|inbound| parse_inbound_protocol(inbound.value()))
        .and_then(|draft| draft.fallbacks().map(|f| f.to_vec()))
        .unwrap_or_default();
    show_fallbacks_readonly(ui, &fallbacks);
}

fn show_fallbacks_readonly(ui: &mut Ui, fallbacks: &[FallbackObject]) {
    ui.add_space(6.0);
    ui.strong("fallbacks");
    if fallbacks.is_empty() {
        ui.label(
            RichText::new("(empty)")
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }
    egui::Grid::new("fallbacks_view_grid")
        .num_columns(5)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label(RichText::new("name").strong());
            ui.label(RichText::new("alpn").strong());
            ui.label(RichText::new("path").strong());
            ui.label(RichText::new("dest").strong());
            ui.label(RichText::new("xver").strong());
            ui.end_row();
            for entry in fallbacks {
                ui.label(if entry.name.is_empty() {
                    "—"
                } else {
                    entry.name.as_str()
                });
                ui.label(if entry.alpn.is_empty() {
                    "—"
                } else {
                    entry.alpn.as_str()
                });
                ui.label(if entry.path.is_empty() {
                    "—"
                } else {
                    entry.path.as_str()
                });
                ui.label(format!(
                    "{} ({})",
                    entry.dest.display(),
                    entry.dest.kind().label()
                ));
                ui.label(entry.xver.to_string());
                ui.end_row();
            }
        });
}

fn show_tunnel_protocol_readonly(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
) {
    let draft = service
        .loaded_config()
        .editable()
        .and_then(|e| e.sections().inbounds().get(row.index))
        .and_then(|inbound| crate::xray::parse_inbound_protocol(inbound.value()));
    let Some(InboundProtocolDraft::Tunnel {
        allowed_network,
        rewrite_address,
        rewrite_port,
        port_map,
        follow_redirect,
        user_level,
    }) = draft
    else {
        ui.label(
            RichText::new("Tunnel settings unavailable.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    };

    egui::Grid::new("tunnel_protocol_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("allowedNetwork");
            ui.label(&allowed_network);
            ui.end_row();
            ui.label("rewriteAddress");
            ui.label(&rewrite_address);
            ui.end_row();
            ui.label("rewritePort");
            ui.label(
                rewrite_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "listen port".to_owned()),
            );
            ui.end_row();
            ui.label("followRedirect");
            ui.label(if follow_redirect { "true" } else { "false" });
            ui.end_row();
            ui.label("userLevel");
            ui.label(user_level.to_string());
            ui.end_row();
        });

    ui.add_space(6.0);
    ui.strong("portMap");
    if port_map.is_empty() {
        ui.label(
            RichText::new("(empty)")
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    } else {
        egui::Grid::new("tunnel_portmap_view_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(RichText::new("local").strong());
                ui.label(RichText::new("target").strong());
                ui.end_row();
                for (local, target) in &port_map {
                    ui.label(local);
                    ui.label(target);
                    ui.end_row();
                }
            });
    }
}

fn show_protocol_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let protocol_kind = service
        .inbound_editor_session()
        .map(|s| match &s.protocol {
            InboundProtocolDraft::Vless { .. } => 0,
            InboundProtocolDraft::Trojan { .. } => 1,
            InboundProtocolDraft::Hysteria { .. } => 2,
            InboundProtocolDraft::Tunnel { .. } => 3,
        });

    let Some(kind) = protocol_kind else {
        return;
    };

    match kind {
        0 => {
            let Some(session) = service.inbound_editor_session_mut() else {
                return;
            };
            let InboundProtocolDraft::Vless { decryption, .. } = &mut session.protocol else {
                return;
            };
            let mut dec = decryption.clone();
            let mut auth = session.vlessenc_auth;
            egui::Grid::new("protocol_edit_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.label("decryption");
                    if ui.text_edit_singleline(&mut dec).changed() {
                        *decryption = dec;
                        session.dirty = true;
                    }
                    ui.end_row();

                    ui.label("encryption");
                    let encryption = session.ephemeral_client_encryption.clone();
                    show_client_field_value(ui, encryption, "vlessenc");
                    ui.end_row();

                    ui.label("vlessenc auth");
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_value(
                                &mut auth,
                                crate::xray::VlessEncAuthKind::X25519,
                                "X25519",
                            )
                            .changed()
                        {
                            session.vlessenc_auth = auth;
                        }
                        if ui
                            .selectable_value(
                                &mut auth,
                                crate::xray::VlessEncAuthKind::MlKem768,
                                "ML-KEM-768",
                            )
                            .changed()
                        {
                            session.vlessenc_auth = auth;
                        }
                    });
                    ui.end_row();
                });

            ui.add_space(6.0);
            if ui
                .add_enabled(!busy, egui::Button::new("Generate vlessenc"))
                .on_hover_text(
                    "Runs remote xray vlessenc; fills decryption + encryption in the grid above",
                )
                .clicked()
                && let Err(e) = service.start_generate_vlessenc()
            {
                service.show_status_message(e);
            }
            show_fallbacks_edit(ui, service, busy);
        }
        1 => {
            show_fallbacks_edit(ui, service, busy);
        }
        2 => {
            let version = service
                .inbound_editor_session()
                .and_then(|s| match &s.protocol {
                    InboundProtocolDraft::Hysteria { version } => Some(*version),
                    _ => None,
                })
                .unwrap_or(2);
            ui.label(format!("Hysteria version: {version} (fixed)"));
        }
        3 => {
            let _ = busy;
            show_tunnel_protocol_edit(ui, service);
        }
        _ => {}
    }
}

fn session_fallbacks_will_strip(session: &InboundEditorSession) -> bool {
    let Some(fallbacks) = session.protocol.fallbacks() else {
        return false;
    };
    if fallbacks.is_empty() {
        return false;
    }
    let transport = session
        .stream
        .method
        .unwrap_or(StreamMethod::Tcp)
        .as_wire();
    let security = session
        .security
        .as_ref()
        .map(|s| s.mode.as_wire())
        .unwrap_or("none");
    !fallbacks_transport_compatible(transport, security)
}

fn show_fallbacks_edit(ui: &mut Ui, service: &mut ApplicationService, busy: bool) {
    let will_strip = service
        .inbound_editor_session()
        .is_some_and(session_fallbacks_will_strip);

    ui.add_space(6.0);
    ui.strong("fallbacks");
    ui.label(
        RichText::new("VLESS/Trojan · TCP + TLS/Reality only. Non-empty Security ALPN required when fallbacks are set.")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );
    if will_strip {
        ui.label(
            RichText::new("Current Stream/Security is incompatible — fallbacks will be removed on Save.")
                .size(13.0)
                .color(Color32::from_rgb(200, 140, 40)),
        );
    }

    let mut dirty = false;
    {
        let Some(session) = service.inbound_editor_session_mut() else {
            return;
        };
        let Some(fallbacks) = session.protocol.fallbacks_mut() else {
            return;
        };

        let mut remove_idx: Option<usize> = None;
        for (idx, entry) in fallbacks.iter_mut().enumerate() {
            ui.add_space(4.0);
            ui.group(|ui| {
                egui::Grid::new(format!("fallback_edit_grid_{idx}"))
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("name (SNI)");
                        if ui.text_edit_singleline(&mut entry.name).changed() {
                            dirty = true;
                        }
                        ui.end_row();

                        ui.label("alpn");
                        if ui.text_edit_singleline(&mut entry.alpn).changed() {
                            dirty = true;
                        }
                        ui.end_row();

                        ui.label("path");
                        if ui
                            .text_edit_singleline(&mut entry.path)
                            .on_hover_text("Empty or must start with /")
                            .changed()
                        {
                            dirty = true;
                        }
                        ui.end_row();

                        ui.label("dest type");
                        let mut kind = entry.dest.kind();
                        ComboBox::from_id_salt(format!("fallback_dest_kind_{idx}"))
                            .selected_text(kind.label())
                            .show_ui(ui, |ui| {
                                for option in [
                                    FallbackDestKind::Port,
                                    FallbackDestKind::TcpAddr,
                                    FallbackDestKind::UnixSocket,
                                ] {
                                    if ui
                                        .selectable_label(kind == option, option.label())
                                        .clicked()
                                        && kind != option
                                    {
                                        kind = option;
                                        entry.dest = FallbackDest::empty(option);
                                        dirty = true;
                                    }
                                }
                            });
                        ui.end_row();

                        ui.label("dest");
                        match &mut entry.dest {
                            FallbackDest::Port(port) => {
                                let mut value = i64::from(*port);
                                if ui
                                    .add(egui::DragValue::new(&mut value).range(1..=65535))
                                    .changed()
                                {
                                    *port = value as u16;
                                    dirty = true;
                                }
                            }
                            FallbackDest::TcpAddr(addr) => {
                                if ui
                                    .text_edit_singleline(addr)
                                    .on_hover_text("host:port")
                                    .changed()
                                {
                                    dirty = true;
                                }
                            }
                            FallbackDest::UnixSocket(path) => {
                                if ui
                                    .text_edit_singleline(path)
                                    .on_hover_text("Absolute path or @/@ abstract")
                                    .changed()
                                {
                                    dirty = true;
                                }
                            }
                        }
                        ui.end_row();

                        ui.label("xver");
                        let mut xver = entry.xver as i64;
                        ComboBox::from_id_salt(format!("fallback_xver_{idx}"))
                            .selected_text(xver.to_string())
                            .show_ui(ui, |ui| {
                                for option in [0_i64, 1, 2] {
                                    if ui
                                        .selectable_label(xver == option, option.to_string())
                                        .clicked()
                                        && xver != option
                                    {
                                        xver = option;
                                        entry.xver = option as u64;
                                        dirty = true;
                                    }
                                }
                            });
                        ui.end_row();
                    });

                if ui
                    .add_enabled(!busy, egui::Button::new("Remove"))
                    .clicked()
                {
                    remove_idx = Some(idx);
                }
            });
        }

        if let Some(idx) = remove_idx {
            fallbacks.remove(idx);
            dirty = true;
        }

        if ui
            .add_enabled(!busy, egui::Button::new("Add fallback"))
            .clicked()
        {
            fallbacks.push(FallbackObject::default());
            dirty = true;
        }
    }

    if dirty && let Some(session) = service.inbound_editor_session_mut() {
        session.dirty = true;
    }
}

fn show_tunnel_protocol_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    if !matches!(session.protocol, InboundProtocolDraft::Tunnel { .. }) {
        return;
    }

    let mut dirty = false;
    {
        let InboundProtocolDraft::Tunnel {
            allowed_network,
            rewrite_address,
            rewrite_port,
            port_map,
            follow_redirect,
            user_level,
        } = &mut session.protocol
        else {
            return;
        };

        let mut network = allowed_network.clone();
        let mut address = rewrite_address.clone();
        let mut port_text = rewrite_port.map(|p| p.to_string()).unwrap_or_default();
        let mut level = *user_level as i64;
        let mut follow = *follow_redirect;

        egui::Grid::new("tunnel_protocol_edit_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label("allowedNetwork");
                ComboBox::from_id_salt("tunnel_allowed_network")
                    .selected_text(&network)
                    .show_ui(ui, |ui| {
                        for option in TUNNEL_NETWORKS {
                            if ui.selectable_label(network == *option, *option).clicked() {
                                network = (*option).to_owned();
                            }
                        }
                    });
                ui.end_row();

                ui.label("rewriteAddress");
                if ui.text_edit_singleline(&mut address).changed() {
                    dirty = true;
                }
                ui.end_row();

                ui.label("rewritePort");
                if ui
                    .text_edit_singleline(&mut port_text)
                    .on_hover_text("Empty or 0 = use listen port")
                    .changed()
                {
                    dirty = true;
                }
                ui.end_row();

                ui.label("followRedirect");
                if ui.checkbox(&mut follow, "").changed() {
                    dirty = true;
                }
                ui.end_row();

                ui.label("userLevel");
                if ui
                    .add(egui::DragValue::new(&mut level).range(0..=u32::MAX as i64))
                    .changed()
                {
                    dirty = true;
                }
                ui.end_row();
            });

        if network != *allowed_network {
            *allowed_network = network;
            dirty = true;
        }
        *rewrite_address = address;
        *rewrite_port = port_text.trim().parse::<u64>().ok().filter(|p| *p != 0);
        *follow_redirect = follow;
        *user_level = level.max(0) as u64;

        ui.add_space(8.0);
        ui.strong("portMap");
        ui.label(
            RichText::new("Target forms: host:port, :port, or host:")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );

        let mut remove_idx: Option<usize> = None;
        egui::Grid::new("tunnel_portmap_edit_grid")
            .num_columns(3)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                ui.label(RichText::new("local").strong());
                ui.label(RichText::new("target").strong());
                ui.label("");
                ui.end_row();

                for (idx, (local, target)) in port_map.iter_mut().enumerate() {
                    let mut local_edit = local.clone();
                    let mut target_edit = target.clone();
                    if ui.text_edit_singleline(&mut local_edit).changed() {
                        *local = local_edit;
                        dirty = true;
                    }
                    let target_resp = ui.text_edit_singleline(&mut target_edit);
                    if target_resp.changed() {
                        *target = target_edit.clone();
                        dirty = true;
                    }
                    if validate_port_map_target(target.trim()).is_err() && !target.trim().is_empty()
                    {
                        target_resp.on_hover_text("Expected host:port, :port, or host:");
                    }
                    if ui.small_button("Del").clicked() {
                        remove_idx = Some(idx);
                    }
                    ui.end_row();
                }
            });
        if let Some(idx) = remove_idx {
            port_map.remove(idx);
            dirty = true;
        }

        let new_id = egui::Id::new("tunnel_portmap_new");
        let (mut new_local, mut new_target) = ui.ctx().data(|d| {
            d.get_temp::<(String, String)>(new_id)
                .unwrap_or_default()
        });
        ui.horizontal(|ui| {
            ui.label("Add");
            ui.add(
                egui::TextEdit::singleline(&mut new_local)
                    .desired_width(80.0)
                    .hint_text("local"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut new_target)
                    .desired_width(160.0)
                    .hint_text("host:port"),
            );
            let can_add = !new_local.trim().is_empty()
                && validate_port_map_target(new_target.trim()).is_ok()
                && !port_map
                    .iter()
                    .any(|(local, _)| local.trim() == new_local.trim());
            if ui
                .add_enabled(can_add, egui::Button::new("Add mapping"))
                .clicked()
            {
                port_map.push((new_local.trim().to_owned(), new_target.trim().to_owned()));
                port_map.sort_by(|a, b| a.0.cmp(&b.0));
                dirty = true;
                new_local.clear();
                new_target.clear();
            }
        });
        ui.ctx()
            .data_mut(|d| d.insert_temp(new_id, (new_local, new_target)));
    }

    if dirty {
        session.dirty = true;
    }
}

// ─── Stream tab (IB-L3) ──────────────────────────────────────────────────────

fn show_stream_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    if !shell_ok {
        ui.label(
            RichText::new("Shell editing is not enabled for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!busy, egui::Button::new("Save"))
                .clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
            && let Err(e) = service.begin_edit_inbound_shell(row.index)
        {
            service.show_status_message(e);
        }
    });
    ui.add_space(8.0);

    if editing {
        show_stream_edit(ui, service);
    } else {
        show_stream_readonly(ui, service, row);
    }
}

fn show_stream_readonly(ui: &mut Ui, service: &ApplicationService, row: &InboundSummary) {
    let draft = service
        .loaded_config()
        .editable()
        .and_then(|e| e.sections().inbounds().get(row.index))
        .map(|inbound| parse_inbound_stream(inbound.value()))
        .unwrap_or_default();

    if let Some(other) = draft.other_method.as_deref() {
        ui.label(
            RichText::new(format!(
                "Transport method `{other}` is not editable in IB-L3; preserved on save."
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    let method = draft.method.unwrap_or(StreamMethod::Tcp);
    egui::Grid::new("stream_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("method");
            ui.label(method.label());
            ui.end_row();
            match method {
                StreamMethod::Tcp => {
                    ui.label("acceptProxyProtocol");
                    ui.label(bool_label(draft.tcp.accept_proxy_protocol));
                    ui.end_row();
                }
                StreamMethod::Xhttp => {
                    ui.label("path");
                    ui.label(if draft.xhttp.path().is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.xhttp.path()
                    });
                    ui.end_row();
                    ui.label("mode");
                    ui.label(if draft.xhttp.mode().is_empty() {
                        XHTTP_MODE_AUTO
                    } else {
                        draft.xhttp.mode()
                    });
                    ui.end_row();
                    ui.label("host");
                    ui.label(if draft.xhttp.host().is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.xhttp.host()
                    });
                    ui.end_row();
                    ui.label("xPaddingBytes");
                    ui.label(format_xhttp_range(draft.xhttp.core.x_padding_bytes));
                    ui.end_row();
                    ui.label("noSSEHeader");
                    ui.label(bool_label(draft.xhttp.core.no_sse_header));
                    ui.end_row();
                    ui.label("scMaxBufferedPosts");
                    ui.label(draft.xhttp.core.sc_max_buffered_posts.to_string());
                    ui.end_row();
                    ui.label("downloadSettings");
                    ui.label(if draft.xhttp.download.is_some() {
                        "enabled"
                    } else {
                        "—"
                    });
                    ui.end_row();
                }
                StreamMethod::Grpc => {
                    ui.label("serviceName");
                    ui.label(if draft.grpc.service_name.is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.grpc.service_name.as_str()
                    });
                    ui.end_row();
                    ui.label("multiMode");
                    ui.label(bool_label(draft.grpc.multi_mode));
                    ui.end_row();
                }
                StreamMethod::Ws => {
                    ui.label("path");
                    ui.label(if draft.ws.path.is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.ws.path.as_str()
                    });
                    ui.end_row();
                    ui.label("host");
                    ui.label(if draft.ws.host.is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.ws.host.as_str()
                    });
                    ui.end_row();
                    ui.label("acceptProxyProtocol");
                    ui.label(bool_label(draft.ws.accept_proxy_protocol));
                    ui.end_row();
                    ui.label("ed");
                    ui.label(
                        draft
                            .ws
                            .ed
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    );
                    ui.end_row();
                }
                StreamMethod::Mkcp => {
                    ui.label("mtu");
                    ui.label(draft.kcp.mtu.to_string());
                    ui.end_row();
                    ui.label("tti");
                    ui.label(format!("{} ms", draft.kcp.tti));
                    ui.end_row();
                    ui.label("uplinkCapacity");
                    ui.label(format!("{} MB/s", draft.kcp.uplink_capacity));
                    ui.end_row();
                    ui.label("downlinkCapacity");
                    ui.label(format!("{} MB/s", draft.kcp.downlink_capacity));
                    ui.end_row();
                    ui.label("congestion");
                    ui.label(bool_label(draft.kcp.congestion));
                    ui.end_row();
                    ui.label("readBufferSize");
                    ui.label(format!("{} MB", draft.kcp.read_buffer_size));
                    ui.end_row();
                    ui.label("writeBufferSize");
                    ui.label(format!("{} MB", draft.kcp.write_buffer_size));
                    ui.end_row();
                }
                StreamMethod::Hysteria => {
                    ui.label("hysteria version");
                    ui.label(
                        draft
                            .hysteria
                            .version
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    );
                    ui.end_row();
                }
            }
        });
}

fn show_stream_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };

    let protocol = match &session.protocol {
        InboundProtocolDraft::Vless { .. } => "vless",
        InboundProtocolDraft::Trojan { .. } => "trojan",
        InboundProtocolDraft::Hysteria { .. } => "hysteria",
        InboundProtocolDraft::Tunnel { .. } => "tunnel",
    };
    let vision_active = session.vision_active;
    let allowed = selectable_stream_methods(protocol, vision_active);

    if let Some(other) = session.stream.other_method.clone() {
        ui.label(
            RichText::new(format!(
                "Transport method `{other}` is not editable in IB-L3; preserved on save."
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    let draft_method = session.stream.method;
    let display =
        coerce_display_stream_method(draft_method, &allowed).unwrap_or(StreamMethod::Tcp);
    if draft_method.is_some() && Some(display) != draft_method {
        ui.label(
            RichText::new(format!(
                "Current transport `{}` is not allowed with this protocol/Vision; showing `{}` until you pick an allowed method (draft unchanged until you edit).",
                draft_method.unwrap().as_wire(),
                display.as_wire()
            ))
            .size(13.0)
            .color(Color32::from_rgb(160, 120, 40)),
        );
        ui.add_space(4.0);
    }

    let mut selected_method: Option<StreamMethod> = None;
    ui.horizontal(|ui| {
        ui.label("method");
        for &method in &allowed {
            let mut selected = display;
            if ui
                .selectable_value(&mut selected, method, method.label())
                .changed()
            {
                selected_method = Some(method);
            }
        }
    });
    if let Some(method) = selected_method {
        let previous = session.stream.method;
        session.stream.method = Some(method);
        session.stream.other_method = None;
        if method == StreamMethod::Mkcp && previous != Some(StreamMethod::Mkcp) {
            session.stream.kcp = KcpStreamSettings::default();
        }
        if method == StreamMethod::Xhttp && previous != Some(StreamMethod::Xhttp) {
            session.stream.xhttp = XhttpStreamSettings::default();
        }
        if let Some(security) = session.security.as_mut() {
            let coerced =
                coerce_security_mode_for_transport(protocol, method.as_wire(), security.mode);
            if coerced != security.mode {
                security.mode = coerced;
            }
        }
        session.dirty = true;
    }
    ui.add_space(6.0);

    match session.stream.method.unwrap_or(StreamMethod::Tcp) {
        StreamMethod::Tcp => {
            let mut accept = session.stream.tcp.accept_proxy_protocol;
            if ui
                .checkbox(&mut accept, "acceptProxyProtocol")
                .changed()
            {
                session.stream.tcp.accept_proxy_protocol = accept;
                session.dirty = true;
            }
        }
        StreamMethod::Xhttp => {
            let mut dirty = false;
            egui::ScrollArea::vertical()
                .id_salt("stream_xhttp_scroll")
                .show(ui, |ui| {
                    ui.heading("Basic");
                    egui::Grid::new("stream_xhttp_basic_grid")
                        .num_columns(2)
                        .spacing([16.0, 6.0])
                        .show(ui, |ui| {
                            dirty |= xhttp_edit_core_basic(ui, &mut session.stream.xhttp.core, "main");
                        });
                    ui.add_space(8.0);
                    ui.heading("Headers");
                    dirty |= xhttp_edit_headers(ui, &mut session.stream.xhttp.core.headers, "main");
                    ui.add_space(8.0);
                    if xhttp_spoiler_header(ui, "padding", "Padding / SSE / gRPC", false) {
                        egui::Grid::new("stream_xhttp_padding_grid")
                            .num_columns(2)
                            .spacing([16.0, 6.0])
                            .show(ui, |ui| {
                                dirty |= xhttp_edit_core_padding(ui, &mut session.stream.xhttp.core, "main");
                            });
                    }
                    ui.add_space(8.0);
                    if xhttp_spoiler_header(ui, "sc", "Packet / stream knobs", false) {
                        egui::Grid::new("stream_xhttp_sc_grid")
                            .num_columns(2)
                            .spacing([16.0, 6.0])
                            .show(ui, |ui| {
                                dirty |= xhttp_edit_core_sc(ui, &mut session.stream.xhttp.core, "main");
                            });
                    }
                    ui.add_space(8.0);
                    if xhttp_spoiler_header(ui, "placement", "Placement / obfuscation", false) {
                        egui::Grid::new("stream_xhttp_place_grid")
                            .num_columns(2)
                            .spacing([16.0, 6.0])
                            .show(ui, |ui| {
                                dirty |= xhttp_edit_core_placement(ui, &mut session.stream.xhttp.core, "main");
                            });
                    }
                    ui.add_space(8.0);
                    if xhttp_spoiler_header(ui, "xmux", "XMUX", false) {
                        egui::Grid::new("stream_xhttp_xmux_grid")
                            .num_columns(2)
                            .spacing([16.0, 6.0])
                            .show(ui, |ui| {
                                dirty |= xhttp_edit_xmux(ui, &mut session.stream.xhttp.core.xmux, "main");
                            });
                    }
                    ui.add_space(8.0);
                    ui.heading("downloadSettings");
                    let mut enabled = session.stream.xhttp.download.is_some();
                    if ui.checkbox(&mut enabled, "Enable downloadSettings").changed() {
                        dirty = true;
                        if enabled {
                            let mut dl = XhttpDownloadDraft::default();
                            dl.xhttp.path = session.stream.xhttp.core.path.clone();
                            session.stream.xhttp.download = Some(dl);
                        } else {
                            session.stream.xhttp.download = None;
                        }
                    }
                    if let Some(download) = session.stream.xhttp.download.as_mut() {
                        egui::Grid::new("stream_xhttp_download_grid")
                            .num_columns(2)
                            .spacing([16.0, 6.0])
                            .show(ui, |ui| {
                                dirty |= xhttp_edit_download(ui, download);
                            });
                        ui.add_space(4.0);
                        ui.label(RichText::new("Nested xhttp (download leg)").strong());
                        egui::Grid::new("stream_xhttp_download_xhttp_grid")
                            .num_columns(2)
                            .spacing([16.0, 6.0])
                            .show(ui, |ui| {
                                dirty |= xhttp_edit_core_basic(ui, &mut download.xhttp, "dl");
                                dirty |= xhttp_edit_core_padding(ui, &mut download.xhttp, "dl");
                                dirty |= xhttp_edit_core_sc(ui, &mut download.xhttp, "dl");
                            });
                    }
                });
            if dirty {
                session.dirty = true;
            }
        }
        StreamMethod::Grpc => {
            let mut service_name = session.stream.grpc.service_name.clone();
            let mut multi = session.stream.grpc.multi_mode;
            egui::Grid::new("stream_grpc_edit_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.label("serviceName");
                    if ui.text_edit_singleline(&mut service_name).changed() {
                        session.stream.grpc.service_name = service_name;
                        session.dirty = true;
                    }
                    ui.end_row();
                    ui.label("multiMode");
                    if ui.checkbox(&mut multi, "").changed() {
                        session.stream.grpc.multi_mode = multi;
                        session.dirty = true;
                    }
                    ui.end_row();
                });
        }
        StreamMethod::Ws => {
            let mut path = session.stream.ws.path.clone();
            let mut host = session.stream.ws.host.clone();
            let mut accept = session.stream.ws.accept_proxy_protocol;
            let mut ed_text = session
                .stream
                .ws
                .ed
                .map(|v| v.to_string())
                .unwrap_or_default();
            egui::Grid::new("stream_ws_edit_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.label("path");
                    if ui.text_edit_singleline(&mut path).changed() {
                        session.stream.ws.path = path;
                        session.dirty = true;
                    }
                    ui.end_row();
                    ui.label("host");
                    if ui.text_edit_singleline(&mut host).changed() {
                        session.stream.ws.host = host;
                        session.dirty = true;
                    }
                    ui.end_row();
                    ui.label("acceptProxyProtocol");
                    if ui.checkbox(&mut accept, "").changed() {
                        session.stream.ws.accept_proxy_protocol = accept;
                        session.dirty = true;
                    }
                    ui.end_row();
                    ui.label("ed");
                    if ui.text_edit_singleline(&mut ed_text).changed() {
                        let trimmed = ed_text.trim();
                        session.stream.ws.ed = if trimmed.is_empty() {
                            None
                        } else {
                            trimmed.parse::<u64>().ok()
                        };
                        session.dirty = true;
                    }
                    ui.end_row();
                });
        }
        StreamMethod::Mkcp => {
            ui.label(
                RichText::new(format!(
                    "mKCP uses UDP — ensure firewall allows the listen port. Legacy header/seed removed by Xray; use FinalMask separately. Ranges: mtu {KCP_MTU_MIN}–{KCP_MTU_MAX}, tti {KCP_TTI_MIN}–{KCP_TTI_MAX} ms."
                ))
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
            );
            ui.add_space(4.0);
            let mut mtu = session.stream.kcp.mtu.to_string();
            let mut tti = session.stream.kcp.tti.to_string();
            let mut uplink = session.stream.kcp.uplink_capacity.to_string();
            let mut downlink = session.stream.kcp.downlink_capacity.to_string();
            let mut read_buf = session.stream.kcp.read_buffer_size.to_string();
            let mut write_buf = session.stream.kcp.write_buffer_size.to_string();
            let congestion = session.stream.kcp.congestion;
            egui::Grid::new("stream_mkcp_edit_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.label("mtu");
                    if ui.text_edit_singleline(&mut mtu).changed() {
                        if let Ok(v) = mtu.trim().parse::<u64>() {
                            session.stream.kcp.mtu = v;
                            session.dirty = true;
                        }
                    }
                    ui.end_row();
                    ui.label("tti (ms)");
                    if ui.text_edit_singleline(&mut tti).changed() {
                        if let Ok(v) = tti.trim().parse::<u64>() {
                            session.stream.kcp.tti = v;
                            session.dirty = true;
                        }
                    }
                    ui.end_row();
                    ui.label("uplinkCapacity (MB/s)");
                    if ui.text_edit_singleline(&mut uplink).changed() {
                        if let Ok(v) = uplink.trim().parse::<u64>() {
                            session.stream.kcp.uplink_capacity = v;
                            session.dirty = true;
                        }
                    }
                    ui.end_row();
                    ui.label("downlinkCapacity (MB/s)");
                    if ui.text_edit_singleline(&mut downlink).changed() {
                        if let Ok(v) = downlink.trim().parse::<u64>() {
                            session.stream.kcp.downlink_capacity = v;
                            session.dirty = true;
                        }
                    }
                    ui.end_row();
                    ui.label("congestion");
                    ComboBox::from_id_salt("stream_mkcp_congestion")
                        .selected_text(if congestion { "true" } else { "false" })
                        .width(120.0)
                        .show_ui(ui, |ui| {
                            for (label, value) in [("false", false), ("true", true)] {
                                if ui.selectable_label(congestion == value, label).clicked()
                                    && congestion != value
                                {
                                    session.stream.kcp.congestion = value;
                                    session.dirty = true;
                                }
                            }
                        });
                    ui.end_row();
                    ui.label("readBufferSize (MB)");
                    if ui.text_edit_singleline(&mut read_buf).changed() {
                        if let Ok(v) = read_buf.trim().parse::<u64>() {
                            session.stream.kcp.read_buffer_size = v;
                            session.dirty = true;
                        }
                    }
                    ui.end_row();
                    ui.label("writeBufferSize (MB)");
                    if ui.text_edit_singleline(&mut write_buf).changed() {
                        if let Ok(v) = write_buf.trim().parse::<u64>() {
                            session.stream.kcp.write_buffer_size = v;
                            session.dirty = true;
                        }
                    }
                    ui.end_row();
                });
        }
        StreamMethod::Hysteria => {
            ui.label(
                RichText::new("Hysteria transport (locked). Congestion via finalmask.quicParams.")
                    .size(13.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
            let mut congestion = session.stream.quic_params.congestion.clone();
            let mut up = session.stream.quic_params.brutal_up.clone();
            let mut down = session.stream.quic_params.brutal_down.clone();
            egui::Grid::new("stream_hy_quic_edit_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.label("congestion");
                    if ui.text_edit_singleline(&mut congestion).changed() {
                        session.stream.quic_params.congestion = congestion;
                        session.stream.write_quic_params = true;
                        session.dirty = true;
                    }
                    ui.end_row();
                    ui.label("brutalUp");
                    if ui.text_edit_singleline(&mut up).changed() {
                        session.stream.quic_params.brutal_up = up;
                        session.stream.write_quic_params = true;
                        session.dirty = true;
                    }
                    ui.end_row();
                    ui.label("brutalDown");
                    if ui.text_edit_singleline(&mut down).changed() {
                        session.stream.quic_params.brutal_down = down;
                        session.stream.write_quic_params = true;
                        session.dirty = true;
                    }
                    ui.end_row();
                });
        }
    }

    if session.stream.method != Some(StreamMethod::Hysteria) && matches!(protocol, "vless" | "trojan")
    {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        ui.strong("FinalMask");
        ui.label(
            RichText::new(
                "Advanced streamSettings.finalmask masking layers. Order matters — the first entry is the innermost layer.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
        let reality_conflict = matches!(
            session.security.as_ref().map(|s| s.mode),
            Some(InboundSecurityMode::Reality)
        ) && !session.stream.finalmask_tcp.is_empty();
        if reality_conflict {
            ui.label(
                RichText::new(
                    "Reality is incompatible with FinalMask tcp layers; Save will be blocked (G4).",
                )
                .color(Color32::from_rgb(220, 160, 60)),
            );
        }
        ui.add_space(4.0);
        ui.label(RichText::new("tcp").strong());
        if show_finalmask_layers_edit(ui, "tcp", TCP_FINALMASK_TYPES, &mut session.stream.finalmask_tcp) {
            session.stream.write_finalmask_tcp = true;
            session.dirty = true;
        }
        ui.add_space(6.0);
        ui.label(RichText::new("udp").strong());
        if show_finalmask_layers_edit(ui, "udp", UDP_FINALMASK_TYPES, &mut session.stream.finalmask_udp) {
            session.stream.write_finalmask_udp = true;
            session.dirty = true;
        }
    }
}

/// Editor for one `finalmask.tcp` / `finalmask.udp` layer chain; returns true when the layer
/// list changed. `id_suffix` distinguishes tcp/udp widget ids.
fn show_finalmask_layers_edit(
    ui: &mut Ui,
    id_suffix: &str,
    type_presets: &[&str],
    layers: &mut Vec<FinalMaskLayerDraft>,
) -> bool {
    let mut dirty = false;
    let mut remove_idx: Option<usize> = None;
    let mut move_up_idx: Option<usize> = None;
    let mut move_down_idx: Option<usize> = None;

    for idx in 0..layers.len() {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(format!("layer[{idx}]"));
                let mut layer_type = layers[idx].layer_type.clone();
                egui::ComboBox::from_id_salt(format!("finalmask_{id_suffix}_type_{idx}"))
                    .selected_text(if layer_type.is_empty() {
                        "(pick type)"
                    } else {
                        layer_type.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in type_presets {
                            ui.selectable_value(&mut layer_type, preset.to_owned(), preset);
                        }
                    });
                if ui.text_edit_singleline(&mut layer_type).changed() {
                    layers[idx].layer_type = layer_type.clone();
                    dirty = true;
                } else if layer_type != layers[idx].layer_type {
                    layers[idx].layer_type = layer_type;
                    dirty = true;
                }
                if ui.small_button("Up").on_hover_text("Move up").clicked() && idx > 0 {
                    move_up_idx = Some(idx);
                }
                if ui.small_button("Down").on_hover_text("Move down").clicked() && idx + 1 < layers.len() {
                    move_down_idx = Some(idx);
                }
                if ui.button("Remove").clicked() {
                    remove_idx = Some(idx);
                }
            });

            let mut settings_text =
                serde_json::to_string_pretty(&layers[idx].settings).unwrap_or_default();
            ui.label(
                RichText::new("settings (JSON object)")
                    .size(12.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
            if resizable_multiline(
                ui,
                &mut settings_text,
                4,
                &format!("finalmask_{id_suffix}_settings_{idx}"),
            )
            .changed()
            {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&settings_text) {
                    if value.is_object() {
                        layers[idx].settings = value;
                        dirty = true;
                    }
                }
            }
        });
    }

    if let Some(idx) = remove_idx {
        layers.remove(idx);
        dirty = true;
    } else if let Some(idx) = move_up_idx {
        layers.swap(idx, idx - 1);
        dirty = true;
    } else if let Some(idx) = move_down_idx {
        layers.swap(idx, idx + 1);
        dirty = true;
    }

    ui.add_space(4.0);
    if ui.button(format!("Add {id_suffix} layer")).clicked() {
        layers.push(FinalMaskLayerDraft::default());
        dirty = true;
    }

    dirty
}

// ─── Security tab (VLESS + Trojan; Reality keygen) ───────────────────────────

fn show_security_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    if !shell_ok {
        ui.label(
            RichText::new("Shell editing is not enabled for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        return;
    }

    let is_security_proto = matches!(
        row.protocol.as_deref().and_then(InboundClientProtocol::from_wire),
        Some(
            InboundClientProtocol::Vless
                | InboundClientProtocol::Trojan
                | InboundClientProtocol::Hysteria
        )
    );
    if !is_security_proto {
        ui.label(
            RichText::new("Security tab is available for VLESS, Trojan, and Hysteria inbounds.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            let alpn_blocked = service
                .inbound_editor_session()
                .is_some_and(session_fallbacks_missing_alpn);
            let save = ui
                .add_enabled(!busy && !alpn_blocked, egui::Button::new("Save"))
                .on_disabled_hover_text(if alpn_blocked {
                    "Fallbacks require a non-empty ALPN list in the Security tab"
                } else {
                    ""
                });
            if save.clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
            ui.add_space(8.0);
            show_security_keygen_actions(ui, service, busy);
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
            && let Err(e) = service.begin_edit_inbound_shell(row.index)
        {
            service.show_status_message(e);
        }
    });
    ui.add_space(8.0);

    if editing {
        show_security_edit(ui, service);
    } else {
        show_security_readonly(ui, service, row);
    }
}

fn security_mode_is_reality(service: &ApplicationService) -> bool {
    service
        .inbound_editor_session()
        .and_then(|s| s.security.as_ref())
        .is_some_and(|sec| matches!(sec.mode, InboundSecurityMode::Reality))
}

fn show_security_keygen_actions(ui: &mut Ui, service: &mut ApplicationService, busy: bool) {
    if !security_mode_is_reality(service) {
        return;
    }
    if ui
        .add_enabled(!busy, egui::Button::new("Generate x25519"))
        .on_hover_text("Run `xray x25519` on the remote host to generate a key pair")
        .clicked()
        && let Err(e) = service.start_generate_x25519()
    {
        service.show_status_message(e);
    }
    if ui
        .add_enabled(!busy, egui::Button::new("Generate mldsa65"))
        .on_hover_text("Run `xray mldsa65` on the remote host to generate a seed/verify pair")
        .clicked()
        && let Err(e) = service.start_generate_mldsa65()
    {
        service.show_status_message(e);
    }
}

fn session_fallbacks_missing_alpn(session: &InboundEditorSession) -> bool {
    let has_fallbacks = session
        .protocol
        .fallbacks()
        .is_some_and(|f| !f.is_empty());
    if !has_fallbacks {
        return false;
    }
    let Some(security) = session.security.as_ref() else {
        return true;
    };
    if !matches!(
        security.mode,
        InboundSecurityMode::Tls | InboundSecurityMode::Reality
    ) {
        return true;
    }
    security.active_alpn().is_empty()
}

fn show_security_readonly(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
) {
    let editable = service.loaded_config().editable();
    let security = editable
        .and_then(|e| e.sections().inbounds().get(row.index))
        .map(|inbound| crate::xray::parse_inbound_security(inbound.value()))
        .unwrap_or_default();

    if security.security_unknown {
        ui.label(
            RichText::new(format!(
                "Unknown security '{}': read-only. Choose none, tls, or reality before Save.",
                security
                    .unknown_security_wire
                    .as_deref()
                    .unwrap_or("?")
            ))
            .color(Color32::from_rgb(220, 160, 60)),
        );
        return;
    }

    let mode_label = match security.mode {
        InboundSecurityMode::None => "none",
        InboundSecurityMode::Tls => "tls",
        InboundSecurityMode::Reality => "reality",
    };

    let public_key = resolved_client_value(
        service,
        Some(row),
        |s| s.ephemeral_public_key.clone(),
        |m| m.public_key.clone(),
    );
    let mldsa65_verify = resolved_client_value(
        service,
        Some(row),
        |s| s.ephemeral_mldsa65_verify.clone(),
        |m| m.mldsa65_verify.clone(),
    );

    egui::Grid::new("security_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("security");
            ui.label(mode_label);
            ui.end_row();
            if matches!(security.mode, InboundSecurityMode::Tls) {
                let tls = &security.tls;
                for (idx, cert) in tls.certificates.iter().enumerate() {
                    ui.label(format!("certificate[{idx}]"));
                    let usage = if cert.usage.is_empty() {
                        "encipherment"
                    } else {
                        cert.usage.as_str()
                    };
                    let material = if !cert.certificate_file.trim().is_empty() {
                        format!("{} / {}", cert.certificate_file, cert.key_file)
                    } else if !cert.certificate.is_empty() {
                        "PEM".to_owned()
                    } else {
                        "—".to_owned()
                    };
                    ui.label(format!("{usage} · {material}"));
                    ui.end_row();
                }
                if !tls.alpn.is_empty() {
                    ui.label("alpn");
                    ui.label(tls.alpn.join(", "));
                    ui.end_row();
                }
                if !tls.server_name.is_empty() {
                    ui.label("serverName");
                    ui.label(&tls.server_name);
                    ui.end_row();
                }
                if !tls.min_version.is_empty() || !tls.max_version.is_empty() {
                    ui.label("TLS version");
                    ui.label(format!(
                        "{} .. {}",
                        if tls.min_version.is_empty() {
                            "—"
                        } else {
                            tls.min_version.as_str()
                        },
                        if tls.max_version.is_empty() {
                            "—"
                        } else {
                            tls.max_version.as_str()
                        }
                    ));
                    ui.end_row();
                }
                if !tls.fingerprint.is_empty() {
                    ui.label("fingerprint");
                    ui.label(&tls.fingerprint);
                    ui.end_row();
                }
                if tls.enable_ech {
                    ui.label("ECH");
                    ui.label("enabled");
                    ui.end_row();
                }
            }
            if matches!(security.mode, InboundSecurityMode::Reality) {
                ui.label("destination");
                ui.label(&security.reality.destination);
                ui.end_row();
                ui.label("serverNames");
                ui.label(security.reality.server_names.join(", "));
                ui.end_row();
                if !security.reality.alpn.is_empty() {
                    ui.label("alpn");
                    ui.label(security.reality.alpn.join(", "));
                    ui.end_row();
                }
                ui.label("shortIds");
                ui.label(security.reality.short_ids.join(", "));
                ui.end_row();
                ui.label("privateKey");
                ui.label("••••••••");
                ui.end_row();
                ui.label("publicKey");
                show_client_field_value(ui, public_key, "x25519");
                ui.end_row();
                if security.reality.mldsa65_seed.is_some() || mldsa65_verify.is_some() {
                    ui.label("mldsa65Seed");
                    ui.label("••••••••");
                    ui.end_row();
                    ui.label("mldsa65Verify");
                    show_client_field_value(ui, mldsa65_verify, "mldsa65");
                    ui.end_row();
                }
                if security.reality.show {
                    ui.label("show");
                    ui.label("true");
                    ui.end_row();
                }
                if let Some(xver) = security.reality.xver {
                    ui.label("xver");
                    ui.label(xver.to_string());
                    ui.end_row();
                }
                if !security.reality.min_client_ver.is_empty()
                    || !security.reality.max_client_ver.is_empty()
                {
                    ui.label("client version");
                    ui.label(format!(
                        "{} .. {}",
                        if security.reality.min_client_ver.is_empty() {
                            "—"
                        } else {
                            security.reality.min_client_ver.as_str()
                        },
                        if security.reality.max_client_ver.is_empty() {
                            "—"
                        } else {
                            security.reality.max_client_ver.as_str()
                        }
                    ));
                    ui.end_row();
                }
                if let Some(max_time_diff) = security.reality.max_time_diff {
                    ui.label("maxTimeDiff");
                    ui.label(format!("{max_time_diff} ms"));
                    ui.end_row();
                }
                if security.reality.limit_fallback_upload.is_some()
                    || security.reality.limit_fallback_download.is_some()
                {
                    ui.label("rate limiting");
                    ui.label(format!(
                        "upload {} / download {}",
                        if security.reality.limit_fallback_upload.is_some() {
                            "on"
                        } else {
                            "off"
                        },
                        if security.reality.limit_fallback_download.is_some() {
                            "on"
                        } else {
                            "off"
                        }
                    ));
                    ui.end_row();
                }
            }
        });
}

fn show_security_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    if session.security.is_none() {
        ui.label(
            RichText::new("Security draft not available for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    let is_trojan = matches!(session.protocol, crate::app::InboundProtocolDraft::Trojan { .. });
    let is_hysteria = matches!(
        session.protocol,
        crate::app::InboundProtocolDraft::Hysteria { .. }
    );
    let method_wire = session
        .stream
        .method
        .map(|m| m.as_wire())
        .or(session.stream.other_method.as_deref())
        .unwrap_or("tcp")
        .to_owned();
    let protocol = if is_trojan {
        "trojan"
    } else if is_hysteria {
        "hysteria"
    } else {
        "vless"
    };
    let allowed_modes = allowed_security_modes(protocol, &method_wire);
    let has_fallbacks = session
        .protocol
        .fallbacks()
        .is_some_and(|f| !f.is_empty());
    let ephemeral_public_key = session.ephemeral_public_key.clone();
    let ephemeral_mldsa65_verify = session.ephemeral_mldsa65_verify.clone();

    let dirty = {
        let security = session.security.as_mut().expect("checked above");

        if security.security_unknown {
            ui.label(
                RichText::new(format!(
                    "Unknown security '{}'. Select a known mode to edit and Save.",
                    security
                        .unknown_security_wire
                        .as_deref()
                        .unwrap_or("?")
                ))
                .color(Color32::from_rgb(220, 160, 60)),
            );
            let mut applied = false;
            ui.horizontal(|ui| {
                ui.label("security");
                let mut mode = InboundSecurityMode::None;
                egui::ComboBox::from_id_salt("inbound_security_mode_unknown")
                    .selected_text("(pick mode)")
                    .show_ui(ui, |ui| {
                        for &allowed in &allowed_modes {
                            let label = match allowed {
                                InboundSecurityMode::None => "none",
                                InboundSecurityMode::Tls => "tls",
                                InboundSecurityMode::Reality => "reality",
                            };
                            ui.selectable_value(&mut mode, allowed, label);
                        }
                    });
                if ui.button("Apply mode").clicked() {
                    security.mode = mode;
                    security.security_unknown = false;
                    security.unknown_security_wire = None;
                    applied = true;
                }
            });
            applied
        } else {
            let mut dirty = false;
            ui.horizontal(|ui| {
                ui.label("security");
                let mut mode = security.mode;
                if !allowed_modes.contains(&mode) {
                    if let Some(first) = allowed_modes.first() {
                        mode = *first;
                    }
                }
                egui::ComboBox::from_id_salt("inbound_security_mode")
                    .selected_text(match mode {
                        InboundSecurityMode::None => "none",
                        InboundSecurityMode::Tls => "tls",
                        InboundSecurityMode::Reality => "reality",
                    })
                    .show_ui(ui, |ui| {
                        for &allowed in &allowed_modes {
                            let label = match allowed {
                                InboundSecurityMode::None => "none",
                                InboundSecurityMode::Tls => "tls",
                                InboundSecurityMode::Reality => "reality",
                            };
                            ui.selectable_value(&mut mode, allowed, label);
                        }
                    });
                if mode != security.mode {
                    security.mode = mode;
                    dirty = true;
                }
            });
            ui.add_space(4.0);

            if has_fallbacks
                && matches!(
                    security.mode,
                    InboundSecurityMode::Tls | InboundSecurityMode::Reality
                )
            {
                ui.label(
                    RichText::new(
                        "Fallbacks require a non-empty ALPN list on this Security tab. Save is blocked until ALPN is set.",
                    )
                    .color(Color32::from_rgb(220, 160, 60)),
                );
                ui.add_space(4.0);
            }

            match security.mode {
                InboundSecurityMode::None => {}
                InboundSecurityMode::Tls => {
                    dirty |= show_tls_settings_edit(ui, &mut security.tls);
                }
                InboundSecurityMode::Reality => {
                    dirty |= show_reality_settings_edit(
                        ui,
                        &mut security.reality,
                        ephemeral_public_key.as_deref(),
                        ephemeral_mldsa65_verify.as_deref(),
                    );
                }
            }
            dirty
        }
    };

    if dirty {
        session.dirty = true;
    }
}

fn show_tls_settings_edit(ui: &mut Ui, tls: &mut TlsSettingsDraft) -> bool {
    let mut dirty = false;
    let mut server_name = tls.server_name.clone();
    let mut verify_by_name = tls.verify_peer_cert_by_name.clone();
    let mut min_version = tls.min_version.clone();
    let mut max_version = tls.max_version.clone();
    let mut cipher_suites = tls.cipher_suites.clone();
    let mut fingerprint = tls.fingerprint.clone();
    let mut pinned = tls.pinned_peer_cert_sha256.clone();
    let mut master_key_log = tls.master_key_log.clone();
    let mut ech_server_keys = tls.ech_server_keys.clone();
    let mut ech_config_list = tls.ech_config_list.clone();
    let mut ech_sockopt_text = tls
        .ech_sockopt
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
        .unwrap_or_default();

    if tls.certificates.is_empty() {
        tls.certificates.push(CertificateDraft::default());
        dirty = true;
    }

    ui.strong("certificates");
    ui.label(
        RichText::new("Each entry needs file paths or PEM (key optional when usage is verify).")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );

    let mut remove_idx: Option<usize> = None;
    for idx in 0..tls.certificates.len() {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.label(RichText::new(format!("certificate[{idx}]")).strong());
            if show_certificate_draft_edit(ui, idx, &mut tls.certificates[idx]) {
                dirty = true;
            }
            let can_remove = tls.certificates.len() > 1;
            if ui
                .add_enabled(can_remove, egui::Button::new("Remove"))
                .on_hover_text(if can_remove {
                    "Remove this certificate entry"
                } else {
                    "At least one certificate entry is required"
                })
                .clicked()
            {
                remove_idx = Some(idx);
            }
        });
    }
    if let Some(idx) = remove_idx {
        if tls.certificates.len() > 1 {
            tls.certificates.remove(idx);
            dirty = true;
        }
    }
    if ui.button("Add certificate").clicked() {
        tls.certificates.push(CertificateDraft::default());
        dirty = true;
    }

    ui.add_space(8.0);
    ui.strong("tlsSettings");

    egui::Grid::new("tls_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("alpn");
            if string_tag_multi_select(ui, "tls_alpn", &mut tls.alpn, ALPN_PRESETS) {
                dirty = true;
            }
            ui.end_row();

            ui.label("serverName");
            if ui.text_edit_singleline(&mut server_name).changed() {
                tls.server_name = server_name.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("verifyPeerCertByName");
            if ui.text_edit_singleline(&mut verify_by_name).changed() {
                tls.verify_peer_cert_by_name = verify_by_name.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("rejectUnknownSni");
            if ui.checkbox(&mut tls.reject_unknown_sni, "").changed() {
                dirty = true;
            }
            ui.end_row();

            ui.label("allowInsecure");
            if ui.checkbox(&mut tls.allow_insecure, "").changed() {
                dirty = true;
            }
            ui.end_row();

            ui.label("minVersion");
            {
                let before = min_version.clone();
                optional_string_combo(ui, "tls_min_ver", &mut min_version, TLS_VERSION_PRESETS);
                if min_version != before {
                    tls.min_version = min_version.clone();
                    dirty = true;
                }
            }
            ui.end_row();

            ui.label("maxVersion");
            {
                let before = max_version.clone();
                optional_string_combo(ui, "tls_max_ver", &mut max_version, TLS_VERSION_PRESETS);
                if max_version != before {
                    tls.max_version = max_version.clone();
                    dirty = true;
                }
            }
            ui.end_row();

            ui.label("cipherSuites");
            if resizable_multiline(ui, &mut cipher_suites, 2, "tls_ciphers").changed() {
                tls.cipher_suites = cipher_suites.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("disableSystemRoot");
            if ui.checkbox(&mut tls.disable_system_root, "").changed() {
                dirty = true;
            }
            ui.end_row();

            ui.label("enableSessionResumption");
            if ui
                .checkbox(&mut tls.enable_session_resumption, "")
                .changed()
            {
                dirty = true;
            }
            ui.end_row();

            ui.label("fingerprint");
            {
                let before = fingerprint.clone();
                optional_string_combo(ui, "tls_fp", &mut fingerprint, FINGERPRINT_PRESETS);
                if fingerprint != before {
                    tls.fingerprint = fingerprint.clone();
                    dirty = true;
                }
            }
            ui.end_row();

            ui.label("pinnedPeerCertSha256");
            if ui.text_edit_singleline(&mut pinned).changed() {
                tls.pinned_peer_cert_sha256 = pinned.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("curvePreferences");
            if string_tag_multi_select(ui, "tls_curves", &mut tls.curve_preferences, CURVE_PRESETS)
            {
                dirty = true;
            }
            ui.end_row();

            ui.label("masterKeyLog");
            if resizable_multiline(ui, &mut master_key_log, 2, "tls_master_log").changed() {
                tls.master_key_log = master_key_log.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("Enable ECH");
            if ui.checkbox(&mut tls.enable_ech, "").changed() {
                if !tls.enable_ech {
                    tls.ech_server_keys.clear();
                    tls.ech_config_list.clear();
                    tls.ech_sockopt = None;
                    ech_server_keys.clear();
                    ech_config_list.clear();
                    ech_sockopt_text.clear();
                }
                dirty = true;
            }
            ui.end_row();
        });

    if tls.enable_ech {
        egui::CollapsingHeader::new("ECH settings")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("tls_ech_grid")
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("echServerKeys");
                        if resizable_multiline(ui, &mut ech_server_keys, 4, "tls_ech_server")
                            .changed()
                        {
                            tls.ech_server_keys = ech_server_keys.clone();
                            dirty = true;
                        }
                        ui.end_row();

                        ui.label("echConfigList");
                        if resizable_multiline(ui, &mut ech_config_list, 4, "tls_ech_config")
                            .changed()
                        {
                            tls.ech_config_list = ech_config_list.clone();
                            dirty = true;
                        }
                        ui.end_row();

                        ui.label("echSockopt (JSON object)");
                        if resizable_multiline(ui, &mut ech_sockopt_text, 5, "tls_ech_sockopt")
                            .changed()
                        {
                            let trimmed = ech_sockopt_text.trim();
                            if trimmed.is_empty() {
                                tls.ech_sockopt = None;
                                dirty = true;
                            } else if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
                            {
                                if value.is_object() {
                                    tls.ech_sockopt = Some(value);
                                    dirty = true;
                                }
                            }
                        }
                        ui.end_row();
                    });
            });
    }

    dirty
}

fn show_certificate_draft_edit(
    ui: &mut Ui,
    idx: usize,
    cert: &mut CertificateDraft,
) -> bool {
    let mut dirty = false;
    let mut cert_file = cert.certificate_file.clone();
    let mut key_file = cert.key_file.clone();
    let mut usage = if cert.usage.is_empty() {
        "encipherment".to_owned()
    } else {
        cert.usage.clone()
    };
    let mut ocsp_text = cert
        .ocsp_stapling
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mut cert_pem = cert.certificate.join("\n");
    let mut key_pem = cert.key.join("\n");

    egui::Grid::new(format!("tls_cert_edit_grid_{idx}"))
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("certificateFile");
            if ui.text_edit_singleline(&mut cert_file).changed() {
                cert.certificate_file = cert_file.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("keyFile");
            if ui.text_edit_singleline(&mut key_file).changed() {
                cert.key_file = key_file.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("certificate (PEM)");
            if resizable_multiline(
                ui,
                &mut cert_pem,
                6,
                &format!("tls_cert_pem_{idx}"),
            )
            .changed()
            {
                cert.certificate = lines_to_vec(&cert_pem);
                dirty = true;
            }
            ui.end_row();

            ui.label("key (PEM)");
            if resizable_multiline(ui, &mut key_pem, 6, &format!("tls_key_pem_{idx}")).changed()
            {
                cert.key = lines_to_vec(&key_pem);
                dirty = true;
            }
            ui.end_row();

            ui.label("usage");
            {
                let before = usage.clone();
                egui::ComboBox::from_id_salt(format!("tls_cert_usage_{idx}"))
                    .selected_text(usage.as_str())
                    .show_ui(ui, |ui| {
                        for preset in CERT_USAGE_PRESETS {
                            ui.selectable_value(&mut usage, (*preset).to_owned(), *preset);
                        }
                    });
                if usage != before {
                    cert.usage = usage.clone();
                    if usage != "issue" {
                        cert.build_chain = false;
                    }
                    dirty = true;
                }
            }
            ui.end_row();

            if usage == "issue" {
                ui.label("buildChain");
                if ui.checkbox(&mut cert.build_chain, "").changed() {
                    dirty = true;
                }
                ui.end_row();
            }

            ui.label("oneTimeLoading");
            if ui.checkbox(&mut cert.one_time_loading, "").changed() {
                dirty = true;
            }
            ui.end_row();

            ui.label("ocspStapling (seconds)");
            if ui.text_edit_singleline(&mut ocsp_text).changed() {
                cert.ocsp_stapling = ocsp_text.trim().parse().ok().filter(|&v| v != 0);
                dirty = true;
            }
            ui.end_row();
        });

    dirty
}

fn show_reality_settings_edit(
    ui: &mut Ui,
    reality: &mut crate::xray::RealitySettingsDraft,
    public_key: Option<&str>,
    mldsa65_verify: Option<&str>,
) -> bool {
    let mut dirty = false;
    let mut dest = reality.destination.clone();
    let mut server_names = reality.server_names.join("\n");
    let mut private_key = reality.private_key.clone();
    let mut short_ids = reality.short_ids.join("\n");
    let mut mldsa65_seed = reality.mldsa65_seed.clone().unwrap_or_default();
    let mut min_client_ver = reality.min_client_ver.clone();
    let mut max_client_ver = reality.max_client_ver.clone();
    let mut max_time_diff = reality
        .max_time_diff
        .map(|v| v.to_string())
        .unwrap_or_default();

    egui::Grid::new("reality_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("destination (host:port)");
            if ui.text_edit_singleline(&mut dest).changed() {
                reality.destination = dest.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("show");
            if ui.checkbox(&mut reality.show, "").changed() {
                dirty = true;
            }
            ui.end_row();

            ui.label("xver");
            let mut xver = reality.xver.unwrap_or(0);
            egui::ComboBox::from_id_salt("reality_xver")
                .selected_text(xver.to_string())
                .show_ui(ui, |ui| {
                    for option in [0u64, 1, 2] {
                        ui.selectable_value(&mut xver, option, option.to_string());
                    }
                });
            if xver != reality.xver.unwrap_or(0) {
                reality.xver = if xver == 0 { None } else { Some(xver) };
                dirty = true;
            }
            ui.end_row();

            ui.label("serverNames (one per line)");
            if ui
                .add(egui::TextEdit::multiline(&mut server_names).desired_rows(3))
                .changed()
            {
                reality.server_names = lines_to_vec(&server_names);
                dirty = true;
            }
            ui.end_row();

            ui.label("alpn");
            if string_tag_multi_select(ui, "reality_alpn", &mut reality.alpn, ALPN_PRESETS) {
                dirty = true;
            }
            ui.end_row();

            ui.label("privateKey");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut private_key)
                        .password(true)
                        .hint_text("generated by x25519 or entered manually"),
                )
                .changed()
            {
                reality.private_key = private_key.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("publicKey");
            show_client_field_value(ui, public_key.map(str::to_owned), "x25519");
            ui.end_row();

            ui.label("shortIds (one per line)");
            if ui
                .add(egui::TextEdit::multiline(&mut short_ids).desired_rows(3))
                .changed()
            {
                reality.short_ids = lines_to_vec(&short_ids);
                dirty = true;
            }
            ui.end_row();

            ui.label("mldsa65Seed");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut mldsa65_seed)
                        .password(true)
                        .hint_text("optional; generated by mldsa65"),
                )
                .changed()
            {
                reality.mldsa65_seed = if mldsa65_seed.trim().is_empty() {
                    None
                } else {
                    Some(mldsa65_seed.clone())
                };
                dirty = true;
            }
            ui.end_row();

            let show_mldsa65_verify = reality
                .mldsa65_seed
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
                || mldsa65_verify.is_some_and(|s| !s.trim().is_empty());
            if show_mldsa65_verify {
                ui.label("mldsa65Verify");
                show_client_field_value(ui, mldsa65_verify.map(str::to_owned), "mldsa65");
                ui.end_row();
            }

            ui.label("minClientVer");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut min_client_ver)
                        .hint_text("optional; x.y.z"),
                )
                .changed()
            {
                reality.min_client_ver = min_client_ver.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("maxClientVer");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut max_client_ver)
                        .hint_text("optional; x.y.z"),
                )
                .changed()
            {
                reality.max_client_ver = max_client_ver.clone();
                dirty = true;
            }
            ui.end_row();

            ui.label("maxTimeDiff (ms)");
            if ui
                .add(
                    egui::TextEdit::singleline(&mut max_time_diff)
                        .hint_text("optional; milliseconds"),
                )
                .changed()
            {
                let trimmed = max_time_diff.trim();
                if trimmed.is_empty() {
                    reality.max_time_diff = None;
                    dirty = true;
                } else if let Ok(value) = trimmed.parse::<u64>() {
                    reality.max_time_diff = Some(value);
                    dirty = true;
                }
            }
            ui.end_row();
        });

    if show_reality_limit_fallback_edit(ui, "upload", &mut reality.limit_fallback_upload) {
        dirty = true;
    }
    if show_reality_limit_fallback_edit(ui, "download", &mut reality.limit_fallback_download) {
        dirty = true;
    }

    dirty
}

/// Editor for one `limitFallbackUpload` / `limitFallbackDownload` sub-object; returns true when
/// the draft changed.
fn show_reality_limit_fallback_edit(
    ui: &mut Ui,
    label: &str,
    limit: &mut Option<crate::xray::RealityLimitFallbackDraft>,
) -> bool {
    let mut dirty = false;
    let mut enabled = limit.is_some();
    ui.horizontal(|ui| {
        if ui
            .checkbox(&mut enabled, format!("Limit fallback {label}"))
            .changed()
        {
            *limit = if enabled {
                Some(crate::xray::RealityLimitFallbackDraft::default())
            } else {
                None
            };
            dirty = true;
        }
    });

    if let Some(limit) = limit.as_mut() {
        let mut after_bytes = limit.after_bytes.map(|v| v.to_string()).unwrap_or_default();
        let mut bytes_per_sec = limit
            .bytes_per_sec
            .map(|v| v.to_string())
            .unwrap_or_default();
        let mut burst_bytes_per_sec = limit
            .burst_bytes_per_sec
            .map(|v| v.to_string())
            .unwrap_or_default();

        egui::Grid::new(format!("reality_limit_fallback_{label}_grid"))
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label("afterBytes");
                if ui.text_edit_singleline(&mut after_bytes).changed() {
                    limit.after_bytes = after_bytes.trim().parse::<u64>().ok();
                    dirty = true;
                }
                ui.end_row();

                ui.label("bytesPerSec");
                if ui.text_edit_singleline(&mut bytes_per_sec).changed() {
                    limit.bytes_per_sec = bytes_per_sec.trim().parse::<u64>().ok();
                    dirty = true;
                }
                ui.end_row();

                ui.label("burstBytesPerSec");
                if ui.text_edit_singleline(&mut burst_bytes_per_sec).changed() {
                    limit.burst_bytes_per_sec = burst_bytes_per_sec.trim().parse::<u64>().ok();
                    dirty = true;
                }
                ui.end_row();
            });
    }

    dirty
}

fn lines_to_vec(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn resizable_multiline(
    ui: &mut Ui,
    text: &mut String,
    rows: usize,
    id: &str,
) -> egui::Response {
    egui::ScrollArea::vertical()
        .id_salt(id)
        .max_height(160.0)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(text)
                    .desired_rows(rows)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            )
        })
        .inner
}

fn optional_string_combo(
    ui: &mut Ui,
    id: &str,
    value: &mut String,
    presets: &[&str],
) -> bool {
    let mut dirty = false;
    let display = if value.is_empty() {
        "(default)".to_owned()
    } else {
        value.clone()
    };
    egui::ComboBox::from_id_salt(id)
        .selected_text(display)
        .show_ui(ui, |ui| {
            if ui
                .selectable_label(value.is_empty(), "(default)")
                .clicked()
            {
                value.clear();
                dirty = true;
            }
            for preset in presets {
                if ui
                    .selectable_label(value == *preset, *preset)
                    .clicked()
                {
                    *value = (*preset).to_owned();
                    dirty = true;
                }
            }
        });
    if ui
        .add(
            egui::TextEdit::singleline(value)
                .desired_width(140.0)
                .hint_text("custom"),
        )
        .changed()
    {
        dirty = true;
    }
    dirty
}

/// Multi-select from presets; selected values shown as removable tags.
fn string_tag_multi_select(
    ui: &mut Ui,
    id: &str,
    selected: &mut Vec<String>,
    presets: &[&str],
) -> bool {
    let mut dirty = false;
    ui.vertical(|ui| {
        ui.horizontal_wrapped(|ui| {
            let mut remove_idx = None;
            for (idx, tag) in selected.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(tag.as_str())
                            .size(12.0)
                            .color(Color32::from_rgb(220, 220, 230)),
                    );
                    if ui.small_button("×").clicked() {
                        remove_idx = Some(idx);
                    }
                });
            }
            if let Some(idx) = remove_idx {
                selected.remove(idx);
                dirty = true;
            }
        });

        let available: Vec<&str> = presets
            .iter()
            .copied()
            .filter(|p| !selected.iter().any(|s| s == p))
            .collect();
        let mut to_add: Option<String> = None;
        egui::ComboBox::from_id_salt(id)
            .selected_text("Add…")
            .show_ui(ui, |ui| {
                for preset in &available {
                    if ui.selectable_label(false, *preset).clicked() {
                        to_add = Some((*preset).to_owned());
                    }
                }
                for tag in selected.iter() {
                    if !presets.contains(&tag.as_str()) {
                        ui.label(
                            RichText::new(format!("custom: {tag}"))
                                .size(11.0)
                                .color(Color32::from_rgb(140, 140, 140)),
                        );
                    }
                }
            });
        if let Some(value) = to_add {
            if !selected.iter().any(|s| s == &value) {
                selected.push(value);
                dirty = true;
            }
        }
    });
    dirty
}

// ─── Sniffing tab ─────────────────────────────────────────────────────────────

fn show_sniffing_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    if !shell_ok {
        ui.label(
            RichText::new("Shell editing is not available for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!busy, egui::Button::new("Save"))
                .clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
            && let Err(e) = service.begin_edit_inbound_shell(row.index)
        {
            service.show_status_message(e);
        }
    });
    ui.add_space(8.0);

    if editing {
        show_sniffing_edit_session(ui, service);
    } else if let Some(settings) = service.inbound_sniffing_view(row.index) {
        show_sniffing_readonly(ui, &settings);
    }
}

fn show_sniffing_readonly(ui: &mut Ui, settings: &SniffingSettings) {
    egui::Grid::new("inbound_sniffing_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("enabled");
            ui.label(bool_label(settings.enabled.unwrap_or(false)));
            ui.end_row();
            ui.label("destOverride");
            ui.label(format_dest_override(settings));
            ui.end_row();
            ui.label("metadataOnly");
            ui.label(bool_label(settings.metadata_only.unwrap_or(false)));
            ui.end_row();
            ui.label("routeOnly");
            ui.label(bool_label(settings.route_only.unwrap_or(false)));
            ui.end_row();
        });
    if !settings.unknown_dest_override.is_empty() {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!(
                "Preserved unknown destOverride: {}",
                settings.unknown_dest_override.join(", ")
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
    if !settings.extras.is_empty() {
        ui.label(
            RichText::new(format!(
                "Preserved sniffing extras: {}",
                settings.extras.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_sniffing_edit_session(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    let settings = &mut session.sniffing;

    let mut enabled = settings.enabled.unwrap_or(false);
    let mut metadata_only = settings.metadata_only.unwrap_or(false);
    let mut route_only = settings.route_only.unwrap_or(false);

    if ui.checkbox(&mut enabled, "enabled").changed() {
        settings.enabled = Some(enabled);
        session.dirty = true;
    }

    ui.label("destOverride");
    ui.horizontal(|ui| {
        for token in KNOWN_DEST_OVERRIDE {
            let mut checked = settings.dest_override.iter().any(|t| t == *token);
            if ui.checkbox(&mut checked, *token).changed() {
                if checked {
                    if !settings.dest_override.iter().any(|t| t == *token) {
                        settings.dest_override.push((*token).to_owned());
                    }
                } else {
                    settings.dest_override.retain(|t| t != *token);
                }
                session.dirty = true;
            }
        }
    });
    if !settings.unknown_dest_override.is_empty() {
        ui.label(
            RichText::new(format!(
                "Preserved: {}",
                settings.unknown_dest_override.join(", ")
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }

    if ui.checkbox(&mut metadata_only, "metadataOnly").changed() {
        settings.metadata_only = Some(metadata_only);
        session.dirty = true;
    }
    if ui.checkbox(&mut route_only, "routeOnly").changed() {
        settings.route_only = Some(route_only);
        session.dirty = true;
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn format_dest_override(settings: &SniffingSettings) -> String {
    let mut parts = settings.dest_override.clone();
    parts.extend(settings.unknown_dest_override.iter().cloned());
    if parts.is_empty() {
        MISSING_FIELD.to_owned()
    } else {
        parts.join(", ")
    }
}

fn detail_tab_id() -> egui::Id {
    egui::Id::new("inbounds_detail_tab")
}

fn focus_general_id() -> egui::Id {
    egui::Id::new("inbounds_focus_general")
}

fn detail_tab(ui: &Ui) -> InboundDetailTab {
    ui.ctx()
        .data(|data| data.get_temp::<InboundDetailTab>(detail_tab_id()))
        .unwrap_or_default()
}

fn set_detail_tab(ui: &Ui, tab: InboundDetailTab) {
    ui.ctx().data_mut(|data| {
        data.insert_temp(detail_tab_id(), tab);
    });
}

fn request_focus_general(ui: &Ui) {
    ui.ctx().data_mut(|data| {
        data.insert_temp(focus_general_id(), true);
    });
}

fn take_focus_general(ui: &Ui) -> bool {
    ui.ctx().data_mut(|data| {
        data.remove_temp::<bool>(focus_general_id()).unwrap_or(false)
    })
}

fn sortable_header(
    ui: &mut Ui,
    service: &mut ApplicationService,
    label: &str,
    column: InboundsSortColumn,
    active: InboundsSortColumn,
) {
    let sort = service.inbounds_sort();
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
        service.set_inbounds_sort_column(column);
    }
}

fn cell_with_menu(
    ui: &mut Ui,
    service: &mut ApplicationService,
    row: &InboundSummary,
    text: &str,
) -> bool {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    let clicked = response.clicked();
    if clicked {
        service.set_selected_users_inbound(row.index);
    }
    show_inbound_context_menu(&response, service, row);
    clicked
}

/// IB-L5: redacted structural JSON diff stored on the editor session.
fn show_json_diff_preview(ui: &mut Ui, service: &ApplicationService) {
    let Some(entries) = service
        .inbound_editor_session()
        .and_then(|s| s.diff_preview.clone())
    else {
        return;
    };

    let title = if entries.is_empty() {
        "JSON changes (none)".to_owned()
    } else {
        format!("JSON changes ({})", entries.len())
    };
    egui::CollapsingHeader::new(title)
        .default_open(true)
        .show(ui, |ui| {
            if entries.is_empty() {
                ui.label(
                    RichText::new("No differences vs the loaded file.")
                        .size(13.0)
                        .color(Color32::from_rgb(140, 140, 140)),
                );
                return;
            }
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for entry in &entries {
                        let color = match entry.kind {
                            crate::xray::JsonDiffKind::Added => Color32::from_rgb(40, 160, 80),
                            crate::xray::JsonDiffKind::Removed => Color32::from_rgb(200, 60, 60),
                            crate::xray::JsonDiffKind::Changed => Color32::from_rgb(210, 170, 40),
                        };
                        let detail = match entry.kind {
                            crate::xray::JsonDiffKind::Added => {
                                format!(
                                    "{} {} = {}",
                                    entry.kind.label(),
                                    entry.path,
                                    entry.after.as_deref().unwrap_or("?")
                                )
                            }
                            crate::xray::JsonDiffKind::Removed => {
                                format!(
                                    "{} {} (was {})",
                                    entry.kind.label(),
                                    entry.path,
                                    entry.before.as_deref().unwrap_or("?")
                                )
                            }
                            crate::xray::JsonDiffKind::Changed => {
                                format!(
                                    "{} {} : {} → {}",
                                    entry.kind.label(),
                                    entry.path,
                                    entry.before.as_deref().unwrap_or("?"),
                                    entry.after.as_deref().unwrap_or("?")
                                )
                            }
                        };
                        ui.label(RichText::new(detail).size(12.0).color(color).monospace());
                    }
                });
        });
}

fn show_inbound_context_menu(
    response: &egui::Response,
    service: &mut ApplicationService,
    row: &InboundSummary,
) {
    response.context_menu(|ui| {
        if ui.button("Copy tag").clicked() {
            let text = row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }
        if ui.button("Copy port").clicked() {
            let text = row
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| MISSING_FIELD.to_owned());
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

        let shell_ok = service.inbound_shell_edit_enabled(row.index);
        let busy = service.is_inbound_shell_mutation_busy();
        if ui
            .add_enabled(shell_ok && !busy, egui::Button::new("Edit"))
            .on_disabled_hover_text(
                "Shell edit is available for VLESS, Trojan, Hysteria, and Tunnel only",
            )
            .clicked()
        {
            request_focus_general(ui);
            if let Err(error) = service.begin_edit_inbound_shell(row.index) {
                service.show_status_message(error);
            }
            ui.close();
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Delete"))
            .on_disabled_hover_text("Delete requires an idle connection")
            .clicked()
        {
            set_pending_inbound_delete(
                ui,
                PendingInboundDelete {
                    index: row.index,
                    tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    unsupported: !shell_ok,
                    error: None,
                },
            );
            ui.close();
        }
        if ui
            .add_enabled(shell_ok && !busy, egui::Button::new("Duplicate"))
            .on_disabled_hover_text(
                "Duplicate is available for VLESS, Trojan, Hysteria, and Tunnel only",
            )
            .clicked()
        {
            if let Err(error) = service.start_duplicate_inbound(row.index) {
                service.show_status_message(error);
            }
            ui.close();
        }
    });
}

#[derive(Clone)]
struct PendingInboundDelete {
    index: usize,
    tag: String,
    /// Protocol is not shell-editable (stronger confirm copy).
    unsupported: bool,
    error: Option<String>,
}

fn pending_inbound_delete_id() -> egui::Id {
    egui::Id::new("inbounds_pending_delete")
}

fn pending_inbound_delete(ui: &Ui) -> Option<PendingInboundDelete> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingInboundDelete>(pending_inbound_delete_id()))
}

fn set_pending_inbound_delete(ui: &Ui, pending: PendingInboundDelete) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_inbound_delete_id(), pending));
}

fn clear_pending_inbound_delete(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingInboundDelete>(pending_inbound_delete_id()));
}

fn show_delete_inbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(pending) = pending_inbound_delete(ui) else {
        return;
    };
    let mut open = true;
    egui::Window::new("Delete inbound")
        .collapsible(false)
        .resizable(false)
        .default_width(380.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(format!(
                    "Delete inbound «{}»? This removes it from the remote configuration.",
                    pending.tag
                ))
                .size(14.0),
            );
            if pending.unsupported {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "This protocol is not editable in Feldjäger. Deletion cannot be undone from the UI (restore from backup if needed).",
                    )
                    .size(13.0)
                    .color(Color32::from_rgb(160, 120, 40)),
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
                let busy = service.is_inbound_shell_mutation_busy();
                if ui
                    .add_enabled(!busy, egui::Button::new("Delete"))
                    .clicked()
                {
                    match service.start_delete_inbound(pending.index) {
                        Ok(()) => clear_pending_inbound_delete(ui),
                        Err(message) => {
                            set_pending_inbound_delete(
                                ui,
                                PendingInboundDelete {
                                    error: Some(message),
                                    ..pending.clone()
                                },
                            );
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    clear_pending_inbound_delete(ui);
                }
            });
        });

    if !open {
        clear_pending_inbound_delete(ui);
    }
}

// ─── XHTTP Stream helpers (Wave C3) ──────────────────────────────────────────

/// Section heading with a spoiler-style disclosure arrow on the right of the title.
/// Returns whether the body should currently be drawn (open state).
fn xhttp_spoiler_header(ui: &mut Ui, id_salt: &str, title: &str, default_open: bool) -> bool {
    let id = ui.make_persistent_id(("xhttp_spoiler", id_salt));
    let mut state =
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, default_open);
    let openness = state.openness(ui.ctx());

    ui.horizontal(|ui| {
        ui.heading(title);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let size = egui::Vec2::splat(ui.spacing().icon_width);
            let (rect, _) = ui.allocate_exact_size(size, Sense::click());
            let response = ui.interact(rect, id, Sense::click());
            egui::collapsing_header::paint_default_icon(
                ui,
                openness,
                &response.clone().with_new_rect(rect),
            );
            if response.clicked() {
                state.toggle(ui);
            }
        });
    });

    state.store(ui.ctx());
    state.is_open()
}

fn format_xhttp_range(range: XhttpRange) -> String {
    if range.from == range.to {
        range.from.to_string()
    } else {
        format!("{}-{}", range.from, range.to)
    }
}

fn xhttp_edit_core_basic(ui: &mut Ui, core: &mut XhttpCoreSettings, salt: &str) -> bool {
    let mut dirty = false;
    ui.label("host");
    let mut host = core.host.clone();
    if ui.text_edit_singleline(&mut host).changed() {
        core.host = host;
        dirty = true;
    }
    ui.end_row();

    ui.label("path");
    let mut path = core.path.clone();
    if ui.text_edit_singleline(&mut path).changed() {
        core.path = if path.trim().is_empty() {
            XHTTP_PATH_DEFAULT.to_owned()
        } else {
            path
        };
        dirty = true;
    }
    ui.end_row();

    ui.label("mode");
    dirty |= xhttp_string_combo(
        ui,
        &format!("stream_xhttp_mode_{salt}"),
        &mut core.mode,
        XHTTP_MODES,
        XHTTP_MODE_AUTO,
    );
    ui.end_row();
    dirty
}

fn xhttp_edit_core_padding(ui: &mut Ui, core: &mut XhttpCoreSettings, salt: &str) -> bool {
    let mut dirty = false;
    ui.label("xPaddingBytes");
    dirty |= xhttp_range_editors(ui, &mut core.x_padding_bytes, &format!("pad_{salt}"));
    ui.end_row();

    ui.label("noGRPCHeader");
    dirty |= xhttp_bool_combo(ui, &format!("no_grpc_{salt}"), &mut core.no_grpc_header);
    ui.end_row();

    ui.label("noSSEHeader");
    dirty |= xhttp_bool_combo(ui, &format!("no_sse_{salt}"), &mut core.no_sse_header);
    ui.end_row();
    dirty
}

fn xhttp_edit_core_sc(ui: &mut Ui, core: &mut XhttpCoreSettings, salt: &str) -> bool {
    let mut dirty = false;
    ui.label("scMaxEachPostBytes");
    dirty |= xhttp_range_editors(ui, &mut core.sc_max_each_post_bytes, &format!("sc_each_{salt}"));
    ui.end_row();

    ui.label("scMinPostsIntervalMs");
    dirty |= xhttp_range_editors(
        ui,
        &mut core.sc_min_posts_interval_ms,
        &format!("sc_min_{salt}"),
    );
    ui.end_row();

    ui.label("scMaxBufferedPosts");
    let mut buffered = core.sc_max_buffered_posts.to_string();
    if ui.text_edit_singleline(&mut buffered).changed() {
        if let Ok(v) = buffered.trim().parse::<i64>() {
            core.sc_max_buffered_posts = v;
            dirty = true;
        }
    }
    ui.end_row();

    ui.label("scStreamUpServerSecs");
    dirty |= xhttp_range_editors(
        ui,
        &mut core.sc_stream_up_server_secs,
        &format!("sc_stream_{salt}"),
    );
    ui.end_row();

    ui.label("serverMaxHeaderBytes");
    let mut header_bytes = core.server_max_header_bytes.to_string();
    if ui.text_edit_singleline(&mut header_bytes).changed() {
        if let Ok(v) = header_bytes.trim().parse::<i64>() {
            core.server_max_header_bytes = v;
            dirty = true;
        }
    }
    ui.end_row();
    dirty
}

fn xhttp_edit_core_placement(ui: &mut Ui, core: &mut XhttpCoreSettings, salt: &str) -> bool {
    let mut dirty = false;
    ui.label("xPaddingObfsMode");
    dirty |= xhttp_bool_combo(ui, &format!("obfs_{salt}"), &mut core.x_padding_obfs_mode);
    ui.end_row();

    ui.label("xPaddingPlacement");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("pad_place_{salt}"),
        &mut core.x_padding_placement,
        XHTTP_PLACEMENTS,
    );
    ui.end_row();

    ui.label("xPaddingMethod");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("pad_method_{salt}"),
        &mut core.x_padding_method,
        XHTTP_PADDING_METHODS,
    );
    ui.end_row();

    ui.label("xPaddingKey");
    let mut key = core.x_padding_key.clone();
    if ui.text_edit_singleline(&mut key).changed() {
        core.x_padding_key = key;
        dirty = true;
    }
    ui.end_row();

    ui.label("xPaddingHeader");
    let mut header = core.x_padding_header.clone();
    if ui.text_edit_singleline(&mut header).changed() {
        core.x_padding_header = header;
        dirty = true;
    }
    ui.end_row();

    ui.label("uplinkHTTPMethod");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("uplink_method_{salt}"),
        &mut core.uplink_http_method,
        XHTTP_UPLINK_METHODS,
    );
    ui.end_row();

    ui.label("sessionIDPlacement");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("sid_place_{salt}"),
        &mut core.session_id_placement,
        XHTTP_PLACEMENTS,
    );
    ui.end_row();

    ui.label("sessionIDKey");
    let mut sid_key = core.session_id_key.clone();
    if ui.text_edit_singleline(&mut sid_key).changed() {
        core.session_id_key = sid_key;
        dirty = true;
    }
    ui.end_row();

    ui.label("seqPlacement");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("seq_place_{salt}"),
        &mut core.seq_placement,
        XHTTP_PLACEMENTS,
    );
    ui.end_row();

    ui.label("seqKey");
    let mut seq_key = core.seq_key.clone();
    if ui.text_edit_singleline(&mut seq_key).changed() {
        core.seq_key = seq_key;
        dirty = true;
    }
    ui.end_row();

    ui.label("uplinkDataPlacement");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("up_place_{salt}"),
        &mut core.uplink_data_placement,
        XHTTP_PLACEMENTS,
    );
    ui.end_row();

    ui.label("uplinkDataKey");
    let mut up_key = core.uplink_data_key.clone();
    if ui.text_edit_singleline(&mut up_key).changed() {
        core.uplink_data_key = up_key;
        dirty = true;
    }
    ui.end_row();

    ui.label("uplinkChunkSize");
    dirty |= xhttp_range_editors(ui, &mut core.uplink_chunk_size, &format!("chunk_{salt}"));
    ui.end_row();

    ui.label("sessionIDTable");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("sid_table_{salt}"),
        &mut core.session_id_table,
        XHTTP_SESSION_ID_TABLES,
    );
    ui.end_row();

    ui.label("sessionIDLength");
    dirty |= xhttp_range_editors(ui, &mut core.session_id_length, &format!("sid_len_{salt}"));
    ui.end_row();
    dirty
}

fn xhttp_edit_xmux(
    ui: &mut Ui,
    xmux: &mut crate::xray::XmuxDraft,
    salt: &str,
) -> bool {
    let mut dirty = false;
    ui.label("maxConcurrency");
    dirty |= xhttp_range_editors(ui, &mut xmux.max_concurrency, &format!("xmux_conc_{salt}"));
    ui.end_row();
    ui.label("maxConnections");
    dirty |= xhttp_range_editors(ui, &mut xmux.max_connections, &format!("xmux_conn_{salt}"));
    ui.end_row();
    ui.label("cMaxReuseTimes");
    dirty |= xhttp_range_editors(ui, &mut xmux.c_max_reuse_times, &format!("xmux_reuse_{salt}"));
    ui.end_row();
    ui.label("hMaxRequestTimes");
    dirty |= xhttp_range_editors(ui, &mut xmux.h_max_request_times, &format!("xmux_req_{salt}"));
    ui.end_row();
    ui.label("hMaxReusableSecs");
    dirty |= xhttp_range_editors(ui, &mut xmux.h_max_reusable_secs, &format!("xmux_secs_{salt}"));
    ui.end_row();
    ui.label("hKeepAlivePeriod");
    let mut keep = xmux.h_keep_alive_period.to_string();
    if ui.text_edit_singleline(&mut keep).changed() {
        if let Ok(v) = keep.trim().parse::<i64>() {
            xmux.h_keep_alive_period = v;
            dirty = true;
        }
    }
    ui.end_row();
    dirty
}

fn xhttp_edit_download(ui: &mut Ui, download: &mut XhttpDownloadDraft) -> bool {
    let mut dirty = false;
    ui.label("address");
    let mut address = download.address.clone();
    if ui.text_edit_singleline(&mut address).changed() {
        download.address = address;
        dirty = true;
    }
    ui.end_row();

    ui.label("port");
    let mut port = download.port.to_string();
    if ui.text_edit_singleline(&mut port).changed() {
        if let Ok(v) = port.trim().parse::<u64>() {
            download.port = v;
            dirty = true;
        }
    }
    ui.end_row();

    ui.label("network");
    ui.label("xhttp");
    ui.end_row();

    ui.label("security");
    dirty |= xhttp_string_combo(
        ui,
        "stream_xhttp_dl_security",
        &mut download.security,
        XHTTP_DOWNLOAD_SECURITIES,
        "tls",
    );
    ui.end_row();

    ui.label("serverName");
    let mut sni = download.server_name.clone();
    if ui.text_edit_singleline(&mut sni).changed() {
        download.server_name = sni;
        dirty = true;
    }
    ui.end_row();
    dirty
}

fn xhttp_edit_headers(ui: &mut Ui, headers: &mut Vec<(String, String)>, salt: &str) -> bool {
    let mut dirty = false;
    let mut remove_at = None;
    for (idx, (key, value)) in headers.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            let mut k = key.clone();
            let mut v = value.clone();
            if ui
                .add(egui::TextEdit::singleline(&mut k).desired_width(120.0).hint_text("key"))
                .changed()
            {
                *key = k;
                dirty = true;
            }
            if ui
                .add(egui::TextEdit::singleline(&mut v).desired_width(180.0).hint_text("value"))
                .changed()
            {
                *value = v;
                dirty = true;
            }
            if ui.button("−").clicked() {
                remove_at = Some(idx);
            }
        });
    }
    if let Some(idx) = remove_at {
        headers.remove(idx);
        dirty = true;
    }
    if ui
        .button(format!("+ header ({salt})"))
        .on_hover_text("Add header row")
        .clicked()
    {
        headers.push((String::new(), String::new()));
        dirty = true;
    }
    dirty
}

fn xhttp_range_editors(ui: &mut Ui, range: &mut XhttpRange, salt: &str) -> bool {
    let mut dirty = false;
    ui.horizontal(|ui| {
        ui.label("from");
        let mut from = range.from.to_string();
        if ui
            .add(egui::TextEdit::singleline(&mut from).id_salt(format!("{salt}_from")).desired_width(80.0))
            .changed()
        {
            if let Ok(v) = from.trim().parse::<i64>() {
                range.from = v;
                dirty = true;
            }
        }
        ui.label("to");
        let mut to = range.to.to_string();
        if ui
            .add(egui::TextEdit::singleline(&mut to).id_salt(format!("{salt}_to")).desired_width(80.0))
            .changed()
        {
            if let Ok(v) = to.trim().parse::<i64>() {
                range.to = v;
                dirty = true;
            }
        }
    });
    dirty
}

fn xhttp_bool_combo(ui: &mut Ui, id: &str, value: &mut bool) -> bool {
    let mut dirty = false;
    ComboBox::from_id_salt(id)
        .selected_text(if *value { "true" } else { "false" })
        .width(100.0)
        .show_ui(ui, |ui| {
            for option in [false, true] {
                let label = if option { "true" } else { "false" };
                if ui.selectable_label(*value == option, label).clicked() && *value != option {
                    *value = option;
                    dirty = true;
                }
            }
        });
    dirty
}

fn xhttp_string_combo(
    ui: &mut Ui,
    id: &str,
    value: &mut String,
    options: &[&str],
    default_label: &str,
) -> bool {
    let mut dirty = false;
    let current = value.clone();
    let selected_label = if current.trim().is_empty() {
        default_label
    } else {
        current.as_str()
    };
    ComboBox::from_id_salt(id)
        .selected_text(selected_label)
        .width(200.0)
        .show_ui(ui, |ui| {
            for option in options {
                let selected = current.trim() == *option
                    || (current.trim().is_empty() && *option == default_label);
                if ui.selectable_label(selected, *option).clicked() && current.trim() != *option {
                    *value = (*option).to_owned();
                    dirty = true;
                }
            }
            let trimmed = current.trim();
            if !trimmed.is_empty() && !options.contains(&trimmed) {
                ui.separator();
                let _ = ui.selectable_label(true, format!("{trimmed} (preserved)"));
            }
        });
    dirty
}

fn xhttp_optional_string_combo(
    ui: &mut Ui,
    id: &str,
    value: &mut String,
    options: &[&str],
) -> bool {
    let mut dirty = false;
    let current = value.clone();
    let selected_label = if current.trim().is_empty() {
        "(default)"
    } else {
        current.as_str()
    };
    ComboBox::from_id_salt(id)
        .selected_text(selected_label)
        .width(200.0)
        .show_ui(ui, |ui| {
            if ui
                .selectable_label(current.trim().is_empty(), "(default)")
                .clicked()
                && !current.trim().is_empty()
            {
                value.clear();
                dirty = true;
            }
            for option in options {
                let selected = current.trim() == *option;
                if ui.selectable_label(selected, *option).clicked() && current.trim() != *option {
                    *value = (*option).to_owned();
                    dirty = true;
                }
            }
            let trimmed = current.trim();
            if !trimmed.is_empty() && !options.contains(&trimmed) {
                ui.separator();
                let _ = ui.selectable_label(true, format!("{trimmed} (preserved)"));
            }
        });
    dirty
}
