//! Inbound Users tab — VLESS client list with Add / Edit / Delete actions.
//!
//! Embedded under Inbounds (General | Users | Sniffing). Data and mutations flow exclusively
//! through [`ApplicationService`]. This page never reads JSON, opens SSH, or
//! mutates remote configuration directly.

use egui::{Color32, ComboBox, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, AddUserRequest, DeleteUserRequest, InboundClientSummary, MISSING_FIELD,
    SecretFieldDraft, SecretString, TrojanClientSummary, UpdateUserRequest, UsersPageModel,
    UsersPageState, UsersProtocolUi, UsersSortColumn, generate_client_auth, generate_client_uuid,
    hysteria_row_display, selected_users_protocol,
    trojan_row_display, user_row_display,
};
use crate::xray::{
    AddInboundClientRequest, HysteriaClientSummary, UpdateInboundClientRequest, UserSummary,
};

/// Allowed VLESS `flow` values in Add/Edit dialogs.
///
/// `xtls-rprx-vision-udp443` is intentionally **not** offered here: current Xray-core inbound
/// docs list only `xtls-rprx-vision` (the `-udp443` variant was merged into it and deprecated).
/// A config that still has it on disk is preserved and surfaced via the "unsupported flow"
/// hint in the Edit dialog until the user explicitly picks an allowed value (Roadmap §2.5:105).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum VlessFlowChoice {
    /// Omit `flow` from the client JSON object.
    #[default]
    None,
    /// `"flow": "xtls-rprx-vision"`.
    XtlsRprxVision,
}

impl VlessFlowChoice {
    const ALL: &[Self] = &[Self::None, Self::XtlsRprxVision];

    fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::XtlsRprxVision => "xtls-rprx-vision",
        }
    }

    fn to_request(self) -> Option<String> {
        match self {
            Self::None => None,
            Self::XtlsRprxVision => Some("xtls-rprx-vision".to_owned()),
        }
    }
}

fn flow_combo(ui: &mut Ui, id_salt: &str, flow: &mut VlessFlowChoice) {
    ComboBox::from_id_salt(id_salt)
        .selected_text(flow.label())
        .width(380.0)
        .show_ui(ui, |ui| {
            for option in VlessFlowChoice::ALL {
                ui.selectable_value(flow, *option, option.label());
            }
        });
}

use super::{ReverseDraftFields, reverse_fields_edit};

/// Protocol-specific dialog draft (Approach B / eng 5A — no Option-soup UI state).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum ClientDialogDraft {
    #[default]
    None,
    AddVless {
        inbound_index: usize,
        email: String,
        uuid: String,
        flow: VlessFlowChoice,
        level: u32,
        /// VLESS-native reverse proxy portal registration (Roadmap §2.1:58); checkbox-driven
        /// presence — see [`ReverseDraftFields`].
        reverse: ReverseDraftFields,
        error: Option<String>,
        /// Redacted JSON diff from the last "Preview changes" click (Roadmap §3:120).
        diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
    },
    EditVless {
        inbound_index: usize,
        client_index: usize,
        email: String,
        uuid: String,
        flow: VlessFlowChoice,
        /// Set when config had a flow value outside the allowed list.
        unsupported_flow_hint: Option<String>,
        level: u32,
        /// VLESS-native reverse proxy portal registration (Roadmap §2.1:58); checkbox-driven
        /// presence — see [`ReverseDraftFields`].
        reverse: ReverseDraftFields,
        expected_fingerprint: String,
        error: Option<String>,
        /// Redacted JSON diff from the last "Preview changes" click (Roadmap §3:120).
        diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
    },
    DeleteVless {
        inbound_index: usize,
        client_index: usize,
        email_label: String,
        expected_fingerprint: String,
        error: Option<String>,
    },
    /// Trojan: Add client (IB-L1).
    AddTrojan {
        inbound_index: usize,
        email: String,
        /// Plain text password entry — converted to SecretString on submit.
        password: String,
        level: u32,
        error: Option<String>,
        /// Redacted JSON diff from the last "Preview changes" click (Roadmap §3:120).
        diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
    },
    /// Trojan: Edit client (IB-L1).
    EditTrojan {
        inbound_index: usize,
        client_index: usize,
        email: String,
        /// Empty = preserve existing; non-empty = replace.
        password_draft: String,
        level: u32,
        expected_fingerprint: String,
        error: Option<String>,
        /// Redacted JSON diff from the last "Preview changes" click (Roadmap §3:120).
        diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
    },
    /// Trojan: Delete client (IB-L1).
    DeleteTrojan {
        inbound_index: usize,
        client_index: usize,
        email_label: String,
        expected_fingerprint: String,
        error: Option<String>,
    },
    /// Hysteria: Add user (Wave A).
    AddHysteria {
        inbound_index: usize,
        email: String,
        auth: String,
        level: u32,
        error: Option<String>,
        /// Redacted JSON diff from the last "Preview changes" click (Roadmap §3:120).
        diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
    },
    /// Hysteria: Edit user (Wave A).
    EditHysteria {
        inbound_index: usize,
        client_index: usize,
        email: String,
        auth_draft: String,
        level: u32,
        expected_fingerprint: String,
        error: Option<String>,
        /// Redacted JSON diff from the last "Preview changes" click (Roadmap §3:120).
        diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
    },
    /// Hysteria: Delete user (Wave A).
    DeleteHysteria {
        inbound_index: usize,
        client_index: usize,
        email_label: String,
        expected_fingerprint: String,
        error: Option<String>,
    },
}

/// Selected row for protocol-dispatched action bar.
enum SelectedClientRow<'a> {
    /// No row selected.
    None,
    /// VLESS row.
    Vless(&'a UserSummary),
    /// Trojan row.
    Trojan(&'a TrojanClientSummary),
    /// Hysteria row.
    Hysteria(&'a HysteriaClientSummary),
}

/// Renders the Users tab for the currently selected inbound.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    let model = service.users_page_model();
    let protocol =
        selected_users_protocol(&model.inbound_choices, model.selected_inbound_index);

    match model.state {
        UsersPageState::NoSshConnection
        | UsersPageState::XrayNotDiscovered
        | UsersPageState::ConfigurationNotLoaded
        | UsersPageState::NoInboundSelected
        | UsersPageState::NoSupportedInboundSelected => {
            show_state_message(ui, model.state);
            show_dialogs(ui, service);
            return;
        }
        UsersPageState::SelectedInboundHasNoUsers => {
            if let Some(protocol) = protocol {
                show_protocol_action_bar(
                    ui,
                    service,
                    protocol,
                    model.selected_inbound_index,
                    SelectedClientRow::None,
                );
            }
            ui.add_space(8.0);
            show_state_message(ui, model.state);
        }
        UsersPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            for warning in &model.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(8.0);
            let model = service.users_page_model();
            let protocol =
                selected_users_protocol(&model.inbound_choices, model.selected_inbound_index);
            show_protocol_users_body(ui, service, &model, protocol);
        }
        UsersPageState::UsersLoaded => {
            show_protocol_users_body(ui, service, &model, protocol);
        }
    }

    show_dialogs(ui, service);
}

fn show_protocol_users_body(
    ui: &mut Ui,
    service: &mut ApplicationService,
    model: &UsersPageModel,
    protocol: Option<UsersProtocolUi>,
) {
    let Some(protocol) = protocol else {
        return;
    };

    match protocol {
        UsersProtocolUi::Vless => {
            let selected = selected_table_row(ui, &model.rows);
            let selected_row = selected.map(SelectedClientRow::Vless);
            show_protocol_action_bar(
                ui,
                service,
                protocol,
                model.selected_inbound_index,
                selected_row.unwrap_or(SelectedClientRow::None),
            );
            ui.add_space(8.0);
            if model.rows.is_empty() {
                ui.label(
                    RichText::new(UsersPageState::SelectedInboundHasNoUsers.message())
                        .size(14.0)
                        .color(Color32::from_rgb(140, 140, 140)),
                );
            } else {
                show_table(ui, service, &model.rows);
            }
        }
        UsersProtocolUi::Trojan => {
            let trojan_rows: Vec<TrojanClientSummary> = model
                .inbound_clients
                .iter()
                .filter_map(|c| match c {
                    InboundClientSummary::Trojan(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            let selected = selected_summary_row(ui, &trojan_rows);
            let selected_row = selected
                .map(SelectedClientRow::Trojan)
                .unwrap_or(SelectedClientRow::None);
            show_protocol_action_bar(
                ui,
                service,
                protocol,
                model.selected_inbound_index,
                selected_row,
            );
            ui.add_space(8.0);
            if trojan_rows.is_empty() {
                ui.label(
                    RichText::new(UsersPageState::SelectedInboundHasNoUsers.message())
                        .size(14.0)
                        .color(Color32::from_rgb(140, 140, 140)),
                );
            } else {
                show_trojan_table(ui, service, &trojan_rows);
            }
        }
        UsersProtocolUi::Hysteria => {
            let hysteria_rows: Vec<HysteriaClientSummary> = model
                .inbound_clients
                .iter()
                .filter_map(|c| match c {
                    InboundClientSummary::Hysteria(h) => Some(h.clone()),
                    _ => None,
                })
                .collect();
            let selected = selected_summary_row(ui, &hysteria_rows);
            let selected_row = selected
                .map(SelectedClientRow::Hysteria)
                .unwrap_or(SelectedClientRow::None);
            show_protocol_action_bar(
                ui,
                service,
                protocol,
                model.selected_inbound_index,
                selected_row,
            );
            ui.add_space(8.0);
            if hysteria_rows.is_empty() {
                ui.label(
                    RichText::new(UsersPageState::SelectedInboundHasNoUsers.message())
                        .size(14.0)
                        .color(Color32::from_rgb(140, 140, 140)),
                );
            } else {
                show_hysteria_table(ui, service, &hysteria_rows);
            }
        }
    }
}

fn show_protocol_action_bar(
    ui: &mut Ui,
    service: &mut ApplicationService,
    protocol: UsersProtocolUi,
    selected_inbound: Option<usize>,
    selected_row: SelectedClientRow<'_>,
) {
    match protocol {
        UsersProtocolUi::Vless => {
            let row = match selected_row {
                SelectedClientRow::Vless(r) => Some(r),
                _ => None,
            };
            show_action_bar(ui, service, selected_inbound, row);
        }
        UsersProtocolUi::Trojan => {
            let row = match selected_row {
                SelectedClientRow::Trojan(r) => Some(r),
                _ => None,
            };
            show_trojan_action_bar(ui, service, selected_inbound, row);
        }
        UsersProtocolUi::Hysteria => {
            let row = match selected_row {
                SelectedClientRow::Hysteria(r) => Some(r),
                _ => None,
            };
            show_hysteria_action_bar(ui, service, selected_inbound, row);
        }
    }
}

fn show_state_message(ui: &mut Ui, state: UsersPageState) {
    let color = match state {
        UsersPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        UsersPageState::SelectedInboundHasNoUsers
        | UsersPageState::NoInboundSelected
        | UsersPageState::NoSupportedInboundSelected
        | UsersPageState::UsersLoaded => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_action_bar(
    ui: &mut Ui,
    service: &mut ApplicationService,
    selected_inbound: Option<usize>,
    selected_row: Option<&UserSummary>,
) {
    let busy = service.is_user_mutation_busy();
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !busy && selected_inbound.is_some(),
                egui::Button::new("Add user"),
            )
            .clicked()
        {
            open_add_dialog(ui, selected_inbound.expect("checked"));
        }
        if ui
            .add_enabled(!busy && selected_row.is_some(), egui::Button::new("Edit"))
            .clicked()
            && let Some(row) = selected_row
        {
            open_edit_dialog(ui, service, row);
        }
        if ui
            .add_enabled(!busy && selected_row.is_some(), egui::Button::new("Delete"))
            .clicked()
            && let Some(row) = selected_row
        {
            open_delete_dialog(ui, service, row);
        }
    });
}

fn show_trojan_action_bar(
    ui: &mut Ui,
    service: &mut ApplicationService,
    selected_inbound: Option<usize>,
    selected_row: Option<&TrojanClientSummary>,
) {
    let busy = service.is_user_mutation_busy();
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !busy && selected_inbound.is_some(),
                egui::Button::new("Add client"),
            )
            .clicked()
        {
            open_add_trojan_dialog(ui, selected_inbound.expect("checked"));
        }
        if ui
            .add_enabled(!busy && selected_row.is_some(), egui::Button::new("Edit"))
            .clicked()
            && let Some(row) = selected_row
        {
            open_edit_trojan_dialog(ui, service, row);
        }
        if ui
            .add_enabled(!busy && selected_row.is_some(), egui::Button::new("Delete"))
            .clicked()
            && let Some(row) = selected_row
        {
            open_delete_trojan_dialog(ui, service, row);
        }
    });
}

fn summary_row_id() -> egui::Id {
    egui::Id::new("users_page_selected_summary_row")
}

fn selected_summary_row_key(ui: &Ui) -> Option<(usize, usize)> {
    ui.ctx()
        .data(|d| d.get_temp::<(usize, usize)>(summary_row_id()))
}

fn set_selected_summary_row(ui: &Ui, inbound_index: usize, client_index: usize) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(summary_row_id(), (inbound_index, client_index)));
}

fn selected_summary_row<'a, T>(ui: &Ui, rows: &'a [T]) -> Option<&'a T>
where
    T: ClientRowKey,
{
    let key = selected_summary_row_key(ui)?;
    rows.iter()
        .find(|r| r.inbound_index() == key.0 && r.client_index() == key.1)
        .or_else(|| rows.first())
}

trait ClientRowKey {
    fn inbound_index(&self) -> usize;
    fn client_index(&self) -> usize;
}

impl ClientRowKey for TrojanClientSummary {
    fn inbound_index(&self) -> usize {
        self.inbound_index
    }
    fn client_index(&self) -> usize {
        self.client_index
    }
}

impl ClientRowKey for HysteriaClientSummary {
    fn inbound_index(&self) -> usize {
        self.inbound_index
    }
    fn client_index(&self) -> usize {
        self.client_index
    }
}

fn selected_trojan_row_key(ui: &Ui) -> Option<(usize, usize)> {
    selected_summary_row_key(ui)
}

fn show_trojan_table(
    ui: &mut Ui,
    service: &mut ApplicationService,
    rows: &[TrojanClientSummary],
) {
    let busy = service.is_user_mutation_busy();
    let selected_key = selected_trojan_row_key(ui);

    egui::Grid::new("trojan_users_table")
        .num_columns(4)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(80.0)
        .show(ui, |ui| {
            ui.strong("Email");
            ui.strong("Password");
            ui.strong("Inbound tag");
            ui.strong("Source file");
            ui.end_row();

            for row in rows {
                let display = trojan_row_display(row);
                let is_selected =
                    selected_key == Some((row.inbound_index, row.client_index));
                let email_text = if is_selected {
                    format!("› {}", display.email)
                } else {
                    display.email.clone()
                };
                let response =
                    ui.add(egui::Label::new(&email_text).sense(Sense::click()));
                if response.clicked() {
                    set_selected_summary_row(ui, row.inbound_index, row.client_index);
                }
                show_trojan_context_menu(&response, service, row, busy);
                ui.label(display.password_masked);
                ui.label(&display.inbound_tag);
                ui.label(display.source_file);
                ui.end_row();
            }
        });
}

fn show_trojan_context_menu(
    response: &egui::Response,
    service: &mut ApplicationService,
    row: &TrojanClientSummary,
    busy: bool,
) {
    response.context_menu(|ui| {
        if ui.button("Copy email").clicked() {
            ui.ctx().copy_text(
                row.email.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.close();
        }
        match service.build_client_share_uri(row.inbound_index, row.client_index) {
            Ok(uri) => {
                if ui.button("Copy share URI").clicked() {
                    ui.ctx().copy_text(uri.clone());
                    ui.close();
                }
                if ui.button("Show QR code").clicked() {
                    open_qr_dialog(ui, uri);
                    ui.close();
                }
            }
            Err(reason) => {
                ui.add_enabled(false, egui::Button::new("Copy share URI"))
                    .on_disabled_hover_text(reason.clone());
                ui.add_enabled(false, egui::Button::new("Show QR code"))
                    .on_disabled_hover_text(reason);
            }
        }
        ui.separator();
        if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            open_edit_trojan_dialog(ui, service, row);
            ui.close();
        }
        if ui.add_enabled(!busy, egui::Button::new("Delete")).clicked() {
            open_delete_trojan_dialog(ui, service, row);
            ui.close();
        }
    });
}

fn show_hysteria_action_bar(
    ui: &mut Ui,
    service: &mut ApplicationService,
    selected_inbound: Option<usize>,
    selected_row: Option<&HysteriaClientSummary>,
) {
    let busy = service.is_user_mutation_busy();
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !busy && selected_inbound.is_some(),
                egui::Button::new("Add user"),
            )
            .clicked()
        {
            open_add_hysteria_dialog(ui, selected_inbound.expect("checked"));
        }
        if ui
            .add_enabled(!busy && selected_row.is_some(), egui::Button::new("Edit"))
            .clicked()
            && let Some(row) = selected_row
        {
            open_edit_hysteria_dialog(ui, service, row);
        }
        if ui
            .add_enabled(!busy && selected_row.is_some(), egui::Button::new("Delete"))
            .clicked()
            && let Some(row) = selected_row
        {
            open_delete_hysteria_dialog(ui, service, row);
        }
    });
}

fn show_hysteria_table(
    ui: &mut Ui,
    service: &mut ApplicationService,
    rows: &[HysteriaClientSummary],
) {
    let busy = service.is_user_mutation_busy();
    let selected_key = selected_summary_row_key(ui);

    egui::Grid::new("hysteria_users_table")
        .num_columns(5)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(80.0)
        .show(ui, |ui| {
            ui.strong("Email");
            ui.strong("Auth");
            ui.strong("Level");
            ui.strong("Inbound tag");
            ui.strong("Source file");
            ui.end_row();

            for row in rows {
                let display = hysteria_row_display(row);
                let is_selected =
                    selected_key == Some((row.inbound_index, row.client_index));
                let email_text = if is_selected {
                    format!("› {}", display.email)
                } else {
                    display.email.clone()
                };
                let response =
                    ui.add(egui::Label::new(&email_text).sense(Sense::click()));
                if response.clicked() {
                    set_selected_summary_row(ui, row.inbound_index, row.client_index);
                }
                show_hysteria_context_menu(&response, service, row, busy);
                ui.label(display.auth_masked);
                ui.label(&display.level);
                ui.label(&display.inbound_tag);
                ui.label(display.source_file);
                ui.end_row();
            }
        });
}

fn show_hysteria_context_menu(
    response: &egui::Response,
    service: &mut ApplicationService,
    row: &HysteriaClientSummary,
    busy: bool,
) {
    response.context_menu(|ui| {
        if ui.button("Copy email").clicked() {
            ui.ctx().copy_text(
                row.email.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.close();
        }
        match service.build_client_share_uri(row.inbound_index, row.client_index) {
            Ok(uri) => {
                if ui.button("Copy share URI").clicked() {
                    ui.ctx().copy_text(uri.clone());
                    ui.close();
                }
                if ui.button("Show QR code").clicked() {
                    open_qr_dialog(ui, uri);
                    ui.close();
                }
            }
            Err(reason) => {
                ui.add_enabled(false, egui::Button::new("Copy share URI"))
                    .on_disabled_hover_text(reason.clone());
                ui.add_enabled(false, egui::Button::new("Show QR code"))
                    .on_disabled_hover_text(reason);
            }
        }
        ui.separator();
        if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            open_edit_hysteria_dialog(ui, service, row);
            ui.close();
        }
        if ui.add_enabled(!busy, egui::Button::new("Delete")).clicked() {
            open_delete_hysteria_dialog(ui, service, row);
            ui.close();
        }
    });
}

fn show_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[UserSummary]) {
    let sort = service.users_sort();
    let busy = service.is_user_mutation_busy();
    let selected_key = selected_row_key(ui);

    egui::Grid::new("users_table")
        .num_columns(6)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(80.0)
        .show(ui, |ui| {
            sortable_header(ui, service, "Email", UsersSortColumn::Email, sort.column);
            sortable_header(ui, service, "UUID / ID", UsersSortColumn::Uuid, sort.column);
            ui.strong("Flow");
            ui.strong("Reverse tag").on_hover_text(
                "VLESS-native reverse proxy portal registration (Roadmap §2.1:58); — = ordinary client",
            );
            ui.strong("Inbound tag");
            ui.strong("Source file");
            ui.end_row();

            for row in rows {
                let display = user_row_display(row);
                let is_selected = selected_key == Some((row.inbound_index, row.client_index));
                let email_text = if is_selected {
                    format!("› {}", display.email)
                } else {
                    display.email.clone()
                };
                if cell_with_menu(ui, service, row, &email_text, busy) {
                    set_selected_row(ui, row);
                }
                cell_with_menu(ui, service, row, &display.id, busy);
                cell_with_menu(ui, service, row, &display.flow, busy);
                cell_with_menu(ui, service, row, &display.reverse_tag, busy);
                cell_with_menu(ui, service, row, &display.inbound_tag, busy);
                cell_with_menu(ui, service, row, display.source_file, busy);
                ui.end_row();
            }
        });
}

fn sortable_header(
    ui: &mut Ui,
    service: &mut ApplicationService,
    label: &str,
    column: UsersSortColumn,
    active: UsersSortColumn,
) {
    let sort = service.users_sort();
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
        service.set_users_sort_column(column);
    }
}

fn cell_with_menu(
    ui: &mut Ui,
    service: &mut ApplicationService,
    row: &UserSummary,
    text: &str,
    busy: bool,
) -> bool {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    let clicked = response.clicked();
    show_user_context_menu(&response, service, row, busy);
    clicked
}

fn selected_row_id() -> egui::Id {
    egui::Id::new("users_page_selected_row")
}

fn selected_row_key(ui: &Ui) -> Option<(usize, usize)> {
    ui.ctx()
        .data(|data| data.get_temp::<(usize, usize)>(selected_row_id()))
}

fn set_selected_row(ui: &Ui, row: &UserSummary) {
    ui.ctx().data_mut(|data| {
        data.insert_temp(selected_row_id(), (row.inbound_index, row.client_index));
    });
}

fn selected_table_row<'a>(ui: &Ui, rows: &'a [UserSummary]) -> Option<&'a UserSummary> {
    let key = selected_row_key(ui)?;
    rows.iter()
        .find(|row| row.inbound_index == key.0 && row.client_index == key.1)
        .or_else(|| rows.first())
}

fn show_user_context_menu(
    response: &egui::Response,
    service: &mut ApplicationService,
    row: &UserSummary,
    busy: bool,
) {
    response.context_menu(|ui| {
        if ui.button("Copy email").clicked() {
            ui.ctx().copy_text(
                row.email
                    .clone()
                    .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.close();
        }
        if ui.button("Copy UUID").clicked() {
            ui.ctx()
                .copy_text(row.id.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()));
            ui.close();
        }
        if ui.button("Copy flow").clicked() {
            ui.ctx()
                .copy_text(row.flow.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()));
            ui.close();
        }
        match service.build_client_share_uri(row.inbound_index, row.client_index) {
            Ok(uri) => {
                if ui.button("Copy share URI").clicked() {
                    ui.ctx().copy_text(uri.clone());
                    ui.close();
                }
                if ui.button("Show QR code").clicked() {
                    open_qr_dialog(ui, uri);
                    ui.close();
                }
            }
            Err(reason) => {
                ui.add_enabled(false, egui::Button::new("Copy share URI"))
                    .on_disabled_hover_text(reason.clone());
                ui.add_enabled(false, egui::Button::new("Show QR code"))
                    .on_disabled_hover_text(reason);
            }
        }

        ui.separator();

        if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            open_edit_dialog(ui, service, row);
            ui.close();
        }
        if ui.add_enabled(!busy, egui::Button::new("Delete")).clicked() {
            open_delete_dialog(ui, service, row);
            ui.close();
        }
    });
}

fn dialog_id() -> egui::Id {
    egui::Id::new("inbound_users_client_dialog")
}

/// Renders a dialog draft's stored "Preview changes" diff, if any (Roadmap §3:120).
fn show_user_diff_preview(ui: &mut Ui, entries: &Option<Vec<crate::xray::JsonDiffEntry>>) {
    if let Some(entries) = entries {
        super::json_diff_preview(ui, entries);
    }
}

fn show_add_trojan_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let busy = service.is_user_mutation_busy();

    let (inbound_index, email, password, level, error, diff_preview) =
        with_dialog_draft(ui, |draft| match draft {
            ClientDialogDraft::AddTrojan {
                inbound_index,
                email,
                password,
                level,
                error,
                diff_preview,
            } => (
                *inbound_index,
                email.clone(),
                password.clone(),
                *level,
                error.clone(),
                diff_preview.clone(),
            ),
            _ => unreachable!(),
        });

    let mut open = true;
    egui::Window::new("Add Trojan Client")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.set_min_width(360.0);
            egui::Grid::new("add_trojan_grid")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Email:");
                    let mut e = email.clone();
                    if ui.text_edit_singleline(&mut e).changed() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddTrojan { email, .. } = d {
                                *email = e;
                            }
                        });
                    }
                    ui.end_row();

                    ui.label("Password:");
                    let mut pw = password.clone();
                    let pw_edit = egui::TextEdit::singleline(&mut pw).password(true);
                    if ui.add(pw_edit).changed() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddTrojan { password, .. } = d {
                                *password = pw;
                            }
                        });
                    }
                    ui.end_row();
                });

            if let Some(err) = &error {
                ui.colored_label(Color32::from_rgb(200, 60, 60), err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Add")).clicked() {
                    if password.is_empty() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddTrojan { error, .. } = d {
                                *error = Some("Password must not be empty.".to_owned());
                            }
                        });
                    } else {
                        let result = service.start_add_trojan_client(
                            inbound_index,
                            email.clone(),
                            SecretString::new(password.clone()),
                            level,
                        );
                        if let Err(msg) = result {
                            with_dialog_draft(ui, |d| {
                                if let ClientDialogDraft::AddTrojan { error, .. } = d {
                                    *error = Some(msg);
                                }
                            });
                        } else {
                            with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                        }
                    }
                }
                if ui.button("Preview changes").clicked() {
                    let request = AddInboundClientRequest::Trojan {
                        inbound_index,
                        email: email.clone(),
                        password: SecretString::new(password.clone()),
                        level,
                    };
                    match service.preview_add_user_diff(request) {
                        Ok(entries) => with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddTrojan { diff_preview, .. } = d {
                                *diff_preview = Some(entries);
                            }
                        }),
                        Err(msg) => with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddTrojan { error, .. } = d {
                                *error = Some(msg);
                            }
                        }),
                    }
                }
                if ui.button("Cancel").clicked() {
                    with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                }
            });
            show_user_diff_preview(ui, &diff_preview);
        });

    if !open {
        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
    }
}

fn show_edit_trojan_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let busy = service.is_user_mutation_busy();

    let (
        inbound_index,
        client_index,
        email,
        password_draft,
        level,
        expected_fingerprint,
        error,
        diff_preview,
    ) = with_dialog_draft(ui, |draft| match draft {
        ClientDialogDraft::EditTrojan {
            inbound_index,
            client_index,
            email,
            password_draft,
            level,
            expected_fingerprint,
            error,
            diff_preview,
        } => (
            *inbound_index,
            *client_index,
            email.clone(),
            password_draft.clone(),
            *level,
            expected_fingerprint.clone(),
            error.clone(),
            diff_preview.clone(),
        ),
        _ => unreachable!(),
    });

    let mut open = true;
    egui::Window::new("Edit Trojan Client")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.set_min_width(360.0);
            egui::Grid::new("edit_trojan_grid")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Email:");
                    let mut e = email.clone();
                    if ui.text_edit_singleline(&mut e).changed() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditTrojan { email, .. } = d {
                                *email = e;
                            }
                        });
                    }
                    ui.end_row();

                    ui.label("Password:");
                    let mut pw = password_draft.clone();
                    let pw_edit = egui::TextEdit::singleline(&mut pw)
                        .hint_text("(leave blank to keep)")
                        .password(true);
                    if ui.add(pw_edit).changed() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditTrojan { password_draft, .. } = d {
                                *password_draft = pw;
                            }
                        });
                    }
                    ui.end_row();
                });

            if let Some(err) = &error {
                ui.colored_label(Color32::from_rgb(200, 60, 60), err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Save")).clicked() {
                    let secret_draft = if password_draft.is_empty() {
                        SecretFieldDraft::Preserve
                    } else {
                        SecretFieldDraft::Replace(SecretString::new(password_draft.clone()))
                    };
                    let result = service.start_update_trojan_client(
                        inbound_index,
                        client_index,
                        email.clone(),
                        secret_draft,
                        level,
                        Some(expected_fingerprint.clone()),
                    );
                    if let Err(msg) = result {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditTrojan { error, .. } = d {
                                *error = Some(msg);
                            }
                        });
                    } else {
                        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                    }
                }
                if ui.button("Preview changes").clicked() {
                    let secret_draft = if password_draft.is_empty() {
                        SecretFieldDraft::Preserve
                    } else {
                        SecretFieldDraft::Replace(SecretString::new(password_draft.clone()))
                    };
                    let request = UpdateInboundClientRequest::Trojan {
                        inbound_index,
                        client_index,
                        email: email.clone(),
                        password: secret_draft,
                        level,
                        expected_fingerprint: Some(expected_fingerprint.clone()),
                    };
                    match service.preview_update_user_diff(request) {
                        Ok(entries) => with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditTrojan { diff_preview, .. } = d {
                                *diff_preview = Some(entries);
                            }
                        }),
                        Err(msg) => with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditTrojan { error, .. } = d {
                                *error = Some(msg);
                            }
                        }),
                    }
                }
                if ui.button("Cancel").clicked() {
                    with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                }
            });
            show_user_diff_preview(ui, &diff_preview);
        });

    if !open {
        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
    }
}

fn show_delete_trojan_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let busy = service.is_user_mutation_busy();

    let (inbound_index, client_index, email_label, expected_fingerprint, error) =
        with_dialog_draft(ui, |draft| match draft {
            ClientDialogDraft::DeleteTrojan {
                inbound_index,
                client_index,
                email_label,
                expected_fingerprint,
                error,
            } => (
                *inbound_index,
                *client_index,
                email_label.clone(),
                expected_fingerprint.clone(),
                error.clone(),
            ),
            _ => unreachable!(),
        });

    let mut open = true;
    egui::Window::new("Delete Trojan Client")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.set_min_width(320.0);
            ui.label(format!("Delete client \"{}\"?", email_label));

            if let Some(err) = &error {
                ui.colored_label(Color32::from_rgb(200, 60, 60), err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new("Delete"))
                    .clicked()
                {
                    use crate::app::DeleteUserRequest;
                    let result = service.start_delete_trojan_client(DeleteUserRequest {
                        inbound_index,
                        client_index,
                        expected_fingerprint: Some(expected_fingerprint),
                    });
                    if let Err(msg) = result {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::DeleteTrojan { error, .. } = d {
                                *error = Some(msg);
                            }
                        });
                    } else {
                        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                    }
                }
                if ui.button("Cancel").clicked() {
                    with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                }
            });
        });

    if !open {
        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
    }
}

fn show_add_hysteria_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let busy = service.is_user_mutation_busy();

    let (inbound_index, email, auth, level, error, diff_preview) =
        with_dialog_draft(ui, |draft| match draft {
            ClientDialogDraft::AddHysteria {
                inbound_index,
                email,
                auth,
                level,
                error,
                diff_preview,
            } => (
                *inbound_index,
                email.clone(),
                auth.clone(),
                *level,
                error.clone(),
                diff_preview.clone(),
            ),
            _ => unreachable!(),
        });

    let mut open = true;
    egui::Window::new("Add Hysteria User")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.set_min_width(360.0);
            egui::Grid::new("add_hysteria_grid")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Email:");
                    let mut e = email.clone();
                    if ui.text_edit_singleline(&mut e).changed() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddHysteria { email, .. } = d {
                                *email = e;
                            }
                        });
                    }
                    ui.end_row();

                    ui.label("Auth:");
                    ui.horizontal(|ui| {
                        let mut a = auth.clone();
                        let auth_edit = egui::TextEdit::singleline(&mut a).password(true);
                        if ui.add(auth_edit).changed() {
                            with_dialog_draft(ui, |d| {
                                if let ClientDialogDraft::AddHysteria { auth, .. } = d {
                                    *auth = a;
                                }
                            });
                        }
                        if ui.button("Regenerate").clicked() {
                            with_dialog_draft(ui, |d| {
                                if let ClientDialogDraft::AddHysteria { auth, .. } = d {
                                    *auth = generate_client_auth();
                                }
                            });
                        }
                    });
                    ui.end_row();
                });

            if let Some(err) = &error {
                ui.colored_label(Color32::from_rgb(200, 60, 60), err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Add")).clicked() {
                    if auth.is_empty() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddHysteria { error, .. } = d {
                                *error = Some("Auth must not be empty.".to_owned());
                            }
                        });
                    } else {
                        let result = service.start_add_hysteria_client(
                            inbound_index,
                            email.clone(),
                            SecretString::new(auth.clone()),
                            level,
                        );
                        if let Err(msg) = result {
                            with_dialog_draft(ui, |d| {
                                if let ClientDialogDraft::AddHysteria { error, .. } = d {
                                    *error = Some(msg);
                                }
                            });
                        } else {
                            with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                        }
                    }
                }
                if ui.button("Preview changes").clicked() {
                    let request = AddInboundClientRequest::Hysteria {
                        inbound_index,
                        email: email.clone(),
                        auth: SecretString::new(auth.clone()),
                        level,
                    };
                    match service.preview_add_user_diff(request) {
                        Ok(entries) => with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddHysteria { diff_preview, .. } = d {
                                *diff_preview = Some(entries);
                            }
                        }),
                        Err(msg) => with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::AddHysteria { error, .. } = d {
                                *error = Some(msg);
                            }
                        }),
                    }
                }
                if ui.button("Cancel").clicked() {
                    with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                }
            });
            show_user_diff_preview(ui, &diff_preview);
        });

    if !open {
        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
    }
}

fn show_edit_hysteria_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let busy = service.is_user_mutation_busy();

    let (
        inbound_index,
        client_index,
        email,
        auth_draft,
        level,
        expected_fingerprint,
        error,
        diff_preview,
    ) = with_dialog_draft(ui, |draft| match draft {
        ClientDialogDraft::EditHysteria {
            inbound_index,
            client_index,
            email,
            auth_draft,
            level,
            expected_fingerprint,
            error,
            diff_preview,
        } => (
            *inbound_index,
            *client_index,
            email.clone(),
            auth_draft.clone(),
            *level,
            expected_fingerprint.clone(),
            error.clone(),
            diff_preview.clone(),
        ),
        _ => unreachable!(),
    });

    let mut open = true;
    egui::Window::new("Edit Hysteria User")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.set_min_width(360.0);
            egui::Grid::new("edit_hysteria_grid")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Email:");
                    let mut e = email.clone();
                    if ui.text_edit_singleline(&mut e).changed() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditHysteria { email, .. } = d {
                                *email = e;
                            }
                        });
                    }
                    ui.end_row();

                    ui.label("Auth:");
                    let mut a = auth_draft.clone();
                    let auth_edit = egui::TextEdit::singleline(&mut a)
                        .hint_text("(leave blank to keep)")
                        .password(true);
                    if ui.add(auth_edit).changed() {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditHysteria { auth_draft, .. } = d {
                                *auth_draft = a;
                            }
                        });
                    }
                    ui.end_row();

                    ui.label("Level:");
                    let mut level_text = level.to_string();
                    if ui.text_edit_singleline(&mut level_text).changed() {
                        if let Ok(parsed) = level_text.trim().parse::<u32>() {
                            with_dialog_draft(ui, |d| {
                                if let ClientDialogDraft::EditHysteria { level, .. } = d {
                                    *level = parsed;
                                }
                            });
                        }
                    }
                    ui.end_row();
                });

            if let Some(err) = &error {
                ui.colored_label(Color32::from_rgb(200, 60, 60), err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Save")).clicked() {
                    let secret_draft = if auth_draft.is_empty() {
                        SecretFieldDraft::Preserve
                    } else {
                        SecretFieldDraft::Replace(SecretString::new(auth_draft.clone()))
                    };
                    let result = service.start_update_hysteria_client(
                        inbound_index,
                        client_index,
                        email.clone(),
                        secret_draft,
                        level,
                        Some(expected_fingerprint.clone()),
                    );
                    if let Err(msg) = result {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditHysteria { error, .. } = d {
                                *error = Some(msg);
                            }
                        });
                    } else {
                        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                    }
                }
                if ui.button("Preview changes").clicked() {
                    let secret_draft = if auth_draft.is_empty() {
                        SecretFieldDraft::Preserve
                    } else {
                        SecretFieldDraft::Replace(SecretString::new(auth_draft.clone()))
                    };
                    let request = UpdateInboundClientRequest::Hysteria {
                        inbound_index,
                        client_index,
                        email: email.clone(),
                        auth: secret_draft,
                        level,
                        expected_fingerprint: Some(expected_fingerprint.clone()),
                    };
                    match service.preview_update_user_diff(request) {
                        Ok(entries) => with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditHysteria { diff_preview, .. } = d {
                                *diff_preview = Some(entries);
                            }
                        }),
                        Err(msg) => with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::EditHysteria { error, .. } = d {
                                *error = Some(msg);
                            }
                        }),
                    }
                }
                if ui.button("Cancel").clicked() {
                    with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                }
            });
            show_user_diff_preview(ui, &diff_preview);
        });

    if !open {
        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
    }
}

fn show_delete_hysteria_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let busy = service.is_user_mutation_busy();

    let (inbound_index, client_index, email_label, expected_fingerprint, error) =
        with_dialog_draft(ui, |draft| match draft {
            ClientDialogDraft::DeleteHysteria {
                inbound_index,
                client_index,
                email_label,
                expected_fingerprint,
                error,
            } => (
                *inbound_index,
                *client_index,
                email_label.clone(),
                expected_fingerprint.clone(),
                error.clone(),
            ),
            _ => unreachable!(),
        });

    let mut open = true;
    egui::Window::new("Delete Hysteria User")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.set_min_width(320.0);
            ui.label(format!("Delete user \"{}\"?", email_label));

            if let Some(err) = &error {
                ui.colored_label(Color32::from_rgb(200, 60, 60), err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new("Delete"))
                    .clicked()
                {
                    let result = service.start_delete_hysteria_client(DeleteUserRequest {
                        inbound_index,
                        client_index,
                        expected_fingerprint: Some(expected_fingerprint),
                    });
                    if let Err(msg) = result {
                        with_dialog_draft(ui, |d| {
                            if let ClientDialogDraft::DeleteHysteria { error, .. } = d {
                                *error = Some(msg);
                            }
                        });
                    } else {
                        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                    }
                }
                if ui.button("Cancel").clicked() {
                    with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
                }
            });
        });

    if !open {
        with_dialog_draft(ui, |d| *d = ClientDialogDraft::None);
    }
}

fn with_dialog_draft<R>(ui: &Ui, f: impl FnOnce(&mut ClientDialogDraft) -> R) -> R {
    ui.ctx().data_mut(|data| {
        let draft = data.get_temp_mut_or_default::<ClientDialogDraft>(dialog_id());
        f(draft)
    })
}

fn open_add_dialog(ui: &Ui, inbound_index: usize) {
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::AddVless {
            inbound_index,
            email: String::new(),
            uuid: generate_client_uuid(),
            flow: VlessFlowChoice::None,
            level: 0,
            reverse: ReverseDraftFields::default(),
            error: None,
            diff_preview: None,
        };
    });
}

/// Opens Add VLESS pre-filled from an imported share URI (Roadmap §3:133) — same dialog as
/// [`open_add_dialog`], just with parsed values instead of a fresh UUID/blank fields. `flow_wire`
/// is the raw `flow=` query value; unrecognized/absent values fall back to `None`, same as the
/// Edit dialog's "unsupported flow" handling.
pub(crate) fn open_add_dialog_prefilled(
    ui: &Ui,
    inbound_index: usize,
    email: String,
    uuid: String,
    flow_wire: Option<&str>,
) {
    let flow = match flow_wire {
        Some("xtls-rprx-vision") => VlessFlowChoice::XtlsRprxVision,
        _ => VlessFlowChoice::None,
    };
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::AddVless {
            inbound_index,
            email,
            uuid,
            flow,
            level: 0,
            reverse: ReverseDraftFields::default(),
            error: None,
            diff_preview: None,
        };
    });
}

fn open_edit_dialog(ui: &Ui, service: &ApplicationService, row: &UserSummary) {
    let (flow, unsupported_flow_hint) = match row.flow.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        None => (VlessFlowChoice::None, None),
        Some("xtls-rprx-vision") => (VlessFlowChoice::XtlsRprxVision, None),
        Some(other) => (VlessFlowChoice::None, Some(other.to_owned())),
    };
    let reverse = ReverseDraftFields {
        enabled: row.reverse_tag.is_some(),
        tag: row.reverse_tag.clone().unwrap_or_default(),
        sniffing_enabled: false,
        sniffing_dest_override: Vec::new(),
    };
    let fingerprint = match service.client_fingerprint(row.inbound_index, row.client_index) {
        Ok(value) => value,
        Err(message) => {
            with_dialog_draft(ui, |draft| {
                *draft = ClientDialogDraft::EditVless {
                    inbound_index: row.inbound_index,
                    client_index: row.client_index,
                    email: row.email.clone().unwrap_or_default(),
                    uuid: row.id.clone().unwrap_or_default(),
                    flow,
                    unsupported_flow_hint: unsupported_flow_hint.clone(),
                    level: 0,
                    reverse: reverse.clone(),
                    expected_fingerprint: String::new(),
                    error: Some(message),
                    diff_preview: None,
                };
            });
            return;
        }
    };
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::EditVless {
            inbound_index: row.inbound_index,
            client_index: row.client_index,
            email: row.email.clone().unwrap_or_default(),
            uuid: row.id.clone().unwrap_or_default(),
            flow,
            unsupported_flow_hint,
            level: 0,
            reverse,
            expected_fingerprint: fingerprint,
            error: None,
            diff_preview: None,
        };
    });
}

fn open_delete_dialog(ui: &Ui, service: &ApplicationService, row: &UserSummary) {
    let fingerprint = match service.client_fingerprint(row.inbound_index, row.client_index) {
        Ok(value) => value,
        Err(message) => {
            with_dialog_draft(ui, |draft| {
                *draft = ClientDialogDraft::DeleteVless {
                    inbound_index: row.inbound_index,
                    client_index: row.client_index,
                    email_label: row
                        .email
                        .clone()
                        .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    expected_fingerprint: String::new(),
                    error: Some(message),
                };
            });
            return;
        }
    };
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::DeleteVless {
            inbound_index: row.inbound_index,
            client_index: row.client_index,
            email_label: row
                .email
                .clone()
                .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            expected_fingerprint: fingerprint,
            error: None,
        };
    });
}

fn close_dialog(ui: &Ui) {
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::None;
    });
}

fn open_add_trojan_dialog(ui: &Ui, inbound_index: usize) {
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::AddTrojan {
            inbound_index,
            email: String::new(),
            password: String::new(),
            level: 0,
            error: None,
            diff_preview: None,
        };
    });
}

/// Opens Add Trojan pre-filled from an imported share URI (Roadmap §3:133).
pub(crate) fn open_add_trojan_dialog_prefilled(ui: &Ui, inbound_index: usize, email: String, password: String) {
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::AddTrojan {
            inbound_index,
            email,
            password,
            level: 0,
            error: None,
            diff_preview: None,
        };
    });
}

fn open_edit_trojan_dialog(ui: &Ui, service: &ApplicationService, row: &TrojanClientSummary) {
    let fingerprint = match service.client_fingerprint(row.inbound_index, row.client_index) {
        Ok(v) => v,
        Err(message) => {
            with_dialog_draft(ui, |draft| {
                *draft = ClientDialogDraft::EditTrojan {
                    inbound_index: row.inbound_index,
                    client_index: row.client_index,
                    email: row.email.clone().unwrap_or_default(),
                    password_draft: String::new(),
                    level: 0,
                    expected_fingerprint: String::new(),
                    error: Some(message),
                    diff_preview: None,
                };
            });
            return;
        }
    };
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::EditTrojan {
            inbound_index: row.inbound_index,
            client_index: row.client_index,
            email: row.email.clone().unwrap_or_default(),
            password_draft: String::new(),
            level: 0,
            expected_fingerprint: fingerprint,
            error: None,
            diff_preview: None,
        };
    });
}

fn open_delete_trojan_dialog(
    ui: &Ui,
    service: &ApplicationService,
    row: &TrojanClientSummary,
) {
    let fingerprint = match service.client_fingerprint(row.inbound_index, row.client_index) {
        Ok(v) => v,
        Err(message) => {
            with_dialog_draft(ui, |draft| {
                *draft = ClientDialogDraft::DeleteTrojan {
                    inbound_index: row.inbound_index,
                    client_index: row.client_index,
                    email_label: row.email.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    expected_fingerprint: String::new(),
                    error: Some(message),
                };
            });
            return;
        }
    };
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::DeleteTrojan {
            inbound_index: row.inbound_index,
            client_index: row.client_index,
            email_label: row.email.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
            expected_fingerprint: fingerprint,
            error: None,
        };
    });
}

/// Opens Add Hysteria pre-filled from an imported share URI (Roadmap §3:133).
pub(crate) fn open_add_hysteria_dialog_prefilled(ui: &Ui, inbound_index: usize, email: String, auth: String) {
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::AddHysteria {
            inbound_index,
            email,
            auth,
            level: 0,
            error: None,
            diff_preview: None,
        };
    });
}

fn open_add_hysteria_dialog(ui: &Ui, inbound_index: usize) {
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::AddHysteria {
            inbound_index,
            email: String::new(),
            auth: generate_client_auth(),
            level: 0,
            error: None,
            diff_preview: None,
        };
    });
}

fn open_edit_hysteria_dialog(ui: &Ui, service: &ApplicationService, row: &HysteriaClientSummary) {
    let fingerprint = match service.client_fingerprint(row.inbound_index, row.client_index) {
        Ok(v) => v,
        Err(message) => {
            with_dialog_draft(ui, |draft| {
                *draft = ClientDialogDraft::EditHysteria {
                    inbound_index: row.inbound_index,
                    client_index: row.client_index,
                    email: row.email.clone().unwrap_or_default(),
                    auth_draft: String::new(),
                    level: row.level,
                    expected_fingerprint: String::new(),
                    error: Some(message),
                    diff_preview: None,
                };
            });
            return;
        }
    };
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::EditHysteria {
            inbound_index: row.inbound_index,
            client_index: row.client_index,
            email: row.email.clone().unwrap_or_default(),
            auth_draft: String::new(),
            level: row.level,
            expected_fingerprint: fingerprint,
            error: None,
            diff_preview: None,
        };
    });
}

fn open_delete_hysteria_dialog(
    ui: &Ui,
    service: &ApplicationService,
    row: &HysteriaClientSummary,
) {
    let fingerprint = match service.client_fingerprint(row.inbound_index, row.client_index) {
        Ok(v) => v,
        Err(message) => {
            with_dialog_draft(ui, |draft| {
                *draft = ClientDialogDraft::DeleteHysteria {
                    inbound_index: row.inbound_index,
                    client_index: row.client_index,
                    email_label: row.email.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    expected_fingerprint: String::new(),
                    error: Some(message),
                };
            });
            return;
        }
    };
    with_dialog_draft(ui, |draft| {
        *draft = ClientDialogDraft::DeleteHysteria {
            inbound_index: row.inbound_index,
            client_index: row.client_index,
            email_label: row.email.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
            expected_fingerprint: fingerprint,
            error: None,
        };
    });
}

fn show_dialogs(ui: &mut Ui, service: &mut ApplicationService) {
    let kind = with_dialog_draft(ui, |draft| {
        match draft {
            ClientDialogDraft::None => 0,
            ClientDialogDraft::AddVless { .. } => 1,
            ClientDialogDraft::EditVless { .. } => 2,
            ClientDialogDraft::DeleteVless { .. } => 3,
            ClientDialogDraft::AddTrojan { .. } => 4,
            ClientDialogDraft::EditTrojan { .. } => 5,
            ClientDialogDraft::DeleteTrojan { .. } => 6,
            ClientDialogDraft::AddHysteria { .. } => 7,
            ClientDialogDraft::EditHysteria { .. } => 8,
            ClientDialogDraft::DeleteHysteria { .. } => 9,
        }
    });
    match kind {
        1 => show_add_dialog(ui, service),
        2 => show_edit_dialog(ui, service),
        3 => show_delete_dialog(ui, service),
        4 => show_add_trojan_dialog(ui, service),
        5 => show_edit_trojan_dialog(ui, service),
        6 => show_delete_trojan_dialog(ui, service),
        7 => show_add_hysteria_dialog(ui, service),
        8 => show_edit_hysteria_dialog(ui, service),
        9 => show_delete_hysteria_dialog(ui, service),
        _ => {}
    }
    // Independent of the Add/Edit/Delete draft — can be open alongside the table (Roadmap §3:122).
    show_qr_dialog(ui);
}

fn qr_dialog_id() -> egui::Id {
    egui::Id::new("inbound_users_qr_dialog")
}

/// Opens the QR dialog for a freshly built share URI (Roadmap §3:122).
fn open_qr_dialog(ui: &Ui, uri: String) {
    ui.ctx().data_mut(|data| data.insert_temp(qr_dialog_id(), uri));
}

fn close_qr_dialog(ui: &Ui) {
    ui.ctx().data_mut(|data| data.remove::<String>(qr_dialog_id()));
}

fn show_qr_dialog(ui: &mut Ui) {
    let Some(uri) = ui
        .ctx()
        .data(|data| data.get_temp::<String>(qr_dialog_id()))
    else {
        return;
    };

    let mut open = true;
    egui::Window::new("Share URI QR code")
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            match super::qr_code(ui, &uri) {
                Ok(()) => {}
                Err(error) => {
                    ui.colored_label(
                        Color32::from_rgb(200, 60, 60),
                        format!("Could not render QR code: {error}"),
                    );
                }
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let mut text = uri.clone();
                ui.add(
                    egui::TextEdit::singleline(&mut text)
                        .desired_width(320.0)
                        .interactive(false),
                );
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(uri.clone());
                }
            });
        });

    if !open {
        close_qr_dialog(ui);
    }
}

fn show_add_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let mut open = true;
    egui::Window::new("Add user")
        .collapsible(false)
        .resizable(false)
        .default_width(420.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            let (mut email, mut uuid, mut flow, mut level_text, mut reverse, error, diff_preview) =
                with_dialog_draft(ui, |draft| {
                    let ClientDialogDraft::AddVless {
                        email,
                        uuid,
                        flow,
                        level,
                        reverse,
                        error,
                        diff_preview,
                        ..
                    } = draft
                    else {
                        return (
                            String::new(),
                            String::new(),
                            VlessFlowChoice::None,
                            "0".to_owned(),
                            ReverseDraftFields::default(),
                            None,
                            None,
                        );
                    };
                    (
                        email.clone(),
                        uuid.clone(),
                        *flow,
                        level.to_string(),
                        reverse.clone(),
                        error.clone(),
                        diff_preview.clone(),
                    )
                });

            ui.label("Email");
            ui.add(egui::TextEdit::singleline(&mut email).desired_width(380.0));
            ui.add_space(6.0);
            ui.label("UUID");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut uuid).desired_width(300.0));
                if ui.button("Generate").clicked() {
                    uuid = generate_client_uuid();
                }
            });
            ui.add_space(6.0);
            ui.label("Flow");
            flow_combo(ui, "add_user_flow", &mut flow);
            ui.add_space(6.0);
            ui.label("Level");
            ui.add(egui::TextEdit::singleline(&mut level_text).desired_width(80.0));
            ui.add_space(6.0);
            reverse_fields_edit(ui, "add_user_reverse_sniffing", &mut reverse);

            if let Some(error) = &error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    let inbound_index = with_dialog_draft(ui, |draft| {
                        if let ClientDialogDraft::AddVless { inbound_index, .. } = draft {
                            Some(*inbound_index)
                        } else {
                            None
                        }
                    });
                    let level = level_text.trim().parse::<u32>().unwrap_or(0);
                    if let Some(inbound_index) = inbound_index {
                        let request = AddUserRequest {
                            inbound_index,
                            email: email.clone(),
                            id: Some(uuid.clone()),
                            flow: flow.to_request(),
                            level,
                            reverse: reverse.to_reverse(),
                        };
                        match service.start_add_user(request) {
                            Ok(()) => close_dialog(ui),
                            Err(message) => {
                                with_dialog_draft(ui, |draft| {
                                    if let ClientDialogDraft::AddVless { error, .. } = draft {
                                        *error = Some(message);
                                    }
                                });
                            }
                        }
                    }
                }
                if ui.button("Preview changes").clicked() {
                    let level = level_text.trim().parse::<u32>().unwrap_or(0);
                    let inbound_index = with_dialog_draft(ui, |draft| {
                        if let ClientDialogDraft::AddVless { inbound_index, .. } = draft {
                            Some(*inbound_index)
                        } else {
                            None
                        }
                    });
                    if let Some(inbound_index) = inbound_index {
                        let request = AddInboundClientRequest::Vless(AddUserRequest {
                            inbound_index,
                            email: email.clone(),
                            id: Some(uuid.clone()),
                            flow: flow.to_request(),
                            level,
                            reverse: reverse.to_reverse(),
                        });
                        match service.preview_add_user_diff(request) {
                            Ok(entries) => with_dialog_draft(ui, |draft| {
                                if let ClientDialogDraft::AddVless { diff_preview, .. } = draft {
                                    *diff_preview = Some(entries);
                                }
                            }),
                            Err(message) => with_dialog_draft(ui, |draft| {
                                if let ClientDialogDraft::AddVless { error, .. } = draft {
                                    *error = Some(message);
                                }
                            }),
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    close_dialog(ui);
                }
            });
            show_user_diff_preview(ui, &diff_preview);

            with_dialog_draft(ui, |draft| {
                if let ClientDialogDraft::AddVless {
                    email: e,
                    uuid: u,
                    flow: f,
                    level,
                    reverse: r,
                    ..
                } = draft
                {
                    *e = email;
                    *u = uuid;
                    *f = flow;
                    *level = level_text.trim().parse::<u32>().unwrap_or(*level);
                    *r = reverse;
                }
            });
        });

    if !open {
        close_dialog(ui);
    }
}

fn show_edit_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let mut open = true;
    egui::Window::new("Edit user")
        .collapsible(false)
        .resizable(false)
        .default_width(420.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            let (
                mut email,
                uuid,
                mut flow,
                mut level_text,
                mut reverse,
                unsupported_hint,
                error,
                diff_preview,
            ) = with_dialog_draft(ui, |draft| {
                    let ClientDialogDraft::EditVless {
                        email,
                        uuid,
                        flow,
                        unsupported_flow_hint,
                        level,
                        reverse,
                        error,
                        diff_preview,
                        ..
                    } = draft
                    else {
                        return (
                            String::new(),
                            String::new(),
                            VlessFlowChoice::None,
                            "0".to_owned(),
                            ReverseDraftFields::default(),
                            None,
                            None,
                            None,
                        );
                    };
                    (
                        email.clone(),
                        uuid.clone(),
                        *flow,
                        level.to_string(),
                        reverse.clone(),
                        unsupported_flow_hint.clone(),
                        error.clone(),
                        diff_preview.clone(),
                    )
                });

            ui.label("Email");
            ui.add(egui::TextEdit::singleline(&mut email).desired_width(380.0));
            ui.add_space(6.0);
            ui.label("UUID");
            ui.add_enabled(
                false,
                egui::TextEdit::singleline(&mut uuid.clone()).desired_width(380.0),
            );
            ui.label(
                RichText::new("UUID cannot be changed (it identifies existing VLESS links).")
                    .size(12.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
            ui.add_space(6.0);
            ui.label("Flow");
            flow_combo(ui, "edit_user_flow", &mut flow);
            if let Some(unsupported) = &unsupported_hint {
                ui.label(
                    RichText::new(format!(
                        "Config had unsupported flow `{unsupported}`. Choose an allowed value or None."
                    ))
                    .size(12.0)
                    .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(6.0);
            ui.label("Level");
            ui.add(egui::TextEdit::singleline(&mut level_text).desired_width(80.0));
            ui.add_space(6.0);
            reverse_fields_edit(ui, "edit_user_reverse_sniffing", &mut reverse);

            if let Some(error) = &error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    let (inbound_index, client_index, fingerprint) =
                        with_dialog_draft(ui, |draft| {
                            if let ClientDialogDraft::EditVless {
                                inbound_index,
                                client_index,
                                expected_fingerprint,
                                ..
                            } = draft
                            {
                                (
                                    Some(*inbound_index),
                                    Some(*client_index),
                                    expected_fingerprint.clone(),
                                )
                            } else {
                                (None, None, String::new())
                            }
                        });
                    let level = level_text.trim().parse::<u32>().unwrap_or(0);
                    if let (Some(inbound_index), Some(client_index)) =
                        (inbound_index, client_index)
                    {
                        let request = UpdateUserRequest {
                            inbound_index,
                            client_index,
                            email: email.clone(),
                            flow: flow.to_request(),
                            level,
                            reverse: reverse.to_reverse(),
                            expected_fingerprint: Some(fingerprint),
                        };
                        match service.start_update_user(request) {
                            Ok(()) => close_dialog(ui),
                            Err(message) => {
                                with_dialog_draft(ui, |draft| {
                                    if let ClientDialogDraft::EditVless { error, .. } = draft {
                                        *error = Some(message);
                                    }
                                });
                            }
                        }
                    }
                }
                if ui.button("Preview changes").clicked() {
                    let (inbound_index, client_index, fingerprint) =
                        with_dialog_draft(ui, |draft| {
                            if let ClientDialogDraft::EditVless {
                                inbound_index,
                                client_index,
                                expected_fingerprint,
                                ..
                            } = draft
                            {
                                (
                                    Some(*inbound_index),
                                    Some(*client_index),
                                    expected_fingerprint.clone(),
                                )
                            } else {
                                (None, None, String::new())
                            }
                        });
                    let level = level_text.trim().parse::<u32>().unwrap_or(0);
                    if let (Some(inbound_index), Some(client_index)) =
                        (inbound_index, client_index)
                    {
                        let request = UpdateInboundClientRequest::Vless(UpdateUserRequest {
                            inbound_index,
                            client_index,
                            email: email.clone(),
                            flow: flow.to_request(),
                            level,
                            reverse: reverse.to_reverse(),
                            expected_fingerprint: Some(fingerprint),
                        });
                        match service.preview_update_user_diff(request) {
                            Ok(entries) => with_dialog_draft(ui, |draft| {
                                if let ClientDialogDraft::EditVless { diff_preview, .. } = draft {
                                    *diff_preview = Some(entries);
                                }
                            }),
                            Err(message) => with_dialog_draft(ui, |draft| {
                                if let ClientDialogDraft::EditVless { error, .. } = draft {
                                    *error = Some(message);
                                }
                            }),
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    close_dialog(ui);
                }
            });
            show_user_diff_preview(ui, &diff_preview);

            with_dialog_draft(ui, |draft| {
                if let ClientDialogDraft::EditVless {
                    email: e,
                    flow: f,
                    level,
                    reverse: r,
                    ..
                } = draft
                {
                    *e = email;
                    *f = flow;
                    *level = level_text.trim().parse::<u32>().unwrap_or(*level);
                    *r = reverse;
                }
            });
        });

    if !open {
        close_dialog(ui);
    }
}

fn show_delete_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let mut open = true;
    egui::Window::new("Delete user")
        .collapsible(false)
        .resizable(false)
        .default_width(360.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            let (email, error) = with_dialog_draft(ui, |draft| {
                if let ClientDialogDraft::DeleteVless {
                    email_label,
                    error,
                    ..
                } = draft
                {
                    (email_label.clone(), error.clone())
                } else {
                    (String::new(), None)
                }
            });
            ui.label(RichText::new(format!("Delete user {email}?")).size(14.0));
            if let Some(error) = error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error)
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Delete").clicked() {
                    let (inbound_index, client_index, fingerprint) =
                        with_dialog_draft(ui, |draft| {
                            if let ClientDialogDraft::DeleteVless {
                                inbound_index,
                                client_index,
                                expected_fingerprint,
                                ..
                            } = draft
                            {
                                (
                                    Some(*inbound_index),
                                    Some(*client_index),
                                    expected_fingerprint.clone(),
                                )
                            } else {
                                (None, None, String::new())
                            }
                        });
                    if let (Some(inbound_index), Some(client_index)) =
                        (inbound_index, client_index)
                    {
                        match service.start_delete_user(DeleteUserRequest {
                            inbound_index,
                            client_index,
                            expected_fingerprint: Some(fingerprint),
                        }) {
                            Ok(()) => close_dialog(ui),
                            Err(message) => {
                                with_dialog_draft(ui, |draft| {
                                    if let ClientDialogDraft::DeleteVless { error, .. } = draft {
                                        *error = Some(message);
                                    }
                                });
                            }
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    close_dialog(ui);
                }
            });
        });

    if !open {
        close_dialog(ui);
    }
}
