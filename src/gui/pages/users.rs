//! Users page — VLESS client list with Add / Edit / Delete actions.
//!
//! Data and mutations flow exclusively through [`ApplicationService`].
//! This page never reads JSON, opens SSH, or mutates remote configuration directly.

use egui::{Color32, ComboBox, RichText, Sense, Ui, Vec2};

use crate::app::{
    AddUserRequest, ApplicationService, DeleteUserRequest, MISSING_FIELD, UpdateUserRequest,
    UsersPageState, UsersSortColumn, generate_client_uuid, user_row_display,
};
use crate::xray::UserSummary;

/// Local UI state for Users page dialogs (owned by the page renderer via egui memory).
#[derive(Debug, Clone, Default)]
struct UsersDialogState {
    mode: UsersDialogMode,
    email: String,
    uuid: String,
    flow: String,
    inbound_index: Option<usize>,
    client_index: Option<usize>,
    error: Option<String>,
    delete_email: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum UsersDialogMode {
    #[default]
    None,
    Add,
    Edit,
    DeleteConfirm,
}

/// Renders the Users page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Users");
    ui.add_space(8.0);

    let model = service.users_page_model();

    match model.state {
        UsersPageState::NoSshConnection
        | UsersPageState::XrayNotDiscovered
        | UsersPageState::ConfigurationNotLoaded
        | UsersPageState::NoSupportedInboundSelected => {
            show_state_message(ui, model.state);
            return;
        }
        UsersPageState::SelectedInboundHasNoUsers => {
            show_inbound_selector(
                ui,
                service,
                &model.inbound_choices,
                model.selected_inbound_index,
            );
            ui.add_space(8.0);
            show_action_bar(ui, service, model.selected_inbound_index, None);
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
            show_inbound_selector(
                ui,
                service,
                &model.inbound_choices,
                model.selected_inbound_index,
            );
            ui.add_space(8.0);
            let model = service.users_page_model();
            let selected = selected_table_row(ui, &model.rows);
            show_action_bar(ui, service, model.selected_inbound_index, selected);
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
        UsersPageState::UsersLoaded => {
            show_inbound_selector(
                ui,
                service,
                &model.inbound_choices,
                model.selected_inbound_index,
            );
            ui.add_space(8.0);
            let model = service.users_page_model();
            let selected = selected_table_row(ui, &model.rows);
            show_action_bar(ui, service, model.selected_inbound_index, selected);
            ui.add_space(8.0);
            if !model.rows.is_empty() {
                show_table(ui, service, &model.rows);
            }
        }
    }

    show_dialogs(ui, service);
}

fn show_state_message(ui: &mut Ui, state: UsersPageState) {
    let color = match state {
        UsersPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        UsersPageState::SelectedInboundHasNoUsers
        | UsersPageState::NoSupportedInboundSelected
        | UsersPageState::UsersLoaded => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_inbound_selector(
    ui: &mut Ui,
    service: &mut ApplicationService,
    choices: &[crate::xray::SupportedUserInbound],
    selected: Option<usize>,
) {
    if choices.is_empty() {
        return;
    }

    ui.horizontal(|ui| {
        ui.label("Inbound:");
        let selected_index = selected.unwrap_or(choices[0].inbound_index);
        let selected_label = choices
            .iter()
            .find(|choice| choice.inbound_index == selected_index)
            .map(crate::xray::SupportedUserInbound::label)
            .unwrap_or_else(|| "—".to_owned());

        ComboBox::from_id_salt("users_inbound_selector")
            .selected_text(selected_label)
            .width(360.0)
            .show_ui(ui, |ui| {
                for choice in choices {
                    let checked = choice.inbound_index == selected_index;
                    if ui.selectable_label(checked, choice.label()).clicked() {
                        service.set_selected_users_inbound(choice.inbound_index);
                    }
                }
            });
    });
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
            open_edit_dialog(ui, row);
        }
        if ui
            .add_enabled(!busy && selected_row.is_some(), egui::Button::new("Delete"))
            .clicked()
            && let Some(row) = selected_row
        {
            open_delete_dialog(ui, row);
        }
    });
}

fn show_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[UserSummary]) {
    let sort = service.users_sort();
    let busy = service.is_user_mutation_busy();
    let selected_key = selected_row_key(ui);

    egui::Grid::new("users_table")
        .num_columns(5)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(80.0)
        .show(ui, |ui| {
            sortable_header(ui, service, "Email", UsersSortColumn::Email, sort.column);
            sortable_header(ui, service, "UUID / ID", UsersSortColumn::Uuid, sort.column);
            ui.strong("Flow");
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
                if cell_with_menu(ui, row, &email_text, busy) {
                    set_selected_row(ui, row);
                }
                cell_with_menu(ui, row, &display.id, busy);
                cell_with_menu(ui, row, &display.flow, busy);
                cell_with_menu(ui, row, &display.inbound_tag, busy);
                cell_with_menu(ui, row, display.source_file, busy);
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

fn cell_with_menu(ui: &mut Ui, row: &UserSummary, text: &str, busy: bool) -> bool {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    let clicked = response.clicked();
    show_user_context_menu(&response, row, busy);
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

fn show_user_context_menu(response: &egui::Response, row: &UserSummary, busy: bool) {
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

        ui.separator();

        if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            open_edit_dialog(ui, row);
            ui.close();
        }
        if ui.add_enabled(!busy, egui::Button::new("Delete")).clicked() {
            open_delete_dialog(ui, row);
            ui.close();
        }
        ui.add_enabled(false, egui::Button::new("Generate VLESS link"))
            .on_disabled_hover_text("Not implemented yet");
    });
}

fn users_dialog_id() -> egui::Id {
    egui::Id::new("users_page_dialog_state")
}

fn with_dialog_state<R>(ui: &Ui, f: impl FnOnce(&mut UsersDialogState) -> R) -> R {
    ui.ctx().data_mut(|data| {
        let state = data.get_temp_mut_or_default::<UsersDialogState>(users_dialog_id());
        f(state)
    })
}

fn open_add_dialog(ui: &Ui, inbound_index: usize) {
    with_dialog_state(ui, |state| {
        *state = UsersDialogState {
            mode: UsersDialogMode::Add,
            email: String::new(),
            uuid: generate_client_uuid(),
            flow: String::new(),
            inbound_index: Some(inbound_index),
            client_index: None,
            error: None,
            delete_email: None,
        };
    });
}

fn open_edit_dialog(ui: &Ui, row: &UserSummary) {
    with_dialog_state(ui, |state| {
        *state = UsersDialogState {
            mode: UsersDialogMode::Edit,
            email: row.email.clone().unwrap_or_default(),
            uuid: row.id.clone().unwrap_or_default(),
            flow: row.flow.clone().unwrap_or_default(),
            inbound_index: Some(row.inbound_index),
            client_index: Some(row.client_index),
            error: None,
            delete_email: None,
        };
    });
}

fn open_delete_dialog(ui: &Ui, row: &UserSummary) {
    with_dialog_state(ui, |state| {
        *state = UsersDialogState {
            mode: UsersDialogMode::DeleteConfirm,
            email: String::new(),
            uuid: String::new(),
            flow: String::new(),
            inbound_index: Some(row.inbound_index),
            client_index: Some(row.client_index),
            error: None,
            delete_email: Some(
                row.email
                    .clone()
                    .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            ),
        };
    });
}

fn close_dialog(ui: &Ui) {
    with_dialog_state(ui, |state| {
        *state = UsersDialogState::default();
    });
}

fn show_dialogs(ui: &mut Ui, service: &mut ApplicationService) {
    let mode = with_dialog_state(ui, |state| state.mode);
    match mode {
        UsersDialogMode::None => {}
        UsersDialogMode::Add => show_add_dialog(ui, service),
        UsersDialogMode::Edit => show_edit_dialog(ui, service),
        UsersDialogMode::DeleteConfirm => show_delete_dialog(ui, service),
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
            let (mut email, mut uuid, mut flow, error) = with_dialog_state(ui, |state| {
                (
                    state.email.clone(),
                    state.uuid.clone(),
                    state.flow.clone(),
                    state.error.clone(),
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
            ui.add(egui::TextEdit::singleline(&mut flow).desired_width(380.0));

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
                    let inbound_index = with_dialog_state(ui, |state| state.inbound_index);
                    if let Some(inbound_index) = inbound_index {
                        let request = AddUserRequest {
                            inbound_index,
                            email: email.clone(),
                            id: Some(uuid.clone()),
                            flow: if flow.trim().is_empty() {
                                None
                            } else {
                                Some(flow.clone())
                            },
                        };
                        match service.start_add_user(request) {
                            Ok(()) => close_dialog(ui),
                            Err(message) => {
                                with_dialog_state(ui, |state| {
                                    state.error = Some(message);
                                });
                            }
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    close_dialog(ui);
                }
            });

            with_dialog_state(ui, |state| {
                state.email = email;
                state.uuid = uuid;
                state.flow = flow;
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
            let (mut email, uuid, mut flow, error) = with_dialog_state(ui, |state| {
                (
                    state.email.clone(),
                    state.uuid.clone(),
                    state.flow.clone(),
                    state.error.clone(),
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
            ui.add(egui::TextEdit::singleline(&mut flow).desired_width(380.0));

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
                    let (inbound_index, client_index) =
                        with_dialog_state(ui, |state| (state.inbound_index, state.client_index));
                    if let (Some(inbound_index), Some(client_index)) = (inbound_index, client_index)
                    {
                        let request = UpdateUserRequest {
                            inbound_index,
                            client_index,
                            email: email.clone(),
                            flow: if flow.trim().is_empty() {
                                None
                            } else {
                                Some(flow.clone())
                            },
                        };
                        match service.start_update_user(request) {
                            Ok(()) => close_dialog(ui),
                            Err(message) => {
                                with_dialog_state(ui, |state| {
                                    state.error = Some(message);
                                });
                            }
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    close_dialog(ui);
                }
            });

            with_dialog_state(ui, |state| {
                state.email = email;
                state.flow = flow;
            });
        });

    if !open {
        close_dialog(ui);
    }
}

fn show_delete_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let mut open = true;
    let email = with_dialog_state(ui, |state| {
        state
            .delete_email
            .clone()
            .unwrap_or_else(|| MISSING_FIELD.to_owned())
    });

    egui::Window::new("Delete user")
        .collapsible(false)
        .resizable(false)
        .default_size(Vec2::new(360.0, 120.0))
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(RichText::new(format!("Delete user {email}?")).size(14.0));
            let error = with_dialog_state(ui, |state| state.error.clone());
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
                    let (inbound_index, client_index) =
                        with_dialog_state(ui, |state| (state.inbound_index, state.client_index));
                    if let (Some(inbound_index), Some(client_index)) = (inbound_index, client_index)
                    {
                        match service.start_delete_user(DeleteUserRequest {
                            inbound_index,
                            client_index,
                        }) {
                            Ok(()) => close_dialog(ui),
                            Err(message) => {
                                with_dialog_state(ui, |state| {
                                    state.error = Some(message);
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
