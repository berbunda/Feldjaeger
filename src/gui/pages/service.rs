//! Service page — remote Xray lifecycle control + unit Create/Edit via ApplicationService.
//!
//! The GUI never executes SSH commands, invokes systemctl, or parses
//! command output. All actions go through [`ApplicationService`].

use egui::{Color32, Id, RichText, ScrollArea, TextEdit, Ui, Vec2};

use crate::app::{
    ApplicationService, ServiceControlState, ServiceOperation, ServicePageModel, UnitApplyRequest,
};
use crate::init::{
    ServiceState, UnitConfigLayout, UnitRunUser, UnitSpec, preview_exec_start, render_unit,
};
use crate::xray::InitSystemKind;
use feldjaeger_ssh::RemotePath;

/// Temporary dialog / form state stored in egui memory.
#[derive(Clone, Default)]
struct ServiceDialogState {
    mode: ServiceDialogMode,
    error: Option<String>,
    /// Draft unit form (Create/Edit).
    form: Option<UnitFormState>,
    sudo_password: String,
    enable_and_start: bool,
    preview: String,
    confirm_unit_body: String,
}

#[derive(Clone, Default)]
struct UnitFormState {
    create: bool,
    unit_name: String,
    binary: String,
    confdir: bool,
    config_path: String,
    user_root: bool,
    wanted_by: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum ServiceDialogMode {
    #[default]
    None,
    Confirm(ServiceOperation),
    UnitForm,
    UnitConfirm,
    RestartAfterApply,
}

fn service_dialog_id() -> Id {
    Id::new("feldjaeger_service_dialog")
}

/// Renders the Service page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Service");
    ui.add_space(8.0);

    let model = service.service_page_model();
    maybe_start_probe(service, &model);

    show_summary(ui, &model);
    ui.add_space(12.0);

    if let Some(reason) = model.blocked_reason {
        let color = if reason == "Do not attempt service management." {
            Color32::from_rgb(210, 170, 40)
        } else {
            Color32::from_rgb(140, 140, 140)
        };
        ui.label(RichText::new(reason).size(14.0).color(color));
    }

    if let ServiceControlState::Failed { kind, detail } = &model.control {
        ui.add_space(8.0);
        ui.label(
            RichText::new(kind.label())
                .size(14.0)
                .color(Color32::from_rgb(200, 60, 60)),
        );
        ui.label(
            RichText::new(detail.clone())
                .size(14.0)
                .color(Color32::from_rgb(200, 60, 60)),
        );
    }

    let busy = model.control.is_busy() || service.unit_apply_busy();

    if model.unit_create_allowed || model.unit_edit_allowed {
        ui.add_space(8.0);
        ui.strong("Unit file");
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if model.unit_create_allowed {
                let label = if model.service_name.is_some() {
                    "Create / override unit"
                } else {
                    "Create unit"
                };
                if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
                    open_unit_form(ui, service, true);
                }
            }
            if model.unit_edit_allowed {
                if ui
                    .add_enabled(!busy, egui::Button::new("Edit unit"))
                    .clicked()
                {
                    open_unit_form(ui, service, false);
                }
            }
        });
    }

    if model.lifecycle_allowed {
        ui.add_space(8.0);
        show_actions(ui, service, busy);
    }

    if service.take_unit_apply_restart_prompt() {
        with_dialog_state(ui, |state| {
            state.mode = ServiceDialogMode::RestartAfterApply;
            state.error = None;
        });
    }

    show_dialogs(ui, service);
}

fn maybe_start_probe(service: &mut ApplicationService, model: &ServicePageModel) {
    if !model.discovery_ready {
        return;
    }
    if !matches!(model.init_system, Some(InitSystemKind::Systemd)) {
        return;
    }
    if model.unit_probe.is_some() {
        return;
    }
    let name = model
        .service_name
        .as_deref()
        .unwrap_or("xray.service");
    let _ = service.start_unit_host_probe(name);
}

fn open_unit_form(ui: &Ui, service: &mut ApplicationService, create: bool) {
    match service.unit_spec_from_discovery(create) {
        Ok(spec) => {
            let form = UnitFormState {
                create,
                unit_name: spec.unit_name.as_str().to_owned(),
                binary: spec.binary.as_str().to_owned(),
                confdir: matches!(spec.config, UnitConfigLayout::ConfigDirectory(_)),
                config_path: spec.config.path().as_str().to_owned(),
                user_root: matches!(spec.user, UnitRunUser::Root),
                wanted_by: spec.wanted_by.clone(),
            };
            let preview = preview_from_form(&form).unwrap_or_default();
            if !create {
                // Fetch the current remote unit body for the before/after diff (Roadmap
                // §3:126); read-only, never on the Apply path. Best-effort — Apply still works
                // if the fetch fails.
                let _ = service.start_fetch_unit_file(&form.unit_name);
            }
            with_dialog_state(ui, |state| {
                *state = ServiceDialogState {
                    mode: ServiceDialogMode::UnitForm,
                    error: None,
                    form: Some(form),
                    sudo_password: String::new(),
                    enable_and_start: false,
                    preview,
                    confirm_unit_body: String::new(),
                };
            });
        }
        Err(message) => {
            with_dialog_state(ui, |state| {
                state.error = Some(message);
            });
        }
    }
}

fn form_to_spec(form: &UnitFormState) -> Result<UnitSpec, String> {
    use crate::init::{ServiceName, DEFAULT_UNIT_DESCRIPTION};

    let unit_name = ServiceName::new(form.unit_name.trim()).map_err(|e| e.message().to_owned())?;
    let binary = RemotePath::new(form.binary.trim()).map_err(|e| e.message().to_owned())?;
    let config_path =
        RemotePath::new(form.config_path.trim()).map_err(|e| e.message().to_owned())?;
    let config = if form.confdir {
        UnitConfigLayout::ConfigDirectory(config_path)
    } else {
        UnitConfigLayout::SingleFile(config_path)
    };
    Ok(UnitSpec {
        unit_name,
        description: DEFAULT_UNIT_DESCRIPTION.to_owned(),
        binary,
        config,
        user: if form.user_root {
            UnitRunUser::Root
        } else {
            UnitRunUser::Nobody
        },
        wanted_by: if form.wanted_by.trim().is_empty() {
            "multi-user.target".to_owned()
        } else {
            form.wanted_by.trim().to_owned()
        },
    })
}

fn preview_from_form(form: &UnitFormState) -> Result<String, String> {
    let spec = form_to_spec(form)?;
    preview_exec_start(&spec).map_err(|e| e.message())
}

/// Shows a before/after line diff of the unit file body for Edit mode (Roadmap §3:126) — Edit
/// fully replaces the file, so this makes the "unmodeled keys will be dropped" warning above
/// concrete instead of just a static sentence.
fn show_unit_body_diff(ui: &mut Ui, service: &ApplicationService, form: &UnitFormState) {
    match service.unit_file_diff_result() {
        None => {
            ui.label(
                RichText::new("Fetching current unit file for comparison...")
                    .size(12.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
        }
        Some(Err(error)) => {
            ui.label(
                RichText::new(format!(
                    "Could not read the current unit file for comparison: {error}"
                ))
                .size(12.0)
                .color(Color32::from_rgb(210, 170, 40)),
            );
        }
        Some(Ok(None)) => {
            ui.label(
                RichText::new(
                    "No existing unit file found on the remote host — everything above will be newly created.",
                )
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
            );
        }
        Some(Ok(Some(current))) => {
            let new_body = form_to_spec(form)
                .and_then(|spec| render_unit(&spec).map_err(|e| e.message()))
                .unwrap_or_default();
            let entries = crate::xray::redacted_json_diff_lines(current, &new_body);
            super::json_diff_preview(ui, &entries);
        }
    }
}

fn show_summary(ui: &mut Ui, model: &ServicePageModel) {
    egui::Grid::new("service_summary")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Service").strong());
            ui.label(
                model
                    .service_name
                    .clone()
                    .unwrap_or_else(|| "—".to_owned()),
            );
            ui.end_row();

            ui.label(RichText::new("Init").strong());
            ui.label(
                model
                    .init_system
                    .map(InitSystemKind::label)
                    .unwrap_or("—")
                    .to_owned(),
            );
            ui.end_row();

            ui.label(RichText::new("State").strong());
            match model.state {
                Some(state) => {
                    ui.label(RichText::new(state.label()).color(state_color(state)));
                }
                None => {
                    ui.label("—");
                }
            }
            ui.end_row();
        });
}

fn state_color(state: ServiceState) -> Color32 {
    match state {
        ServiceState::Running => Color32::from_rgb(46, 160, 67),
        ServiceState::Failed => Color32::from_rgb(200, 60, 60),
        ServiceState::Stopped | ServiceState::Inactive => Color32::from_rgb(210, 170, 40),
        ServiceState::Unknown => Color32::from_rgb(140, 140, 140),
    }
}

fn show_actions(ui: &mut Ui, service: &mut ApplicationService, busy: bool) {
    ui.strong("Operations");
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        for operation in [
            ServiceOperation::Start,
            ServiceOperation::Stop,
            ServiceOperation::Restart,
            ServiceOperation::Reload,
            ServiceOperation::Enable,
            ServiceOperation::Disable,
        ] {
            let button = ui.add_enabled(!busy, egui::Button::new(operation.button_label()));
            if button.clicked() {
                if operation.confirmation_prompt().is_some() {
                    open_confirm_dialog(ui, operation);
                } else if let Err(message) = service.start_service_operation(operation) {
                    with_dialog_state(ui, |state| {
                        state.error = Some(message);
                    });
                }
            }
        }
    });

    let immediate_error = with_dialog_state(ui, |state| {
        if state.mode == ServiceDialogMode::None {
            state.error.clone()
        } else {
            None
        }
    });
    if let Some(error) = immediate_error {
        ui.add_space(8.0);
        ui.label(
            RichText::new(error)
                .size(14.0)
                .color(Color32::from_rgb(200, 60, 60)),
        );
    }
}

fn with_dialog_state<R>(ui: &Ui, f: impl FnOnce(&mut ServiceDialogState) -> R) -> R {
    ui.ctx().data_mut(|data| {
        let state = data.get_temp_mut_or_default::<ServiceDialogState>(service_dialog_id());
        f(state)
    })
}

fn open_confirm_dialog(ui: &Ui, operation: ServiceOperation) {
    with_dialog_state(ui, |state| {
        *state = ServiceDialogState {
            mode: ServiceDialogMode::Confirm(operation),
            error: None,
            form: None,
            sudo_password: String::new(),
            enable_and_start: false,
            preview: String::new(),
            confirm_unit_body: String::new(),
        };
    });
}

fn close_dialog(ui: &Ui) {
    with_dialog_state(ui, |state| {
        *state = ServiceDialogState::default();
    });
}

fn show_dialogs(ui: &mut Ui, service: &mut ApplicationService) {
    let mode = with_dialog_state(ui, |state| state.mode);
    match mode {
        ServiceDialogMode::Confirm(operation) => show_confirm_dialog(ui, service, operation),
        ServiceDialogMode::UnitForm => show_unit_form_dialog(ui, service),
        ServiceDialogMode::UnitConfirm => show_unit_confirm_dialog(ui, service),
        ServiceDialogMode::RestartAfterApply => show_restart_after_apply(ui, service),
        ServiceDialogMode::None => {}
    }
}

fn show_confirm_dialog(ui: &mut Ui, service: &mut ApplicationService, operation: ServiceOperation) {
    let prompt = operation
        .confirmation_prompt()
        .unwrap_or("Confirm operation?");
    let mut open = true;

    egui::Window::new("Confirm")
        .collapsible(false)
        .resizable(false)
        .default_size(Vec2::new(360.0, 120.0))
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(RichText::new(prompt).size(14.0));
            let error = with_dialog_state(ui, |state| state.error.clone());
            if let Some(error) = error {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(error)
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    close_dialog(ui);
                }
                if ui.button("Confirm").clicked() {
                    match service.start_service_operation(operation) {
                        Ok(()) => close_dialog(ui),
                        Err(message) => {
                            with_dialog_state(ui, |state| {
                                state.error = Some(message);
                            });
                        }
                    }
                }
            });
        });

    if !open {
        close_dialog(ui);
    }
}

fn show_unit_form_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let mut open = true;
    egui::Window::new("Unit file")
        .collapsible(false)
        .resizable(true)
        .default_size(Vec2::new(520.0, 420.0))
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            let mut form = with_dialog_state(ui, |state| state.form.clone()).unwrap_or_default();
            let create = form.create;
            ui.label(if create {
                "Create / override systemd unit"
            } else {
                "Edit systemd unit (full replace — unmodeled keys will be dropped)"
            });
            ui.add_space(8.0);

            egui::Grid::new("unit_form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Unit name");
                    ui.add_enabled(
                        create,
                        TextEdit::singleline(&mut form.unit_name).desired_width(280.0),
                    );
                    ui.end_row();

                    ui.label("Binary");
                    ui.add(TextEdit::singleline(&mut form.binary).desired_width(280.0));
                    ui.end_row();

                    ui.label("Layout");
                    ui.horizontal(|ui| {
                        if ui.radio_value(&mut form.confdir, false, "Single file").clicked() {
                            // keep path
                        }
                        ui.radio_value(&mut form.confdir, true, "Confdir");
                    });
                    ui.end_row();

                    ui.label(if form.confdir {
                        "Config directory"
                    } else {
                        "Config file"
                    });
                    ui.add(TextEdit::singleline(&mut form.config_path).desired_width(280.0));
                    ui.end_row();

                    ui.label("User");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut form.user_root, false, "nobody");
                        ui.radio_value(&mut form.user_root, true, "root");
                    });
                    ui.end_row();

                    ui.label("WantedBy");
                    ui.add(TextEdit::singleline(&mut form.wanted_by).desired_width(280.0));
                    ui.end_row();
                });

            let preview = preview_from_form(&form).unwrap_or_else(|e| e);
            ui.add_space(8.0);
            ui.label(RichText::new("ExecStart preview").strong());
            ui.label(RichText::new(&preview).monospace());

            if !create {
                ui.add_space(8.0);
                show_unit_body_diff(ui, service, &form);
            }

            let error = with_dialog_state(ui, |state| state.error.clone());
            if let Some(error) = error {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(error)
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }

            with_dialog_state(ui, |state| {
                state.form = Some(form.clone());
                state.preview = preview;
            });

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    close_dialog(ui);
                }
                if ui.button("Review…").clicked() {
                    match form_to_spec(&form).and_then(|spec| {
                        render_unit(&spec).map_err(|e| e.message())
                    }) {
                        Ok(body) => {
                            with_dialog_state(ui, |state| {
                                state.confirm_unit_body = body;
                                state.mode = ServiceDialogMode::UnitConfirm;
                                state.error = None;
                                state.sudo_password.clear();
                            });
                        }
                        Err(message) => {
                            with_dialog_state(ui, |state| {
                                state.error = Some(message);
                            });
                        }
                    }
                }
            });
        });
    if !open {
        close_dialog(ui);
    }
}

fn show_unit_confirm_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let mut open = true;
    let needs_sudo = service
        .service_page_model()
        .unit_probe
        .map(|p| !p.can_write_unit_dir)
        .unwrap_or(true);

    egui::Window::new("Apply unit")
        .collapsible(false)
        .resizable(true)
        .default_size(Vec2::new(560.0, 480.0))
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            let create = with_dialog_state(ui, |s| {
                s.form.as_ref().map(|f| f.create).unwrap_or(true)
            });
            if !create {
                ui.label(
                    RichText::new(
                        "Warning: full replace — keys not modeled in Feldjaeger will be dropped.",
                    )
                    .color(Color32::from_rgb(210, 170, 40)),
                );
                ui.add_space(6.0);
            }

            let body = with_dialog_state(ui, |s| s.confirm_unit_body.clone());
            ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                ui.label(RichText::new(body).monospace());
            });

            ui.add_space(8.0);
            let mut enable = with_dialog_state(ui, |s| s.enable_and_start);
            ui.checkbox(&mut enable, "Enable and start after Apply");
            with_dialog_state(ui, |s| s.enable_and_start = enable);

            if needs_sudo {
                ui.add_space(6.0);
                ui.label("Sudo password (sent only via sudo -S stdin; never logged)");
                let mut pw = with_dialog_state(ui, |s| s.sudo_password.clone());
                ui.add(
                    TextEdit::singleline(&mut pw)
                        .password(true)
                        .desired_width(280.0),
                );
                with_dialog_state(ui, |s| s.sudo_password = pw);
            }

            let error = with_dialog_state(ui, |s| s.error.clone());
            if let Some(error) = error {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(error)
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Back").clicked() {
                    with_dialog_state(ui, |s| {
                        s.mode = ServiceDialogMode::UnitForm;
                        s.error = None;
                    });
                }
                if ui.button("Apply").clicked() {
                    let (form, enable_and_start, sudo_password) = with_dialog_state(ui, |s| {
                        (
                            s.form.clone(),
                            s.enable_and_start,
                            if needs_sudo {
                                Some(s.sudo_password.clone())
                            } else {
                                None
                            },
                        )
                    });
                    // Wipe password from dialog state immediately after copy
                    with_dialog_state(ui, |s| s.sudo_password.clear());

                    let Some(form) = form else {
                        return;
                    };
                    match form_to_spec(&form) {
                        Ok(spec) => {
                            let request = UnitApplyRequest {
                                spec,
                                sudo_password,
                                enable_and_start,
                            };
                            match service.start_unit_apply(request) {
                                Ok(()) => close_dialog(ui),
                                Err(message) => {
                                    with_dialog_state(ui, |s| s.error = Some(message));
                                }
                            }
                        }
                        Err(message) => {
                            with_dialog_state(ui, |s| s.error = Some(message));
                        }
                    }
                }
            });
        });
    if !open {
        close_dialog(ui);
    }
}

fn show_restart_after_apply(ui: &mut Ui, service: &mut ApplicationService) {
    let mut open = true;
    egui::Window::new("Restart service?")
        .collapsible(false)
        .resizable(false)
        .default_size(Vec2::new(400.0, 140.0))
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                "Unit file updated. The running process still uses the previous ExecStart until Restart.",
            );
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Not now").clicked() {
                    close_dialog(ui);
                }
                if ui.button("Restart now").clicked() {
                    match service.start_service_operation(ServiceOperation::Restart) {
                        Ok(()) => close_dialog(ui),
                        Err(message) => {
                            with_dialog_state(ui, |s| s.error = Some(message));
                        }
                    }
                }
            });
        });
    if !open {
        close_dialog(ui);
    }
}
