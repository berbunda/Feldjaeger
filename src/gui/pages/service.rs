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

use super::HelpText;

// ─── Help text (Roadmap §4.4) ─────────────────────────────────────────────────
//
// From `init::unit` (`render_unit`, `install_or_replace_unit`), `init::systemd` and
// `app::service_control`.

const HELP_OPERATIONS: HelpText = HelpText::new(
    "Start / Stop / Restart run systemctl for the unit. Xray reads its configuration only at \
     start: changes saved on any page take effect after Restart — there is no reload, Xray has \
     no hot reload. Enable — start at boot (systemctl enable, the unit's WantedBy target); it \
     does not start the service now. Disable — no start at boot; a running service keeps \
     running. Stop, Restart and Disable ask for confirmation. A unit created here has \
     Restart=on-failure: systemd restarts Xray after a crash, but not after Stop.",
    "Start / Stop / Restart выполняют systemctl для unit. Xray читает конфигурацию только при \
     запуске: изменения, сохранённые на любой странице, вступают в силу после Restart — reload \
     нет, горячей перезагрузки у Xray нет. Enable — запуск при загрузке системы (systemctl \
     enable, цель WantedBy unit); сервис сейчас не запускается. Disable — без запуска при \
     загрузке; работающий сервис продолжает работать. Stop, Restart и Disable просят \
     подтверждения. У unit, созданного здесь, есть Restart=on-failure: systemd перезапускает \
     Xray после сбоя, но не после Stop.",
);
const HELP_UNIT_FILE: HelpText = HelpText::new(
    "Feldjäger writes the whole file /etc/systemd/system/<unit name>: [Unit] Description, After= \
     network.target nss-lookup.target; [Service] User=, capabilities, ExecStart=, \
     Restart=on-failure, LimitNPROC=10000; [Install] WantedBy=. A unit in /etc/systemd/system \
     takes precedence over one with the same name in /usr/lib/systemd/system or \
     /lib/systemd/system (e.g. from a package) — that is the \"override\".\n\n\
     Edit replaces the whole file: lines Feldjäger does not model (Environment=, LimitNOFILE=, \
     …) are dropped — the comparison shows them. Drop-ins in <unit>.d/ are not touched and still \
     apply. Apply backs up an existing file, writes the new one, runs systemctl daemon-reload and \
     restores the backup if that fails.",
    "Feldjäger записывает весь файл /etc/systemd/system/<имя unit>: [Unit] Description, After= \
     network.target nss-lookup.target; [Service] User=, capabilities, ExecStart=, \
     Restart=on-failure, LimitNPROC=10000; [Install] WantedBy=. Unit в /etc/systemd/system \
     важнее одноимённого unit в /usr/lib/systemd/system или /lib/systemd/system (например, из \
     пакета) — это и есть «override».\n\n\
     Edit заменяет файл целиком: строки, которых Feldjäger не знает (Environment=, \
     LimitNOFILE=, …), удаляются — сравнение их показывает. Drop-in файлы в <unit>.d/ не \
     затрагиваются и продолжают действовать. Apply копирует существующий файл, записывает новый, \
     выполняет systemctl daemon-reload и при ошибке восстанавливает копию.",
);
const HELP_UNIT_NAME: HelpText = HelpText::new(
    "Name of the unit file, e.g. xray.service; it can be set only when creating. Template units \
     such as xray@.service are not supported.",
    "Имя unit-файла, например xray.service; задаётся только при создании. Шаблонные unit вроде \
     xray@.service не поддерживаются.",
);
const HELP_UNIT_BINARY: HelpText = HelpText::new(
    "Absolute path of the xray executable on the server, as found by discovery (default \
     /usr/local/bin/xray).",
    "Абсолютный путь к исполняемому файлу xray на сервере, найденный при обнаружении (по \
     умолчанию /usr/local/bin/xray).",
);
const HELP_UNIT_LAYOUT: HelpText = HelpText::new(
    "Single file — ExecStart=<binary> run -config <file>. Confdir — run -confdir <directory>: \
     Xray merges every config file of the directory (see the Config Files page). Before Apply \
     Feldjäger checks that the configuration is readable by others and its parent directories \
     are searchable — what nobody needs; the check is made for root too.",
    "Single file — ExecStart=<бинарник> run -config <файл>. Confdir — run -confdir <каталог>: \
     Xray объединяет все файлы конфигурации каталога (см. страницу Config Files). Перед Apply \
     Feldjäger проверяет, что конфигурация доступна на чтение остальным, а родительские каталоги \
     — на проход, как нужно nobody; проверка выполняется и для root.",
);
const HELP_UNIT_USER: HelpText = HelpText::new(
    "nobody — Xray runs unprivileged with CAP_NET_ADMIN and CAP_NET_BIND_SERVICE (ports below \
     1024, TUN, transparent proxy) and NoNewPrivileges. Configuration, certificates and log \
     files must be accessible to nobody — a log directory it cannot write to stops Xray from \
     starting. root — no restrictions; the capability lines are written commented out.",
    "nobody — Xray работает без привилегий с CAP_NET_ADMIN и CAP_NET_BIND_SERVICE (порты ниже \
     1024, TUN, прозрачный прокси) и NoNewPrivileges. Конфигурация, сертификаты и файлы журналов \
     должны быть доступны nobody — если каталог журнала недоступен на запись, Xray не \
     запустится. root — без ограничений; строки capabilities записываются закомментированными.",
);
const HELP_UNIT_WANTED_BY: HelpText = HelpText::new(
    "[Install] target used by Enable; multi-user.target (the default) starts Xray at a normal \
     boot.",
    "Цель [Install], которую использует Enable; multi-user.target (по умолчанию) запускает Xray \
     при обычной загрузке системы.",
);
const HELP_ENABLE_AND_START: HelpText = HelpText::new(
    "After a successful Apply: systemctl enable (start at boot), then systemctl start. If the \
     service is already running, start does nothing — Feldjäger then offers Restart, so that the \
     new unit takes effect.",
    "После успешного Apply: systemctl enable (запуск при загрузке), затем systemctl start. Если \
     сервис уже работает, start ничего не делает — тогда Feldjäger предлагает Restart, чтобы \
     новый unit вступил в силу.",
);
const HELP_SUDO_PASSWORD: HelpText = HelpText::new(
    "Asked when the SSH user cannot write /etc/systemd/system. The password goes only to sudo -S \
     on standard input, to write the unit and run daemon-reload; it is not saved or logged and is \
     cleared from the dialog right after Apply.",
    "Запрашивается, если пользователь SSH не может писать в /etc/systemd/system. Пароль \
     передаётся только в sudo -S через стандартный ввод — для записи unit и daemon-reload; он не \
     сохраняется, не попадает в журнал и стирается из окна сразу после Apply.",
);

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
    super::show_help_dialog(ui);
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
    ui.horizontal(|ui| {
        super::help_button(ui, "Operations", HELP_OPERATIONS);
        ui.strong("Operations");
    });
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        // Reload is intentionally omitted: xray-core has no config hot-reload and the
        // unit file defines no ExecReload, so `systemctl reload` only ever errors.
        // Use Restart to apply configuration changes.
        for operation in [
            ServiceOperation::Start,
            ServiceOperation::Stop,
            ServiceOperation::Restart,
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
            ui.horizontal(|ui| {
                super::help_button(ui, "Unit file", HELP_UNIT_FILE);
                ui.label(if create {
                    "Create / override systemd unit"
                } else {
                    "Edit systemd unit (full replace — unmodeled keys will be dropped)"
                });
            });
            ui.add_space(8.0);

            egui::Grid::new("unit_form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    super::field_label(ui, "Unit name", HELP_UNIT_NAME);
                    ui.add_enabled(
                        create,
                        TextEdit::singleline(&mut form.unit_name).desired_width(280.0),
                    );
                    ui.end_row();

                    super::field_label(ui, "Binary", HELP_UNIT_BINARY);
                    ui.add(TextEdit::singleline(&mut form.binary).desired_width(280.0));
                    ui.end_row();

                    super::field_label(ui, "Layout", HELP_UNIT_LAYOUT);
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

                    super::field_label(ui, "User", HELP_UNIT_USER);
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut form.user_root, false, "nobody");
                        ui.radio_value(&mut form.user_root, true, "root");
                    });
                    ui.end_row();

                    super::field_label(ui, "WantedBy", HELP_UNIT_WANTED_BY);
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
            super::help_checkbox(
                ui,
                "Enable and start after Apply",
                HELP_ENABLE_AND_START,
                &mut enable,
            );
            with_dialog_state(ui, |s| s.enable_and_start = enable);

            if needs_sudo {
                ui.add_space(6.0);
                super::field_label(
                    ui,
                    "Sudo password (sent only via sudo -S stdin; never logged)",
                    HELP_SUDO_PASSWORD,
                );
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
