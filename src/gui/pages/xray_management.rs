//! Xray Management page — install / update / remove via ApplicationService.
//!
//! The GUI never executes shell commands, downloads files, manages install
//! paths, or parses command output.

use egui::{Color32, Id, RichText, Ui, Vec2};

use crate::app::{
    ApplicationService, InstallationStatus, XrayLifecycleOperation, XrayLifecycleState,
    XrayManagementPageModel,
};
use crate::xray::InstallChannel;

/// Temporary dialog state stored in egui memory.
#[derive(Clone, Default)]
struct MgmtDialogState {
    mode: MgmtDialogMode,
    error: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Default)]
enum MgmtDialogMode {
    #[default]
    None,
    Confirm {
        operation: XrayLifecycleOperation,
        prompt: String,
    },
}

fn dialog_id() -> Id {
    Id::new("feldjaeger_xray_management_dialog")
}

/// Renders the Xray Management page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Xray Management");
    ui.add_space(8.0);

    let model = service.xray_management_page_model();
    show_summary(ui, &model);
    ui.add_space(12.0);

    show_channel(ui, service, &model);
    ui.add_space(8.0);

    if let Some(reason) = model.blocked_reason {
        let color = if reason.contains("already installed") || reason.contains("Unsupported") {
            Color32::from_rgb(210, 170, 40)
        } else {
            Color32::from_rgb(140, 140, 140)
        };
        ui.label(RichText::new(reason).size(14.0).color(color));
        ui.add_space(8.0);
    }

    if let Some(hint) = model.channel_hint {
        ui.label(
            RichText::new(hint)
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        ui.add_space(8.0);
    }

    if let XrayLifecycleState::Failed { kind, detail } = &model.lifecycle {
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
        ui.add_space(8.0);
    }

    show_version_check(ui, service, &model);
    ui.add_space(12.0);
    show_actions(ui, service, &model);
    show_dialogs(ui, service);
}

fn show_summary(ui: &mut Ui, model: &XrayManagementPageModel) {
    egui::Grid::new("xray_management_summary")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            row(ui, "Installation status", model.status.label());
            row(
                ui,
                "Installed version",
                model.current_version.as_deref().unwrap_or("—"),
            );
            row(
                ui,
                "Available (stable)",
                model.available_stable.as_deref().unwrap_or("—"),
            );
            row(
                ui,
                "Available (beta)",
                model.available_beta.as_deref().unwrap_or("—"),
            );
            row(
                ui,
                "Binary path",
                model.binary_path.as_deref().unwrap_or("—"),
            );
            row(
                ui,
                "Service name",
                model.service_name.as_deref().unwrap_or("—"),
            );
            row(
                ui,
                "Configuration path",
                model.config_path.as_deref().unwrap_or("—"),
            );
            if let Some(init) = model.init_system {
                row(ui, "Init system", init.label());
            }
        });
}

fn row(ui: &mut Ui, key: &str, value: &str) {
    ui.label(RichText::new(key).strong());
    ui.label(value);
    ui.end_row();
}

fn show_channel(ui: &mut Ui, service: &mut ApplicationService, model: &XrayManagementPageModel) {
    ui.strong("Release channel");
    ui.add_space(4.0);
    let busy = model.version_check_busy || model.lifecycle.is_busy();
    let mut channel = service.install_channel();
    ui.add_enabled_ui(!busy, |ui| {
        ui.horizontal(|ui| {
            ui.radio_value(&mut channel, InstallChannel::Stable, "Stable");
            ui.radio_value(&mut channel, InstallChannel::Beta, "Beta");
        });
    });
    if channel != service.install_channel() {
        service.set_install_channel(channel);
    }
    if channel == InstallChannel::Beta {
        ui.label(
            RichText::new(
                "Uses official install --beta (newest listed release with a matching download for this host; may be pre-release).",
            )
            .size(13.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_version_check(ui: &mut Ui, service: &mut ApplicationService, model: &XrayManagementPageModel) {
    ui.horizontal(|ui| {
        ui.strong("Version");
        let label = if model.version_check_busy {
            "Checking..."
        } else {
            "Check versions"
        };
        let button = ui.add_enabled(model.can_check_version, egui::Button::new(label));
        if button.clicked()
            && let Err(message) = service.start_version_check()
        {
            with_dialog_state(ui, |state| {
                state.error = Some(message);
            });
        }
    });

    if model.stable_error.is_some() || model.beta_error.is_some() {
        ui.add_space(4.0);
        if let Some(err) = &model.stable_error {
            ui.label(
                RichText::new(format!("Stable check: {err}"))
                    .size(13.0)
                    .color(Color32::from_rgb(200, 60, 60)),
            );
        }
        if let Some(err) = &model.beta_error {
            ui.label(
                RichText::new(format!("Beta check: {err}"))
                    .size(13.0)
                    .color(Color32::from_rgb(200, 60, 60)),
            );
        }
    }

    if model.status == InstallationStatus::Installed
        && let Some(current) = &model.current_version
    {
        ui.label(
            RichText::new(format!(
                "Installed:\n{current}\nStable:\n{}\nBeta:\n{}",
                model.available_stable.as_deref().unwrap_or("—"),
                model.available_beta.as_deref().unwrap_or("—"),
            ))
            .size(13.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_actions(ui: &mut Ui, _service: &mut ApplicationService, model: &XrayManagementPageModel) {
    ui.strong("Actions");
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        for operation in [
            XrayLifecycleOperation::Install,
            XrayLifecycleOperation::Update,
            XrayLifecycleOperation::Remove,
        ] {
            let enabled = match operation {
                XrayLifecycleOperation::Install => model.can_install,
                XrayLifecycleOperation::Update => model.can_update,
                XrayLifecycleOperation::Remove => model.can_remove,
            };
            let button = ui.add_enabled(enabled, egui::Button::new(operation.button_label()));
            if button.clicked() {
                let prompt = operation.confirmation_prompt(
                    model.channel,
                    model.current_version.as_deref(),
                    model.available_version.as_deref(),
                );
                open_confirm_dialog(ui, operation, prompt);
            }
        }
    });

    let immediate_error = with_dialog_state(ui, |state| {
        if matches!(state.mode, MgmtDialogMode::None) {
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

fn with_dialog_state<R>(ui: &Ui, f: impl FnOnce(&mut MgmtDialogState) -> R) -> R {
    ui.ctx().data_mut(|data| {
        let state = data.get_temp_mut_or_default::<MgmtDialogState>(dialog_id());
        f(state)
    })
}

fn open_confirm_dialog(ui: &Ui, operation: XrayLifecycleOperation, prompt: String) {
    with_dialog_state(ui, |state| {
        *state = MgmtDialogState {
            mode: MgmtDialogMode::Confirm { operation, prompt },
            error: None,
        };
    });
}

fn close_dialog(ui: &Ui) {
    with_dialog_state(ui, |state| {
        *state = MgmtDialogState::default();
    });
}

fn show_dialogs(ui: &mut Ui, service: &mut ApplicationService) {
    let mode = with_dialog_state(ui, |state| state.mode.clone());
    if let MgmtDialogMode::Confirm { operation, prompt } = mode {
        show_confirm_dialog(ui, service, operation, &prompt);
    }
}

fn show_confirm_dialog(
    ui: &mut Ui,
    service: &mut ApplicationService,
    operation: XrayLifecycleOperation,
    prompt: &str,
) {
    let mut open = true;
    egui::Window::new("Confirm")
        .collapsible(false)
        .resizable(false)
        .default_size(Vec2::new(420.0, 160.0))
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(RichText::new(prompt).size(14.0));
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
                if ui.button("Cancel").clicked() {
                    close_dialog(ui);
                }
                if ui.button("Confirm").clicked() {
                    match service.start_xray_lifecycle(operation) {
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
