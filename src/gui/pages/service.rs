//! Service page — remote Xray lifecycle control via ApplicationService.
//!
//! The GUI never executes SSH commands, invokes systemctl, or parses
//! command output. All actions go through [`ApplicationService`].

use egui::{Color32, Id, RichText, Ui, Vec2};

use crate::app::{ApplicationService, ServiceControlState, ServiceOperation, ServicePageModel};
use crate::init::ServiceState;
use crate::xray::InitSystemKind;

/// Temporary dialog state stored in egui memory.
#[derive(Clone, Default)]
struct ServiceDialogState {
    mode: ServiceDialogMode,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum ServiceDialogMode {
    #[default]
    None,
    Confirm(ServiceOperation),
}

fn service_dialog_id() -> Id {
    Id::new("feldjaeger_service_dialog")
}

/// Renders the Service page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Service");
    ui.add_space(8.0);

    let model = service.service_page_model();
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

    if model.management_allowed {
        ui.add_space(8.0);
        show_actions(ui, service, model.control.is_busy());
    }

    show_dialogs(ui, service);
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
    if let ServiceDialogMode::Confirm(operation) = mode {
        show_confirm_dialog(ui, service, operation);
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
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error)
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button(operation.button_label()).clicked() {
                    match service.start_service_operation(operation) {
                        Ok(()) => close_dialog(ui),
                        Err(message) => {
                            with_dialog_state(ui, |state| {
                                state.error = Some(message);
                            });
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
