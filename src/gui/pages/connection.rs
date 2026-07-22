//! Connection page — edit and save a remote SSH connection profile.

use egui::{Color32, RichText, TextEdit, Ui};
use feldjaeger_ssh::AuthMethod;

use crate::app::{
    ApplicationService, DiscoveryState, format_installation_summary, format_not_found_summary,
};
use crate::xray::DiscoveryErrorKind;

/// Renders the Connection page.
///
/// All persistence and SSH testing go through [`ApplicationService`]. This page
/// never touches `config.json`, `SshBackend`, or the network directly.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Connection");
    ui.add_space(8.0);

    if service.connection_has_unsaved_changes() {
        ui.label(RichText::new("Unsaved changes").color(Color32::from_rgb(210, 170, 40)));
        ui.add_space(4.0);
    }

    let errors = service.connection_errors().clone();
    let test_state = service.connection_test_state().clone();
    let testing = test_state.is_connecting();
    let discovering = service.discovery_state().is_discovering();
    let form_locked = testing || discovering;

    egui::Grid::new("connection_form")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .striped(false)
        .show(ui, |ui| {
            ui.label("Profile name");
            ui.vertical(|ui| {
                ui.add_enabled_ui(!form_locked, |ui| {
                    ui.add(
                        TextEdit::singleline(&mut service.connection_draft_mut().profile_name)
                            .desired_width(320.0),
                    );
                });
                field_error(ui, errors.profile_name.as_deref());
            });
            ui.end_row();

            ui.label("Host / IP address");
            ui.vertical(|ui| {
                ui.add_enabled_ui(!form_locked, |ui| {
                    ui.add(
                        TextEdit::singleline(&mut service.connection_draft_mut().host)
                            .desired_width(320.0),
                    );
                });
                field_error(ui, errors.host.as_deref());
            });
            ui.end_row();

            ui.label("Port");
            ui.vertical(|ui| {
                ui.add_enabled_ui(!form_locked, |ui| {
                    ui.add(
                        TextEdit::singleline(&mut service.connection_draft_mut().port)
                            .desired_width(80.0),
                    );
                });
                field_error(ui, errors.port.as_deref());
            });
            ui.end_row();

            ui.label("Username");
            ui.vertical(|ui| {
                ui.add_enabled_ui(!form_locked, |ui| {
                    ui.add(
                        TextEdit::singleline(&mut service.connection_draft_mut().username)
                            .desired_width(320.0),
                    );
                });
                field_error(ui, errors.username.as_deref());
            });
            ui.end_row();

            ui.label("Authentication method");
            ui.add_enabled_ui(!form_locked, |ui| {
                ui.horizontal(|ui| {
                    let method = service.connection_draft().auth_method;
                    if ui
                        .selectable_label(
                            method == AuthMethod::Password,
                            AuthMethod::Password.label(),
                        )
                        .clicked()
                    {
                        service.connection_draft_mut().auth_method = AuthMethod::Password;
                    }
                    if ui
                        .selectable_label(
                            method == AuthMethod::PrivateKey,
                            AuthMethod::PrivateKey.label(),
                        )
                        .clicked()
                    {
                        service.connection_draft_mut().auth_method = AuthMethod::PrivateKey;
                    }
                });
            });
            ui.end_row();

            match service.connection_draft().auth_method {
                AuthMethod::Password => {
                    ui.label("Password");
                    ui.vertical(|ui| {
                        ui.add_enabled_ui(!form_locked, |ui| {
                            ui.add(
                                TextEdit::singleline(
                                    service.connection_secrets_mut().password_mut(),
                                )
                                .password(true)
                                .desired_width(320.0),
                            );
                        });
                        field_error(ui, errors.password.as_deref());
                    });
                    ui.end_row();
                }
                AuthMethod::PrivateKey => {
                    ui.label("Private key path");
                    ui.vertical(|ui| {
                        ui.add_enabled_ui(!form_locked, |ui| {
                            ui.add(
                                TextEdit::singleline(
                                    &mut service.connection_draft_mut().private_key_path,
                                )
                                .desired_width(320.0),
                            );
                        });
                        field_error(ui, errors.private_key_path.as_deref());
                    });
                    ui.end_row();

                    ui.label("Private key passphrase");
                    ui.vertical(|ui| {
                        ui.add_enabled_ui(!form_locked, |ui| {
                            ui.add(
                                TextEdit::singleline(
                                    service.connection_secrets_mut().passphrase_mut(),
                                )
                                .password(true)
                                .desired_width(320.0),
                            );
                        });
                    });
                    ui.end_row();
                }
            }
        });

    ui.add_space(16.0);

    ui.horizontal(|ui| {
        ui.add_enabled_ui(!form_locked, |ui| {
            if ui.button("Save profile").clicked() {
                let _ = service.save_connection_profile();
            }
            if ui.button("Reset changes").clicked() {
                service.reset_connection_profile();
            }
        });

        let test = ui.add_enabled(!form_locked, egui::Button::new(test_state.button_label()));
        if test.clicked() {
            let _ = service.start_connection_test();
        }

        let can_discover = service.can_start_discovery();
        let discover_label = service.discovery_state().button_label();
        let discover = ui.add_enabled(can_discover, egui::Button::new(discover_label));
        if discover.clicked() {
            let _ = service.start_discovery();
        }
    });

    if let Some(detail) = test_state.failure_detail() {
        ui.add_space(8.0);
        ui.label(
            RichText::new(detail)
                .color(Color32::from_rgb(200, 60, 60))
                .size(14.0),
        )
        .on_hover_text(detail);
    }

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(8.0);
    ui.heading("Xray discovery");
    ui.add_space(6.0);
    show_discovery_summary(ui, service.discovery_state());
}

fn show_discovery_summary(ui: &mut Ui, state: &DiscoveryState) {
    match state {
        DiscoveryState::Idle => {
            ui.label(
                RichText::new("Run Discover Xray after a successful SSH connection.")
                    .color(Color32::from_rgb(140, 140, 140)),
            );
        }
        DiscoveryState::Discovering => {
            ui.label(
                RichText::new("Discovering Xray installation...")
                    .color(Color32::from_rgb(210, 170, 40)),
            );
        }
        DiscoveryState::Succeeded(installation) => {
            ui.label(
                RichText::new("Discovery summary (read-only)")
                    .color(Color32::from_rgb(46, 160, 67)),
            );
            ui.add_space(4.0);
            show_key_value_grid(ui, &format_installation_summary(installation));
        }
        DiscoveryState::NotFound {
            operating_system,
            architecture,
            init_system,
            warnings,
        } => {
            ui.label(
                RichText::new("Xray installation not found")
                    .color(Color32::from_rgb(210, 170, 40))
                    .size(14.0),
            );
            ui.add_space(4.0);
            show_key_value_grid(
                ui,
                &format_not_found_summary(operating_system, architecture, *init_system, warnings),
            );
        }
        DiscoveryState::Failed { kind, detail } => {
            let title = match kind {
                DiscoveryErrorKind::SshConnectionLost => "SSH connection lost",
                DiscoveryErrorKind::PermissionDenied => "Permission denied",
                DiscoveryErrorKind::Unexpected => "Unexpected discovery error",
            };
            ui.label(
                RichText::new(title)
                    .color(Color32::from_rgb(200, 60, 60))
                    .size(14.0),
            );
            ui.label(
                RichText::new(detail)
                    .color(Color32::from_rgb(200, 60, 60))
                    .size(14.0),
            );
        }
    }
}

fn show_key_value_grid(ui: &mut Ui, rows: &[(String, String)]) {
    egui::Grid::new("discovery_summary")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            for (key, value) in rows {
                ui.label(RichText::new(key).strong());
                ui.label(value);
                ui.end_row();
            }
        });
}

fn field_error(ui: &mut Ui, message: Option<&str>) {
    if let Some(message) = message {
        ui.label(
            RichText::new(message)
                .color(Color32::from_rgb(200, 60, 60))
                .size(14.0),
        );
    }
}
