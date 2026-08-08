//! Cloudflare WARP page — managed Xray WireGuard outbound via ApplicationService.
//!
//! The GUI never executes shell commands, downloads helpers, parses raw Xray
//! JSON, or inserts credentials. All work goes through [`ApplicationService`].

use egui::{Color32, RichText, Ui};

use crate::app::{
    ApplicationService, WarpPageModel, WarpPendingConfirm, WarpUiState,
};
use crate::xray::WarpErrorKind;

/// Renders the Cloudflare WARP management page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Cloudflare WARP");
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "Manages Cloudflare WARP as an Xray WireGuard outbound. \
Creating a WARP outbound does not route traffic through it automatically.",
        )
        .size(13.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
    ui.add_space(10.0);

    let model = service.warp_page_model();
    show_pending_confirm(ui, service, &model);
    show_status_section(ui, &model);
    ui.add_space(12.0);
    show_integration_section(ui, &model);
    ui.add_space(12.0);
    show_connectivity_section(ui, &model);
    ui.add_space(12.0);
    show_maintenance_section(ui, service, &model);
    ui.add_space(12.0);
    show_warnings_section(ui, &model);
    ui.add_space(12.0);
    show_actions(ui, service, &model);
}

fn show_pending_confirm(ui: &mut Ui, service: &mut ApplicationService, model: &WarpPageModel) {
    let Some(pending) = &model.pending_confirm else {
        return;
    };

    ui.group(|ui| {
        ui.strong("Confirmation required");
        ui.add_space(4.0);
        match pending {
            WarpPendingConfirm::InstallHelper => {
                ui.label(
                    "The WARP registration helper will be installed on the remote server.",
                );
            }
            WarpPendingConfirm::Setup { preferred_tag } => {
                ui.label(format!(
                    "Register a new Cloudflare WARP device and add WireGuard outbound `{preferred_tag}`."
                ));
                ui.label("No routing rules will be changed.");
            }
            WarpPendingConfirm::Adopt {
                outbound_tag,
                summary_line,
            } => {
                ui.label(format!(
                    "Feldjäger will begin managing outbound `{outbound_tag}`."
                ));
                ui.label(summary_line.clone());
                ui.label("Adoption does not regenerate credentials.");
            }
            WarpPendingConfirm::Regenerate => {
                ui.label("The current WARP identity will be replaced.");
                ui.label(
                    "Existing credentials will stop being used by this Xray configuration.",
                );
            }
            WarpPendingConfirm::RemoveIntegration {
                outbound_tag,
                blocking_references,
            } => {
                ui.label(format!(
                    "Remove Feldjäger-managed WARP outbound `{outbound_tag}`."
                ));
                if !blocking_references.is_empty() {
                    ui.label(
                        RichText::new("Removal is blocked by configuration references:")
                            .color(Color32::from_rgb(200, 60, 60)),
                    );
                    for reference in blocking_references {
                        ui.label(format!("• {reference}"));
                    }
                }
            }
            WarpPendingConfirm::RemoveHelper => {
                ui.label("Remove registration helper from the remote server");
                ui.label("Only Feldjäger-managed helper files will be deleted.");
            }
            WarpPendingConfirm::RestartXray => {
                ui.label("Xray configuration was updated.");
                ui.label("Restart Xray to apply the change.");
            }
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let confirm_label = match pending {
                WarpPendingConfirm::RestartXray => "Restart now",
                WarpPendingConfirm::RemoveIntegration {
                    blocking_references,
                    ..
                } if !blocking_references.is_empty() => "Blocked",
                _ => "Confirm",
            };
            let can_confirm = !matches!(
                pending,
                WarpPendingConfirm::RemoveIntegration {
                    blocking_references,
                    ..
                } if !blocking_references.is_empty()
            );
            if ui
                .add_enabled(can_confirm, egui::Button::new(confirm_label))
                .clicked()
                && let Err(message) = service.confirm_warp_pending()
            {
                service.show_status_message(message);
            }
            if ui.button("Cancel").clicked() {
                service.cancel_warp_pending();
            }
        });
    });
    ui.add_space(12.0);
}

fn show_status_section(ui: &mut Ui, model: &WarpPageModel) {
    ui.strong("Status");
    ui.add_space(4.0);

    if let Some(reason) = &model.blocked_reason {
        ui.label(
            RichText::new(reason.clone())
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        ui.add_space(6.0);
    }

    if let WarpUiState::Failed { kind, detail } = &model.ui_state {
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
        ui.add_space(6.0);
    }

    let summary = match &model.summary {
        Some(summary) => summary,
        None => {
            ui.label("No WARP discovery data yet. Click Refresh.");
            return;
        }
    };

    egui::Grid::new("warp_status_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            row(ui, "Integration", summary.state.label());
            row(
                ui,
                "Helper status",
                if summary.helper_installed {
                    "Installed"
                } else {
                    "Not installed"
                },
            );
            row(
                ui,
                "Helper version",
                summary.helper_version.as_deref().unwrap_or("—"),
            );
            row(
                ui,
                "Outbound tag",
                summary.outbound_tag.as_deref().unwrap_or("—"),
            );
            row(
                ui,
                "Endpoint",
                summary.endpoint.as_deref().unwrap_or("—"),
            );
            let addresses = if summary.addresses.is_empty() {
                "—".to_owned()
            } else {
                summary.addresses.join(", ")
            };
            row(ui, "Assigned addresses", &addresses);
            row(
                ui,
                "Configuration status",
                summary
                    .outbound_classification
                    .map(|c| c.label())
                    .unwrap_or("—"),
            );
            row(
                ui,
                "Connectivity status",
                summary
                    .connectivity_status
                    .as_deref()
                    .unwrap_or("Not tested"),
            );
        });
}

fn show_integration_section(ui: &mut Ui, model: &WarpPageModel) {
    ui.strong("Xray integration");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Preferred outbound tag");
        // Tag editing is done via ApplicationService; show current draft.
        ui.label(
            RichText::new(&model.preferred_tag)
                .strong()
                .color(Color32::from_rgb(60, 120, 180)),
        );
    });
    ui.label(
        RichText::new("Default tag is `warp`. If taken, Feldjäger suggests `warp-2`, …")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );

    if let Some(proposed) = &model.proposed_change {
        ui.add_space(6.0);
        ui.label(format!("Last applied proposal: {}", proposed.summary_line));
    }

    if let Some(notice) = &model.routing_notice {
        ui.add_space(6.0);
        ui.label(
            RichText::new(notice.clone())
                .color(Color32::from_rgb(40, 140, 80)),
        );
    }

    if let Some(summary) = &model.summary {
        ui.add_space(4.0);
        ui.label(format!(
            "Routing rules referencing WARP outbound: {}",
            summary.routing_reference_count
        ));
        if model.restart_recommended || summary.restart_recommended {
            ui.label(
                RichText::new("Xray configuration was updated. Restart Xray to apply the change.")
                    .color(Color32::from_rgb(210, 170, 40)),
            );
        }
        if let Some(warning) = &summary.compatibility_warning {
            ui.label(
                RichText::new(warning.clone()).color(Color32::from_rgb(210, 170, 40)),
            );
        }
    }
}

fn show_connectivity_section(ui: &mut Ui, model: &WarpPageModel) {
    ui.strong("Connectivity");
    ui.add_space(4.0);

    let Some(summary) = &model.summary else {
        ui.label("—");
        return;
    };

    egui::Grid::new("warp_connectivity_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            row(
                ui,
                "Status",
                summary
                    .connectivity_status
                    .as_deref()
                    .unwrap_or("Not tested"),
            );
            row(
                ui,
                "WARP active",
                bool_label(summary.warp_active),
            );
            row(ui, "IPv4 available", bool_label(summary.ipv4_available));
            row(ui, "IPv6 available", bool_label(summary.ipv6_available));
            row(
                ui,
                "Observed public IP",
                summary.observed_public_ip.as_deref().unwrap_or("—"),
            );
        });

    if let Some(note) = &summary.connectivity_note {
        ui.add_space(4.0);
        ui.label(
            RichText::new(note.clone())
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_maintenance_section(ui: &mut Ui, service: &mut ApplicationService, model: &WarpPageModel) {
    ui.strong("Maintenance");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Preferred tag");
        let mut tag = model.preferred_tag.clone();
        if ui
            .add_enabled(
                model.can_setup || model.page_state.label() == "Ready",
                egui::TextEdit::singleline(&mut tag).desired_width(160.0),
            )
            .changed()
        {
            service.set_warp_preferred_tag(tag);
        }
    });

    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "Regenerate replaces the WARP identity. Remove integration deletes only \
Feldjäger-managed WireGuard outbound. Helper removal is separate.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn show_warnings_section(ui: &mut Ui, model: &WarpPageModel) {
    ui.strong("Warnings");
    ui.add_space(4.0);

    let mut any = false;
    if let Some(summary) = &model.summary {
        for warning in &summary.warnings {
            any = true;
            ui.label(
                RichText::new(warning.clone()).color(Color32::from_rgb(210, 170, 40)),
            );
        }
        for reference in &summary.routing_references {
            any = true;
            ui.label(
                RichText::new(format!("Routing reference: {reference}"))
                    .color(Color32::from_rgb(210, 170, 40)),
            );
        }
    }
    if !any {
        ui.label("None");
    }
}

fn show_actions(ui: &mut Ui, service: &mut ApplicationService, model: &WarpPageModel) {
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(model.can_discover, egui::Button::new("Refresh"))
            .clicked()
            && let Err(message) = service.request_warp_discover()
        {
            service.show_status_message(message);
        }

        if ui
            .add_enabled(model.can_install_helper, egui::Button::new("Install helper"))
            .clicked()
            && let Err(message) = service.request_warp_install_helper()
        {
            service.show_status_message(message);
        }

        if ui
            .add_enabled(model.can_setup, egui::Button::new("Set up WARP"))
            .clicked()
            && let Err(message) = service.request_warp_setup()
        {
            service.show_status_message(message);
        }

        if ui
            .add_enabled(model.can_adopt, egui::Button::new("Adopt outbound"))
            .clicked()
            && let Err(message) = service.request_warp_adopt()
        {
            service.show_status_message(message);
        }

        if ui
            .add_enabled(model.can_test, egui::Button::new("Test WARP"))
            .clicked()
            && let Err(message) = service.request_warp_test()
        {
            service.show_status_message(message);
        }

        if ui
            .add_enabled(model.can_regenerate, egui::Button::new("Regenerate WARP credentials"))
            .clicked()
            && let Err(message) = service.request_warp_regenerate()
        {
            service.show_status_message(message);
        }

        if ui
            .add_enabled(
                model.can_remove_integration,
                egui::Button::new("Remove WARP integration"),
            )
            .clicked()
            && let Err(message) = service.request_warp_remove_integration()
        {
            service.show_status_message(message);
        }

        if ui
            .add_enabled(
                model.can_remove_helper,
                egui::Button::new("Remove registration helper"),
            )
            .clicked()
            && let Err(message) = service.request_warp_remove_helper()
        {
            service.show_status_message(message);
        }
    });

    let _ = WarpErrorKind::NoSshConnection; // keep import used if panels expand
}

fn row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).strong());
    ui.label(value);
    ui.end_row();
}

fn bool_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "—",
    }
}
