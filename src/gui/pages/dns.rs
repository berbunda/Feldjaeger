//! DNS page — read-only view of the discovered Xray DNS configuration.
//!
//! Data flows exclusively through [`ApplicationService`] and DNS summaries.
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, DnsPageState, MISSING_FIELD, dns_general_display, dns_host_row_display,
    dns_server_row_display,
};
use crate::xray::{DnsHostSummary, DnsServerSummary, DnsSummary};

/// Renders the DNS page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_dns_page_status();

    ui.heading("DNS");
    ui.add_space(8.0);

    let model = service.dns_page_model();
    match model.state {
        DnsPageState::NoSshConnection
        | DnsPageState::XrayNotDiscovered
        | DnsPageState::ConfigurationNotLoaded
        | DnsPageState::DnsSectionMissing => {
            show_state_message(ui, model.state);
            return;
        }
        DnsPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            for warning in &model.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(8.0);
        }
        DnsPageState::ConfigurationLoaded => {}
    }

    let Some(summary) = model.summary.as_ref() else {
        show_state_message(ui, DnsPageState::DnsSectionMissing);
        return;
    };

    show_general_information(ui, summary);
    ui.add_space(12.0);
    show_servers(ui, &summary.servers);
    ui.add_space(12.0);
    show_hosts(ui, &summary.hosts);
}

fn show_state_message(ui: &mut Ui, state: DnsPageState) {
    let color = match state {
        DnsPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        DnsPageState::DnsSectionMissing | DnsPageState::ConfigurationLoaded => {
            Color32::from_rgb(140, 140, 140)
        }
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_general_information(ui: &mut Ui, summary: &DnsSummary) {
    let display = dns_general_display(summary);
    ui.strong("General information");
    ui.add_space(4.0);
    egui::Grid::new("dns_general_information")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            general_row(ui, "Query strategy", &display.query_strategy);
            general_row(ui, "Disable cache", &display.disable_cache);
            general_row(ui, "Disable fallback", &display.disable_fallback);
            general_row(
                ui,
                "Disable fallback if match",
                &display.disable_fallback_if_match,
            );
            general_row(ui, "Tag", &display.tag);
            general_row(ui, "Source file", &display.source_file);
        });
}

fn general_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn show_servers(ui: &mut Ui, servers: &[DnsServerSummary]) {
    ui.strong("DNS servers");
    ui.add_space(4.0);
    if servers.is_empty() {
        ui.label(
            RichText::new("No DNS servers configured.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    egui::ScrollArea::horizontal()
        .id_salt("dns_servers_scroll")
        .show(ui, |ui| {
            egui::Grid::new("dns_servers_table")
                .num_columns(5)
                .striped(true)
                .spacing([16.0, 6.0])
                .min_col_width(90.0)
                .show(ui, |ui| {
                    ui.strong("Address");
                    ui.strong("Domains");
                    ui.strong("Expected IPs");
                    ui.strong("Skip fallback");
                    ui.strong("Client IP");
                    ui.end_row();

                    for server in servers {
                        let display = dns_server_row_display(server);
                        server_cell(ui, server, &display.address);
                        server_cell(ui, server, &display.domains);
                        server_cell(ui, server, &display.expected_ips);
                        server_cell(ui, server, &display.skip_fallback);
                        server_cell(ui, server, &display.client_ip);
                        ui.end_row();
                    }
                });
        });
}

fn show_hosts(ui: &mut Ui, hosts: &[DnsHostSummary]) {
    ui.strong("Static hosts");
    ui.add_space(4.0);
    if hosts.is_empty() {
        ui.label(
            RichText::new("No static hosts configured.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    egui::Grid::new("dns_hosts_table")
        .num_columns(2)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(140.0)
        .show(ui, |ui| {
            ui.strong("Domain");
            ui.strong("IP / Target");
            ui.end_row();

            for host in hosts {
                let display = dns_host_row_display(host);
                host_cell(ui, host, &display.domain);
                host_cell(ui, host, &display.target);
                ui.end_row();
            }
        });
}

fn server_cell(ui: &mut Ui, server: &DnsServerSummary, text: &str) {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    response.context_menu(|ui| {
        if ui.button("Copy address").clicked() {
            ui.ctx().copy_text(
                server
                    .address
                    .clone()
                    .unwrap_or_else(|| MISSING_FIELD.to_owned()),
            );
            ui.close();
        }
        if ui.button("Copy domains").clicked() {
            let domains = if server.domains.is_empty() {
                MISSING_FIELD.to_owned()
            } else {
                server.domains.join(", ")
            };
            ui.ctx().copy_text(domains);
            ui.close();
        }
        disabled_actions(ui);
    });
}

fn host_cell(ui: &mut Ui, host: &DnsHostSummary, text: &str) {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    response.context_menu(|ui| {
        if ui.button("Copy domain").clicked() {
            ui.ctx().copy_text(host.domain.clone());
            ui.close();
        }
        if ui.button("Copy IP").clicked() {
            ui.ctx().copy_text(host.target.clone());
            ui.close();
        }
        disabled_actions(ui);
    });
}

fn disabled_actions(ui: &mut Ui) {
    ui.separator();
    ui.add_enabled(false, egui::Button::new("Edit"))
        .on_disabled_hover_text("Not implemented yet");
    ui.add_enabled(false, egui::Button::new("Delete"))
        .on_disabled_hover_text("Not implemented yet");
    ui.add_enabled(false, egui::Button::new("Duplicate"))
        .on_disabled_hover_text("Not implemented yet");
}
