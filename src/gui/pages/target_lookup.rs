//! Target Lookup page — SNI/Dest/host search by ASN (Roadmap §3:131), plus an AS-range REALITY
//! candidate scan built on top of it (follow-up roadmap item).
//!
//! The only page in Feldjäger with no SSH precondition — it never touches the managed host.
//! Data flows exclusively through [`ApplicationService`]; this page never opens a socket itself.

use egui::{Color32, RichText, Ui};

use crate::app::{ApplicationService, DEFAULT_SCAN_THREADS, PROBE_PAUSE};

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);

/// Upper bound on concurrent scan workers — a UI guardrail, not a hard protocol limit.
const MAX_SCAN_THREADS: u32 = 32;
/// Upper bound on the configurable pause between one worker's successive probes, in seconds.
const MAX_SCAN_PAUSE_SECS: u32 = 300;

fn input_id() -> egui::Id {
    egui::Id::new("target_lookup_input")
}

fn draft_input(ui: &Ui) -> String {
    ui.ctx()
        .data(|d| d.get_temp::<String>(input_id()))
        .unwrap_or_default()
}

fn set_draft_input(ui: &Ui, value: String) {
    ui.ctx().data_mut(|d| d.insert_temp(input_id(), value));
}

fn scan_cidr_id() -> egui::Id {
    egui::Id::new("target_scan_cidr_input")
}

fn draft_scan_cidr(ui: &Ui) -> String {
    ui.ctx()
        .data(|d| d.get_temp::<String>(scan_cidr_id()))
        .unwrap_or_default()
}

fn set_draft_scan_cidr(ui: &Ui, value: String) {
    ui.ctx().data_mut(|d| d.insert_temp(scan_cidr_id(), value));
}

fn scan_threads_id() -> egui::Id {
    egui::Id::new("target_scan_threads_input")
}

fn draft_scan_threads(ui: &Ui) -> u32 {
    ui.ctx()
        .data(|d| d.get_temp::<u32>(scan_threads_id()))
        .unwrap_or(DEFAULT_SCAN_THREADS as u32)
}

fn set_draft_scan_threads(ui: &Ui, value: u32) {
    ui.ctx().data_mut(|d| d.insert_temp(scan_threads_id(), value));
}

fn scan_pause_id() -> egui::Id {
    egui::Id::new("target_scan_pause_input")
}

fn draft_scan_pause_secs(ui: &Ui) -> u32 {
    ui.ctx()
        .data(|d| d.get_temp::<u32>(scan_pause_id()))
        .unwrap_or(PROBE_PAUSE.as_secs() as u32)
}

fn set_draft_scan_pause_secs(ui: &Ui, value: u32) {
    ui.ctx().data_mut(|d| d.insert_temp(scan_pause_id(), value));
}

fn scan_limit_enabled_id() -> egui::Id {
    egui::Id::new("target_scan_limit_enabled")
}

fn draft_scan_limit_enabled(ui: &Ui) -> bool {
    ui.ctx()
        .data(|d| d.get_temp::<bool>(scan_limit_enabled_id()))
        .unwrap_or(false)
}

fn set_draft_scan_limit_enabled(ui: &Ui, value: bool) {
    ui.ctx().data_mut(|d| d.insert_temp(scan_limit_enabled_id(), value));
}

fn scan_limit_value_id() -> egui::Id {
    egui::Id::new("target_scan_limit_value")
}

fn draft_scan_limit_value(ui: &Ui) -> u32 {
    ui.ctx()
        .data(|d| d.get_temp::<u32>(scan_limit_value_id()))
        .unwrap_or(256)
}

fn set_draft_scan_limit_value(ui: &Ui, value: u32) {
    ui.ctx().data_mut(|d| d.insert_temp(scan_limit_value_id(), value));
}

fn scan_start_error_id() -> egui::Id {
    egui::Id::new("target_scan_start_error")
}

fn draft_scan_start_error(ui: &Ui) -> Option<String> {
    ui.ctx().data(|d| d.get_temp::<String>(scan_start_error_id()))
}

fn set_draft_scan_start_error(ui: &Ui, value: Option<String>) {
    ui.ctx().data_mut(|d| match value {
        Some(message) => {
            d.insert_temp(scan_start_error_id(), message);
        }
        None => {
            d.remove_temp::<String>(scan_start_error_id());
        }
    });
}

/// Renders the Target Lookup page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Target Lookup");
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "Look up which organization/ASN owns a domain or IP — an authoring aid for judging \
             REALITY `dest`, TLS `serverName`, or routing `domain` candidates before wiring them \
             into a config. Independent of any SSH connection.",
        )
        .size(12.0)
        .color(MUTED_COLOR),
    );
    ui.label(
        RichText::new(
            "Queries go to whois.cymru.com (and, for the network scan below, DNS resolvers and \
             candidate hosts directly) over the public internet — the only page in Feldjäger \
             that reaches anywhere other than the managed host.",
        )
        .size(11.0)
        .color(WARN_COLOR),
    );
    ui.add_space(8.0);

    let model = service.target_lookup_page_model();

    let mut input = draft_input(ui);
    ui.horizontal(|ui| {
        ui.label("Domain or IP:");
        ui.text_edit_singleline(&mut input);
        if ui
            .add_enabled(!model.is_running, egui::Button::new("Look up"))
            .clicked()
        {
            let _ = service.start_target_lookup(input.clone());
        }
        if model.is_running {
            ui.label(RichText::new("Looking up...").size(12.0).color(MUTED_COLOR));
        }
    });
    set_draft_input(ui, input);

    ui.add_space(8.0);

    if let Some(host) = model.last_queried_host.clone() {
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong("Results for:");
            ui.label(&host);
        });

        if let Some(error) = &model.error {
            ui.label(RichText::new(error.clone()).size(13.0).color(ERROR_COLOR));
        } else if let Some(result) = &model.result {
            egui::Grid::new("target_lookup_result_grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Resolved IP:");
                    ui.label(&result.resolved_ip);
                    ui.end_row();
                    ui.label("ASN:");
                    ui.label(&result.asn);
                    ui.end_row();
                    ui.label("AS Name:");
                    ui.label(&result.as_name);
                    ui.end_row();
                    ui.label("BGP Prefix:");
                    ui.label(&result.bgp_prefix);
                    ui.end_row();
                    ui.label("Country:");
                    ui.label(&result.country_code);
                    ui.end_row();
                    ui.label("Registry:");
                    ui.label(&result.registry);
                    ui.end_row();
                    ui.label("Allocated:");
                    ui.label(&result.allocated);
                    ui.end_row();
                });

            if result.asn == "—" {
                ui.add_space(4.0);
                ui.label(
                    RichText::new("No ASN on record — likely unrouted or private address space.")
                        .size(12.0)
                        .color(MUTED_COLOR),
                );
            }
        }
    }

    show_scan_section(ui, service);
}

fn show_scan_section(ui: &mut Ui, service: &mut ApplicationService) {
    let model = service.target_scan_page_model();

    ui.add_space(12.0);
    ui.separator();
    ui.heading("Scan network for REALITY candidates");
    ui.label(
        RichText::new(
            "Probes hosts in a network (every address by default, or a smaller count below) for a \
             valid REALITY dest candidate: reverse DNS + forward-resolve consistency (fixes the \
             classic RealiTLScanner problem of a certificate SAN domain that doesn't actually \
             resolve back to the scanned IP), then a TLS 1.3 handshake checking negotiated ALPN and \
             key-exchange group. Invalid results are not shown. Runs entirely on this machine — \
             never through the managed SSH host — with a configurable pause between one worker's \
             successive probes, as a courtesy to the network being scanned.",
        )
        .size(11.0)
        .color(MUTED_COLOR),
    );

    ui.add_space(6.0);

    let mut cidr = draft_scan_cidr(ui);
    ui.horizontal(|ui| {
        ui.label("Network (CIDR):");
        ui.add_enabled(
            !model.is_running,
            egui::TextEdit::singleline(&mut cidr).hint_text("e.g. 93.184.216.0/24"),
        );
        if let Some(prefix) = &model.available_prefix
            && ui
                .add_enabled(!model.is_running, egui::Button::new("Use looked-up prefix"))
                .on_hover_text(prefix)
                .clicked()
        {
            cidr = prefix.clone();
        }
    });
    set_draft_scan_cidr(ui, cidr.clone());

    let mut threads = draft_scan_threads(ui);
    let mut pause_secs = draft_scan_pause_secs(ui);
    ui.horizontal(|ui| {
        ui.label("Concurrent workers:");
        ui.add_enabled(
            !model.is_running,
            egui::DragValue::new(&mut threads).range(1..=MAX_SCAN_THREADS),
        );
        ui.add_space(12.0);
        ui.label("Pause between probes (s):");
        ui.add_enabled(
            !model.is_running,
            egui::DragValue::new(&mut pause_secs).range(1..=MAX_SCAN_PAUSE_SECS),
        );
    });
    set_draft_scan_threads(ui, threads);
    set_draft_scan_pause_secs(ui, pause_secs);

    let mut limit_enabled = draft_scan_limit_enabled(ui);
    let mut limit_value = draft_scan_limit_value(ui);
    ui.horizontal(|ui| {
        ui.add_enabled(
            !model.is_running,
            egui::Checkbox::new(&mut limit_enabled, "Limit to"),
        );
        ui.add_enabled(
            !model.is_running && limit_enabled,
            egui::DragValue::new(&mut limit_value).range(1..=u32::MAX),
        );
        ui.label(
            RichText::new("addresses (unchecked = scan the entire network)")
                .size(11.0)
                .color(MUTED_COLOR),
        );
    });
    set_draft_scan_limit_enabled(ui, limit_enabled);
    set_draft_scan_limit_value(ui, limit_value);

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!model.is_running, egui::Button::new("Scan network"))
            .clicked()
        {
            let cidr_override = if cidr.trim().is_empty() { None } else { Some(cidr.as_str()) };
            let pause = std::time::Duration::from_secs(u64::from(pause_secs));
            let address_limit = limit_enabled.then_some(limit_value as usize);
            match service.start_target_scan(cidr_override, threads as usize, pause, address_limit) {
                Ok(()) => set_draft_scan_start_error(ui, None),
                Err(message) => set_draft_scan_start_error(ui, Some(message)),
            }
        }
        if model.is_running && ui.button("Stop").clicked() {
            service.stop_target_scan();
        }
        if model.is_running {
            ui.label(RichText::new("Scanning...").size(12.0).color(MUTED_COLOR));
        }
    });

    if let Some(error) = draft_scan_start_error(ui) {
        ui.label(RichText::new(error).size(12.0).color(ERROR_COLOR));
    }

    let Some(scanned_prefix) = &model.scanned_prefix else {
        return;
    };

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(format!("Scanning: {scanned_prefix}"));
        if let Some(total) = model.prefix_total
            && total > model.capped_total
        {
            ui.label(
                RichText::new(format!(
                    "(prefix has {total} addresses — showing first {})",
                    model.capped_total
                ))
                .size(11.0)
                .color(MUTED_COLOR),
            );
        }
    });
    ui.label(format!("Checked {} / {}", model.checked, model.capped_total));

    if model.rows.is_empty() {
        ui.label(
            RichText::new(if model.is_running {
                "No candidates found yet."
            } else {
                "No valid candidates found in this range."
            })
            .size(12.0)
            .color(MUTED_COLOR),
        );
        return;
    }

    ui.add_space(4.0);
    egui::ScrollArea::vertical()
        .max_height(320.0)
        .show(ui, |ui| {
            egui::Grid::new("target_scan_result_grid")
                .num_columns(5)
                .striped(true)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("IP");
                    ui.strong("Domain");
                    ui.strong("cert-domain");
                    ui.strong("ALPN");
                    ui.strong("curve");
                    ui.end_row();
                    for row in &model.rows {
                        ui.label(&row.ip);
                        ui.label(&row.domain);
                        ui.label(&row.cert_domains);
                        ui.label(&row.alpn);
                        ui.label(&row.curve);
                        ui.end_row();
                    }
                });
        });
}
