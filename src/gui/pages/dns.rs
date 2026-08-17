//! DNS page — view / edit the Xray top-level `dns` object (Roadmap §2.1:46).
//!
//! Full coverage of the official `DnsObject` (12 top-level fields) and `DnsServerObject` (14
//! fields per `servers[]` entry), plus `hosts{}` (domain → one-or-many targets). Mirrors the
//! View/Edit/Save/Cancel/Preview changes chrome already established by API Settings — this page
//! has no separate live/runtime counterpart to split away from, so (unlike API Settings vs. the
//! API Console) it stays a single page for both view and edit.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, TextEdit, Ui};

use crate::app::{ApplicationService, DnsPageState};
use crate::xray::{DnsHostEntry, DnsServerEntry, DnsSettings, QueryStrategy};

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);

/// One preset DNS server: `(label, address)`. `address` is whatever
/// [`DnsServerEntry::address`] would hold — plain IP, `IP:port`, or a `tcp://`/`https://`/
/// `quic+local://` scheme per the official address formats.
type DnsPreset = (&'static str, &'static str);

/// One named group of [`DnsPreset`]s for the servers "Presets" menu.
struct DnsPresetGroup {
    /// Menu submenu label (provider name).
    name: &'static str,
    /// Presets offered under this provider.
    servers: &'static [DnsPreset],
}

/// Well-known public DNS resolvers, grouped by provider — a convenience starting point, not an
/// endorsement or exhaustive list. Plain UDP and DNS-over-HTTPS (`https://.../dns-query`) forms
/// are offered side by side where the provider publishes both; IPv6 addresses are included for
/// providers that publish a stable one. Presented on a separate "Presets" button (never
/// auto-filled) so they never interfere with manually typed addresses — matches the same
/// separation already used for the DNS/FakeDNS docs the pages link to.
const DNS_SERVER_PRESET_GROUPS: &[DnsPresetGroup] = &[
    DnsPresetGroup {
        name: "Cloudflare",
        servers: &[
            ("1.1.1.1", "1.1.1.1"),
            ("1.0.0.1", "1.0.0.1"),
            ("2606:4700:4700::1111 (IPv6)", "2606:4700:4700::1111"),
            ("DoH — cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
        ],
    },
    DnsPresetGroup {
        name: "Google",
        servers: &[
            ("8.8.8.8", "8.8.8.8"),
            ("8.8.4.4", "8.8.4.4"),
            ("2001:4860:4860::8888 (IPv6)", "2001:4860:4860::8888"),
            ("DoH — dns.google", "https://dns.google/dns-query"),
        ],
    },
    DnsPresetGroup {
        name: "Quad9",
        servers: &[
            ("9.9.9.9", "9.9.9.9"),
            ("149.112.112.112", "149.112.112.112"),
            ("2620:fe::fe (IPv6)", "2620:fe::fe"),
            ("DoH — dns.quad9.net", "https://dns.quad9.net/dns-query"),
        ],
    },
    DnsPresetGroup {
        name: "OpenDNS (Cisco)",
        servers: &[
            ("208.67.222.222", "208.67.222.222"),
            ("208.67.220.220", "208.67.220.220"),
        ],
    },
    DnsPresetGroup {
        name: "AdGuard DNS",
        servers: &[
            ("94.140.14.14", "94.140.14.14"),
            ("94.140.15.15", "94.140.15.15"),
            ("DoH — dns.adguard-dns.com", "https://dns.adguard-dns.com/dns-query"),
        ],
    },
    DnsPresetGroup {
        name: "CleanBrowsing",
        servers: &[
            ("185.228.168.9 (Security)", "185.228.168.9"),
            ("185.228.169.9 (Security)", "185.228.169.9"),
        ],
    },
    DnsPresetGroup {
        name: "DNS.WATCH",
        servers: &[
            ("84.200.69.80", "84.200.69.80"),
            ("84.200.70.40", "84.200.70.40"),
        ],
    },
    DnsPresetGroup {
        name: "Comodo Secure DNS",
        servers: &[
            ("8.26.56.26", "8.26.56.26"),
            ("8.20.247.20", "8.20.247.20"),
        ],
    },
    DnsPresetGroup {
        name: "Yandex DNS",
        servers: &[
            ("77.88.8.8", "77.88.8.8"),
            ("77.88.8.1", "77.88.8.1"),
        ],
    },
    DnsPresetGroup {
        name: "Verisign",
        servers: &[
            ("64.6.64.6", "64.6.64.6"),
            ("64.6.65.6", "64.6.65.6"),
        ],
    },
    DnsPresetGroup {
        name: "Special (Xray-documented)",
        servers: &[
            ("localhost (use system resolver)", "localhost"),
            ("fakedns (route through FakeDNS)", "fakedns"),
        ],
    },
];

/// Renders the DNS page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_dns_page_status();

    ui.heading("DNS");
    ui.add_space(8.0);

    let model = service.dns_page_model();

    match model.state {
        DnsPageState::NoSshConnection
        | DnsPageState::XrayNotDiscovered
        | DnsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        DnsPageState::MalformedDnsObject => {
            show_state_message(ui, model.state);
            for warning in &model.settings.warnings {
                ui.label(RichText::new(warning.clone()).size(14.0).color(ERROR_COLOR));
            }
            return;
        }
        DnsPageState::ViewMode
        | DnsPageState::EditMode
        | DnsPageState::ValidationError
        | DnsPageState::Saving
        | DnsPageState::Saved
        | DnsPageState::SaveFailed => {
            show_state_message(ui, model.state);
            for warning in &model.settings.warnings {
                ui.label(RichText::new(warning.clone()).size(14.0).color(WARN_COLOR));
            }
            if let Some(error) = &model.error_message {
                ui.label(RichText::new(error.clone()).size(14.0).color(ERROR_COLOR));
            }
            ui.add_space(8.0);
        }
    }

    show_actions(ui, service, model.editing, model.state);
    ui.add_space(12.0);

    if model.editing {
        if !model.change_summary.is_empty() {
            ui.strong("Change summary");
            ui.add_space(4.0);
            for line in &model.change_summary {
                for part in line.lines() {
                    ui.label(RichText::new(part.to_owned()).size(13.0));
                }
                ui.add_space(4.0);
            }
            ui.add_space(8.0);
        }
        if let Some(entries) = service.dns_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        egui::ScrollArea::vertical()
            .id_salt("dns_edit_scroll")
            .show(ui, |ui| show_edit_form(ui, service));
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: DnsPageState) {
    let color = match state {
        DnsPageState::ValidationError | DnsPageState::Saved => WARN_COLOR,
        DnsPageState::ViewMode | DnsPageState::EditMode => MUTED_COLOR,
        DnsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(ui: &mut Ui, service: &mut ApplicationService, editing: bool, state: DnsPageState) {
    let busy = matches!(state, DnsPageState::Saving | DnsPageState::SaveFailed)
        && service.is_dns_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_dns_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_dns_settings();
            }
            if ui
                .add_enabled(
                    !service.is_dns_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_dns_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_dns_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_dns_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_dns_settings();
        }
    });
}

// ─── View mode ─────────────────────────────────────────────────────────────

fn show_view(ui: &mut Ui, settings: &DnsSettings) {
    ui.strong("General information");
    ui.add_space(4.0);
    egui::Grid::new("dns_general_information")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            view_row(ui, "clientIp", settings.client_ip.as_deref().unwrap_or("(none)"));
            view_row(ui, "queryStrategy", settings.query_strategy.as_str());
            view_row(ui, "disableCache", bool_str(settings.disable_cache));
            view_row(ui, "serveStale", bool_str(settings.serve_stale));
            view_row(ui, "serveExpiredTTL", &settings.serve_expired_ttl.to_string());
            view_row(ui, "disableFallback", bool_str(settings.disable_fallback));
            view_row(
                ui,
                "disableFallbackIfMatch",
                bool_str(settings.disable_fallback_if_match),
            );
            view_row(
                ui,
                "enableParallelQuery",
                bool_str(settings.enable_parallel_query),
            );
            view_row(ui, "useSystemHosts", bool_str(settings.use_system_hosts));
            view_row(ui, "tag", settings.tag.as_deref().unwrap_or("(none)"));
        });

    if let Some(source) = &settings.source_file {
        ui.add_space(12.0);
        ui.label(format!("Source file: {source}"));
    } else if !settings.section_present {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "No dns object in the remote configuration. Defaults are shown; the object is \
                 created only when you save changes.",
            )
            .size(12.0)
            .color(MUTED_COLOR),
        );
    }

    ui.add_space(16.0);
    ui.strong(format!("DNS servers ({})", settings.servers.len()));
    ui.add_space(4.0);
    if settings.servers.is_empty() {
        ui.label(RichText::new("No DNS servers configured.").size(13.0).color(MUTED_COLOR));
    } else {
        for (index, server) in settings.servers.iter().enumerate() {
            show_server_view_row(ui, index, server);
        }
    }

    ui.add_space(16.0);
    ui.strong(format!("Static hosts ({})", settings.hosts.len()));
    ui.add_space(4.0);
    if settings.hosts.is_empty() {
        ui.label(RichText::new("No static hosts configured.").size(13.0).color(MUTED_COLOR));
    } else {
        egui::Grid::new("dns_hosts_view_grid")
            .num_columns(2)
            .striped(true)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.strong("Domain");
                ui.strong("Target(s)");
                ui.end_row();
                for host in &settings.hosts {
                    ui.label(&host.domain);
                    ui.label(host.targets.join(", "));
                    ui.end_row();
                }
            });
    }
}

fn show_server_view_row(ui: &mut Ui, index: usize, server: &DnsServerEntry) {
    let title = if server.address.is_empty() {
        format!("Server {} (no address)", index + 1)
    } else {
        format!("Server {}: {}", index + 1, server.address)
    };
    egui::CollapsingHeader::new(title)
        .id_salt(("dns_server_view", index))
        .show(ui, |ui| {
            egui::Grid::new(("dns_server_view_grid", index))
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    view_row(ui, "port", &server.port.map(|p| p.to_string()).unwrap_or_else(|| "(default 53)".to_owned()));
                    view_row(ui, "domains", &join_or_none(&server.domains));
                    view_row(ui, "expectedIPs", &join_or_none(&server.expected_ips));
                    view_row(ui, "unexpectedIPs", &join_or_none(&server.unexpected_ips));
                    view_row(ui, "skipFallback", bool_str(server.skip_fallback));
                    view_row(ui, "finalQuery", bool_str(server.final_query));
                    view_row(
                        ui,
                        "timeoutMs",
                        &server
                            .timeout_ms
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "(default 4000)".to_owned()),
                    );
                    view_row(ui, "tag", server.tag.as_deref().unwrap_or("(none)"));
                    view_row(ui, "clientIP", server.client_ip.as_deref().unwrap_or("(none)"));
                    view_row(
                        ui,
                        "queryStrategy",
                        &server
                            .query_strategy
                            .as_ref()
                            .map(QueryStrategy::display_label)
                            .unwrap_or_else(|| "(inherit)".to_owned()),
                    );
                    view_row(ui, "disableCache", &optional_bool_str(server.disable_cache));
                    view_row(ui, "serveStale", &optional_bool_str(server.serve_stale));
                    view_row(
                        ui,
                        "serveExpiredTTL",
                        &server
                            .serve_expired_ttl
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "(inherit)".to_owned()),
                    );
                });
        });
}

fn view_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn bool_str(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn optional_bool_str(value: Option<bool>) -> String {
    match value {
        Some(true) => "true".to_owned(),
        Some(false) => "false".to_owned(),
        None => "(inherit)".to_owned(),
    }
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".to_owned()
    } else {
        values.join(", ")
    }
}

// ─── Edit mode ──────────────────────────────────────────────────────────────

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(draft) = service.dns_settings_draft_mut() else {
        return;
    };

    ui.strong("General information");
    ui.add_space(4.0);

    optional_text_row(ui, "clientIp", &mut draft.client_ip, "1.2.3.4");

    ui.horizontal(|ui| {
        ui.label("queryStrategy");
        query_strategy_combo(ui, "dns_query_strategy", &mut draft.query_strategy);
    });

    ui.checkbox(&mut draft.disable_cache, "disableCache");
    ui.checkbox(&mut draft.serve_stale, "serveStale");
    ui.horizontal(|ui| {
        ui.label("serveExpiredTTL");
        ui.add(egui::DragValue::new(&mut draft.serve_expired_ttl).range(0..=i64::MAX));
    });
    ui.checkbox(&mut draft.disable_fallback, "disableFallback");
    ui.checkbox(&mut draft.disable_fallback_if_match, "disableFallbackIfMatch");
    ui.checkbox(&mut draft.enable_parallel_query, "enableParallelQuery");
    ui.checkbox(&mut draft.use_system_hosts, "useSystemHosts");

    optional_text_row(ui, "tag", &mut draft.tag, "dns-out");

    ui.add_space(16.0);
    ui.separator();
    ui.strong("DNS servers");
    ui.add_space(4.0);

    let mut remove_server: Option<usize> = None;
    for index in 0..draft.servers.len() {
        egui::Frame::group(ui.style())
            .show(ui, |ui| show_server_edit_form(ui, draft, index, &mut remove_server));
        ui.add_space(6.0);
    }
    if let Some(index) = remove_server {
        draft.servers.remove(index);
    }
    ui.horizontal(|ui| {
        if ui.button("Add server").clicked() {
            draft.servers.push(DnsServerEntry::blank());
        }
        show_dns_server_presets_button(ui, draft);
    });

    ui.add_space(16.0);
    ui.separator();
    ui.strong("Static hosts");
    ui.add_space(4.0);

    let mut remove_host: Option<usize> = None;
    for index in 0..draft.hosts.len() {
        egui::Frame::group(ui.style())
            .show(ui, |ui| show_host_edit_form(ui, draft, index, &mut remove_host));
        ui.add_space(6.0);
    }
    if let Some(index) = remove_host {
        draft.hosts.remove(index);
    }
    if ui.button("Add host").clicked() {
        draft.hosts.push(DnsHostEntry::blank());
    }
}

/// "Presets" menu button — appends a new server pre-filled with a well-known public resolver's
/// address. Deliberately separate from "Add server" and every address text field: clicking a
/// preset only ever adds a new list entry, it never overwrites what the user has already typed.
fn show_dns_server_presets_button(ui: &mut Ui, draft: &mut DnsSettings) {
    ui.menu_button("Presets ▼", |ui| {
        for group in DNS_SERVER_PRESET_GROUPS {
            ui.menu_button(group.name, |ui| {
                for (label, address) in group.servers {
                    if ui.button(*label).clicked() {
                        let mut entry = DnsServerEntry::blank();
                        entry.address = (*address).to_owned();
                        draft.servers.push(entry);
                        ui.close();
                    }
                }
            });
        }
    });
}

fn show_server_edit_form(
    ui: &mut Ui,
    draft: &mut DnsSettings,
    index: usize,
    remove: &mut Option<usize>,
) {
    let server = &mut draft.servers[index];
    ui.horizontal(|ui| {
        ui.label(format!("Server {}", index + 1));
        if ui.small_button("Remove").clicked() {
            *remove = Some(index);
        }
    });

    ui.horizontal(|ui| {
        ui.label("address");
        ui.add(TextEdit::singleline(&mut server.address).desired_width(220.0).hint_text("8.8.8.8 or https://dns.google/dns-query"));
    });

    optional_u16_row(ui, "port", &mut server.port, ("dns_server_port", index));
    multiline_list_row(ui, "domains (one per line)", &mut server.domains, ("dns_server_domains", index));
    multiline_list_row(ui, "expectedIPs (one per line)", &mut server.expected_ips, ("dns_server_expected", index));
    multiline_list_row(ui, "unexpectedIPs (one per line)", &mut server.unexpected_ips, ("dns_server_unexpected", index));
    ui.checkbox(&mut server.skip_fallback, "skipFallback");
    ui.checkbox(&mut server.final_query, "finalQuery");
    optional_u32_row(ui, "timeoutMs", &mut server.timeout_ms, ("dns_server_timeout", index));
    optional_text_row(ui, "tag", &mut server.tag, "server-tag");
    optional_text_row(ui, "clientIP", &mut server.client_ip, "1.2.3.4");

    ui.horizontal(|ui| {
        ui.label("queryStrategy");
        optional_query_strategy_combo(ui, ("dns_server_query_strategy", index), &mut server.query_strategy);
    });
    ui.horizontal(|ui| {
        ui.label("disableCache");
        optional_bool_combo(ui, ("dns_server_disable_cache", index), &mut server.disable_cache);
    });
    ui.horizontal(|ui| {
        ui.label("serveStale");
        optional_bool_combo(ui, ("dns_server_serve_stale", index), &mut server.serve_stale);
    });
    optional_i64_row(ui, "serveExpiredTTL", &mut server.serve_expired_ttl, ("dns_server_ttl", index));
}

fn show_host_edit_form(
    ui: &mut Ui,
    draft: &mut DnsSettings,
    index: usize,
    remove: &mut Option<usize>,
) {
    let host = &mut draft.hosts[index];
    ui.horizontal(|ui| {
        ui.label(format!("Host {}", index + 1));
        if ui.small_button("Remove").clicked() {
            *remove = Some(index);
        }
    });
    ui.horizontal(|ui| {
        ui.label("domain");
        ui.add(TextEdit::singleline(&mut host.domain).desired_width(220.0).hint_text("example.com"));
    });
    multiline_list_row(ui, "targets (one per line)", &mut host.targets, ("dns_host_targets", index));
}

// ─── Small editing widgets ──────────────────────────────────────────────────

fn optional_text_row(ui: &mut Ui, label: &str, value: &mut Option<String>, hint: &str) {
    let mut text = value.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label(label);
        if ui
            .add(TextEdit::singleline(&mut text).desired_width(220.0).hint_text(hint))
            .changed()
        {
            let trimmed = text.trim();
            *value = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
}

fn multiline_list_row(ui: &mut Ui, label: &str, values: &mut Vec<String>, id: impl std::hash::Hash + std::fmt::Debug) {
    ui.push_id(id, |ui| {
        ui.label(label);
        let mut text = values.join("\n");
        if ui.add(TextEdit::multiline(&mut text).desired_rows(2)).changed() {
            *values = lines_to_vec(&text);
        }
    });
}

fn optional_u16_row(ui: &mut Ui, label: &str, value: &mut Option<u16>, id: impl std::hash::Hash + std::fmt::Debug) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(53);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut enabled, label);
            ui.add_enabled(enabled, egui::DragValue::new(&mut number).range(1..=65535));
        });
    });
    *value = if enabled { Some(number) } else { None };
}

fn optional_u32_row(ui: &mut Ui, label: &str, value: &mut Option<u32>, id: impl std::hash::Hash + std::fmt::Debug) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(4000);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut enabled, label);
            ui.add_enabled(enabled, egui::DragValue::new(&mut number).range(0..=u32::MAX));
        });
    });
    *value = if enabled { Some(number) } else { None };
}

fn optional_i64_row(ui: &mut Ui, label: &str, value: &mut Option<i64>, id: impl std::hash::Hash + std::fmt::Debug) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(0);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut enabled, label);
            ui.add_enabled(enabled, egui::DragValue::new(&mut number).range(0..=i64::MAX));
        });
    });
    *value = if enabled { Some(number) } else { None };
}

fn query_strategy_combo(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, value: &mut QueryStrategy) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.display_label())
        .show_ui(ui, |ui| {
            for preset in [
                QueryStrategy::UseIp,
                QueryStrategy::UseIPv4,
                QueryStrategy::UseIPv6,
                QueryStrategy::UseSystem,
            ] {
                let label = preset.display_label();
                ui.selectable_value(value, preset, label);
            }
        });
}

fn optional_query_strategy_combo(
    ui: &mut Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    value: &mut Option<QueryStrategy>,
) {
    let selected_text = value
        .as_ref()
        .map(QueryStrategy::display_label)
        .unwrap_or_else(|| "Inherit".to_owned());
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected_text)
        .show_ui(ui, |ui| {
            ui.selectable_value(value, None, "Inherit");
            for preset in [
                QueryStrategy::UseIp,
                QueryStrategy::UseIPv4,
                QueryStrategy::UseIPv6,
                QueryStrategy::UseSystem,
            ] {
                let label = preset.display_label();
                ui.selectable_value(value, Some(preset), label);
            }
        });
}

fn optional_bool_combo(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, value: &mut Option<bool>) {
    let selected_text = match value {
        Some(true) => "On",
        Some(false) => "Off",
        None => "Inherit",
    };
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected_text)
        .show_ui(ui, |ui| {
            ui.selectable_value(value, None, "Inherit");
            ui.selectable_value(value, Some(true), "On");
            ui.selectable_value(value, Some(false), "Off");
        });
}

fn lines_to_vec(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
