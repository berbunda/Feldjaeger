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
use crate::gui::pages::{HelpText, field_label, help_button, help_checkbox, help_multiline_list_row};
use crate::xray::{DnsHostEntry, DnsServerEntry, DnsSettings, QueryStrategy};

// ─── Field help text (Roadmap §4.4) ──────────────────────────────────────────
//
// Condensed from https://xtls.github.io/config/dns.html and checked against Xray-core
// (`infra/conf/dns.go`; `app/dns` for the cache and UseSystem semantics).

// General.
const HELP_CLIENT_IP: HelpText = HelpText::new(
    "IP address sent in the EDNS Client Subnet extension, so the DNS server answers for that \
     location — usually this server's public IP. Empty = not sent. A server's own clientIP \
     overrides it.",
    "IP-адрес, передаваемый в расширении EDNS Client Subnet, чтобы DNS-сервер отвечал для этого \
     местоположения, — обычно публичный IP этого сервера. Пусто — не передаётся. Собственный \
     clientIP сервера его переопределяет.",
);
const HELP_QUERY_STRATEGY: HelpText = HelpText::new(
    "Which records the built-in DNS asks for: UseIP — A and AAAA (default); UseIPv4 — A only; \
     UseIPv6 — AAAA only; UseSystem — A and/or AAAA depending on which of IPv4 / IPv6 the system \
     has routes for. Applies to every server; a server can only narrow it further.",
    "Какие записи запрашивает встроенный DNS: UseIP — A и AAAA (по умолчанию); UseIPv4 — только A; \
     UseIPv6 — только AAAA; UseSystem — A и/или AAAA в зависимости от того, для каких из IPv4 / \
     IPv6 в системе есть маршруты. Действует на все серверы; сервер может только сузить выбор.",
);
const HELP_DISABLE_CACHE: HelpText = HelpText::new(
    "Turns off the DNS cache: every lookup goes to the servers. Default off.",
    "Отключает кэш DNS: каждый запрос уходит на серверы. По умолчанию выключено.",
);
const HELP_SERVE_STALE: HelpText = HelpText::new(
    "Optimistic caching: an expired cache entry is still answered at once while it is refreshed \
     in the background (for up to serveExpiredTTL seconds). Default off.",
    "Оптимистичное кэширование: на устаревшую запись кэша всё равно сразу отвечают, обновляя её в \
     фоне (не дольше serveExpiredTTL секунд). По умолчанию выключено.",
);
const HELP_SERVE_EXPIRED_TTL: HelpText = HelpText::new(
    "With serveStale: for how many seconds after expiry an entry may still be served. 0 \
     (default) = no limit.",
    "При serveStale: сколько секунд после истечения запись ещё можно отдавать. 0 (по умолчанию) — \
     без ограничения.",
);
const HELP_DISABLE_FALLBACK: HelpText = HelpText::new(
    "Ask only the servers whose domains match the query; never fall back to the other servers. \
     Default off.",
    "Спрашивать только серверы, чьи domains совпали с запросом; никогда не переходить к остальным \
     серверам. По умолчанию выключено.",
);
const HELP_DISABLE_FALLBACK_IF_MATCH: HelpText = HelpText::new(
    "No fallback to the other servers when a server's domains matched the query (queries that \
     matched no domains list still fall back). Default off.",
    "Не переходить к остальным серверам, если с запросом совпали domains какого-то сервера \
     (запросы без совпадений по-прежнему переходят). По умолчанию выключено.",
);
const HELP_ENABLE_PARALLEL_QUERY: HelpText = HelpText::new(
    "Query servers in parallel instead of one after another: they are grouped dynamically and \
     the fastest answer within a group wins. Default off.",
    "Опрашивать серверы параллельно, а не по очереди: они динамически группируются, и внутри \
     группы побеждает самый быстрый ответ. По умолчанию выключено.",
);
const HELP_USE_SYSTEM_HOSTS: HelpText = HelpText::new(
    "Adds the system hosts file (/etc/hosts on Linux) to the static hosts below. Default off.",
    "Добавляет системный файл hosts (/etc/hosts в Linux) к статическим hosts ниже. По умолчанию \
     выключено.",
);
const HELP_TAG: HelpText = HelpText::new(
    "Inbound tag of the queries the built-in DNS sends itself, so routing rules (inboundTag) can \
     pick the outbound for them. Empty = routed like other traffic. A server's own tag overrides \
     it.",
    "Тег inbound для запросов, которые отправляет сам встроенный DNS, чтобы правила \
     маршрутизации (inboundTag) могли выбрать для них outbound. Пусто — маршрутизируются как \
     остальной трафик. Собственный tag сервера его переопределяет.",
);

// DNS servers.
const HELP_SERVER_ADDRESS: HelpText = HelpText::new(
    "The DNS server: an IP (plain UDP), tcp://host or https://host/dns-query (DoH); the +local \
     forms tcp+local://, https+local:// and quic+local:// (DNS over QUIC, local only) connect \
     directly instead of through routing. localhost = the system resolver; fakedns = answer \
     from the FakeDNS pool.",
    "DNS-сервер: IP (обычный UDP), tcp://host или https://host/dns-query (DoH); формы с +local — \
     tcp+local://, https+local:// и quic+local:// (DNS over QUIC, только local) — подключаются \
     напрямую, минуя маршрутизацию. localhost — системный резолвер; fakedns — ответ из пула \
     FakeDNS.",
);
const HELP_SERVER_PORT: HelpText = HelpText::new(
    "Port of the server; unchecked = 53 (or the scheme's own default).",
    "Порт сервера; без отметки — 53 (или стандартный порт схемы).",
);
const HELP_SERVER_DOMAINS: HelpText = HelpText::new(
    "Queries for these domains go to this server first (routing domain syntax: domain:, full:, \
     keyword:, regexp:, geosite:…). Empty = no priority list.",
    "Запросы этих доменов сначала идут на этот сервер (синтаксис доменов маршрутизации: domain:, \
     full:, keyword:, regexp:, geosite:…). Пусто — без приоритетного списка.",
);
const HELP_SERVER_EXPECTED_IPS: HelpText = HelpText::new(
    "Checks the server's answer: only addresses inside these ranges (CIDR, geoip:…) are \
     returned. Empty = any answer.",
    "Проверяет ответ сервера: возвращаются только адреса из этих диапазонов (CIDR, geoip:…). \
     Пусто — любой ответ.",
);
const HELP_SERVER_UNEXPECTED_IPS: HelpText = HelpText::new(
    "The reverse of expectedIPs: answers inside these ranges (CIDR, geoip:…) are removed. Empty \
     = nothing removed.",
    "Обратное expectedIPs: ответы из этих диапазонов (CIDR, geoip:…) удаляются. Пусто — ничего не \
     удаляется.",
);
const HELP_SERVER_SKIP_FALLBACK: HelpText = HelpText::new(
    "Never ask this server as a fallback — only for queries matching its domains. Default off.",
    "Никогда не спрашивать этот сервер в порядке перехода — только для запросов, совпавших с его \
     domains. По умолчанию выключено.",
);
const HELP_SERVER_FINAL_QUERY: HelpText = HelpText::new(
    "This server's answer is final: when it is asked, no further server is tried after it. \
     Default off.",
    "Ответ этого сервера окончательный: если он опрошен, следующие серверы после него не \
     пробуются. По умолчанию выключено.",
);
const HELP_SERVER_TIMEOUT: HelpText = HelpText::new(
    "Query timeout in milliseconds; unchecked = 4000.",
    "Таймаут запроса в миллисекундах; без отметки — 4000.",
);
const HELP_SERVER_TAG: HelpText = HelpText::new(
    "Inbound tag of this server's queries for routing rules; empty = the global tag.",
    "Тег inbound для запросов этого сервера в правилах маршрутизации; пусто — глобальный tag.",
);
const HELP_SERVER_CLIENT_IP: HelpText = HelpText::new(
    "EDNS Client Subnet IP for this server; empty = the global clientIp.",
    "IP для EDNS Client Subnet у этого сервера; пусто — глобальный clientIp.",
);
const HELP_SERVER_QUERY_STRATEGY: HelpText = HelpText::new(
    "Record types for this server (see the global queryStrategy); Inherit = the global value. \
     It can only narrow the global one — UseIPv6 here does nothing under a global UseIPv4.",
    "Типы записей для этого сервера (см. глобальный queryStrategy); Inherit — глобальное значение. \
     Может только сузить глобальное — UseIPv6 здесь ничего не даёт при глобальном UseIPv4.",
);
const HELP_SERVER_DISABLE_CACHE: HelpText = HelpText::new(
    "Cache off / on for this server; Inherit = the global disableCache.",
    "Выключить / включить кэш для этого сервера; Inherit — глобальный disableCache.",
);
const HELP_SERVER_SERVE_STALE: HelpText = HelpText::new(
    "Optimistic caching for this server; Inherit = the global serveStale.",
    "Оптимистичное кэширование для этого сервера; Inherit — глобальный serveStale.",
);
const HELP_SERVER_SERVE_EXPIRED_TTL: HelpText = HelpText::new(
    "serveExpiredTTL for this server; unchecked = the global value.",
    "serveExpiredTTL для этого сервера; без отметки — глобальное значение.",
);

// Static hosts.
const HELP_HOST_DOMAIN: HelpText = HelpText::new(
    "The name to answer: a plain domain, or domain:, full:, keyword:, regexp:, geosite:… as in \
     routing.",
    "Имя, на которое нужно отвечать: обычный домен или domain:, full:, keyword:, regexp:, \
     geosite:…, как в маршрутизации.",
);
const HELP_HOST_TARGETS: HelpText = HelpText::new(
    "The answer, one per line: IP addresses, or a single domain that is then resolved instead \
     (like a CNAME).",
    "Ответ, по одному на строку: IP-адреса или один домен, который тогда разрешается вместо \
     исходного (как CNAME).",
);

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
    super::show_help_dialog(ui);

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

    super::optional_text_row(ui, "clientIp", HELP_CLIENT_IP, &mut draft.client_ip, "1.2.3.4", 220.0, "dns_client_ip");

    ui.horizontal(|ui| {
        field_label(ui, "queryStrategy", HELP_QUERY_STRATEGY);
        query_strategy_combo(ui, "dns_query_strategy", &mut draft.query_strategy);
    });

    help_checkbox(ui, "disableCache", HELP_DISABLE_CACHE, &mut draft.disable_cache);
    help_checkbox(ui, "serveStale", HELP_SERVE_STALE, &mut draft.serve_stale);
    ui.horizontal(|ui| {
        field_label(ui, "serveExpiredTTL", HELP_SERVE_EXPIRED_TTL);
        ui.add(egui::DragValue::new(&mut draft.serve_expired_ttl).range(0..=i64::MAX));
    });
    help_checkbox(ui, "disableFallback", HELP_DISABLE_FALLBACK, &mut draft.disable_fallback);
    help_checkbox(
        ui,
        "disableFallbackIfMatch",
        HELP_DISABLE_FALLBACK_IF_MATCH,
        &mut draft.disable_fallback_if_match,
    );
    help_checkbox(ui, "enableParallelQuery", HELP_ENABLE_PARALLEL_QUERY, &mut draft.enable_parallel_query);
    help_checkbox(ui, "useSystemHosts", HELP_USE_SYSTEM_HOSTS, &mut draft.use_system_hosts);

    super::optional_text_row(ui, "tag", HELP_TAG, &mut draft.tag, "dns-out", 220.0, "dns_tag");

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
        field_label(ui, "address", HELP_SERVER_ADDRESS);
        ui.add(TextEdit::singleline(&mut server.address).desired_width(220.0).hint_text("8.8.8.8 or https://dns.google/dns-query"));
    });

    optional_u16_row(ui, "port", HELP_SERVER_PORT, &mut server.port, ("dns_server_port", index));
    help_multiline_list_row(ui, "domains (one per line)", HELP_SERVER_DOMAINS, &mut server.domains, ("dns_server_domains", index));
    help_multiline_list_row(
        ui,
        "expectedIPs (one per line)",
        HELP_SERVER_EXPECTED_IPS,
        &mut server.expected_ips,
        ("dns_server_expected", index),
    );
    help_multiline_list_row(
        ui,
        "unexpectedIPs (one per line)",
        HELP_SERVER_UNEXPECTED_IPS,
        &mut server.unexpected_ips,
        ("dns_server_unexpected", index),
    );
    help_checkbox(ui, "skipFallback", HELP_SERVER_SKIP_FALLBACK, &mut server.skip_fallback);
    help_checkbox(ui, "finalQuery", HELP_SERVER_FINAL_QUERY, &mut server.final_query);
    optional_u32_row(ui, "timeoutMs", HELP_SERVER_TIMEOUT, &mut server.timeout_ms, ("dns_server_timeout", index));
    super::optional_text_row(ui, "tag", HELP_SERVER_TAG, &mut server.tag, "server-tag", 220.0, ("dns_server_tag", index));
    super::optional_text_row(ui, "clientIP", HELP_SERVER_CLIENT_IP, &mut server.client_ip, "1.2.3.4", 220.0, ("dns_server_client_ip", index));

    ui.horizontal(|ui| {
        field_label(ui, "queryStrategy", HELP_SERVER_QUERY_STRATEGY);
        optional_query_strategy_combo(ui, ("dns_server_query_strategy", index), &mut server.query_strategy);
    });
    ui.horizontal(|ui| {
        field_label(ui, "disableCache", HELP_SERVER_DISABLE_CACHE);
        optional_bool_combo(ui, ("dns_server_disable_cache", index), &mut server.disable_cache);
    });
    ui.horizontal(|ui| {
        field_label(ui, "serveStale", HELP_SERVER_SERVE_STALE);
        optional_bool_combo(ui, ("dns_server_serve_stale", index), &mut server.serve_stale);
    });
    optional_i64_row(
        ui,
        "serveExpiredTTL",
        HELP_SERVER_SERVE_EXPIRED_TTL,
        &mut server.serve_expired_ttl,
        ("dns_server_ttl", index),
    );
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
        field_label(ui, "domain", HELP_HOST_DOMAIN);
        ui.add(TextEdit::singleline(&mut host.domain).desired_width(220.0).hint_text("example.com"));
    });
    help_multiline_list_row(ui, "targets (one per line)", HELP_HOST_TARGETS, &mut host.targets, ("dns_host_targets", index));
}

// ─── Small editing widgets ──────────────────────────────────────────────────

fn optional_u16_row(
    ui: &mut Ui,
    label: &'static str,
    help: HelpText,
    value: &mut Option<u16>,
    id: impl std::hash::Hash + std::fmt::Debug,
) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(53);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            help_button(ui, label, help);
            ui.checkbox(&mut enabled, label);
            ui.add_enabled(enabled, egui::DragValue::new(&mut number).range(1..=65535));
        });
    });
    *value = if enabled { Some(number) } else { None };
}

fn optional_u32_row(
    ui: &mut Ui,
    label: &'static str,
    help: HelpText,
    value: &mut Option<u32>,
    id: impl std::hash::Hash + std::fmt::Debug,
) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(4000);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            help_button(ui, label, help);
            ui.checkbox(&mut enabled, label);
            ui.add_enabled(enabled, egui::DragValue::new(&mut number).range(0..=u32::MAX));
        });
    });
    *value = if enabled { Some(number) } else { None };
}

fn optional_i64_row(
    ui: &mut Ui,
    label: &'static str,
    help: HelpText,
    value: &mut Option<i64>,
    id: impl std::hash::Hash + std::fmt::Debug,
) {
    let mut enabled = value.is_some();
    let mut number = value.unwrap_or(0);
    ui.push_id(id, |ui| {
        ui.horizontal(|ui| {
            help_button(ui, label, help);
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

