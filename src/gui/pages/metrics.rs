//! Metrics page — `metrics` HTTP endpoint (`/debug/vars`) scrape + dashboard
//! (Roadmap §3:130).
//!
//! Same manual-refresh, warn-don't-block philosophy as the Statistics page (Roadmap §3:129):
//! every "Refresh" click is exactly one SSH-exec round trip on the remote host, nothing polls in
//! the background. Data flows exclusively through [`ApplicationService`] — this page never
//! parses `/debug/vars` itself, only renders the already-typed [`MetricsPageModel`].

use egui::{Color32, RichText, Ui};

use super::HelpText;
use crate::app::{
    ApplicationService, MetricsPageModel, MetricsPageState, TrafficCategory, TrafficSeriesDisplay,
};

const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const OK_COLOR: Color32 = Color32::from_rgb(60, 160, 80);

// ─── Help text (Roadmap §4.4) ─────────────────────────────────────────────────
//
// From Xray-core v26.9.30 (`app/metrics/metrics.go`) and `/debug/vars` of a live
// `xray.exe` 26.9.30 with stats and observatory.

const HELP_LISTEN: HelpText = HelpText::new(
    "Refresh runs curl (or wget, if curl is missing) on the server against \
     http://<metrics.listen>/debug/vars — Go's expvar JSON with the keys stats, observatory, \
     memstats and cmdline. Only metrics.listen works here: a metrics object reachable only by \
     tag through routing cannot be fetched this way.\n\n\
     The endpoint has no authentication and also serves /debug/pprof (profiles, command line) — \
     keep it on 127.0.0.1. Traffic shows the same counters as the Statistics page (they need \
     stats and the policy stats switches), with its own history; the rate is the average between \
     the last two Refresh clicks.",
    "Refresh выполняет на сервере curl (или wget, если curl нет) по адресу \
     http://<metrics.listen>/debug/vars — JSON expvar из Go с ключами stats, observatory, \
     memstats и cmdline. Здесь работает только metrics.listen: объект metrics, доступный лишь по \
     тегу через маршрутизацию, так прочитать нельзя.\n\n\
     У адреса нет аутентификации, и он отдаёт ещё /debug/pprof (профили, командную строку) — \
     держите его на 127.0.0.1. Traffic показывает те же счётчики, что и страница Statistics (им \
     нужны stats и переключатели stats* в policy), со своей историей; скорость — среднее между \
     двумя последними нажатиями Refresh.",
);
const HELP_OBSERVATORY: HelpText = HelpText::new(
    "Live results of observatory / burstObservatory, per probed outbound: green / red — alive \
     after the last probe; delay — of the last successful probe; last seen — time of the last \
     success, last try — of the last attempt; the error of a failed probe. For burstObservatory \
     also the health-ping summary: average, min / max and failed / all of the recent probes. \
     Empty until the first probe completes.",
    "Живые результаты observatory / burstObservatory для каждого проверяемого outbound: \
     зелёный / красный — доступен ли после последней проверки; delay — задержка последней \
     успешной проверки; last seen — время последнего успеха, last try — последней попытки; \
     ошибка неудачной проверки. Для burstObservatory — ещё сводка health ping: среднее, \
     min / max и неудачных / всего среди недавних проверок. Пусто, пока не завершится первая \
     проверка.",
);
const HELP_OTHER_COUNTERS: HelpText = HelpText::new(
    "Counters whose name does not match an inbound or outbound tag of the loaded configuration: \
     per-user counters user>>>email>>>traffic>>>uplink / downlink (they need the policy level \
     switches statsUserUplink / statsUserDownlink and an email on the user), and counters of tags \
     that are not in the configuration — e.g. added live on the API Console.",
    "Счётчики, имя которых не совпадает с тегом inbound или outbound загруженной конфигурации: \
     счётчики пользователей user>>>email>>>traffic>>>uplink / downlink (для них нужны \
     переключатели уровня policy statsUserUplink / statsUserDownlink и email у пользователя), и \
     счётчики тегов, которых нет в конфигурации, — например, добавленных на ходу в API Console.",
);
const HELP_RUNTIME: HelpText = HelpText::new(
    "Go memstats of the Xray process: heap in use (Alloc), total ever allocated (TotalAlloc), \
     memory obtained from the OS (Sys), live heap objects, Mallocs / Frees, GC cycles and their \
     total pause; cmdline — how Xray was started (binary, -config / -confdir). The field set \
     differs from statssys on the Statistics page.",
    "memstats процесса Xray из Go: занятая куча (Alloc), всего выделено (TotalAlloc), память, \
     полученная от ОС (Sys), живые объекты кучи, Mallocs / Frees, циклы GC и их суммарная пауза; \
     cmdline — как запущен Xray (бинарник, -config / -confdir). Набор полей отличается от \
     statssys на странице Statistics.",
);

/// Renders the Metrics page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    super::show_help_dialog(ui);
    ui.heading("Metrics");
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "Live data read from the running Xray process's `metrics` HTTP endpoint \
             (`/debug/vars` — a plain JSON dump, not a Prometheus scrape target). Fetched by \
             running curl/wget on the remote host, the same way the Statistics page reaches the \
             gRPC API. Refresh is manual.",
        )
        .size(12.0)
        .color(MUTED_COLOR),
    );
    ui.add_space(8.0);

    let model = service.metrics_page_model();
    if model.state != MetricsPageState::Ready {
        show_state_message(ui, model.state);
        return;
    }

    ui.horizontal(|ui| {
        super::help_button(ui, "Metrics", HELP_LISTEN);
        ui.strong("Metrics listen:");
        ui.label(model.listen_addr.as_deref().unwrap_or("?"));
        if ui
            .add_enabled(!model.is_running, egui::Button::new("Refresh"))
            .clicked()
        {
            let _ = service.start_metrics_scrape();
        }
        if model.is_running {
            ui.label(RichText::new("Loading...").size(12.0).color(MUTED_COLOR));
        }
    });
    if let Some(error) = &model.last_error {
        ui.label(RichText::new(error.clone()).size(12.0).color(ERROR_COLOR));
    }
    for warning in &model.wiring_warnings {
        ui.label(RichText::new(warning.clone()).size(12.0).color(WARN_COLOR));
    }
    ui.add_space(8.0);

    show_traffic_section(ui, &model);
    ui.separator();
    show_observatory_section(ui, &model);
    ui.separator();
    show_other_counters_section(ui, &model);
    ui.separator();
    show_runtime_section(ui, &model);
}

fn show_state_message(ui: &mut Ui, state: MetricsPageState) {
    let color = match state {
        MetricsPageState::MetricsNotConfigured => WARN_COLOR,
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_traffic_section(ui: &mut Ui, model: &MetricsPageModel) {
    ui.heading("Traffic");
    if model.traffic.is_empty() {
        ui.label(
            RichText::new("No inbound or outbound tags in the loaded configuration.")
                .size(12.0)
                .color(MUTED_COLOR),
        );
        return;
    }
    show_traffic_category(ui, model, TrafficCategory::Inbound);
    ui.add_space(6.0);
    show_traffic_category(ui, model, TrafficCategory::Outbound);
}

fn show_traffic_category(ui: &mut Ui, model: &MetricsPageModel, category: TrafficCategory) {
    let rows: Vec<&TrafficSeriesDisplay> = model
        .traffic
        .iter()
        .filter(|series| series.category == category)
        .collect();
    if rows.is_empty() {
        return;
    }
    egui::CollapsingHeader::new(category.label())
        .default_open(true)
        .show(ui, |ui| {
            for series in rows {
                show_traffic_row(ui, series);
            }
        });
}

fn show_traffic_row(ui: &mut Ui, series: &TrafficSeriesDisplay) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{} — {}", series.tag, series.direction.label()))
                .strong()
                .size(13.0),
        );
        ui.label(RichText::new(series.current_display.clone()).size(13.0));
        if let Some(rate) = &series.rate_display {
            ui.label(RichText::new(rate.clone()).size(12.0).color(MUTED_COLOR));
        }
    });
    super::sparkline(ui, &series.points, 260.0, 32.0);
    ui.add_space(4.0);
}

fn show_observatory_section(ui: &mut Ui, model: &MetricsPageModel) {
    let title = if model.observatory.is_empty() {
        "Observatory (no data)".to_owned()
    } else {
        format!("Observatory ({})", model.observatory.len())
    };
    egui::CollapsingHeader::new(title)
        .default_open(true)
        .show(ui, |ui| {
            super::help_button(ui, "Observatory", HELP_OBSERVATORY);
            if model.observatory.is_empty() {
                ui.label(
                    RichText::new(
                        "No live Observatory data — either `observatory`/`burstObservatory` is \
                         not configured, or no probe has completed yet.",
                    )
                    .size(12.0)
                    .color(MUTED_COLOR),
                );
                return;
            }
            for row in &model.observatory {
                ui.horizontal(|ui| {
                    let (dot, color) = if row.alive {
                        ("●", OK_COLOR)
                    } else {
                        ("●", ERROR_COLOR)
                    };
                    ui.label(RichText::new(dot).color(color));
                    ui.label(RichText::new(&row.outbound_tag).strong().size(13.0));
                    ui.label(RichText::new(&row.delay_display).size(13.0));
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "Last seen {} · last try {}",
                            row.last_seen_display, row.last_try_display
                        ))
                        .size(11.0)
                        .color(MUTED_COLOR),
                    );
                });
                if row.last_error_reason != "—" {
                    ui.label(
                        RichText::new(&row.last_error_reason)
                            .size(11.0)
                            .color(WARN_COLOR),
                    );
                }
                if let Some(ping) = &row.health_ping_display {
                    ui.label(RichText::new(ping).size(11.0).color(MUTED_COLOR));
                }
                ui.add_space(6.0);
            }
        });
}

fn show_other_counters_section(ui: &mut Ui, model: &MetricsPageModel) {
    let title = if model.other_counters.is_empty() {
        "Other counters (none)".to_owned()
    } else {
        format!("Other counters ({})", model.other_counters.len())
    };
    egui::CollapsingHeader::new(title)
        .default_open(false)
        .show(ui, |ui| {
            super::help_button(ui, "Other counters", HELP_OTHER_COUNTERS);
            if model.other_counters.is_empty() {
                ui.label(
                    RichText::new(
                        "Counters that don't match a known inbound/outbound tag — e.g. \
                         per-user (`user>>>...`) counters, or tags no longer in the loaded \
                         configuration.",
                    )
                    .size(12.0)
                    .color(MUTED_COLOR),
                );
                return;
            }
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for counter in &model.other_counters {
                        ui.label(
                            RichText::new(format!("{} = {}", counter.name, counter.value))
                                .monospace()
                                .size(12.0),
                        );
                    }
                });
        });
}

fn show_runtime_section(ui: &mut Ui, model: &MetricsPageModel) {
    ui.horizontal(|ui| {
        super::help_button(ui, "Runtime", HELP_RUNTIME);
        ui.heading("Runtime");
    });
    ui.label(
        RichText::new(
            "From Go's default `memstats`/`cmdline` expvars — a different, smaller field set \
             than the Statistics page's `statssys`.",
        )
        .size(11.0)
        .color(MUTED_COLOR),
    );
    let Some(mem) = &model.memstats else {
        ui.label(
            RichText::new("No data yet — click Refresh.")
                .size(12.0)
                .color(MUTED_COLOR),
        );
        return;
    };
    egui::Grid::new("metrics_runtime_grid")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            ui.label("Heap in use (Alloc):");
            ui.label(&mem.alloc);
            ui.end_row();
            ui.label("Total allocated:");
            ui.label(&mem.total_alloc);
            ui.end_row();
            ui.label("Obtained from OS (Sys):");
            ui.label(&mem.sys);
            ui.end_row();
            ui.label("Live heap objects:");
            ui.label(&mem.heap_objects);
            ui.end_row();
            ui.label("Mallocs / Frees:");
            ui.label(format!("{} / {}", mem.mallocs, mem.frees));
            ui.end_row();
            ui.label("GC cycles:");
            ui.label(&mem.num_gc);
            ui.end_row();
            ui.label("GC pause (total):");
            ui.label(&mem.pause_total);
            ui.end_row();
        });
    if let Some(cmdline) = &model.cmdline {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("cmdline: {cmdline}"))
                .monospace()
                .size(11.0)
                .color(MUTED_COLOR),
        );
    }
}
