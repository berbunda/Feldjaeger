//! Stats page — live `xray api statsquery`/`statssys` read + charts (Roadmap §3:129).
//!
//! Same precondition and warn-don't-block philosophy as the API Console (§3:128): a resolved
//! `api.listen` address, `StatsService` in `api.services`. Refresh is manual only (a button, not
//! a timer) — every click is exactly one SSH-exec round trip on the remote host, and a passive
//! dashboard should not keep a background poll running against a server the user isn't looking
//! at.
//!
//! Data flows exclusively through [`ApplicationService`] — this page never parses the
//! `statsquery`/`statssys` JSON itself, only renders the already-typed [`StatsPageModel`].

use egui::{Color32, RichText, Ui};

use crate::app::{
    ApiConsolePageState, ApplicationService, StatsPageModel, TrafficCategory, TrafficSeriesDisplay,
};

use super::HelpText;

const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);

// ─── Help text (Roadmap §4.4) ─────────────────────────────────────────────────
//
// From Xray-core v26.9.30 (`app/stats`, `main/commands/all/api/stats_*.go`) and
// `xray api statsquery` / `statssys` against a live `xray.exe` 26.9.30.

const HELP_TRAFFIC: HelpText = HelpText::new(
    "Refresh runs xray api statsquery on the server (needs StatsService in api.services) and \
     reads every counter. Counters exist only with a top-level \"stats\": {} plus the policy \
     switches: system statsInboundUplink / Downlink and statsOutboundUplink / Downlink for \
     inbounds and outbounds; only tagged inbounds and outbounds get counters.\n\n\
     Values are bytes since Xray started — a restart resets them to 0; Feldjäger never resets \
     them itself. Inbound uplink is what clients sent, downlink what they received; outbound \
     uplink is what Xray sent out, downlink what came back.\n\n\
     The rate is the average between the last two Refresh clicks; the chart holds up to 120 \
     refreshes, kept only while Feldjäger runs.",
    "Refresh выполняет на сервере xray api statsquery (нужен StatsService в api.services) и \
     читает все счётчики. Счётчики существуют, только если есть объект верхнего уровня \
     \"stats\": {} и включены переключатели policy: system statsInboundUplink / Downlink и \
     statsOutboundUplink / Downlink для inbound и outbound; счётчики получают только inbound и \
     outbound с тегом.\n\n\
     Значения — байты с момента запуска Xray: перезапуск обнуляет их; сам Feldjäger их не \
     сбрасывает. Uplink у inbound — то, что отправили клиенты, downlink — то, что они получили; \
     uplink у outbound — то, что Xray отправил наружу, downlink — то, что вернулось.\n\n\
     Скорость — среднее между двумя последними нажатиями Refresh; график хранит до 120 \
     обновлений и только пока работает Feldjäger.",
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
const HELP_SYSTEM: HelpText = HelpText::new(
    "xray api statssys — the Xray process itself: Uptime (seconds since start), Goroutines, GC \
     cycles and their total pause, heap in use (Alloc), total ever allocated (TotalAlloc — only \
     grows), memory obtained from the OS (Sys — the closest to the process footprint), live \
     objects = Mallocs − Frees. Steadily growing Goroutines or Alloc under constant load can \
     point to stuck connections.",
    "xray api statssys — сам процесс Xray: Uptime (секунды с запуска), число горутин, циклы GC и \
     их суммарная пауза, занятая куча (Alloc), всего выделено (TotalAlloc — только растёт), \
     память, полученная от ОС (Sys — ближе всего к размеру процесса), живые объекты = Mallocs − \
     Frees. Постоянный рост числа горутин или Alloc при неизменной нагрузке может указывать на \
     зависшие соединения.",
);

/// Renders the Stats page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    super::show_help_dialog(ui);
    ui.heading("Statistics");
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "Live counters read from the running Xray process via its gRPC API. Refresh is \
             manual — click the buttons below to fetch a fresh snapshot.",
        )
        .size(12.0)
        .color(MUTED_COLOR),
    );
    ui.add_space(8.0);

    let model = service.stats_page_model();
    if model.state != ApiConsolePageState::Ready {
        show_state_message(ui, model.state);
        return;
    }

    ui.horizontal(|ui| {
        ui.strong("API server:");
        ui.label(model.server_addr.as_deref().unwrap_or("?"));
    });
    if let Some(warning) = &model.stats_service_warning {
        ui.label(RichText::new(warning.clone()).size(12.0).color(WARN_COLOR));
    }
    for warning in &model.wiring_warnings {
        ui.label(RichText::new(warning.clone()).size(12.0).color(WARN_COLOR));
    }
    ui.add_space(8.0);

    show_traffic_section(ui, service, &model);
    ui.separator();
    show_other_counters_section(ui, &model);
    ui.separator();
    show_sys_stats_section(ui, service, &model);
}

fn show_state_message(ui: &mut Ui, state: ApiConsolePageState) {
    let color = match state {
        ApiConsolePageState::ApiNotConfigured => WARN_COLOR,
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_traffic_section(ui: &mut Ui, service: &mut ApplicationService, model: &StatsPageModel) {
    ui.horizontal(|ui| {
        super::help_button(ui, "Traffic", HELP_TRAFFIC);
        ui.heading("Traffic");
        if ui
            .add_enabled(!model.is_query_running, egui::Button::new("Refresh"))
            .clicked()
        {
            let _ = service.start_stats_query();
        }
        if model.is_query_running {
            ui.label(RichText::new("Loading...").size(12.0).color(MUTED_COLOR));
        }
    });
    if let Some(error) = &model.last_query_error {
        ui.label(RichText::new(error.clone()).size(12.0).color(ERROR_COLOR));
    }
    ui.add_space(4.0);

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

fn show_traffic_category(ui: &mut Ui, model: &StatsPageModel, category: TrafficCategory) {
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

fn show_other_counters_section(ui: &mut Ui, model: &StatsPageModel) {
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

fn show_sys_stats_section(ui: &mut Ui, service: &mut ApplicationService, model: &StatsPageModel) {
    ui.horizontal(|ui| {
        super::help_button(ui, "System", HELP_SYSTEM);
        ui.heading("System");
        if ui
            .add_enabled(!model.is_sys_running, egui::Button::new("Refresh"))
            .clicked()
        {
            let _ = service.start_stats_sys_query();
        }
        if model.is_sys_running {
            ui.label(RichText::new("Loading...").size(12.0).color(MUTED_COLOR));
        }
    });
    if let Some(error) = &model.last_sys_error {
        ui.label(RichText::new(error.clone()).size(12.0).color(ERROR_COLOR));
    }
    let Some(sys) = &model.sys else {
        ui.label(
            RichText::new("No data yet — click Refresh.")
                .size(12.0)
                .color(MUTED_COLOR),
        );
        return;
    };
    egui::Grid::new("stats_sys_grid")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            ui.label("Uptime:");
            ui.label(&sys.uptime);
            ui.end_row();
            ui.label("Goroutines:");
            ui.label(&sys.num_goroutine);
            ui.end_row();
            ui.label("GC cycles:");
            ui.label(&sys.num_gc);
            ui.end_row();
            ui.label("GC pause (total):");
            ui.label(&sys.pause_total);
            ui.end_row();
            ui.label("Heap in use (Alloc):");
            ui.label(&sys.alloc);
            ui.end_row();
            ui.label("Total allocated:");
            ui.label(&sys.total_alloc);
            ui.end_row();
            ui.label("Obtained from OS (Sys):");
            ui.label(&sys.sys);
            ui.end_row();
            ui.label("Live objects:");
            ui.label(&sys.live_objects);
            ui.end_row();
            ui.label("Mallocs / Frees:");
            ui.label(format!("{} / {}", sys.mallocs, sys.frees));
            ui.end_row();
        });
}
