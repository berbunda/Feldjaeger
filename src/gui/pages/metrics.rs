//! Metrics page — `metrics` HTTP endpoint (`/debug/vars`) scrape + dashboard
//! (Roadmap §3:130).
//!
//! Same manual-refresh, warn-don't-block philosophy as the Statistics page (Roadmap §3:129):
//! every "Refresh" click is exactly one SSH-exec round trip on the remote host, nothing polls in
//! the background. Data flows exclusively through [`ApplicationService`] — this page never
//! parses `/debug/vars` itself, only renders the already-typed [`MetricsPageModel`].

use egui::{Color32, RichText, Ui};

use crate::app::{
    ApplicationService, MetricsPageModel, MetricsPageState, TrafficCategory, TrafficSeriesDisplay,
};

const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const OK_COLOR: Color32 = Color32::from_rgb(60, 160, 80);

/// Renders the Metrics page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
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
    ui.heading("Runtime");
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
