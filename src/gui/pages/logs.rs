//! Xray Logs page — read-only remote access/error/journal viewing.
//!
//! The GUI never runs SSH, journalctl, or opens remote files. All work goes
//! through [`ApplicationService`].

use egui::{Color32, FontId, RichText, TextEdit, Ui};

use crate::app::{ApplicationService, XrayLogsPageModel, XrayLogsPageState, XrayLogsUiState};
use crate::xray::{XrayLogLineLimit, XrayLogSourceKind};

/// Renders the Xray Logs page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.ensure_xray_log_sources_probed();

    ui.heading("Xray Logs");
    ui.add_space(8.0);

    let model = service.xray_logs_page_model();

    ui.label(
        RichText::new(&model.privacy_notice)
            .size(13.0)
            .color(Color32::from_rgb(160, 120, 40)),
    );
    ui.add_space(8.0);

    if let Some(reason) = &model.blocked_reason {
        ui.label(
            RichText::new(reason.clone())
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        ui.add_space(8.0);
        return;
    }

    show_source_selector(ui, service, &model);
    ui.add_space(8.0);
    show_source_info(ui, &model);
    ui.add_space(8.0);
    show_toolbar(ui, service, &model);
    ui.add_space(8.0);
    show_status(ui, &model);
    ui.add_space(8.0);
    show_log_view(ui, &model);
}

fn show_source_selector(ui: &mut Ui, service: &mut ApplicationService, model: &XrayLogsPageModel) {
    ui.strong("Log source");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        for source in &model.sources {
            let selected = source.kind == model.selected;
            // Disabled sources stay visible; they can be selected to inspect status.
            let label = format!("{}  {}", source.display_name, source.availability.label());
            let enabled = !model.ui_state.is_busy() || selected;
            ui.add_enabled_ui(enabled, |ui| {
                if ui.selectable_label(selected, label).clicked() {
                    service.select_xray_log_source(source.kind);
                }
            });
        }
    });
}

fn show_source_info(ui: &mut Ui, model: &XrayLogsPageModel) {
    ui.strong("Source information");
    ui.add_space(4.0);

    let Some(source) = &model.selected_source else {
        ui.label("No source selected.");
        return;
    };

    egui::Grid::new("xray_log_source_info")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Type").strong());
            ui.label(source.kind.type_label());
            ui.end_row();

            let key = match source.kind {
                XrayLogSourceKind::Journal => "Service",
                _ => "Path",
            };
            ui.label(RichText::new(key).strong());
            ui.label(&source.source);
            ui.end_row();

            ui.label(RichText::new("Status").strong());
            ui.label(source.availability.label());
            ui.end_row();
        });

    for warning in &source.warnings {
        ui.label(
            RichText::new(warning.clone())
                .size(13.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
}

fn show_toolbar(ui: &mut Ui, service: &mut ApplicationService, model: &XrayLogsPageModel) {
    ui.horizontal(|ui| {
        ui.label("Lines:");
        for limit in XrayLogLineLimit::ALL {
            let selected = model.line_limit == *limit;
            if ui
                .add_enabled(
                    !model.ui_state.is_following(),
                    egui::Button::selectable(selected, limit.label()),
                )
                .clicked()
            {
                service.set_xray_log_line_limit(*limit);
            }
        }

        ui.separator();

        if ui
            .add_enabled(model.can_refresh, egui::Button::new("Refresh"))
            .clicked()
            && let Err(message) = service.start_xray_log_refresh()
        {
            service.show_status_message(message);
        }

        if model.can_stop_follow {
            if ui.button("Stop Follow").clicked() {
                service.stop_xray_log_follow();
            }
        } else if ui
            .add_enabled(model.can_follow, egui::Button::new("Follow"))
            .clicked()
            && let Err(message) = service.start_xray_log_follow()
        {
            service.show_status_message(message);
        }

        ui.separator();

        ui.label("Search:");
        let mut query = model.search.query.clone();
        let response = ui.add(
            TextEdit::singleline(&mut query)
                .desired_width(160.0)
                .hint_text("Find in loaded lines"),
        );
        if response.changed() {
            service.set_xray_log_search_query(&query);
        }
        if ui
            .add_enabled(model.search.match_count() > 0, egui::Button::new("Prev"))
            .clicked()
        {
            service.xray_log_search_previous();
        }
        if ui
            .add_enabled(model.search.match_count() > 0, egui::Button::new("Next"))
            .clicked()
        {
            service.xray_log_search_next();
        }
        if model.search.match_count() > 0 {
            let current = model.search.current.map(|i| i + 1).unwrap_or(0);
            ui.label(format!("{current}/{}", model.search.match_count()));
        }
    });
}

fn show_status(ui: &mut Ui, model: &XrayLogsPageModel) {
    let color = match model.page_state {
        XrayLogsPageState::Error | XrayLogsPageState::FollowInterrupted => {
            Color32::from_rgb(200, 60, 60)
        }
        XrayLogsPageState::SourceDisabled | XrayLogsPageState::SourceUnavailable => {
            Color32::from_rgb(210, 170, 40)
        }
        XrayLogsPageState::Following | XrayLogsPageState::Loading => {
            Color32::from_rgb(80, 140, 200)
        }
        _ => Color32::from_rgb(120, 120, 120),
    };
    ui.label(
        RichText::new(model.page_state.label())
            .size(14.0)
            .color(color),
    );

    if let XrayLogsUiState::Failed { kind, detail } = &model.ui_state {
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

    if model.page_state == XrayLogsPageState::EmptyLog {
        ui.label(
            RichText::new("No log entries.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_log_view(ui: &mut Ui, model: &XrayLogsPageModel) {
    let text = model
        .entries
        .iter()
        .map(|entry| entry.display_text())
        .collect::<Vec<_>>()
        .join("\n");

    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .stick_to_bottom(model.ui_state.is_following())
        .show(ui, |ui| {
            // Read-only monospaced stream: selectable/copyable, not editable.
            let response = ui.add(
                egui::Label::new(RichText::new(&text).font(FontId::monospace(13.0)))
                    .selectable(true)
                    .wrap_mode(egui::TextWrapMode::Extend),
            );
            response.context_menu(|ui| {
                if ui.button("Copy All").clicked() {
                    ui.ctx().copy_text(text.clone());
                    ui.close();
                }
            });
        });
}
