//! Metrics Settings page — view / edit the Xray top-level `metrics` object (Roadmap §2.1:53).
//!
//! Enables/edits `metrics.tag` / `metrics.listen` in the configuration file — the exact same two
//! fields as `api.tag`/`api.listen` (`gui/pages/api_settings.rs`), minus `services[]`. Live HTTP
//! scraping of an already-configured endpoint lives on the separate Metrics page (Roadmap
//! §3:130) — the same split as API Settings (this page's closest sibling) vs. API Console.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, TextEdit, Ui};

use crate::app::{ApplicationService, MetricsSettingsPageState};

/// Renders the Metrics Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Metrics Settings");
    ui.add_space(8.0);

    let model = service.metrics_settings_page_model();

    match model.state {
        MetricsSettingsPageState::NoSshConnection
        | MetricsSettingsPageState::XrayNotDiscovered
        | MetricsSettingsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        MetricsSettingsPageState::MalformedMetricsObject => {
            show_state_message(ui, model.state);
            for warning in &model.settings.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            return;
        }
        MetricsSettingsPageState::ViewMode
        | MetricsSettingsPageState::EditMode
        | MetricsSettingsPageState::ValidationError
        | MetricsSettingsPageState::Saving
        | MetricsSettingsPageState::Saved
        | MetricsSettingsPageState::SaveFailed => {
            show_state_message(ui, model.state);
            for warning in &model.settings.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            if let Some(error) = &model.error_message {
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
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
        if let Some(entries) = service.metrics_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: MetricsSettingsPageState) {
    let color = match state {
        MetricsSettingsPageState::ValidationError | MetricsSettingsPageState::Saved => {
            Color32::from_rgb(210, 170, 40)
        }
        MetricsSettingsPageState::ViewMode | MetricsSettingsPageState::EditMode => {
            Color32::from_rgb(140, 140, 140)
        }
        MetricsSettingsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: MetricsSettingsPageState,
) {
    let busy = matches!(
        state,
        MetricsSettingsPageState::Saving | MetricsSettingsPageState::SaveFailed
    ) && service.is_metrics_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_metrics_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_metrics_settings();
            }
            if ui
                .add_enabled(
                    !service.is_metrics_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_metrics_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_metrics_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_metrics_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_metrics_settings();
        }
    });
}

fn show_view(ui: &mut Ui, settings: &crate::xray::MetricsSettings) {
    show_notice(ui);
    ui.add_space(8.0);

    egui::Grid::new("metrics_settings_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("tag");
            ui.label(settings.tag.as_deref().unwrap_or("(none)"));
            ui.end_row();
            ui.label("listen");
            ui.label(settings.listen.as_deref().unwrap_or("(none)"));
            ui.end_row();
        });

    if let Some(source) = &settings.source_file {
        ui.add_space(12.0);
        ui.label(format!("Source file: {source}"));
    } else if !settings.section_present {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "No metrics object in the remote configuration. Defaults are shown; the object \
                 is created only when you save changes.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }

    if settings.tag.is_none() && settings.listen.is_none() && settings.section_present {
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Neither `tag` nor `listen` is set — per the official documentation, Xray-core \
                 will fail to start with an empty `metrics` object.",
            )
            .size(12.0)
            .color(Color32::from_rgb(200, 60, 60)),
        );
    } else if settings.listen.is_none() {
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Without `listen`, the endpoint is only reachable by routing an inbound to \
                 `tag` — this editor does not wire that routing rule automatically.",
            )
            .size(12.0)
            .color(Color32::from_rgb(160, 140, 80)),
        );
    }
}

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    show_notice(ui);
    ui.add_space(8.0);

    let Some(draft) = service.metrics_settings_draft_mut() else {
        return;
    };

    let mut tag = draft.tag.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("tag");
        if ui
            .add(
                TextEdit::singleline(&mut tag)
                    .desired_width(240.0)
                    .hint_text("Metrics"),
            )
            .changed()
        {
            let trimmed = tag.trim();
            draft.tag = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
    ui.label(
        RichText::new(
            "Outbound tag Xray auto-creates for the metrics endpoint. Empty = auto-defaults to \
             \"Metrics\" once the section is otherwise meaningful.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );

    ui.add_space(8.0);
    let mut listen = draft.listen.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("listen");
        if ui
            .add(
                TextEdit::singleline(&mut listen)
                    .desired_width(240.0)
                    .hint_text("127.0.0.1:11111"),
            )
            .changed()
        {
            let trimmed = listen.trim();
            draft.listen = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
    ui.label(
        RichText::new(
            "Address to listen on directly. Empty = only reachable via routing (not wired here).",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );

    if draft.tag.is_none() && draft.listen.is_none() {
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Neither `tag` nor `listen` is set — per the official documentation, Xray-core \
                 will fail to start with an empty `metrics` object.",
            )
            .size(12.0)
            .color(Color32::from_rgb(200, 60, 60)),
        );
    }
}

fn show_notice(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "This edits the configuration file's `metrics` object only. It does not open a live \
             scrape view by itself — see the Metrics page once `listen` is set and the running \
             Xray picks up the change (restart/reload).",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}
