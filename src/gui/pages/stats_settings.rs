//! Stats Settings page — view / edit the Xray top-level `stats` object (Roadmap §2.1:52).
//!
//! `StatsObject` has no documented fields — its only meaningful state is whether the top-level
//! `stats` key exists at all, so this page is a single enable/disable toggle rather than a
//! field-by-field form, unlike its five siblings (DNS/Routing/Policy/Observatory/
//! BurstObservatory). Live counter reads against an already-enabled module live on the separate
//! Statistics page (Roadmap §3:129) — the same split as API Settings (this page's closest
//! sibling) vs. API Console.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, Ui};

use crate::app::{ApplicationService, StatsSettingsPageState};

/// Renders the Stats Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Stats Settings");
    ui.add_space(8.0);

    let model = service.stats_settings_page_model();

    match model.state {
        StatsSettingsPageState::NoSshConnection
        | StatsSettingsPageState::XrayNotDiscovered
        | StatsSettingsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        StatsSettingsPageState::MalformedStatsObject => {
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
        StatsSettingsPageState::ViewMode
        | StatsSettingsPageState::EditMode
        | StatsSettingsPageState::ValidationError
        | StatsSettingsPageState::Saving
        | StatsSettingsPageState::Saved
        | StatsSettingsPageState::SaveFailed => {
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
        if let Some(entries) = service.stats_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: StatsSettingsPageState) {
    let color = match state {
        StatsSettingsPageState::ValidationError | StatsSettingsPageState::Saved => {
            Color32::from_rgb(210, 170, 40)
        }
        StatsSettingsPageState::ViewMode | StatsSettingsPageState::EditMode => {
            Color32::from_rgb(140, 140, 140)
        }
        StatsSettingsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: StatsSettingsPageState,
) {
    let busy = matches!(
        state,
        StatsSettingsPageState::Saving | StatsSettingsPageState::SaveFailed
    ) && service.is_stats_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_stats_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_stats_settings();
            }
            if ui
                .add_enabled(
                    !service.is_stats_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_stats_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_stats_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_stats_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_stats_settings();
        }
    });
}

fn show_view(ui: &mut Ui, settings: &crate::xray::StatsSettings) {
    show_notice(ui);
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("stats");
        ui.label(if settings.enabled { "Enabled" } else { "Disabled" });
    });

    if let Some(source) = &settings.source_file {
        ui.add_space(12.0);
        ui.label(format!("Source file: {source}"));
    } else {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "No stats object in the remote configuration (disabled). The object is created \
                 only when you save changes with it enabled.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }

    if !settings.extra.is_empty() {
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!(
                "{} unrecognized field(s) preserved on disk (not documented by StatsObject).",
                settings.extra.len()
            ))
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    show_notice(ui);
    ui.add_space(8.0);

    let Some(draft) = service.stats_settings_draft_mut() else {
        return;
    };

    ui.checkbox(&mut draft.enabled, "stats (enable statistics collection)");
    ui.label(
        RichText::new(
            "Presence of an (empty) `stats` object is the only setting StatsObject has — actual \
             data collection is then driven by `policy`/`api`/`metrics` wiring (see the Policy \
             page's wiring warnings).",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );

    if !draft.extra.is_empty() {
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!(
                "{} unrecognized field(s) already on disk will be preserved when saved.",
                draft.extra.len()
            ))
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_notice(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "This edits the configuration file's `stats` object only. It does not open a live \
             counter view by itself — see the Statistics page once enabled and the running Xray \
             picks up the change (restart/reload).",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}
