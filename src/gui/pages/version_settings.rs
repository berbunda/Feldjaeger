//! Version Settings page — view / edit the Xray top-level `version` object (Roadmap §2.1:56).
//!
//! `version.min`/`version.max` are a guard-rail pair (both optional strings, syntax `x.y.z`) that
//! let a config file refuse to run on an unwanted Xray-core client version — structurally the
//! same shape as `metrics.tag`/`metrics.listen` (two flat optional strings, no enum, no nested
//! object), so this page follows `gui/pages/metrics_settings.rs` closely.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, TextEdit, Ui};

use crate::app::{ApplicationService, VersionSettingsPageState};

/// Renders the Version Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Version Settings");
    ui.add_space(8.0);

    let model = service.version_settings_page_model();

    match model.state {
        VersionSettingsPageState::NoSshConnection
        | VersionSettingsPageState::XrayNotDiscovered
        | VersionSettingsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        VersionSettingsPageState::MalformedVersionObject => {
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
        VersionSettingsPageState::ViewMode
        | VersionSettingsPageState::EditMode
        | VersionSettingsPageState::ValidationError
        | VersionSettingsPageState::Saving
        | VersionSettingsPageState::Saved
        | VersionSettingsPageState::SaveFailed => {
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
        if let Some(entries) = service.version_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: VersionSettingsPageState) {
    let color = match state {
        VersionSettingsPageState::ValidationError | VersionSettingsPageState::Saved => {
            Color32::from_rgb(210, 170, 40)
        }
        VersionSettingsPageState::ViewMode | VersionSettingsPageState::EditMode => {
            Color32::from_rgb(140, 140, 140)
        }
        VersionSettingsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: VersionSettingsPageState,
) {
    let busy = matches!(
        state,
        VersionSettingsPageState::Saving | VersionSettingsPageState::SaveFailed
    ) && service.is_version_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_version_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_version_settings();
            }
            if ui
                .add_enabled(
                    !service.is_version_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_version_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_version_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_version_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_version_settings();
        }
    });
}

fn show_view(ui: &mut Ui, settings: &crate::xray::VersionSettings) {
    show_notice(ui);
    ui.add_space(8.0);

    egui::Grid::new("version_settings_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("min");
            ui.label(settings.min.as_deref().unwrap_or("(none)"));
            ui.end_row();
            ui.label("max");
            ui.label(settings.max.as_deref().unwrap_or("(none)"));
            ui.end_row();
        });

    if let Some(source) = &settings.source_file {
        ui.add_space(12.0);
        ui.label(format!("Source file: {source}"));
    } else if !settings.section_present {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "No version object in the remote configuration. Defaults are shown; the object \
                 is created only when you save changes.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    show_notice(ui);
    ui.add_space(8.0);

    let Some(draft) = service.version_settings_draft_mut() else {
        return;
    };

    let mut min = draft.min.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("min");
        if ui
            .add(
                TextEdit::singleline(&mut min)
                    .desired_width(160.0)
                    .hint_text("25.8.3"),
            )
            .changed()
        {
            let trimmed = min.trim();
            draft.min = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
    ui.label(
        RichText::new("Lowest Xray-core version this config is allowed to run on. Empty = no lower bound.")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );

    ui.add_space(8.0);
    let mut max = draft.max.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("max");
        if ui
            .add(
                TextEdit::singleline(&mut max)
                    .desired_width(160.0)
                    .hint_text("26.0.0"),
            )
            .changed()
        {
            let trimmed = max.trim();
            draft.max = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
    ui.label(
        RichText::new("Highest Xray-core version this config is allowed to run on. Empty = no upper bound.")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn show_notice(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "This edits the configuration file's `version` object only — a guard rail exchanged \
             alongside the config that lets Xray-core refuse to start on an unwanted client \
             version. Values must follow the `x.y.z` syntax but do not need to be a version that \
             actually exists. Version-constraint checking was added in Xray-core 25.8.3 — older \
             running binaries silently ignore this object.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}
