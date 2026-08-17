//! Env Settings page — view / edit the Xray top-level `env` object (Roadmap §2.1:55).
//!
//! `env` is a free-form environment-variable name→string map (unlike every other root-section
//! editor, it has no fixed field set) — see `crate::xray::config::env_settings` for why three
//! documented variable names (`XRAY_LOCATION_CONFIG`, `XRAY_LOCATION_CONFDIR`,
//! `XRAY_JSON_STRICT`) are deliberately excluded from the [`KNOWN_ENV_VARS`] preset list: Xray-core
//! reads them from the real OS/systemd environment before it parses the config, so setting them
//! here has no effect.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, ComboBox, RichText, TextEdit, Ui};

use crate::app::{ApplicationService, EnvSettingsPageState};
use crate::xray::{EnvVarEntry, KNOWN_ENV_VARS};

/// Renders the Env Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Env Settings");
    ui.add_space(8.0);

    let model = service.env_settings_page_model();

    match model.state {
        EnvSettingsPageState::NoSshConnection
        | EnvSettingsPageState::XrayNotDiscovered
        | EnvSettingsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        EnvSettingsPageState::MalformedEnvObject => {
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
        EnvSettingsPageState::ViewMode
        | EnvSettingsPageState::EditMode
        | EnvSettingsPageState::ValidationError
        | EnvSettingsPageState::Saving
        | EnvSettingsPageState::Saved
        | EnvSettingsPageState::SaveFailed => {
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
        if let Some(entries) = service.env_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: EnvSettingsPageState) {
    let color = match state {
        EnvSettingsPageState::ValidationError | EnvSettingsPageState::Saved => {
            Color32::from_rgb(210, 170, 40)
        }
        EnvSettingsPageState::ViewMode | EnvSettingsPageState::EditMode => {
            Color32::from_rgb(140, 140, 140)
        }
        EnvSettingsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: EnvSettingsPageState,
) {
    let busy = matches!(
        state,
        EnvSettingsPageState::Saving | EnvSettingsPageState::SaveFailed
    ) && service.is_env_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_env_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_env_settings();
            }
            if ui
                .add_enabled(
                    !service.is_env_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_env_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_env_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_env_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_env_settings();
        }
    });
}

fn show_view(ui: &mut Ui, settings: &crate::xray::EnvSettings) {
    show_notice(ui);
    ui.add_space(8.0);

    if settings.variables.is_empty() {
        ui.label(
            RichText::new("No environment variables set.")
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    } else {
        egui::Grid::new("env_settings_view")
            .num_columns(2)
            .spacing([20.0, 6.0])
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Name");
                ui.strong("Value");
                ui.end_row();
                for entry in &settings.variables {
                    ui.label(&entry.name);
                    ui.label(&entry.value);
                    ui.end_row();
                }
            });
    }

    if let Some(source) = &settings.source_file {
        ui.add_space(12.0);
        ui.label(format!("Source file: {source}"));
    } else if !settings.section_present {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "No env object in the remote configuration. Defaults are shown; the object is \
                 created only when you save changes.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    show_notice(ui);
    ui.add_space(8.0);

    let Some(draft) = service.env_settings_draft_mut() else {
        return;
    };

    let mut remove_index = None;
    egui::Grid::new("env_settings_edit")
        .num_columns(3)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.strong("Name");
            ui.strong("Value");
            ui.end_row();

            for (index, entry) in draft.variables.iter_mut().enumerate() {
                show_name_combo(ui, &mut entry.name, index);
                ui.add(
                    TextEdit::singleline(&mut entry.value)
                        .desired_width(260.0)
                        .hint_text("value"),
                );
                if ui.button("Remove").clicked() {
                    remove_index = Some(index);
                }
                ui.end_row();
            }
        });

    if let Some(index) = remove_index {
        draft.variables.remove(index);
    }

    ui.add_space(8.0);
    if ui.button("Add variable").clicked() {
        draft.variables.push(EnvVarEntry::blank());
    }
}

fn show_name_combo(ui: &mut Ui, name: &mut String, index: usize) {
    ui.horizontal(|ui| {
        ComboBox::from_id_salt(("env_settings_name_combo", index))
            .selected_text(if name.is_empty() {
                "(select or type)".to_owned()
            } else {
                name.clone()
            })
            .show_ui(ui, |ui| {
                for known in KNOWN_ENV_VARS {
                    if ui.selectable_label(name == known, *known).clicked() {
                        *name = (*known).to_owned();
                    }
                }
            });
        ui.add(
            TextEdit::singleline(name)
                .desired_width(180.0)
                .hint_text("VAR_NAME"),
        );
    });
}

fn show_notice(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "This edits the configuration file's `env` object only — arbitrary environment \
             variables for the Xray-core process. `XRAY_LOCATION_CONFIG`, `XRAY_LOCATION_CONFDIR`, \
             and `XRAY_JSON_STRICT` are intentionally omitted from the preset list below: per the \
             official documentation, Xray-core reads them from the real OS/systemd environment \
             before it parses the config, so setting them here has no effect. You may still type \
             them manually, but they will be silently ignored by Xray-core.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}
