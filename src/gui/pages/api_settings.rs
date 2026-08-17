//! API Settings page — view / edit the Xray top-level `api` object (Roadmap §2.1:54).
//!
//! Enables/edits `api.tag` / `api.listen` / `api.services` in the configuration file. Live gRPC
//! calls against an already-configured endpoint live on the separate API Console page (Roadmap
//! §3:128) — the same split as Log Settings (this page's sibling) vs. Xray Logs.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, TextEdit, Ui};

use crate::app::{ApiSettingsPageState, ApplicationService};
use crate::xray::KNOWN_API_SERVICES;

/// Renders the API Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("API Settings");
    ui.add_space(8.0);

    let model = service.api_settings_page_model();

    match model.state {
        ApiSettingsPageState::NoSshConnection
        | ApiSettingsPageState::XrayNotDiscovered
        | ApiSettingsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        ApiSettingsPageState::MalformedApiObject => {
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
        ApiSettingsPageState::ViewMode
        | ApiSettingsPageState::EditMode
        | ApiSettingsPageState::ValidationError
        | ApiSettingsPageState::Saving
        | ApiSettingsPageState::Saved
        | ApiSettingsPageState::SaveFailed => {
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
        if let Some(entries) = service.api_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: ApiSettingsPageState) {
    let color = match state {
        ApiSettingsPageState::ValidationError | ApiSettingsPageState::Saved => {
            Color32::from_rgb(210, 170, 40)
        }
        ApiSettingsPageState::ViewMode | ApiSettingsPageState::EditMode => {
            Color32::from_rgb(140, 140, 140)
        }
        ApiSettingsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: ApiSettingsPageState,
) {
    let busy = matches!(
        state,
        ApiSettingsPageState::Saving | ApiSettingsPageState::SaveFailed
    ) && service.is_api_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_api_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_api_settings();
            }
            if ui
                .add_enabled(
                    !service.is_api_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_api_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_api_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_api_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_api_settings();
        }
    });
}

fn show_view(ui: &mut Ui, settings: &crate::app::ApiSettings) {
    show_notice(ui);
    ui.add_space(8.0);

    egui::Grid::new("api_settings_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("tag");
            ui.label(settings.tag.as_deref().unwrap_or("(none)"));
            ui.end_row();
            ui.label("listen");
            ui.label(settings.listen.as_deref().unwrap_or("(none)"));
            ui.end_row();
            ui.label("services");
            ui.label(if settings.services.is_empty() {
                "(none)".to_owned()
            } else {
                settings.services.join(", ")
            });
            ui.end_row();
        });

    if let Some(source) = &settings.source_file {
        ui.add_space(12.0);
        ui.label(format!("Source file: {source}"));
    } else if !settings.section_present {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "No api object in the remote configuration. Defaults are shown; the object is \
                 created only when you save changes.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }

    if settings.listen.is_none() {
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Without `listen`, the API is only reachable by routing an inbound to `tag` — \
                 this editor does not wire that routing rule automatically.",
            )
            .size(12.0)
            .color(Color32::from_rgb(160, 140, 80)),
        );
    }
}

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    show_notice(ui);
    ui.add_space(8.0);

    let Some(draft) = service.api_settings_draft_mut() else {
        return;
    };

    let mut tag = draft.tag.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("tag");
        if ui
            .add(
                TextEdit::singleline(&mut tag)
                    .desired_width(240.0)
                    .hint_text("api"),
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
        RichText::new("Outbound tag Xray auto-creates for the API endpoint. Empty = omit.")
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
                    .hint_text("127.0.0.1:8080"),
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

    ui.add_space(8.0);
    ui.label("services (one per line)");
    ui.horizontal_wrapped(|ui| {
        for known in KNOWN_API_SERVICES {
            let present = draft.services.iter().any(|s| s == known);
            let mut checked = present;
            if ui.checkbox(&mut checked, *known).changed() {
                if checked {
                    if !present {
                        draft.services.push((*known).to_owned());
                    }
                } else {
                    draft.services.retain(|s| s != known);
                }
            }
        }
    });
    let mut services_text = draft.services.join("\n");
    if ui
        .add(TextEdit::multiline(&mut services_text).desired_rows(3))
        .changed()
    {
        draft.services = lines_to_vec(&services_text);
    }
    ui.label(
        RichText::new(
            "Toggle known services above, or list them (including unrecognized/future values) \
             one per line here — both edit the same list.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn lines_to_vec(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn show_notice(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "This edits the configuration file's `api` object only. It does not enable a live \
             operations panel by itself — see the API Console page once `listen` is set and the \
             running Xray picks up the change (restart/reload).",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}
