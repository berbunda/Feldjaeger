//! GeoData Settings page — view / edit the Xray top-level `geodata` object (Roadmap §2.1:57).
//!
//! `geodata.cron`/`geodata.outbound` are flat optional strings (same shape as
//! `version.min`/`.max`, `metrics.tag`/`.listen`) — this page follows
//! `gui/pages/version_settings.rs` for those two fields. `geodata.assets[]` is a variable-length
//! list of `{ url, file }` pairs, rendered the same way as `env.variables`/`dns.hosts` — plain
//! inline rows, no `CollapsingHeader` spoiler, since each entry is only two fields (unlike
//! Routing rules/balancers, which are genuinely large nested blocks).
//!
//! **Not to be confused with the existing GeoData page** (`gui/pages/geodata.rs`) — that page
//! performs live SSH file operations (download/replace `geoip.dat`/`geosite.dat` on the remote
//! host right now); this page only edits the configuration file's `geodata` object, which tells
//! the running Xray-core process to reload/re-download those same files on its own `cron`
//! schedule.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, TextEdit, Ui};

use crate::app::{ApplicationService, GeodataSettingsPageState};
use crate::xray::GeodataAssetEntry;

/// Renders the GeoData Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("GeoData Settings");
    ui.add_space(8.0);

    let model = service.geodata_settings_page_model();

    match model.state {
        GeodataSettingsPageState::NoSshConnection
        | GeodataSettingsPageState::XrayNotDiscovered
        | GeodataSettingsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        GeodataSettingsPageState::MalformedGeodataObject => {
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
        GeodataSettingsPageState::ViewMode
        | GeodataSettingsPageState::EditMode
        | GeodataSettingsPageState::ValidationError
        | GeodataSettingsPageState::Saving
        | GeodataSettingsPageState::Saved
        | GeodataSettingsPageState::SaveFailed => {
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
        if let Some(entries) = service.geodata_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: GeodataSettingsPageState) {
    let color = match state {
        GeodataSettingsPageState::ValidationError | GeodataSettingsPageState::Saved => {
            Color32::from_rgb(210, 170, 40)
        }
        GeodataSettingsPageState::ViewMode | GeodataSettingsPageState::EditMode => {
            Color32::from_rgb(140, 140, 140)
        }
        GeodataSettingsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: GeodataSettingsPageState,
) {
    let busy = matches!(
        state,
        GeodataSettingsPageState::Saving | GeodataSettingsPageState::SaveFailed
    ) && service.is_geodata_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_geodata_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_geodata_settings();
            }
            if ui
                .add_enabled(
                    !service.is_geodata_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_geodata_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_geodata_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_geodata_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_geodata_settings();
        }
    });
}

fn show_view(ui: &mut Ui, settings: &crate::xray::GeodataSettings) {
    show_notice(ui);
    ui.add_space(8.0);

    egui::Grid::new("geodata_settings_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("cron");
            ui.label(settings.cron.as_deref().unwrap_or("(none)"));
            ui.end_row();
            ui.label("outbound");
            ui.label(settings.outbound.as_deref().unwrap_or("(none)"));
            ui.end_row();
        });

    ui.add_space(12.0);
    ui.strong(format!("assets ({})", settings.assets.len()));
    ui.add_space(4.0);
    if settings.assets.is_empty() {
        ui.label(
            RichText::new(
                "No assets configured — a scheduled reload (if `cron` is set) only re-reads \
                 already-present files without downloading anything.",
            )
            .size(13.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    } else {
        egui::Grid::new("geodata_settings_assets_view")
            .num_columns(2)
            .spacing([20.0, 6.0])
            .striped(true)
            .show(ui, |ui| {
                ui.strong("url");
                ui.strong("file");
                ui.end_row();
                for asset in &settings.assets {
                    ui.label(&asset.url);
                    ui.label(&asset.file);
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
                "No geodata object in the remote configuration. Defaults are shown; the object \
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

    let Some(draft) = service.geodata_settings_draft_mut() else {
        return;
    };

    let mut cron = draft.cron.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("cron");
        if ui
            .add(
                TextEdit::singleline(&mut cron)
                    .desired_width(160.0)
                    .hint_text("0 4 * * *"),
            )
            .changed()
        {
            let trimmed = cron.trim();
            draft.cron = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
    ui.label(
        RichText::new(
            "Standard 5-field cron expression (local timezone). Empty = no scheduled reload.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );

    ui.add_space(8.0);
    let mut outbound = draft.outbound.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label("outbound");
        if ui
            .add(
                TextEdit::singleline(&mut outbound)
                    .desired_width(160.0)
                    .hint_text("proxy"),
            )
            .changed()
        {
            let trimmed = outbound.trim();
            draft.outbound = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
    ui.label(
        RichText::new("Outbound tag used when downloading assets. Empty = routing decides.")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );

    ui.add_space(12.0);
    ui.strong("assets");
    ui.add_space(4.0);

    let mut remove_index = None;
    for index in 0..draft.assets.len() {
        show_asset_edit_form(ui, draft, index, &mut remove_index);
        ui.add_space(6.0);
    }
    if let Some(index) = remove_index {
        draft.assets.remove(index);
    }

    if ui.button("Add asset").clicked() {
        draft.assets.push(GeodataAssetEntry::blank());
    }
}

fn show_asset_edit_form(
    ui: &mut Ui,
    draft: &mut crate::xray::GeodataSettings,
    index: usize,
    remove: &mut Option<usize>,
) {
    let asset = &mut draft.assets[index];
    ui.horizontal(|ui| {
        ui.label(format!("Asset {}", index + 1));
        if ui.small_button("Remove").clicked() {
            *remove = Some(index);
        }
    });
    ui.horizontal(|ui| {
        ui.label("url");
        ui.add(
            TextEdit::singleline(&mut asset.url)
                .desired_width(320.0)
                .hint_text("https://example.com/geoip.dat"),
        );
    });
    ui.horizontal(|ui| {
        ui.label("file");
        ui.add(
            TextEdit::singleline(&mut asset.file)
                .desired_width(200.0)
                .hint_text("geoip.dat"),
        );
    });
}

fn show_notice(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "This edits the configuration file's `geodata` object only — it tells the running \
             Xray-core process to periodically re-download/reload geo data files on its own \
             schedule. It does not perform any download itself; use the GeoData page for an \
             immediate one-off update.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}
