//! Config Files page — add/remove empty confdir files (Roadmap §2.5:107).
//!
//! Data flows exclusively through [`ApplicationService`]. This page never reads JSON,
//! opens SSH, or mutates remote configuration directly.

use egui::{Color32, RichText, Sense, Ui};

use crate::app::{ApplicationService, ConfdirFileRow, ConfdirFilesPageState};

/// Renders the Config Files page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    show_add_file_dialog(ui, service);
    show_remove_file_dialog(ui, service);

    ui.heading("Config Files");
    ui.add_space(8.0);

    let model = service.confdir_files_page_model();

    match model.state {
        ConfdirFilesPageState::NoSshConnection
        | ConfdirFilesPageState::XrayNotDiscovered
        | ConfdirFilesPageState::ConfigurationNotLoaded
        | ConfdirFilesPageState::NotAConfdir => {
            show_state_message(ui, model.state);
            return;
        }
        ConfdirFilesPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            for warning in &model.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(8.0);
        }
        ConfdirFilesPageState::ConfigurationLoaded => {}
    }

    show_header(ui, service);
    ui.add_space(4.0);
    show_table(ui, service, &model.rows);
}

fn show_header(ui: &mut Ui, service: &mut ApplicationService) {
    ui.horizontal(|ui| {
        ui.strong("Files");
        ui.add_space(12.0);
        let busy = service.is_confdir_file_mutation_busy();
        if ui
            .add_enabled(!busy, egui::Button::new("Add file"))
            .clicked()
        {
            set_pending_add(
                ui,
                PendingConfdirFileAdd {
                    filename: String::new(),
                    error: None,
                },
            );
        }
    });
}

fn show_state_message(ui: &mut Ui, state: ConfdirFilesPageState) {
    let color = match state {
        ConfdirFilesPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        ConfdirFilesPageState::NotAConfdir | ConfdirFilesPageState::ConfigurationLoaded => {
            Color32::from_rgb(140, 140, 140)
        }
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[ConfdirFileRow]) {
    if rows.is_empty() {
        ui.label(
            RichText::new("No files found.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    egui::Grid::new("confdir_files_table")
        .num_columns(3)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(72.0)
        .show(ui, |ui| {
            ui.strong("File");
            ui.strong("Empty");
            ui.strong("Contents");
            ui.end_row();

            for row in rows {
                let response = ui.add(egui::Label::new(&row.display_name).sense(Sense::click()));
                show_context_menu(&response, service, row);
                ui.label(if row.is_empty { "Yes" } else { "No" });
                ui.label(&row.contents_summary);
                ui.end_row();
            }
        });
}

fn show_context_menu(response: &egui::Response, service: &mut ApplicationService, row: &ConfdirFileRow) {
    response.context_menu(|ui| {
        if ui.button("Copy path").clicked() {
            ui.ctx().copy_text(row.path.clone());
            ui.close();
        }

        ui.separator();

        let busy = service.is_confdir_file_mutation_busy();
        if ui
            .add_enabled(row.is_empty && !busy, egui::Button::new("Remove"))
            .on_disabled_hover_text(if row.is_empty {
                "Remove requires an idle connection"
            } else {
                "File still contains a config section — move or remove it first"
            })
            .clicked()
        {
            set_pending_remove(
                ui,
                PendingConfdirFileRemove {
                    path: row.path.clone(),
                    display_name: row.display_name.clone(),
                    error: None,
                },
            );
            ui.close();
        }
    });
}

#[derive(Clone)]
struct PendingConfdirFileAdd {
    filename: String,
    error: Option<String>,
}

fn pending_add_id() -> egui::Id {
    egui::Id::new("confdir_files_pending_add")
}

fn pending_add(ui: &Ui) -> Option<PendingConfdirFileAdd> {
    ui.ctx().data(|d| d.get_temp::<PendingConfdirFileAdd>(pending_add_id()))
}

fn set_pending_add(ui: &Ui, pending: PendingConfdirFileAdd) {
    ui.ctx().data_mut(|d| d.insert_temp(pending_add_id(), pending));
}

fn clear_pending_add(ui: &Ui) {
    ui.ctx().data_mut(|d| d.remove::<PendingConfdirFileAdd>(pending_add_id()));
}

fn show_add_file_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_add(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Add confdir file")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                ui.label("File name:");
                ui.text_edit_singleline(&mut pending.filename);
            });
            ui.label(
                RichText::new(
                    "Must end in .json. Xray merges confdir files in lexicographic order — \
                     e.g. 10-custom.json.",
                )
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
            );
            ui.label(
                RichText::new("The new file starts empty ({}) — it changes nothing until you add content to it.")
                    .size(12.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_confdir_file_mutation_busy();
                let can_submit = !busy && !pending.filename.trim().is_empty();
                if ui
                    .add_enabled(can_submit, egui::Button::new("Add"))
                    .clicked()
                {
                    match service.start_add_confdir_file(pending.filename.trim().to_owned()) {
                        Ok(()) => closed = true,
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui.button("Cancel").clicked() {
                    closed = true;
                }
            });
        });

    if closed || !open {
        clear_pending_add(ui);
    } else {
        set_pending_add(ui, pending);
    }
}

#[derive(Clone)]
struct PendingConfdirFileRemove {
    path: String,
    display_name: String,
    error: Option<String>,
}

fn pending_remove_id() -> egui::Id {
    egui::Id::new("confdir_files_pending_remove")
}

fn pending_remove(ui: &Ui) -> Option<PendingConfdirFileRemove> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingConfdirFileRemove>(pending_remove_id()))
}

fn set_pending_remove(ui: &Ui, pending: PendingConfdirFileRemove) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_remove_id(), pending));
}

fn clear_pending_remove(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingConfdirFileRemove>(pending_remove_id()));
}

fn show_remove_file_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(pending) = pending_remove(ui) else {
        return;
    };
    let mut open = true;
    egui::Window::new("Remove confdir file")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(format!(
                    "Remove «{}»? It is already empty — this only removes the file itself.",
                    pending.display_name
                ))
                .size(14.0),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Removal cannot be undone from the UI (restore from backup if needed).",
                )
                .size(13.0)
                .color(Color32::from_rgb(160, 120, 40)),
            );
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_confdir_file_mutation_busy();
                if ui
                    .add_enabled(!busy, egui::Button::new("Remove"))
                    .clicked()
                {
                    match service.start_remove_confdir_file(pending.path.clone()) {
                        Ok(()) => clear_pending_remove(ui),
                        Err(message) => {
                            set_pending_remove(
                                ui,
                                PendingConfdirFileRemove {
                                    error: Some(message),
                                    ..pending.clone()
                                },
                            );
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    clear_pending_remove(ui);
                }
            });
        });

    if !open {
        clear_pending_remove(ui);
    }
}

