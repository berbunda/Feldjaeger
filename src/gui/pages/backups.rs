//! Backups page — list and restore previously created config backups (Roadmap §3:127).
//!
//! Every remote configuration write already creates a timestamped backup next to the original
//! file before overwriting it (`BackupManager::create_backup`); until this page, nothing in the
//! GUI ever listed or restored one manually — only an automatic restore-on-failed
//! `xray run -test` existed. Covers the Xray configuration file(s) only (single file, or every
//! confdir member) — not the systemd unit file, which is a deliberately separate concern.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never reads JSON, opens
//! SSH, or touches the remote configuration model directly.

use egui::{Color32, RichText, Ui};

use crate::app::{
    ApplicationService, BackupFileRow, BackupsPageState, ConfigBackup, display_source_file,
    format_backup_timestamp, format_size,
};

use super::HelpText;

// ─── Help text (Roadmap §4.4) ─────────────────────────────────────────────────
//
// From `remote::BackupManager` and `app::backup_ops` (restore through `write_config_validated`).

const HELP_BACKUPS: HelpText = HelpText::new(
    "Before every change of a configuration file — on any page, on restore, on removing a \
     confdir file — Feldjäger copies the file to <file>.feldjaeger.bak.<unix time> in the same \
     directory. Xray ignores these copies (a confdir loads only *.json, *.jsonc, *.toml, *.yaml, \
     *.yml). Feldjäger never deletes them: they accumulate, remove old ones over SSH.\n\n\
     The list covers the files of the loaded configuration only. The systemd unit file is backed \
     up the same way (/etc/systemd/system/<unit>.feldjaeger.bak.<time>) but is not listed here. \
     List backups runs one find in the file's directory and needs find with -printf (GNU \
     findutils; BusyBox find lacks it).",
    "Перед каждым изменением файла конфигурации — на любой странице, при восстановлении, при \
     удалении файла confdir — Feldjäger копирует файл в <файл>.feldjaeger.bak.<unix-время> в том \
     же каталоге. Xray эти копии не читает (confdir загружает только *.json, *.jsonc, *.toml, \
     *.yaml, *.yml). Feldjäger их никогда не удаляет: они накапливаются, старые удаляйте по \
     SSH.\n\n\
     Список охватывает только файлы загруженной конфигурации. Unit-файл systemd копируется так \
     же (/etc/systemd/system/<unit>.feldjaeger.bak.<время>), но здесь не показывается. List \
     backups выполняет один find в каталоге файла, и ему нужен find с -printf (GNU findutils; у \
     find из BusyBox его нет).",
);
const HELP_RESTORE: HelpText = HelpText::new(
    "Restore writes the backup's content over the live file. It is refused if the file on the \
     server changed since Feldjäger loaded it — reload the configuration first. The current \
     content is backed up first, then xray run -test checks the result; if it fails, the file is \
     put back. The comparison shows current → backup, with secrets hidden. The running Xray \
     keeps its old configuration until it is restarted on the Service page.",
    "Restore записывает содержимое копии поверх рабочего файла. Восстановление отклоняется, \
     если файл на сервере изменился после загрузки в Feldjäger, — сначала перезагрузите \
     конфигурацию. Текущее содержимое сначала копируется, затем результат проверяет xray run \
     -test; если проверка не прошла, файл возвращается. Сравнение показывает текущее → копия, \
     секреты скрыты. Работающий Xray использует старую конфигурацию, пока его не перезапустят \
     на странице Service.",
);

/// Renders the Backups page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    super::show_help_dialog(ui);
    show_restore_dialog(ui, service);

    ui.horizontal(|ui| {
        super::help_button(ui, "Backups", HELP_BACKUPS);
        ui.heading("Backups");
    });
    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "Every configuration write creates a timestamped backup next to the original file \
             before overwriting it. This page lists them per file and lets you restore one.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
    ui.add_space(8.0);

    let model = service.backups_page_model();

    match model.state {
        BackupsPageState::NoSshConnection
        | BackupsPageState::XrayNotDiscovered
        | BackupsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        BackupsPageState::ConfigurationContainsWarnings => {
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
        BackupsPageState::ConfigurationLoaded => {}
    }

    if model.rows.is_empty() {
        ui.label(
            RichText::new("No configuration files found.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    for row in &model.rows {
        show_file_section(ui, service, row);
        ui.add_space(10.0);
    }
}

fn show_state_message(ui: &mut Ui, state: BackupsPageState) {
    let color = match state {
        BackupsPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        BackupsPageState::ConfigurationLoaded => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_file_section(ui: &mut Ui, service: &mut ApplicationService, row: &BackupFileRow) {
    ui.separator();
    ui.horizontal(|ui| {
        ui.strong(&row.display_name);
        ui.label(
            RichText::new(&row.path)
                .size(11.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        ui.add_space(8.0);
        let busy = service.is_listing_backups(&row.path);
        if ui
            .add_enabled(!busy, egui::Button::new("List backups"))
            .clicked()
        {
            let _ = service.start_list_backups(row.path.clone());
        }
    });
    ui.add_space(4.0);

    if service.is_listing_backups(&row.path) {
        ui.label(
            RichText::new("Loading backups...")
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    let Some(result) = service.backup_list_result(&row.path) else {
        return;
    };

    match result {
        Err(error) => {
            ui.label(
                RichText::new(error.clone())
                    .size(13.0)
                    .color(Color32::from_rgb(200, 60, 60)),
            );
        }
        Ok(backups) if backups.is_empty() => {
            ui.label(
                RichText::new("No backups found yet.")
                    .size(13.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
        }
        Ok(backups) => {
            let backups = backups.clone();
            egui::Grid::new(("backups_table", row.path.as_str()))
                .num_columns(3)
                .striped(true)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Created");
                    ui.strong("Size");
                    ui.strong("");
                    ui.end_row();

                    for backup in &backups {
                        ui.label(format_backup_timestamp(backup.created_at_unix));
                        ui.label(format_size(backup.size_bytes as u64));
                        if ui.button("Restore").clicked() {
                            open_restore_dialog(ui, service, row.path.clone(), backup);
                        }
                        ui.end_row();
                    }
                });
        }
    }
}

// ─── Restore confirm dialog (Roadmap §3:127) ─────────────────────────────────

#[derive(Clone)]
struct PendingBackupRestore {
    original_path: String,
    backup_path: String,
    created_at_unix: u64,
    size_bytes: usize,
    error: Option<String>,
}

fn pending_restore_id() -> egui::Id {
    egui::Id::new("backups_pending_restore")
}

fn pending_restore(ui: &Ui) -> Option<PendingBackupRestore> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingBackupRestore>(pending_restore_id()))
}

fn set_pending_restore(ui: &Ui, pending: PendingBackupRestore) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_restore_id(), pending));
}

fn clear_pending_restore(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingBackupRestore>(pending_restore_id()));
}

fn open_restore_dialog(
    ui: &Ui,
    service: &mut ApplicationService,
    original_path: String,
    backup: &ConfigBackup,
) {
    let backup_path = backup.backup_path.as_str().to_owned();
    // Kick off the pre-restore diff fetch right away — by the time the dialog paints, the
    // answer has often already arrived (same pattern as the Edit-unit before/after diff,
    // Roadmap §3:126).
    let _ = service.start_fetch_backup_content(backup_path.clone());
    set_pending_restore(
        ui,
        PendingBackupRestore {
            original_path,
            backup_path,
            created_at_unix: backup.created_at_unix,
            size_bytes: backup.size_bytes,
            error: None,
        },
    );
}

fn show_restore_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_restore(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Restore backup")
        .collapsible(false)
        .resizable(true)
        .default_width(520.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                super::help_button(ui, "Restore backup", HELP_RESTORE);
                ui.label(
                    RichText::new(format!(
                        "Restore the backup from {} ({}) over «{}»?",
                        format_backup_timestamp(pending.created_at_unix),
                        format_size(pending.size_bytes as u64),
                        display_source_file(&pending.original_path),
                    ))
                    .size(14.0),
                );
            });
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "This overwrites the live file. The current state is backed up first \
                     automatically, and reverted if the post-write `xray run -test` fails — \
                     restoring is itself reversible, same as every other configuration change.",
                )
                .size(12.0)
                .color(Color32::from_rgb(160, 120, 40)),
            );
            ui.add_space(8.0);

            show_restore_diff(ui, service, &pending);

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
                let busy = service.is_restoring_backup();
                if ui
                    .add_enabled(!busy, egui::Button::new("Restore"))
                    .clicked()
                {
                    match service
                        .start_restore_backup(pending.original_path.clone(), pending.backup_path.clone())
                    {
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
        clear_pending_restore(ui);
    } else {
        set_pending_restore(ui, pending);
    }
}

fn show_restore_diff(ui: &mut Ui, service: &ApplicationService, pending: &PendingBackupRestore) {
    if service.is_fetching_backup_content(&pending.backup_path) {
        ui.label(
            RichText::new("Fetching backup content for comparison...")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }
    match service.backup_content_result(&pending.backup_path) {
        None => {
            ui.label(
                RichText::new("Fetching backup content for comparison...")
                    .size(12.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
        }
        Some(Err(error)) => {
            ui.label(
                RichText::new(format!("Could not read the backup for comparison: {error}"))
                    .size(12.0)
                    .color(Color32::from_rgb(210, 170, 40)),
            );
        }
        Some(Ok(backup_bytes)) => match service.current_source_file_bytes(&pending.original_path) {
            Some(current_bytes) => {
                let entries =
                    crate::xray::redacted_json_diff_bytes(&current_bytes, backup_bytes);
                super::json_diff_preview(ui, &entries);
            }
            None => {
                ui.label(
                    RichText::new("Current content unavailable for comparison.")
                        .size(12.0)
                        .color(Color32::from_rgb(140, 140, 140)),
                );
            }
        },
    }
}
