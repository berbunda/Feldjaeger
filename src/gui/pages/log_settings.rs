//! Log Settings page — view / edit the Xray top-level `log` object.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never
//! parses raw JSON, opens SSH, or writes remote files directly.

use egui::{Color32, ComboBox, RichText, TextEdit, Ui};

use crate::app::{
    ApplicationService, LogLevel, LogOutput, LogSettingsPageState, MaskAddress, log_level_display,
    log_output_display, mask_address_display,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Stdout,
    File,
    Disabled,
    Unknown,
}

impl OutputMode {
    fn label(self) -> &'static str {
        match self {
            Self::Stdout => "Standard Output",
            Self::File => "File",
            Self::Disabled => "Disabled",
            Self::Unknown => "Unknown",
        }
    }

    fn from_output(output: &LogOutput) -> Self {
        match output {
            LogOutput::Stdout => Self::Stdout,
            LogOutput::File(_) => Self::File,
            LogOutput::Disabled => Self::Disabled,
            LogOutput::Unknown(_) => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaskMode {
    Disabled,
    Quarter,
    Half,
    Full,
    Custom,
    Unknown,
}

impl MaskMode {
    fn label(self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::Quarter => "Quarter",
            Self::Half => "Half",
            Self::Full => "Full",
            Self::Custom => "Custom",
            Self::Unknown => "Unknown",
        }
    }

    fn from_mask(mask: &MaskAddress) -> Self {
        match mask {
            MaskAddress::Disabled => Self::Disabled,
            MaskAddress::Quarter => Self::Quarter,
            MaskAddress::Half => Self::Half,
            MaskAddress::Full => Self::Full,
            MaskAddress::Custom(_) => Self::Custom,
            MaskAddress::Unknown(_) => Self::Unknown,
        }
    }
}

/// Renders the Log Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Log Settings");
    ui.add_space(8.0);

    let model = service.log_settings_page_model();

    match model.state {
        LogSettingsPageState::NoSshConnection
        | LogSettingsPageState::XrayNotDiscovered
        | LogSettingsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        LogSettingsPageState::MalformedLogObject => {
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
        LogSettingsPageState::UnknownConfigurationValue
        | LogSettingsPageState::ViewMode
        | LogSettingsPageState::EditMode
        | LogSettingsPageState::ValidationError
        | LogSettingsPageState::Saving
        | LogSettingsPageState::Saved
        | LogSettingsPageState::SaveFailed => {
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
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: LogSettingsPageState) {
    let color = match state {
        LogSettingsPageState::UnknownConfigurationValue
        | LogSettingsPageState::ValidationError
        | LogSettingsPageState::Saved => Color32::from_rgb(210, 170, 40),
        LogSettingsPageState::ViewMode | LogSettingsPageState::EditMode => {
            Color32::from_rgb(140, 140, 140)
        }
        LogSettingsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: LogSettingsPageState,
) {
    let busy = matches!(
        state,
        LogSettingsPageState::Saving | LogSettingsPageState::SaveFailed
    ) && service.is_log_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!service.is_log_settings_mutation_busy(), egui::Button::new("Save"))
                .clicked()
            {
                if let Err(error) = service.start_save_log_settings() {
                    // Error already stored on the service for page display.
                    let _ = error;
                }
            }
            if ui
                .add_enabled(!service.is_log_settings_mutation_busy(), egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_edit_log_settings();
            }
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
        {
            let _ = service.begin_edit_log_settings();
        }
    });
}

fn show_view(ui: &mut Ui, settings: &crate::app::LogSettings) {
    show_privacy_notices(ui, false);
    ui.add_space(8.0);

    ui.strong("Access log");
    ui.add_space(4.0);
    egui::Grid::new("log_settings_access_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("Destination");
            ui.label(log_output_display(&settings.access));
            ui.end_row();
        });
    ui.label(
        RichText::new("Access logs may contain client addresses and destination information.")
            .size(12.0)
            .color(Color32::from_rgb(160, 140, 80)),
    );

    ui.add_space(12.0);
    ui.strong("Error log");
    ui.add_space(4.0);
    egui::Grid::new("log_settings_error_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("Destination");
            ui.label(log_output_display(&settings.error));
            ui.end_row();
            ui.label("Log level");
            ui.label(log_level_display(&settings.log_level));
            ui.end_row();
        });

    ui.add_space(12.0);
    ui.strong("Additional log entries");
    ui.add_space(4.0);
    egui::Grid::new("log_settings_extra_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("DNS query logging");
            ui.label(if settings.dns_log { "Enabled" } else { "Disabled" });
            ui.end_row();
        });
    ui.label(
        RichText::new("DNS logging may expose queried domain names and resolved addresses.")
            .size(12.0)
            .color(Color32::from_rgb(160, 140, 80)),
    );

    ui.add_space(12.0);
    ui.strong("Privacy");
    ui.add_space(4.0);
    egui::Grid::new("log_settings_privacy_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("Mask IP addresses");
            ui.label(mask_address_display(&settings.mask_address));
            ui.end_row();
        });
    if matches!(settings.mask_address, MaskAddress::Disabled) {
        ui.label(
            RichText::new("Disabling IP masking may expose complete IP addresses.")
                .size(12.0)
                .color(Color32::from_rgb(160, 140, 80)),
        );
    }

    if let Some(source) = &settings.source_file {
        ui.add_space(12.0);
        ui.label(format!("Source file: {source}"));
    } else if !settings.section_present {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "No log object in the remote configuration. Defaults are shown; the object is created only when you save changes.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    show_privacy_notices(ui, true);
    ui.add_space(8.0);

    let Some(draft) = service.log_settings_draft_mut() else {
        return;
    };

    ui.strong("Access log");
    ui.add_space(4.0);
    edit_output(ui, "access", &mut draft.access);
    ui.label(
        RichText::new("Access logs may contain client addresses and destination information.")
            .size(12.0)
            .color(Color32::from_rgb(160, 140, 80)),
    );

    ui.add_space(12.0);
    ui.strong("Error log");
    ui.add_space(4.0);
    edit_output(ui, "error", &mut draft.error);
    ui.horizontal(|ui| {
        ui.label("Log level");
        let current = draft.log_level.display_label();
        ComboBox::from_id_salt("log_settings_level")
            .selected_text(current)
            .show_ui(ui, |ui| {
                for level in [
                    LogLevel::Debug,
                    LogLevel::Info,
                    LogLevel::Warning,
                    LogLevel::Error,
                    LogLevel::None,
                ] {
                    ui.selectable_value(&mut draft.log_level, level.clone(), level.display_label());
                }
                if matches!(draft.log_level, LogLevel::Unknown(_)) {
                    let raw = match &draft.log_level {
                        LogLevel::Unknown(raw) => raw.clone(),
                        _ => String::new(),
                    };
                    ui.selectable_value(
                        &mut draft.log_level,
                        LogLevel::Unknown(raw.clone()),
                        format!("Unknown ({raw})"),
                    );
                }
            });
    });

    ui.add_space(12.0);
    ui.strong("Additional log entries");
    ui.add_space(4.0);
    ui.checkbox(&mut draft.dns_log, "Enable DNS query logging");
    ui.label(
        RichText::new("DNS logging may expose queried domain names and resolved addresses.")
            .size(12.0)
            .color(Color32::from_rgb(160, 140, 80)),
    );

    ui.add_space(12.0);
    ui.strong("Privacy");
    ui.add_space(4.0);
    edit_mask(ui, &mut draft.mask_address);
    if matches!(draft.mask_address, MaskAddress::Disabled) {
        ui.label(
            RichText::new("Disabling IP masking may expose complete IP addresses.")
                .size(12.0)
                .color(Color32::from_rgb(160, 140, 80)),
        );
    }
}

fn edit_output(ui: &mut Ui, id: &str, output: &mut LogOutput) {
    let mut mode = OutputMode::from_output(output);
    let mut path = match output {
        LogOutput::File(path) => path.clone(),
        _ => String::new(),
    };
    let unknown = match output {
        LogOutput::Unknown(raw) => Some(raw.clone()),
        _ => None,
    };

    ui.horizontal(|ui| {
        ui.label("Destination");
        ComboBox::from_id_salt(format!("log_settings_{id}_mode"))
            .selected_text(mode.label())
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut mode, OutputMode::Stdout, OutputMode::Stdout.label());
                ui.selectable_value(&mut mode, OutputMode::File, OutputMode::File.label());
                ui.selectable_value(
                    &mut mode,
                    OutputMode::Disabled,
                    OutputMode::Disabled.label(),
                );
                if unknown.is_some() {
                    ui.selectable_value(
                        &mut mode,
                        OutputMode::Unknown,
                        OutputMode::Unknown.label(),
                    );
                }
            });
    });

    if mode == OutputMode::File {
        ui.horizontal(|ui| {
            ui.label("File path");
            ui.add(
                TextEdit::singleline(&mut path)
                    .desired_width(360.0)
                    .hint_text("/var/log/xray/access.log"),
            );
        });
    } else if mode == OutputMode::Unknown {
        if let Some(raw) = &unknown {
            ui.label(format!("Preserved value: {raw}"));
        }
    }

    *output = match mode {
        OutputMode::Stdout => LogOutput::Stdout,
        OutputMode::File => LogOutput::File(path),
        OutputMode::Disabled => LogOutput::Disabled,
        OutputMode::Unknown => LogOutput::Unknown(unknown.unwrap_or_default()),
    };
}

fn edit_mask(ui: &mut Ui, mask: &mut MaskAddress) {
    let mut mode = MaskMode::from_mask(mask);
    let mut custom = match mask {
        MaskAddress::Custom(raw) => raw.clone(),
        _ => "/16+/32".to_owned(),
    };
    let unknown = match mask {
        MaskAddress::Unknown(raw) => Some(raw.clone()),
        _ => None,
    };

    ui.horizontal(|ui| {
        ui.label("Mask IP addresses in logs");
        ComboBox::from_id_salt("log_settings_mask_mode")
            .selected_text(mode.label())
            .show_ui(ui, |ui| {
                for option in [
                    MaskMode::Disabled,
                    MaskMode::Quarter,
                    MaskMode::Half,
                    MaskMode::Full,
                    MaskMode::Custom,
                ] {
                    ui.selectable_value(&mut mode, option, option.label());
                }
                if unknown.is_some() {
                    ui.selectable_value(&mut mode, MaskMode::Unknown, MaskMode::Unknown.label());
                }
            });
    });

    if mode == MaskMode::Custom {
        ui.horizontal(|ui| {
            ui.label("Custom format");
            ui.add(
                TextEdit::singleline(&mut custom)
                    .desired_width(160.0)
                    .hint_text("/16+/32"),
            );
        });
    } else if mode == MaskMode::Unknown {
        if let Some(raw) = &unknown {
            ui.label(format!("Preserved value: {raw}"));
        }
    }

    *mask = match mode {
        MaskMode::Disabled => MaskAddress::Disabled,
        MaskMode::Quarter => MaskAddress::Quarter,
        MaskMode::Half => MaskAddress::Half,
        MaskMode::Full => MaskAddress::Full,
        MaskMode::Custom => MaskAddress::Custom(custom),
        MaskMode::Unknown => MaskAddress::Unknown(unknown.unwrap_or_default()),
    };
}

fn show_privacy_notices(ui: &mut Ui, _editing: bool) {
    ui.label(
        RichText::new(
            "These settings control the remote Xray process logs, not Feldjäger application logs.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}
