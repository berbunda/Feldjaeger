//! Settings page: application preferences stored in the local `config.json`.

use egui::{Color32, RichText, Ui};

use crate::app::ApplicationService;
use crate::storage::HelpLanguage;

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);

/// Renders the Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Settings");
    ui.add_space(8.0);

    ui.label(RichText::new("Help").strong());
    ui.add_space(4.0);
    let current = service.ui_config().help_language;
    let mut selected = current;
    ui.horizontal(|ui| {
        ui.label("Help language");
        egui::ComboBox::from_id_salt("settings_help_language")
            .selected_text(selected.native_name())
            .show_ui(ui, |ui| {
                for language in HelpLanguage::ALL {
                    ui.selectable_value(&mut selected, language, language.native_name());
                }
            });
    });
    if selected != current {
        service.set_help_language(selected);
    }
    ui.label(
        RichText::new(
            "Language of the pop-up help opened with the \"h\" buttons next to fields. Field \
             names stay as in the Xray config; help without a translation is shown in English.",
        )
        .size(12.0)
        .color(MUTED_COLOR),
    );
}
