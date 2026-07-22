//! Left navigation sidebar.

use egui::Ui;

use crate::gui::navigation::Page;

/// Renders the persistent sidebar and updates the active page selection.
pub fn show(ui: &mut Ui, current: &mut Page) {
    ui.heading("Feldjäger");
    ui.separator();

    for page in Page::ALL {
        let selected = *current == *page;
        if ui.selectable_label(selected, page.label()).clicked() {
            *current = *page;
        }
    }
}
