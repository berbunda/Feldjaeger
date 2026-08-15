//! Content pages for the main window.

use egui::{Color32, RichText, Sense, Ui, vec2};

pub mod burst_observatory;
pub mod confdir_files;
pub mod connection;
pub mod dashboard;
pub mod dns;
pub mod fakedns;
pub mod geodata;
pub mod inbounds;
pub mod log_settings;
pub mod logs;
pub mod observatory;
pub mod outbounds;
pub mod policy;
pub mod routing;
pub mod service;
pub mod settings;
pub mod users;
pub mod warp;
pub mod xray_management;

/// Renders a placeholder page with a title and a not-implemented message.
pub(crate) fn placeholder(ui: &mut Ui, title: &str) {
    ui.heading(title);
    ui.add_space(8.0);
    ui.label("This page is not implemented yet.");
}

/// Redacted structural JSON diff list (IB-L5, Roadmap §3:114; Users tab follow-up, §3:120).
///
/// Shared by the Inbound Shell "Preview changes" and the Users tab Add/Edit dialogs.
pub(crate) fn json_diff_preview(ui: &mut Ui, entries: &[crate::xray::JsonDiffEntry]) {
    let title = if entries.is_empty() {
        "JSON changes (none)".to_owned()
    } else {
        format!("JSON changes ({})", entries.len())
    };
    egui::CollapsingHeader::new(title)
        .default_open(true)
        .show(ui, |ui| {
            if entries.is_empty() {
                ui.label(
                    RichText::new("No differences vs the loaded file.")
                        .size(13.0)
                        .color(Color32::from_rgb(140, 140, 140)),
                );
                return;
            }
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for entry in entries {
                        let color = match entry.kind {
                            crate::xray::JsonDiffKind::Added => Color32::from_rgb(40, 160, 80),
                            crate::xray::JsonDiffKind::Removed => Color32::from_rgb(200, 60, 60),
                            crate::xray::JsonDiffKind::Changed => Color32::from_rgb(210, 170, 40),
                        };
                        let detail = match entry.kind {
                            crate::xray::JsonDiffKind::Added => format!(
                                "{} {} = {}",
                                entry.kind.label(),
                                entry.path,
                                entry.after.as_deref().unwrap_or("?")
                            ),
                            crate::xray::JsonDiffKind::Removed => format!(
                                "{} {} (was {})",
                                entry.kind.label(),
                                entry.path,
                                entry.before.as_deref().unwrap_or("?")
                            ),
                            crate::xray::JsonDiffKind::Changed => format!(
                                "{} {} : {} → {}",
                                entry.kind.label(),
                                entry.path,
                                entry.before.as_deref().unwrap_or("?"),
                                entry.after.as_deref().unwrap_or("?")
                            ),
                        };
                        ui.label(RichText::new(detail).size(12.0).color(color).monospace());
                    }
                });
        });
}

/// Draws a QR code for `data` directly with the painter (no texture upload, no `image` crate
/// dependency — Roadmap §3:122). Modules are filled rectangles on a white quiet-zone background,
/// per the QR standard's minimum 4-module margin.
///
/// Returns an error message (e.g. "data too long for a QR code") instead of the widget when
/// encoding fails — share URIs with very large `extra=` XHTTP payloads can exceed QR capacity.
pub(crate) fn qr_code(ui: &mut Ui, data: &str) -> Result<(), String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|error| error.to_string())?;
    let width = code.width();
    let colors = code.to_colors();

    const QUIET_ZONE_MODULES: usize = 4;
    const MODULE_PX: f32 = 4.0;
    let total_modules = width + QUIET_ZONE_MODULES * 2;
    let side = total_modules as f32 * MODULE_PX;

    let (rect, _response) = ui.allocate_exact_size(vec2(side, side), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 0.0, Color32::WHITE);
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                let module_min = rect.min
                    + vec2(
                        (x + QUIET_ZONE_MODULES) as f32 * MODULE_PX,
                        (y + QUIET_ZONE_MODULES) as f32 * MODULE_PX,
                    );
                painter.rect_filled(
                    egui::Rect::from_min_size(module_min, vec2(MODULE_PX, MODULE_PX)),
                    0.0,
                    Color32::BLACK,
                );
            }
        }
    }
    Ok(())
}

// ─── Field help overlays (Roadmap §3:124) ────────────────────────────────────

fn help_dialog_id() -> egui::Id {
    egui::Id::new("field_help_dialog")
}

/// Small circular "h" button; on click, opens a pop-up window with `help_text` for `title`
/// (Roadmap §3:124). Place immediately to the left of a field's label.
///
/// Source: field descriptions come from the official Xray-core config docs
/// (<https://xtls.github.io/config/>), condensed to what's relevant for the exposed control.
pub(crate) fn help_button(ui: &mut Ui, title: &'static str, help_text: &'static str) {
    let button = egui::Button::new(RichText::new("h").size(10.0).strong())
        .corner_radius(egui::CornerRadius::same(u8::MAX))
        .min_size(vec2(16.0, 16.0));
    if ui
        .add(button)
        .on_hover_text(format!("Help: {title}"))
        .clicked()
    {
        ui.ctx()
            .data_mut(|d| d.insert_temp(help_dialog_id(), (title, help_text)));
    }
}

/// Label preceded by a [`help_button`] for `help_text` — drop-in replacement for `ui.label(text)`
/// in a form (Roadmap §3:124).
pub(crate) fn field_label(ui: &mut Ui, text: &'static str, help_text: &'static str) {
    ui.horizontal(|ui| {
        help_button(ui, text, help_text);
        ui.label(text);
    });
}

/// Renders the pop-up window opened by the last-clicked [`help_button`], if any. Call once per
/// page after the fields that may contain help buttons.
pub(crate) fn show_help_dialog(ui: &mut Ui) {
    let Some((title, text)) = ui
        .ctx()
        .data(|d| d.get_temp::<(&'static str, &'static str)>(help_dialog_id()))
    else {
        return;
    };

    let mut open = true;
    let mut close_clicked = false;
    egui::Window::new(format!("Help — {title}"))
        .collapsible(false)
        .resizable(true)
        .default_width(360.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(text);
            ui.add_space(10.0);
            if ui.button("Close").clicked() {
                close_clicked = true;
            }
        });

    if !open || close_clicked {
        ui.ctx()
            .data_mut(|d| d.remove::<(&'static str, &'static str)>(help_dialog_id()));
    }
}
