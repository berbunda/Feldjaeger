//! Content pages for the main window.

use egui::{Color32, RichText, Sense, Ui, vec2};

pub mod api_console;
pub mod api_settings;
pub mod backups;
pub mod burst_observatory;
pub mod confdir_files;
pub mod connection;
pub mod dashboard;
pub mod dns;
pub mod env_settings;
pub mod fakedns;
pub mod geodata;
pub mod geodata_settings;
pub mod inbounds;
pub mod log_settings;
pub mod logs;
pub mod metrics;
pub mod metrics_settings;
pub mod observatory;
pub mod outbounds;
pub mod policy;
pub mod routing;
pub mod service;
pub mod settings;
pub mod stats;
pub mod stats_settings;
pub mod target_lookup;
pub mod users;
pub mod version_settings;
pub mod warp;
pub mod xray_management;

/// Renders a placeholder page with a title and a not-implemented message.
pub(crate) fn placeholder(ui: &mut Ui, title: &str) {
    ui.heading(title);
    ui.add_space(8.0);
    ui.label("This page is not implemented yet.");
}

/// Flat GUI draft for a VLESS-native `reverse` object (Roadmap §2.1:58 —
/// <https://xtls.github.io/en/document/level-2/vless_reverse.html>). Shared by the Users tab
/// Add/Edit VLESS client dialogs (portal side, `inbounds[].settings.clients[].reverse`) and the
/// Outbounds VLESS Shell (bridge side, `outbounds[].settings.reverse`) — identical JSON shape in
/// both placements. `enabled` drives presence; `sniffing_enabled` + `sniffing_dest_override`
/// cover the one advanced sub-object the doc shows riding along on `reverse` (kept under a
/// spoiler — `metadataOnly`/`routeOnly` are not exposed here and simply stay unset, same
/// minimal-scope choice already used elsewhere for rarely-needed sniffing flags).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ReverseDraftFields {
    pub(crate) enabled: bool,
    pub(crate) tag: String,
    pub(crate) sniffing_enabled: bool,
    pub(crate) sniffing_dest_override: Vec<String>,
}

impl ReverseDraftFields {
    pub(crate) fn from_reverse(reverse: Option<&crate::app::ReverseTagDraft>) -> Self {
        let Some(reverse) = reverse else {
            return Self::default();
        };
        let sniffing = reverse.sniffing.as_ref();
        Self {
            enabled: true,
            tag: reverse.tag.clone(),
            sniffing_enabled: sniffing.is_some_and(|s| s.enabled),
            sniffing_dest_override: sniffing.map(|s| s.dest_override.clone()).unwrap_or_default(),
        }
    }

    pub(crate) fn to_reverse(&self) -> Option<crate::app::ReverseTagDraft> {
        if !self.enabled {
            return None;
        }
        let sniffing = if self.sniffing_enabled || !self.sniffing_dest_override.is_empty() {
            Some(crate::app::ReverseSniffingDraft {
                enabled: self.sniffing_enabled,
                dest_override: self.sniffing_dest_override.clone(),
                unknown_dest_override: Vec::new(),
                metadata_only: false,
                route_only: false,
                extras: Default::default(),
            })
        } else {
            None
        };
        Some(crate::app::ReverseTagDraft {
            tag: self.tag.trim().to_owned(),
            sniffing,
            extras: Default::default(),
        })
    }
}

/// Checkbox-gated `reverse` editor: presence toggle + `tag` field + a "Sniffing (advanced)"
/// spoiler with `enabled` and the known `destOverride` checkboxes.
pub(crate) fn reverse_fields_edit(ui: &mut Ui, id_salt: &str, draft: &mut ReverseDraftFields) {
    ui.checkbox(&mut draft.enabled, "reverse (VLESS-native reverse proxy)")
        .on_hover_text(
            "https://xtls.github.io/en/document/level-2/vless_reverse.html — registers this side \
             under a local tag routed via routing outboundTag",
        );
    if !draft.enabled {
        return;
    }
    ui.horizontal(|ui| {
        ui.label("reverse.tag");
        ui.add(egui::TextEdit::singleline(&mut draft.tag).desired_width(300.0))
            .on_hover_text("Local-only identifier; the two sides do not need matching tags");
    });
    egui::CollapsingHeader::new("Sniffing (advanced)")
        .id_salt(id_salt)
        .default_open(false)
        .show(ui, |ui| {
            ui.checkbox(&mut draft.sniffing_enabled, "enabled");
            for token in crate::app::KNOWN_DEST_OVERRIDE {
                let mut selected = draft.sniffing_dest_override.iter().any(|t| t == token);
                if ui.checkbox(&mut selected, *token).changed() {
                    if selected {
                        if !draft.sniffing_dest_override.iter().any(|t| t == token) {
                            draft.sniffing_dest_override.push((*token).to_owned());
                        }
                    } else {
                        draft.sniffing_dest_override.retain(|t| t != token);
                    }
                }
            }
        });
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

/// Draws a small line-chart sparkline for `points` directly with the painter (no plotting crate
/// dependency — same "draw it ourselves" call as [`qr_code`], Roadmap §3:129). `points` is
/// oldest-first; a single point (or none) draws a flat/empty placeholder line instead of
/// panicking on a degenerate min==max range.
pub(crate) fn sparkline(ui: &mut Ui, points: &[i64], width: f32, height: f32) {
    let (rect, _response) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 2.0, Color32::from_rgb(30, 30, 34));

    if points.len() < 2 {
        let y = rect.center().y;
        painter.line_segment(
            [egui::pos2(rect.min.x, y), egui::pos2(rect.max.x, y)],
            egui::Stroke::new(1.0, Color32::from_rgb(90, 90, 96)),
        );
        return;
    }

    let min = *points.iter().min().unwrap();
    let max = *points.iter().max().unwrap();
    let span = (max - min).max(1) as f32;
    let step_x = width / (points.len() - 1) as f32;

    let plot_points: Vec<egui::Pos2> = points
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let normalized = (*value - min) as f32 / span;
            egui::pos2(
                rect.min.x + i as f32 * step_x,
                rect.max.y - normalized * height,
            )
        })
        .collect();

    painter.add(egui::Shape::line(
        plot_points,
        egui::Stroke::new(1.5, Color32::from_rgb(90, 170, 230)),
    ));
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
