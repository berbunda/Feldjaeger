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

// Shared `streamSettings` editors (Roadmap §2.6 stage 0.4).
mod outbound_stream;
mod stream_finalmask;
mod stream_sockopt;

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

// ─── Danger warnings ─────────────────────────────────────────────────────────

/// Text colour of a danger warning ([`danger_warning`]).
const DANGER_RED: Color32 = Color32::from_rgb(230, 50, 50);

/// Road sign 1.33 "Other dangers" (Russian road rules; Vienna Convention A,32), drawn with the
/// painter like [`qr_code`]: a white point-up triangle with a red border and a black exclamation
/// mark. `side` is the triangle's side length in points.
pub(crate) fn danger_sign(ui: &mut Ui, side: f32) -> egui::Response {
    let height = side * 3f32.sqrt() / 2.0;
    let (rect, response) = ui.allocate_exact_size(vec2(side, height), Sense::hover());
    let painter = ui.painter();
    let top = egui::pos2(rect.center().x, rect.min.y);
    let corners = [top, rect.right_bottom(), rect.left_bottom()];
    painter.add(egui::Shape::convex_polygon(
        corners.to_vec(),
        Color32::from_rgb(210, 20, 20),
        egui::Stroke::NONE,
    ));
    // The white field is the same triangle shrunk toward the centroid: scaling the inradius
    // (height / 3) down by `border` leaves a border of equal width on all three sides.
    let border = (side * 0.12).max(1.5);
    let centroid = egui::pos2(rect.center().x, rect.min.y + height * 2.0 / 3.0);
    let scale = ((height / 3.0 - border) / (height / 3.0)).max(0.0);
    let field = corners.map(|corner| centroid + (corner - centroid) * scale);
    painter.add(egui::Shape::convex_polygon(field.to_vec(), Color32::WHITE, egui::Stroke::NONE));
    // Exclamation mark on the axis, low enough to clear the narrow apex of the white field.
    let stroke = side * 0.09;
    let x = rect.center().x;
    painter.line_segment(
        [
            egui::pos2(x, rect.min.y + height * 0.42),
            egui::pos2(x, rect.min.y + height * 0.66),
        ],
        egui::Stroke::new(stroke, Color32::BLACK),
    );
    painter.circle_filled(egui::pos2(x, rect.min.y + height * 0.75), stroke * 0.55, Color32::BLACK);
    response
}

/// A danger-level warning line: [`danger_sign`] followed by `text` in bold red.
pub(crate) fn danger_warning(ui: &mut Ui, text: &str) {
    ui.horizontal_wrapped(|ui| {
        danger_sign(ui, 20.0);
        ui.label(RichText::new(text).color(DANGER_RED).strong());
    });
}

// ─── Field help overlays (Roadmap §3:124) ────────────────────────────────────

fn help_dialog_id() -> egui::Id {
    egui::Id::new("field_help_dialog")
}

/// Gap between the pointer and the nearest edge of the help window.
const HELP_DIALOG_POINTER_GAP: f32 = 12.0;

/// The open help pop-up: what it shows and where it was asked for.
#[derive(Clone, Copy)]
struct HelpDialog {
    title: &'static str,
    text: &'static str,
    /// Pointer position at the click that opened it.
    anchor: egui::Pos2,
    /// False until the window has been put next to `anchor`; afterwards the user may drag it.
    placed: bool,
}

/// Small circular "h" button; on click, opens a pop-up window with `help_text` for `title`
/// (Roadmap §3:124) next to the pointer. Place immediately to the left of a field's label.
///
/// Source: field descriptions come from the official Xray-core config docs
/// (<https://xtls.github.io/config/>), condensed to what's relevant for the exposed control.
pub(crate) fn help_button(ui: &mut Ui, title: &'static str, help_text: &'static str) {
    let button = egui::Button::new(RichText::new("h").size(10.0).strong())
        .corner_radius(egui::CornerRadius::same(u8::MAX))
        .min_size(vec2(16.0, 16.0));
    let response = ui.add(button).on_hover_text(format!("Help: {title}"));
    if response.clicked() {
        let anchor = response
            .interact_pointer_pos()
            .unwrap_or_else(|| response.rect.right_bottom());
        let dialog = HelpDialog {
            title,
            text: help_text,
            anchor,
            placed: false,
        };
        ui.ctx().data_mut(|d| d.insert_temp(help_dialog_id(), dialog));
    }
}

/// Left-top corner for a window of `size` next to `anchor`, `gap` away from it, inside `bounds`.
///
/// Like a tooltip: below-right of the pointer by default; flipped to the left / above when that
/// side would cross `bounds` and the opposite side fits; otherwise pushed back inside `bounds`
/// (a window larger than `bounds` keeps its left / top edge visible).
fn help_dialog_left_top(anchor: egui::Pos2, size: egui::Vec2, bounds: egui::Rect, gap: f32) -> egui::Pos2 {
    fn axis(anchor: f32, size: f32, min: f32, max: f32, gap: f32) -> f32 {
        let after = anchor + gap;
        let before = anchor - gap - size;
        if after + size <= max {
            after
        } else if before >= min {
            before
        } else {
            after.min(max - size).max(min)
        }
    }
    egui::pos2(
        axis(anchor.x, size.x, bounds.min.x, bounds.max.x, gap),
        axis(anchor.y, size.y, bounds.min.y, bounds.max.y, gap),
    )
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
    let ctx = ui.ctx().clone();
    let Some(mut dialog) = ctx.data(|d| d.get_temp::<HelpDialog>(help_dialog_id())) else {
        return;
    };

    let window_id = egui::Id::new(("field_help_window", dialog.title));
    let mut window = egui::Window::new(format!("Help — {}", dialog.title))
        .id(window_id)
        .collapsible(false)
        .resizable(true)
        .default_width(360.0);
    if !dialog.placed {
        // The size is unknown until egui has laid the window out once (its first frame is an
        // invisible sizing pass), so it is first put at the plain below-right spot and moved
        // to the final, edge-aware spot as soon as a size is known. Positioning stops after
        // that so the user can drag the window; egui keeps it inside the app area (`constrain`).
        let size = egui::AreaState::load(&ctx, window_id).and_then(|state| state.size);
        let left_top = match size {
            Some(size) => {
                dialog.placed = true;
                help_dialog_left_top(dialog.anchor, size, ctx.content_rect(), HELP_DIALOG_POINTER_GAP)
            }
            None => dialog.anchor + vec2(HELP_DIALOG_POINTER_GAP, HELP_DIALOG_POINTER_GAP),
        };
        window = window.current_pos(left_top);
    }

    let mut open = true;
    let mut close_clicked = false;
    window.open(&mut open).show(&ctx, |ui| {
        ui.label(dialog.text);
        ui.add_space(10.0);
        if ui.button("Close").clicked() {
            close_clicked = true;
        }
    });

    ctx.data_mut(|d| {
        if !open || close_clicked {
            d.remove::<HelpDialog>(help_dialog_id());
        } else {
            d.insert_temp(help_dialog_id(), dialog);
        }
    });
}

// ─── Shared form widgets (Roadmap §2.6 stage 0.4) ───────────────────────────
//
// Used by several pages (Inbounds Stream/Security tabs, the `stream_*` editors, DNS, Routing,
// API Settings); previously copy-pasted per page.

/// Splits a one-per-line text area into trimmed, non-empty entries.
pub(crate) fn lines_to_vec(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Monospace multi-line editor inside a vertical scroll area capped at 160 px.
pub(crate) fn resizable_multiline(
    ui: &mut Ui,
    text: &mut String,
    rows: usize,
    id: &str,
) -> egui::Response {
    egui::ScrollArea::vertical()
        .id_salt(id)
        .max_height(160.0)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(text)
                    .desired_rows(rows)
                    .desired_width(f32::INFINITY)
                    .code_editor(),
            )
        })
        .inner
}

/// Preset ComboBox with a `(default)` entry (= empty string) plus a free-text override.
/// Returns true when the value changed.
pub(crate) fn optional_string_combo(
    ui: &mut Ui,
    id: &str,
    value: &mut String,
    presets: &[&str],
) -> bool {
    let mut dirty = false;
    let display = if value.is_empty() {
        "(default)".to_owned()
    } else {
        value.clone()
    };
    egui::ComboBox::from_id_salt(id)
        .selected_text(display)
        .show_ui(ui, |ui| {
            if ui
                .selectable_label(value.is_empty(), "(default)")
                .clicked()
            {
                value.clear();
                dirty = true;
            }
            for preset in presets {
                if ui
                    .selectable_label(value == *preset, *preset)
                    .clicked()
                {
                    *value = (*preset).to_owned();
                    dirty = true;
                }
            }
        });
    if ui
        .add(
            egui::TextEdit::singleline(value)
                .desired_width(140.0)
                .hint_text("custom"),
        )
        .changed()
    {
        dirty = true;
    }
    dirty
}

// ─── Frame-persistent text buffers (Roadmap §2.6 stage 0.2) ─────────────────
//
// egui is immediate-mode: a widget whose text is re-derived from the model every frame loses
// whatever the user typed that the model normalizes away (a trailing Enter in a one-per-line
// list, half-typed JSON). A `SourcedTextBuffer` keeps the typed text in egui temp memory next
// to the model value it was rendered from, and is discarded as soon as the model changes from
// elsewhere.

/// A text buffer tied to the value it was rendered from (see the section comment above).
#[derive(Clone)]
pub(crate) struct SourcedTextBuffer<S> {
    /// The model value `text` was rendered from / last applied to.
    pub(crate) source: S,
    /// The text as the user left it.
    pub(crate) text: String,
}

/// Returns the buffered text for `source` if the buffer at `id` still belongs to it, else `render()`.
pub(crate) fn load_text_buffer<S: Clone + PartialEq + Send + Sync + 'static>(
    ui: &Ui,
    id: egui::Id,
    source: &S,
    render: impl FnOnce() -> String,
) -> String {
    ui.ctx()
        .data(|d| d.get_temp::<SourcedTextBuffer<S>>(id))
        .filter(|buffer| buffer.source == *source)
        .map(|buffer| buffer.text)
        .unwrap_or_else(render)
}

/// Stores `text` as the buffer for `source` at `id`.
pub(crate) fn store_text_buffer<S: Clone + Send + Sync + 'static>(
    ui: &Ui,
    id: egui::Id,
    source: S,
    text: String,
) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(id, SourcedTextBuffer { source, text }));
}

/// One-per-line `Vec<String>` text area with a frame-persistent buffer: blank lines being typed
/// (a trailing Enter) survive although `lines_to_vec` drops them from the model. `add` draws the
/// widget (any `TextEdit` flavour, a scroll area, a grid cell — no extra layout is added here).
/// Returns true only when the parsed list differs from `values`.
pub(crate) fn persistent_list_text_edit(
    ui: &mut Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    values: &mut Vec<String>,
    add: impl FnOnce(&mut Ui, &mut String) -> egui::Response,
) -> bool {
    let buffer_id = ui.make_persistent_id(id);
    let mut text = load_text_buffer(ui, buffer_id, values, || values.join("\n"));
    let mut changed = false;
    if add(ui, &mut text).changed() {
        let parsed = lines_to_vec(&text);
        if parsed != *values {
            *values = parsed;
            changed = true;
        }
    }
    store_text_buffer(ui, buffer_id, values.clone(), text);
    changed
}

/// Labelled two-row `persistent_list_text_edit` — the standard "(one per line)" field.
pub(crate) fn persistent_multiline_list_row(
    ui: &mut Ui,
    label: &str,
    values: &mut Vec<String>,
    id: impl std::hash::Hash + std::fmt::Debug,
) -> bool {
    ui.push_id(id, |ui| {
        ui.label(label);
        persistent_list_text_edit(ui, "list_text", values, |ui, text| {
            ui.add(egui::TextEdit::multiline(text).desired_rows(2))
        })
    })
    .inner
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen() -> egui::Rect {
        egui::Rect::from_min_size(egui::Pos2::ZERO, vec2(1000.0, 800.0))
    }

    #[test]
    fn help_dialog_opens_below_right_of_the_pointer() {
        let pos = help_dialog_left_top(egui::pos2(100.0, 100.0), vec2(360.0, 200.0), screen(), 12.0);
        assert_eq!(pos, egui::pos2(112.0, 112.0));
    }

    #[test]
    fn help_dialog_flips_away_from_the_right_and_bottom_edges() {
        let size = vec2(360.0, 200.0);
        // Right edge: 900 + 12 + 360 > 1000 → to the left of the pointer, same vertical rule.
        let pos = help_dialog_left_top(egui::pos2(900.0, 100.0), size, screen(), 12.0);
        assert_eq!(pos, egui::pos2(900.0 - 12.0 - 360.0, 112.0));
        // Bottom edge: above the pointer.
        let pos = help_dialog_left_top(egui::pos2(100.0, 700.0), size, screen(), 12.0);
        assert_eq!(pos, egui::pos2(112.0, 700.0 - 12.0 - 200.0));
        // Bottom-right corner: both flips.
        let pos = help_dialog_left_top(egui::pos2(990.0, 790.0), size, screen(), 12.0);
        assert_eq!(pos, egui::pos2(990.0 - 372.0, 790.0 - 212.0));
    }

    #[test]
    fn help_dialog_is_clamped_when_neither_side_fits() {
        // 700 px tall in an 800 px area: no room above or below a pointer at y = 400.
        let pos = help_dialog_left_top(egui::pos2(100.0, 400.0), vec2(360.0, 700.0), screen(), 12.0);
        assert_eq!(pos, egui::pos2(112.0, 100.0));
        // Wider than the area: the left edge stays visible.
        let pos = help_dialog_left_top(egui::pos2(500.0, 100.0), vec2(1200.0, 200.0), screen(), 12.0);
        assert_eq!(pos, egui::pos2(0.0, 112.0));
    }

    #[test]
    fn lines_to_vec_trims_and_skips_blank_lines() {
        assert_eq!(lines_to_vec(" a \n\n  \nb"), vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn list_row_keeps_a_trailing_newline_being_typed() {
        let ctx = egui::Context::default();
        let mut values = vec!["1.1.1.1".to_owned()];
        let mut buffer_id = egui::Id::NULL;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            buffer_id = ui.push_id("ips", |ui| ui.make_persistent_id("list_text")).inner;
        })
        .drop_without_applying_deltas();
        ctx.data_mut(|d| {
            d.insert_temp(
                buffer_id,
                SourcedTextBuffer {
                    source: values.clone(),
                    text: "1.1.1.1\n".to_owned(),
                },
            );
        });

        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            changed = persistent_multiline_list_row(ui, "ips", &mut values, "ips");
        })
        .drop_without_applying_deltas();
        assert!(!changed);
        assert_eq!(values, vec!["1.1.1.1".to_owned()]);
        let stored = ctx
            .data(|d| d.get_temp::<SourcedTextBuffer<Vec<String>>>(buffer_id))
            .expect("buffer");
        assert_eq!(stored.text, "1.1.1.1\n");
    }

    #[test]
    fn list_buffer_is_dropped_when_the_model_changes_elsewhere() {
        let ctx = egui::Context::default();
        let mut values = vec!["a".to_owned()];
        let mut buffer_id = egui::Id::NULL;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            buffer_id = ui.make_persistent_id("list");
        })
        .drop_without_applying_deltas();
        ctx.data_mut(|d| {
            d.insert_temp(
                buffer_id,
                SourcedTextBuffer {
                    source: vec!["a".to_owned()],
                    text: "a\n".to_owned(),
                },
            );
        });

        // A checkbox / "Migrate" button replaced the list since the buffer was stored.
        values = vec!["b".to_owned(), "c".to_owned()];
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            changed = persistent_list_text_edit(ui, "list", &mut values, |ui, text| {
                ui.add(egui::TextEdit::multiline(text))
            });
        })
        .drop_without_applying_deltas();
        assert!(!changed);
        let stored = ctx
            .data(|d| d.get_temp::<SourcedTextBuffer<Vec<String>>>(buffer_id))
            .expect("buffer");
        assert_eq!(stored.text, "b\nc");
        assert_eq!(stored.source, values);
    }
}
