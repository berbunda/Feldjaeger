//! FakeDNS page — view / edit the Xray top-level `fakedns` value (Roadmap §2.1:47).
//!
//! Full coverage of the official `FakeDnsObject` (`ipPool`, `poolSize`), plus the single-object-
//! or-array top-level shape (one pool vs. several, e.g. simultaneous IPv4 + IPv6 ranges). Mirrors
//! the View/Edit/Save/Cancel/Preview changes chrome already established by DNS (§2.1:46) — this
//! page has no separate live/runtime counterpart to split away from, so it stays a single page
//! for both view and edit.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, TextEdit, Ui};

use crate::app::{ApplicationService, FakeDnsPageState};
use crate::xray::{FakeDnsPoolEntry, FakeDnsSettings};

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);

/// One preset FakeDNS pool: `(label, ipPool CIDR, poolSize)`. `poolSize` is `None` when the
/// pool is large enough that the default (65535) fits comfortably; `Some(n)` for the small
/// RFC 5737 test-net presets, where 65535 would exceed the block's actual address count.
type FakeDnsPreset = (&'static str, &'static str, Option<u64>);

/// Alternatives to the Xray-documented default (`198.18.0.0/15`, RFC 2544 benchmarking range —
/// still offered here too, first in the list) for the FakeDNS `ipPool`. Every entry is drawn from
/// an IANA special-purpose block that is not expected to be routed on the real internet — the
/// property that actually matters for a FakeDNS pool (its addresses are synthetic and never
/// leave the local Xray process, but picking a block that could collide with something real on
/// the network avoids confusing overlaps). RFC 1918 private ranges (`10.0.0.0/8`, `192.168.0.0/16`,
/// …) are deliberately not offered — unlike these IANA-reserved test/benchmark blocks, a private
/// range is very likely already used by the user's own LAN or VPN, so suggesting one as a default
/// would be actively risky rather than merely a convenience. Presented on a separate "Presets"
/// button (never auto-filled) so it never interferes with a manually typed `ipPool`.
const FAKEDNS_POOL_PRESETS: &[FakeDnsPreset] = &[
    (
        "198.18.0.0/15 — default (RFC 2544 benchmarking, ~131k addresses)",
        "198.18.0.0/15",
        None,
    ),
    (
        "198.18.0.0/16 — half of the default range (~65k addresses)",
        "198.18.0.0/16",
        None,
    ),
    (
        "198.19.0.0/16 — other half of the default range (~65k addresses)",
        "198.19.0.0/16",
        None,
    ),
    (
        "192.0.2.0/24 — TEST-NET-1 (RFC 5737, small pool, 256 addresses)",
        "192.0.2.0/24",
        Some(200),
    ),
    (
        "198.51.100.0/24 — TEST-NET-2 (RFC 5737, small pool, 256 addresses)",
        "198.51.100.0/24",
        Some(200),
    ),
    (
        "203.0.113.0/24 — TEST-NET-3 (RFC 5737, small pool, 256 addresses)",
        "203.0.113.0/24",
        Some(200),
    ),
    (
        "fc00::/18 (IPv6) — unique local address range",
        "fc00::/18",
        None,
    ),
    (
        "2001:db8::/32 (IPv6) — documentation range (RFC 3849)",
        "2001:db8::/32",
        None,
    ),
];

/// Renders the FakeDNS page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_fakedns_page_status();

    ui.heading("FakeDNS");
    ui.add_space(8.0);

    let model = service.fakedns_page_model();

    match model.state {
        FakeDnsPageState::NoSshConnection
        | FakeDnsPageState::XrayNotDiscovered
        | FakeDnsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        FakeDnsPageState::MalformedFakeDnsObject => {
            show_state_message(ui, model.state);
            for warning in &model.settings.warnings {
                ui.label(RichText::new(warning.clone()).size(14.0).color(ERROR_COLOR));
            }
            return;
        }
        FakeDnsPageState::ViewMode
        | FakeDnsPageState::EditMode
        | FakeDnsPageState::ValidationError
        | FakeDnsPageState::Saving
        | FakeDnsPageState::Saved
        | FakeDnsPageState::SaveFailed => {
            show_state_message(ui, model.state);
            for warning in &model.settings.warnings {
                ui.label(RichText::new(warning.clone()).size(14.0).color(WARN_COLOR));
            }
            if let Some(error) = &model.error_message {
                ui.label(RichText::new(error.clone()).size(14.0).color(ERROR_COLOR));
            }
            ui.add_space(8.0);
        }
    }

    show_info_note(ui);
    ui.add_space(8.0);

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
        if let Some(entries) = service.fakedns_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: FakeDnsPageState) {
    let color = match state {
        FakeDnsPageState::ValidationError | FakeDnsPageState::Saved => WARN_COLOR,
        FakeDnsPageState::ViewMode | FakeDnsPageState::EditMode => MUTED_COLOR,
        FakeDnsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_info_note(ui: &mut Ui) {
    ui.label(
        RichText::new("FakeDNS requires corresponding DNS and routing configuration.")
            .size(13.0)
            .color(MUTED_COLOR),
    );
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: FakeDnsPageState,
) {
    let busy = matches!(
        state,
        FakeDnsPageState::Saving | FakeDnsPageState::SaveFailed
    ) && service.is_fakedns_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_fakedns_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_fakedns_settings();
            }
            if ui
                .add_enabled(
                    !service.is_fakedns_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_fakedns_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_fakedns_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_fakedns_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_fakedns_settings();
        }
    });
}

// ─── View mode ─────────────────────────────────────────────────────────────

fn show_view(ui: &mut Ui, settings: &FakeDnsSettings) {
    if let Some(source) = &settings.source_file {
        ui.label(format!("Source file: {source}"));
        ui.add_space(8.0);
    } else if !settings.section_present {
        ui.label(
            RichText::new(
                "No fakedns value in the remote configuration. Defaults are shown; the value is \
                 created only when you save changes.",
            )
            .size(12.0)
            .color(MUTED_COLOR),
        );
        ui.add_space(8.0);
    }

    ui.strong(format!("Pools ({})", settings.pools.len()));
    ui.add_space(4.0);
    if settings.pools.is_empty() {
        ui.label(
            RichText::new("No FakeDNS pools configured.")
                .size(13.0)
                .color(MUTED_COLOR),
        );
        return;
    }

    egui::Grid::new("fakedns_pools_view_grid")
        .num_columns(2)
        .striped(true)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.strong("ipPool");
            ui.strong("poolSize");
            ui.end_row();
            for pool in &settings.pools {
                ui.label(&pool.ip_pool);
                ui.label(
                    pool.pool_size
                        .map(|size| size.to_string())
                        .unwrap_or_else(|| "(default 65535)".to_owned()),
                );
                ui.end_row();
            }
        });
}

// ─── Edit mode ──────────────────────────────────────────────────────────────

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(draft) = service.fakedns_settings_draft_mut() else {
        return;
    };

    ui.strong("Pools");
    ui.add_space(4.0);

    let mut remove_pool: Option<usize> = None;
    for index in 0..draft.pools.len() {
        egui::Frame::group(ui.style())
            .show(ui, |ui| show_pool_edit_form(ui, draft, index, &mut remove_pool));
        ui.add_space(6.0);
    }
    if let Some(index) = remove_pool {
        draft.pools.remove(index);
    }
    ui.horizontal(|ui| {
        if ui.button("Add pool").clicked() {
            draft.pools.push(FakeDnsPoolEntry::blank());
        }
        show_fakedns_pool_presets_button(ui, draft);
    });
}

/// "Presets" menu button — appends a new pool pre-filled with a known-safe `ipPool`/`poolSize`
/// pair. Deliberately separate from "Add pool" and the `ipPool` text field: clicking a preset
/// only ever adds a new list entry, it never overwrites what the user has already typed.
fn show_fakedns_pool_presets_button(ui: &mut Ui, draft: &mut FakeDnsSettings) {
    ui.menu_button("Presets ▼", |ui| {
        for (label, cidr, pool_size) in FAKEDNS_POOL_PRESETS {
            if ui.button(*label).clicked() {
                draft.pools.push(FakeDnsPoolEntry {
                    ip_pool: (*cidr).to_owned(),
                    pool_size: *pool_size,
                    extra: Default::default(),
                });
                ui.close();
            }
        }
    });
}

fn show_pool_edit_form(
    ui: &mut Ui,
    draft: &mut FakeDnsSettings,
    index: usize,
    remove: &mut Option<usize>,
) {
    let pool = &mut draft.pools[index];
    ui.horizontal(|ui| {
        ui.label(format!("Pool {}", index + 1));
        if ui.small_button("Remove").clicked() {
            *remove = Some(index);
        }
    });

    ui.horizontal(|ui| {
        ui.label("ipPool");
        ui.add(
            TextEdit::singleline(&mut pool.ip_pool)
                .desired_width(220.0)
                .hint_text("198.18.0.0/15"),
        );
    });

    let mut enabled = pool.pool_size.is_some();
    let mut number = pool.pool_size.unwrap_or(65535);
    ui.push_id(("fakedns_pool_size", index), |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut enabled, "poolSize");
            ui.add_enabled(enabled, egui::DragValue::new(&mut number).range(1..=u64::MAX));
        });
    });
    pool.pool_size = if enabled { Some(number) } else { None };

    if !pool.extra.is_empty() {
        ui.label(
            RichText::new(format!(
                "{} additional field(s) on this pool are preserved but not editable here.",
                pool.extra.len()
            ))
            .size(11.0)
            .color(MUTED_COLOR),
        );
    }
}
