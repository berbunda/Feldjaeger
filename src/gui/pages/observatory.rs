//! Observatory page — read-only view of the discovered Xray Observatory section.
//!
//! Data flows exclusively through [`ApplicationService`] and Observatory summaries.
//! This page never reads JSON, opens SSH, or mutates remote configuration.

use egui::{Color32, RichText, Sense, TextEdit, Ui};

use super::HelpText;
use crate::app::{
    ApplicationService, MISSING_FIELD, ObservatoryPageState, observatory_general_display,
};
use crate::xray::ObservatorySummary;

const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);

// ─── Field help text (Roadmap §4.4) ──────────────────────────────────────────
//
// Condensed from https://xtls.github.io/config/observatory.html; behaviour and defaults are
// Xray-core's (`app/observatory/observer.go`, `infra/conf/observatory.go`,
// `infra/conf/cfgcommon/duration`, `app/proxyman/outbound` `Select` v26.9.30).

const HELP_PROBE_URL: HelpText = HelpText::new(
    "URL requested with HTTP GET through each selected outbound; the time to the response is \
     the outbound's latency. Any HTTP response within 5 s counts as alive — the status code is \
     not checked and redirects are not followed; an error or timeout marks the outbound dead. \
     Empty = https://www.google.com/generate_204.",
    "URL, который запрашивается методом HTTP GET через каждый выбранный outbound; время до \
     ответа — задержка этого outbound. Любой HTTP-ответ в пределах 5 с считается «жив» — код \
     ответа не проверяется, перенаправления не выполняются; ошибка или таймаут помечают outbound \
     как недоступный. Пусто — https://www.google.com/generate_204.",
);
const HELP_PROBE_INTERVAL: HelpText = HelpText::new(
    "Pause between probes, a number with a unit: ns, us, ms, s, m, h (e.g. 10s, 1m30s); a bare \
     number is rejected by Xray-core. With enableConcurrency off the pause follows every single \
     outbound, so one round over N outbounds takes about N × probeInterval. Empty or 0 = 10s.",
    "Пауза между проверками — число с единицей: ns, us, ms, s, m, h (например, 10s, 1m30s); \
     число без единицы Xray-core отвергает. При выключенном enableConcurrency пауза идёт после \
     каждого outbound, поэтому один круг по N outbound занимает около N × probeInterval. Пусто \
     или 0 — 10s.",
);
const HELP_ENABLE_CONCURRENCY: HelpText = HelpText::new(
    "Off (default): outbounds are probed one at a time in tag order, with probeInterval after \
     each. On: all selected outbounds are probed at once, then Observatory waits probeInterval — \
     results refresh faster, at the cost of a burst of simultaneous requests.",
    "Выключено (по умолчанию): outbound проверяются по одному в порядке тегов, после каждого — \
     пауза probeInterval. Включено: все выбранные outbound проверяются одновременно, затем \
     Observatory ждёт probeInterval — результаты обновляются быстрее ценой всплеска \
     одновременных запросов.",
);
const HELP_SUBJECT_SELECTORS: HelpText = HelpText::new(
    "Outbound tag prefixes, one per line: every outbound whose tag starts with one of them is \
     probed (\"proxy\" matches proxy-a and proxy-b). With an empty list Observatory does not run \
     at all. The results are used by balancers with the leastPing / leastLoad strategy (Routing \
     → Balancers) and reported by the API's ObservatoryService.",
    "Префиксы тегов outbound, по одному на строку: проверяется каждый outbound, тег которого \
     начинается с одного из них (\"proxy\" подходит к proxy-a и proxy-b). При пустом списке \
     Observatory не запускается вовсе. Результаты используют балансировщики со стратегией \
     leastPing / leastLoad (Routing → Balancers), их также отдаёт ObservatoryService в API.",
);

/// Renders the Observatory page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_observatory_page_status();
    super::show_help_dialog(ui);

    ui.heading("Observatory");
    ui.add_space(8.0);

    let model = service.observatory_page_model();

    match model.state {
        ObservatoryPageState::NoSshConnection
        | ObservatoryPageState::XrayNotDiscovered
        | ObservatoryPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        ObservatoryPageState::MalformedObservatoryObject => {
            show_state_message(ui, model.state);
            for warning in &model.observatory_settings.warnings {
                ui.label(RichText::new(warning.clone()).size(14.0).color(ERROR_COLOR));
            }
            return;
        }
        _ => {}
    }

    show_state_message(ui, model.state);
    show_warnings(ui, &model.warnings);
    if let Some(error) = &model.error_message {
        ui.label(RichText::new(error.clone()).size(14.0).color(ERROR_COLOR));
    }
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
        if let Some(entries) = service.observatory_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        egui::ScrollArea::vertical()
            .id_salt("observatory_edit_scroll")
            .show(ui, |ui| show_edit_form(ui, service));
        return;
    }

    if model.state == ObservatoryPageState::ObservatorySectionMissing {
        return;
    }

    let Some(summary) = model.summary.as_ref() else {
        return;
    };

    show_info_note(ui);
    ui.add_space(12.0);
    show_general(ui, summary);
    ui.add_space(12.0);
    show_subjects(ui, summary);
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: ObservatoryPageState,
) {
    let busy = matches!(state, ObservatoryPageState::Saving | ObservatoryPageState::SaveFailed)
        && service.is_observatory_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_observatory_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_observatory_settings();
            }
            if ui
                .add_enabled(
                    !service.is_observatory_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_observatory_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_observatory_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_observatory_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_observatory_settings();
        }
    });
}

fn show_state_message(ui: &mut Ui, state: ObservatoryPageState) {
    let color = match state {
        ObservatoryPageState::ConfigurationContainsWarnings
        | ObservatoryPageState::ValidationError
        | ObservatoryPageState::Saved => WARN_COLOR,
        ObservatoryPageState::ObservatorySectionMissing
        | ObservatoryPageState::NoSubjectSelectors
        | ObservatoryPageState::ConfigurationLoaded
        | ObservatoryPageState::EditMode => MUTED_COLOR,
        ObservatoryPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_warnings(ui: &mut Ui, warnings: &[String]) {
    for warning in warnings {
        ui.label(
            RichText::new(warning.clone())
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
}

fn show_info_note(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "Runtime latency and availability require the Tier 3 Xray API and are not available yet.",
        )
        .size(14.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn show_general(ui: &mut Ui, summary: &ObservatorySummary) {
    let display = observatory_general_display(summary);
    ui.strong("General");
    ui.add_space(4.0);
    egui::Grid::new("observatory_general")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("Probe URL");
            let response = ui.add(egui::Label::new(&display.probe_url).sense(Sense::click()));
            response.context_menu(|ui| {
                if ui.button("Copy Probe URL").clicked() {
                    ui.ctx().copy_text(
                        summary
                            .probe_url
                            .clone()
                            .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    );
                    ui.close();
                }
            });
            ui.end_row();

            general_row(ui, "Probe Interval", &display.probe_interval);
            general_row(
                ui,
                "Subject Selector count",
                &display.subject_selector_count,
            );
            general_row(ui, "Source file", &display.source_file);
        });
}

fn general_row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn show_subjects(ui: &mut Ui, summary: &ObservatorySummary) {
    ui.strong("Subjects");
    ui.add_space(4.0);
    if summary.subject_selectors.is_empty() {
        ui.label(
            RichText::new("No subject selectors configured.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    egui::Grid::new("observatory_subjects_table")
        .num_columns(2)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(40.0)
        .show(ui, |ui| {
            ui.strong("#");
            ui.strong("Selector");
            ui.end_row();

            for (index, selector) in summary.subject_selectors.iter().enumerate() {
                ui.label((index + 1).to_string());
                let response = ui.add(egui::Label::new(selector).sense(Sense::click()));
                response.context_menu(|ui| {
                    if ui.button("Copy Selector").clicked() {
                        ui.ctx().copy_text(selector.clone());
                        ui.close();
                    }
                });
                ui.end_row();
            }
        });
}

// ─── Edit mode ──────────────────────────────────────────────────────────────

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(draft) = service.observatory_settings_draft_mut() else {
        return;
    };

    ui.strong("General");
    ui.add_space(4.0);

    super::optional_text_row(
        ui,
        "probeUrl",
        HELP_PROBE_URL,
        &mut draft.probe_url,
        "https://www.google.com/generate_204",
        280.0,
        "observatory_probe_url",
    );
    super::optional_text_row(
        ui,
        "probeInterval",
        HELP_PROBE_INTERVAL,
        &mut draft.probe_interval,
        "10s",
        280.0,
        "observatory_probe_interval",
    );
    ui.horizontal(|ui| {
        super::help_button(ui, "enableConcurrency", HELP_ENABLE_CONCURRENCY);
        ui.checkbox(&mut draft.enable_concurrency, "enableConcurrency");
    });

    ui.add_space(16.0);
    ui.separator();
    ui.horizontal(|ui| {
        super::help_button(ui, "subjectSelector", HELP_SUBJECT_SELECTORS);
        ui.strong(format!("Subject selectors ({})", draft.subject_selectors.len()));
    });
    ui.add_space(4.0);
    super::persistent_list_text_edit(ui, "observatory_subject_selectors", &mut draft.subject_selectors, |ui, text| {
        ui.add(TextEdit::multiline(text).desired_rows(4).hint_text("one outbound tag prefix per line"))
    });
}

