//! API Settings page — view / edit the Xray top-level `api` object (Roadmap §2.1:54).
//!
//! Enables/edits `api.tag` / `api.listen` / `api.services` in the configuration file. Live gRPC
//! calls against an already-configured endpoint live on the separate API Console page (Roadmap
//! §3:128) — the same split as Log Settings (this page's sibling) vs. Xray Logs.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never parses raw JSON, opens
//! SSH, or writes remote files directly.

use egui::{Color32, RichText, TextEdit, Ui};

use super::HelpText;
use crate::app::{ApiSettingsPageState, ApplicationService};
use crate::gui::pages::persistent_list_text_edit;
use crate::xray::KNOWN_API_SERVICES;

// ─── Field help text (Roadmap §4.4) ──────────────────────────────────────────
//
// Condensed from https://xtls.github.io/config/api.html; behaviour is Xray-core's
// (`infra/conf/api.go`, `app/commander/commander.go` v26.9.30), checked with `xray run -test`.

const HELP_TAG: HelpText = HelpText::new(
    "Required: Xray-core refuses to load an api object without a tag (\"API tag can't be \
     empty.\"). Without listen, Xray creates an outbound with this tag that serves the API — \
     route traffic to it, usually a dokodemo-door inbound on 127.0.0.1 plus a routing rule \
     inboundTag → outboundTag = this tag. With listen set the tag is still required but unused.",
    "Обязательно: без tag Xray-core не загружает объект api («API tag can't be empty.»). Без \
     listen Xray создаёт outbound с этим тегом, который обслуживает API, — к нему нужно \
     направить трафик, обычно inbound dokodemo-door на 127.0.0.1 и правило маршрутизации \
     inboundTag → outboundTag = этот тег. При заданном listen tag всё равно обязателен, но не \
     используется.",
);
const HELP_LISTEN: HelpText = HelpText::new(
    "Address the gRPC API listens on by itself, e.g. 127.0.0.1:10085; a value starting with / or \
     @ is a Unix socket (file path / abstract name). The API has no authentication — keep it on \
     loopback. The API Console and Statistics pages connect to this address on the server. \
     Empty = no own listener: the API is reachable only through the tag outbound and routing.",
    "Адрес, на котором gRPC API слушает сам, например 127.0.0.1:10085; значение, начинающееся с \
     / или @, — Unix-сокет (путь к файлу / абстрактное имя). У API нет аутентификации — держите \
     его на loopback. Страницы API Console и Statistics подключаются к этому адресу на сервере. \
     Пусто — без собственного слушателя: API доступен только через outbound tag и маршрутизацию.",
);
const HELP_SERVICES: HelpText = HelpText::new(
    "gRPC services the API exposes: HandlerService — add / remove inbounds, outbounds and users \
     at runtime; LoggerService — restart the logger (log rotation); StatsService — traffic \
     counters (they exist only with stats and the policy stats* switches); RoutingService — \
     routing rules and balancers at runtime; ReflectionService — gRPC reflection, lets grpcurl \
     list the methods; ObservatoryService — Observatory / BurstObservatory results (Xray does \
     not start without one of those sections). Names are case-insensitive; an unknown name is \
     silently ignored.",
    "gRPC-сервисы, которые открывает API: HandlerService — добавление / удаление inbound, \
     outbound и пользователей на ходу; LoggerService — перезапуск логгера (ротация логов); \
     StatsService — счётчики трафика (они есть только при stats и включённых stats* в policy); \
     RoutingService — правила маршрутизации и балансировщики на ходу; ReflectionService — \
     gRPC reflection, позволяет grpcurl получить список методов; ObservatoryService — результаты \
     Observatory / BurstObservatory (без одной из этих секций Xray не запускается). Регистр в \
     именах не важен; неизвестное имя молча игнорируется.",
);

/// Renders the API Settings page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    super::show_help_dialog(ui);
    ui.heading("API Settings");
    ui.add_space(8.0);

    let model = service.api_settings_page_model();

    match model.state {
        ApiSettingsPageState::NoSshConnection
        | ApiSettingsPageState::XrayNotDiscovered
        | ApiSettingsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        ApiSettingsPageState::MalformedApiObject => {
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
        ApiSettingsPageState::ViewMode
        | ApiSettingsPageState::EditMode
        | ApiSettingsPageState::ValidationError
        | ApiSettingsPageState::Saving
        | ApiSettingsPageState::Saved
        | ApiSettingsPageState::SaveFailed => {
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
        if let Some(entries) = service.api_settings_diff_preview() {
            super::json_diff_preview(ui, entries);
            ui.add_space(8.0);
        }
        show_edit_form(ui, service);
    } else {
        show_view(ui, &model.settings);
    }
}

fn show_state_message(ui: &mut Ui, state: ApiSettingsPageState) {
    let color = match state {
        ApiSettingsPageState::ValidationError | ApiSettingsPageState::Saved => {
            Color32::from_rgb(210, 170, 40)
        }
        ApiSettingsPageState::ViewMode | ApiSettingsPageState::EditMode => {
            Color32::from_rgb(140, 140, 140)
        }
        ApiSettingsPageState::Saving => Color32::from_rgb(100, 140, 200),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    editing: bool,
    state: ApiSettingsPageState,
) {
    let busy = matches!(
        state,
        ApiSettingsPageState::Saving | ApiSettingsPageState::SaveFailed
    ) && service.is_api_settings_mutation_busy();

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(
                    !service.is_api_settings_mutation_busy(),
                    egui::Button::new("Save"),
                )
                .clicked()
            {
                let _ = service.start_save_api_settings();
            }
            if ui
                .add_enabled(
                    !service.is_api_settings_mutation_busy(),
                    egui::Button::new("Preview changes"),
                )
                .clicked()
            {
                let _ = service.preview_api_settings_diff();
            }
            if ui
                .add_enabled(
                    !service.is_api_settings_mutation_busy(),
                    egui::Button::new("Cancel"),
                )
                .clicked()
            {
                service.cancel_edit_api_settings();
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked() {
            let _ = service.begin_edit_api_settings();
        }
    });
}

fn show_view(ui: &mut Ui, settings: &crate::app::ApiSettings) {
    show_notice(ui);
    ui.add_space(8.0);

    egui::Grid::new("api_settings_view")
        .num_columns(2)
        .spacing([20.0, 6.0])
        .show(ui, |ui| {
            ui.label("tag");
            ui.label(settings.tag.as_deref().unwrap_or("(none)"));
            ui.end_row();
            ui.label("listen");
            ui.label(settings.listen.as_deref().unwrap_or("(none)"));
            ui.end_row();
            ui.label("services");
            ui.label(if settings.services.is_empty() {
                "(none)".to_owned()
            } else {
                settings.services.join(", ")
            });
            ui.end_row();
        });

    if let Some(source) = &settings.source_file {
        ui.add_space(12.0);
        ui.label(format!("Source file: {source}"));
    } else if !settings.section_present {
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "No api object in the remote configuration. Defaults are shown; the object is \
                 created only when you save changes.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }

    if settings.listen.is_none() {
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Without `listen`, the API is only reachable by routing an inbound to `tag` — \
                 this editor does not wire that routing rule automatically.",
            )
            .size(12.0)
            .color(Color32::from_rgb(160, 140, 80)),
        );
    }
}

fn show_edit_form(ui: &mut Ui, service: &mut ApplicationService) {
    show_notice(ui);
    ui.add_space(8.0);

    let Some(draft) = service.api_settings_draft_mut() else {
        return;
    };

    let mut tag = draft.tag.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        super::help_button(ui, "tag", HELP_TAG);
        ui.label("tag");
        if ui
            .add(
                TextEdit::singleline(&mut tag)
                    .desired_width(240.0)
                    .hint_text("api"),
            )
            .changed()
        {
            let trimmed = tag.trim();
            draft.tag = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });
    if draft.tag.is_none() {
        ui.label(
            RichText::new(
                "Required: Xray-core refuses to load the api object without a tag. Save stays \
                 blocked until it is set.",
            )
            .size(12.0)
            .color(Color32::from_rgb(200, 60, 60)),
        );
    }

    ui.add_space(8.0);
    let mut listen = draft.listen.clone().unwrap_or_default();
    ui.horizontal(|ui| {
        super::help_button(ui, "listen", HELP_LISTEN);
        ui.label("listen");
        if ui
            .add(
                TextEdit::singleline(&mut listen)
                    .desired_width(240.0)
                    .hint_text("127.0.0.1:8080"),
            )
            .changed()
        {
            let trimmed = listen.trim();
            draft.listen = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
        }
    });

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        super::help_button(ui, "services", HELP_SERVICES);
        ui.label("services (one per line)");
    });
    ui.horizontal_wrapped(|ui| {
        for known in KNOWN_API_SERVICES {
            let present = draft.services.iter().any(|s| s == known);
            let mut checked = present;
            if ui.checkbox(&mut checked, *known).changed() {
                if checked {
                    if !present {
                        draft.services.push((*known).to_owned());
                    }
                } else {
                    draft.services.retain(|s| s != known);
                }
            }
        }
    });
    persistent_list_text_edit(ui, "api_services", &mut draft.services, |ui, text| {
        ui.add(TextEdit::multiline(text).desired_rows(3))
    });
    ui.label(
        RichText::new(
            "Toggle known services above, or list them (including unrecognized/future values) \
             one per line here — both edit the same list.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}

fn show_notice(ui: &mut Ui) {
    ui.label(
        RichText::new(
            "This edits the configuration file's `api` object only. It does not enable a live \
             operations panel by itself — see the API Console page once `listen` is set and the \
             running Xray picks up the change (restart/reload).",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
}
