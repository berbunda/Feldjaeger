//! API Console page — live `xray api` gRPC operations (Roadmap §3:128).
//!
//! Every action here reaches into the **running** Xray process over the `api.listen` gRPC
//! endpoint (via `xray api <subcommand>`, executed on the remote host through the same SSH-exec
//! transport as `xray x25519`/`xray run -test`). Nothing here is written to the configuration
//! file, backed up, or validated — a live add/remove is gone on the next restart/reload. That is
//! a deliberate, user-confirmed departure from how every other page in this application behaves,
//! and every section below repeats it so it is never mistaken for a config-file change.
//!
//! Data flows exclusively through [`ApplicationService`]. This page never reads JSON, opens SSH,
//! or builds `xray` command-line arguments directly — [`crate::app`]'s `*_request` builders do
//! that.

use egui::{Color32, FontId, RichText, Ui};

use crate::app::{
    ApiCallRequest, ApiConsolePageState, ApplicationService, add_inbound_users_request,
    add_inbounds_request, add_outbounds_request, add_rules_request, balancer_info_request,
    balancer_override_request, inbound_user_count_request, inbound_users_request,
    list_inbounds_request, list_outbounds_request, list_rules_request,
    remove_inbound_users_request, remove_inbounds_request, remove_outbounds_request,
    remove_rules_request, restart_logger_request, source_ip_block_request,
};

use super::HelpText;

const WARN_COLOR: Color32 = Color32::from_rgb(210, 170, 40);
const ERROR_COLOR: Color32 = Color32::from_rgb(200, 60, 60);
const MUTED_COLOR: Color32 = Color32::from_rgb(140, 140, 140);

// ─── Help text (Roadmap §4.4) ─────────────────────────────────────────────────
//
// From Xray-core v26.9.30 (`main/commands/all/api/*.go`) and each command run against a live
// `xray.exe` 26.9.30 with HandlerService / RoutingService / LoggerService.

const HELP_API_SERVER: HelpText = HelpText::new(
    "Every button runs one xray api command on the server over SSH, against the address in \
     api.listen (an api object without listen, reachable only through routing, cannot be used \
     here). The call changes only the running Xray process: nothing is written to the \
     configuration file, there is no backup and no xray run -test, and everything is lost on the \
     next restart. To keep a change, make it on the Inbounds / Outbounds / Users / Routing \
     pages.\n\n\
     Required api.services: HandlerService — inbounds, outbounds, users; RoutingService — \
     routing rules, balancer, source IP block; LoggerService — logger. A call times out after \
     3 seconds. Some commands report a partial failure only in their output (\"Added 0 user(s)\", \
     \"Removed 0 user(s)\") — open \"Last call\" to read it.",
    "Каждая кнопка выполняет на сервере по SSH одну команду xray api по адресу из api.listen \
     (объект api без listen, доступный только через маршрутизацию, здесь не подходит). Вызов \
     меняет только работающий процесс Xray: в файл конфигурации ничего не пишется, нет ни \
     резервной копии, ни xray run -test, и всё пропадает при следующем перезапуске. Чтобы \
     изменение сохранилось, делайте его на страницах Inbounds / Outbounds / Users / Routing.\n\n\
     Нужные api.services: HandlerService — inbound, outbound, пользователи; RoutingService — \
     правила маршрутизации, балансировщик, блокировка по IP источника; LoggerService — логгер. \
     Тайм-аут вызова — 3 секунды. О частичной неудаче некоторые команды сообщают только в \
     выводе («Added 0 user(s)», «Removed 0 user(s)») — раскройте «Last call», чтобы его прочитать.",
);
const HELP_API_LOGGER: HelpText = HelpText::new(
    "xray api restartlogger — closes and reopens the access and error log files. After \
     logrotate moves a log file away (without copytruncate), Xray keeps writing into the moved \
     file until the logger is restarted; call this from logrotate's postrotate or by hand. \
     Needs LoggerService.",
    "xray api restartlogger — закрывает и заново открывает файлы журналов доступа и ошибок. \
     После того как logrotate переместил файл журнала (без copytruncate), Xray продолжает писать \
     в перемещённый файл, пока логгер не перезапущен; вызывайте это из postrotate logrotate или \
     вручную. Нужен LoggerService.",
);
const HELP_API_INBOUNDS: HelpText = HelpText::new(
    "List — xray api lsi. Add — xray api adi: the body is a configuration document \
     {\"inbounds\": [ … ]}; a bare inbound object is rejected (\"no valid inbound found\"). Each \
     inbound is built as at start-up (listen / port required, settings checked); a tag that \
     already exists is refused (\"existing tag found\"). Remove — xray api rmi with the tags; an \
     unknown tag fails. Needs HandlerService.",
    "List — xray api lsi. Add — xray api adi: тело — документ конфигурации \
     {\"inbounds\": [ … ]}; голый объект inbound отвергается («no valid inbound found»). Каждый \
     inbound собирается так же, как при запуске (нужны listen / port, settings проверяются); уже \
     существующий тег отвергается («existing tag found»). Remove — xray api rmi с тегами; \
     неизвестный тег — ошибка. Нужен HandlerService.",
);
const HELP_API_OUTBOUNDS: HelpText = HelpText::new(
    "List — xray api lso. Add — xray api ado: the body is {\"outbounds\": [ … ]}. An added \
     outbound does not become the default one (the first outbound of the configuration stays \
     default) — traffic reaches it only through routing rules or a balancer. Remove — xray api \
     rmo with the tags; connections matched by a rule that still points to a removed outbound \
     are closed (warning \"non existing outTag\"), not sent to the default outbound. Needs \
     HandlerService.",
    "List — xray api lso. Add — xray api ado: тело — {\"outbounds\": [ … ]}. Добавленный \
     outbound не становится outbound по умолчанию (им остаётся первый outbound конфигурации) — \
     трафик попадает в него только через правила маршрутизации или балансировщик. Remove — xray \
     api rmo с тегами; соединения, попавшие под правило, которое всё ещё указывает на \
     удалённый outbound, закрываются (предупреждение «non existing outTag»), а не уходят в \
     outbound по умолчанию. Нужен HandlerService.",
);
const HELP_API_USERS: HelpText = HelpText::new(
    "List users — xray api inbounduser -tag (optionally one -email); Count users — xray api \
     inboundusercount.\n\n\
     Add — xray api adu: the body is {\"inbounds\": [ { the whole inbound: tag, listen, port, \
     protocol, settings with clients / users } ]}. Xray builds that inbound (so it must be \
     valid as a whole), takes its users and adds them to the running inbound with the same tag. \
     Users without an email are skipped; protocols: VMess, VLESS, Trojan, Shadowsocks (also \
     2022 multi-user), Hysteria, MASQUE. A bare inbound object adds nothing and still \
     \"succeeds\" — check the output for \"Added N user(s)\".\n\n\
     Remove — xray api rmu -tag with the emails; an unknown email is reported in the output, the \
     call itself succeeds. Needs HandlerService.",
    "List users — xray api inbounduser -tag (можно указать один -email); Count users — xray api \
     inboundusercount.\n\n\
     Add — xray api adu: тело — {\"inbounds\": [ { весь inbound: tag, listen, port, protocol, \
     settings с clients / users } ]}. Xray собирает этот inbound (поэтому он должен быть \
     корректен целиком), берёт из него пользователей и добавляет их в работающий inbound с тем \
     же тегом. Пользователи без email пропускаются; протоколы: VMess, VLESS, Trojan, Shadowsocks \
     (в том числе 2022 multi-user), Hysteria, MASQUE. Голый объект inbound ничего не добавляет и \
     всё равно «успешен» — проверьте в выводе «Added N user(s)».\n\n\
     Remove — xray api rmu -tag с email; о неизвестном email сообщается в выводе, сам вызов \
     успешен. Нужен HandlerService.",
);
const HELP_API_RULES: HelpText = HelpText::new(
    "List — xray api lsrules (rule tag and target of every live rule). Add — xray api adrules: \
     the body is {\"routing\": {\"rules\": [ … ], \"balancers\": [ … ]}}. By default the rules \
     are appended to the end of the live list, so earlier rules still match first; a rule tag \
     that already exists is refused (\"duplicate ruleTag\").\n\n\
     \"Replace ALL\" drops every live rule and every balancer — including those from the \
     configuration — and installs only what the body contains (checked: balancers missing from \
     the body are gone afterwards).\n\n\
     Remove — xray api rmrules with rule tags; an unknown tag is silently ignored, a rule \
     without ruleTag cannot be removed. Needs RoutingService.",
    "List — xray api lsrules (тег и цель каждого живого правила). Add — xray api adrules: тело — \
     {\"routing\": {\"rules\": [ … ], \"balancers\": [ … ]}}. По умолчанию правила добавляются \
     в конец живого списка, поэтому более ранние правила по-прежнему срабатывают первыми; уже \
     существующий тег правила отвергается («duplicate ruleTag»).\n\n\
     «Replace ALL» удаляет все живые правила и все балансировщики — в том числе из \
     конфигурации — и ставит только то, что есть в теле (проверено: балансировщики, которых нет \
     в теле, после этого исчезают).\n\n\
     Remove — xray api rmrules с тегами правил; неизвестный тег молча игнорируется, правило без \
     ruleTag удалить нельзя. Нужен RoutingService.",
);
const HELP_API_BALANCER: HelpText = HelpText::new(
    "Balancer info — xray api bi with a balancer tag (required; there is no \"all balancers\" \
     form): the override, if any, and the outbounds the balancer currently selects from. Apply \
     override — xray api bo: the balancer always picks this outbound until the override is \
     removed or Xray restarts; Remove override returns it to its strategy. Needs RoutingService.",
    "Balancer info — xray api bi с тегом балансировщика (обязателен; формы «все балансировщики» \
     нет): переопределение, если оно есть, и outbound, из которых балансировщик сейчас выбирает. \
     Apply override — xray api bo: балансировщик всегда выбирает этот outbound, пока \
     переопределение не снято или Xray не перезапущен; Remove override возвращает его к своей \
     стратегии. Нужен RoutingService.",
);
const HELP_API_SIB: HelpText = HelpText::new(
    "xray api sib adds one routing rule — rule tag (default sourceIpBlock), inbound tag if set, \
     source = the listed IPs / CIDRs, outbound tag (usually a blackhole) — to the END of the live \
     rules: an earlier rule that matches the same traffic wins, and the block does not apply to \
     it.\n\n\
     A second Apply with the same rule tag fails (\"duplicate ruleTag\"); tick Reset to replace \
     the IP list — the rule with this tag is removed first, then the new one is added. Reset does \
     not lift the block: remove the rule tag in \"Routing rules (live)\" for that. At least one IP \
     is required. Needs RoutingService.",
    "xray api sib добавляет одно правило маршрутизации — тег правила (по умолчанию \
     sourceIpBlock), тег inbound, если задан, source = перечисленные IP / CIDR, тег outbound \
     (обычно blackhole) — в КОНЕЦ живых правил: более раннее правило, подходящее под тот же \
     трафик, срабатывает первым, и блокировка на него не действует.\n\n\
     Повторный Apply с тем же тегом правила завершается ошибкой («duplicate ruleTag»); отметьте \
     Reset, чтобы заменить список IP, — правило с этим тегом сначала удаляется, затем добавляется \
     новое. Reset не снимает блокировку: для этого удалите тег правила в «Routing rules (live)». \
     Нужен хотя бы один IP. Нужен RoutingService.",
);

/// Renders the API Console page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    super::show_help_dialog(ui);
    show_removal_dialog(ui, service);

    ui.heading("API Console");
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "Live operations against the running Xray process via its gRPC API. Changes here \
             are NOT written to the configuration file — they are lost on the next Xray \
             restart or reload.",
        )
        .size(12.0)
        .color(WARN_COLOR),
    );
    ui.add_space(8.0);

    let model = service.api_console_page_model();
    if model.state != ApiConsolePageState::Ready {
        show_state_message(ui, model.state);
        return;
    }

    ui.horizontal(|ui| {
        super::help_button(ui, "API Console", HELP_API_SERVER);
        ui.strong("API server:");
        ui.label(model.server_addr.as_deref().unwrap_or("?"));
    });
    ui.horizontal(|ui| {
        ui.strong("api.services:");
        if model.services.is_empty() {
            ui.label(RichText::new("(none listed)").color(MUTED_COLOR));
        } else {
            ui.label(model.services.join(", "));
        }
    });
    if let Some(warning) = &model.missing_services_warning {
        ui.label(RichText::new(warning.clone()).size(12.0).color(WARN_COLOR));
    }
    show_last_mutation_result(ui, service);
    ui.add_space(8.0);

    let mut form = api_console_form(ui);

    ui.separator();
    show_logger_section(ui, service);
    ui.separator();
    show_inbounds_section(ui, service, &mut form);
    ui.separator();
    show_outbounds_section(ui, service, &mut form);
    ui.separator();
    show_users_section(ui, service, &mut form);
    ui.separator();
    show_rules_section(ui, service, &mut form);
    ui.separator();
    show_balancer_section(ui, service, &mut form);
    ui.separator();
    show_sib_section(ui, service, &mut form);

    set_api_console_form(ui, form);
}

fn show_state_message(ui: &mut Ui, state: ApiConsolePageState) {
    let color = match state {
        ApiConsolePageState::ApiNotConfigured => WARN_COLOR,
        _ => ERROR_COLOR,
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_last_mutation_result(ui: &mut Ui, service: &ApplicationService) {
    let Some((label, result)) = service.api_mutation_result() else {
        return;
    };
    ui.add_space(4.0);
    match result {
        Ok(text) => {
            egui::CollapsingHeader::new(format!("Last call: {label} — succeeded"))
                .default_open(false)
                .show(ui, |ui| {
                    show_output_text(ui, text);
                });
        }
        Err(error) => {
            ui.label(
                RichText::new(format!("Last call: {label} — {}", error.message()))
                    .size(13.0)
                    .color(ERROR_COLOR),
            );
        }
    }
}

// ─── Shared form draft state (GUI-local; not app state — mirrors `RawJsonEditState`) ─────────

#[derive(Debug, Clone, Default)]
struct ApiConsoleForm {
    add_inbound_json: String,
    remove_inbound_tags: String,
    add_outbound_json: String,
    remove_outbound_tags: String,
    users_inbound_tag: String,
    users_email_filter: String,
    add_user_json: String,
    remove_user_tag: String,
    remove_user_emails: String,
    add_rules_json: String,
    /// Default `false` = `adrules -append`; replacing drops every live rule and balancer.
    add_rules_replace: bool,
    remove_rule_tags: String,
    balancer_info_tag: String,
    balancer_override_tag: String,
    balancer_override_outbound: String,
    sib_outbound: String,
    sib_inbound: String,
    sib_ruletag: String,
    sib_reset: bool,
    sib_ips: String,
}

fn api_console_form_id() -> egui::Id {
    egui::Id::new("api_console_form")
}

fn api_console_form(ui: &Ui) -> ApiConsoleForm {
    ui.ctx()
        .data(|d| d.get_temp::<ApiConsoleForm>(api_console_form_id()))
        .unwrap_or_default()
}

fn set_api_console_form(ui: &Ui, form: ApiConsoleForm) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(api_console_form_id(), form));
}

/// Splits a free-form list field (newline, comma, or space separated) into trimmed, non-empty
/// entries — used for tag/email/IP lists where a table editor would be overkill for a live,
/// non-persisted action.
fn parse_list(input: &str) -> Vec<String> {
    input
        .split(|c: char| c == '\n' || c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn non_empty(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

// ─── Output rendering ─────────────────────────────────────────────────────────

fn show_output_text(ui: &mut Ui, text: &str) {
    if text.is_empty() {
        ui.label(RichText::new("(empty output)").size(12.0).color(MUTED_COLOR));
        return;
    }
    egui::ScrollArea::vertical()
        .max_height(220.0)
        .id_salt(("api_console_output", text.len()))
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(RichText::new(text).font(FontId::monospace(12.0)))
                    .selectable(true)
                    .wrap_mode(egui::TextWrapMode::Extend),
            );
        });
}

fn show_read_result(ui: &mut Ui, service: &ApplicationService, request: &ApiCallRequest) {
    if service.is_running_api_read(request) {
        ui.label(RichText::new("Loading...").size(12.0).color(MUTED_COLOR));
        return;
    }
    match service.api_read_result(request) {
        None => {}
        Some(Ok(text)) => show_output_text(ui, text),
        Some(Err(error)) => {
            ui.label(
                RichText::new(error.message())
                    .size(12.0)
                    .color(ERROR_COLOR),
            );
        }
    }
}

fn read_button(ui: &mut Ui, service: &mut ApplicationService, text: &str, request: ApiCallRequest) {
    let busy = service.is_running_api_read(&request);
    if ui.add_enabled(!busy, egui::Button::new(text)).clicked() {
        let _ = service.start_api_read(request);
    }
}

fn mutation_error_slot(ui: &Ui) -> Option<String> {
    ui.ctx()
        .data(|d| d.get_temp::<String>(egui::Id::new("api_console_mutation_error")))
}

fn set_mutation_error(ui: &Ui, message: Option<String>) {
    ui.ctx().data_mut(|d| {
        let id = egui::Id::new("api_console_mutation_error");
        match message {
            Some(message) => {
                d.insert_temp(id, message);
            }
            None => {
                d.remove::<String>(id);
            }
        }
    });
}

fn submit_mutation_button(ui: &mut Ui, service: &mut ApplicationService, text: &str, request: ApiCallRequest) {
    let busy = service.is_running_api_mutation();
    if ui.add_enabled(!busy, egui::Button::new(text)).clicked() {
        if let Err(message) = service.start_api_mutation(request) {
            set_mutation_error(ui, Some(message));
        } else {
            set_mutation_error(ui, None);
        }
    }
    if let Some(error) = mutation_error_slot(ui) {
        ui.label(RichText::new(error).size(12.0).color(ERROR_COLOR));
    }
}

// ─── Removal confirm dialog (shared by inbounds/outbounds/users/rules) ───────

#[derive(Debug, Clone)]
struct PendingLiveRemoval {
    description: String,
    request: ApiCallRequest,
    error: Option<String>,
}

fn pending_removal_id() -> egui::Id {
    egui::Id::new("api_console_pending_removal")
}

fn pending_removal(ui: &Ui) -> Option<PendingLiveRemoval> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingLiveRemoval>(pending_removal_id()))
}

fn set_pending_removal(ui: &Ui, pending: PendingLiveRemoval) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_removal_id(), pending));
}

fn clear_pending_removal(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingLiveRemoval>(pending_removal_id()));
}

fn show_removal_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_removal(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Remove live object(s)")
        .collapsible(false)
        .resizable(true)
        .default_width(480.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(RichText::new(pending.description.clone()).size(14.0));
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "This changes only the running Xray process. Nothing is written to the \
                     configuration file, and the change is lost on the next restart or reload.",
                )
                .size(12.0)
                .color(WARN_COLOR),
            );
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(RichText::new(error.clone()).size(13.0).color(ERROR_COLOR));
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let busy = service.is_running_api_mutation();
                if ui
                    .add_enabled(!busy, egui::Button::new("Remove"))
                    .clicked()
                {
                    match service.start_api_mutation(pending.request.clone()) {
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
        clear_pending_removal(ui);
    } else {
        set_pending_removal(ui, pending);
    }
}

// ─── Logger ────────────────────────────────────────────────────────────────

fn show_logger_section(ui: &mut Ui, service: &mut ApplicationService) {
    egui::CollapsingHeader::new("Logger")
        .default_open(false)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                super::help_button(ui, "Logger", HELP_API_LOGGER);
                ui.label(
                    RichText::new(
                        "Restarts Xray's built-in logger — useful alongside external `logrotate`.",
                    )
                    .size(12.0)
                    .color(MUTED_COLOR),
                );
            });
            submit_mutation_button(ui, service, "Restart Logger", restart_logger_request());
        });
}

// ─── Inbounds (live) ──────────────────────────────────────────────────────

fn show_inbounds_section(ui: &mut Ui, service: &mut ApplicationService, form: &mut ApiConsoleForm) {
    egui::CollapsingHeader::new("Inbounds (live)")
        .default_open(false)
        .show(ui, |ui| {
            let list_request = list_inbounds_request();
            ui.horizontal(|ui| {
                super::help_button(ui, "Inbounds (live)", HELP_API_INBOUNDS);
                read_button(ui, service, "List live inbounds", list_request.clone());
            });
            show_read_result(ui, service, &list_request);

            ui.add_space(8.0);
            ui.label(RichText::new("Add — JSON body (`{\"inbounds\": [...]}`)").size(12.0));
            ui.add(
                egui::TextEdit::multiline(&mut form.add_inbound_json)
                    .desired_rows(5)
                    .desired_width(f32::INFINITY),
            );
            submit_mutation_button(
                ui,
                service,
                "Add inbound(s)",
                add_inbounds_request(form.add_inbound_json.as_bytes().to_vec()),
            );

            ui.add_space(8.0);
            ui.label(RichText::new("Remove — tags (comma/newline separated)").size(12.0));
            ui.add(egui::TextEdit::singleline(&mut form.remove_inbound_tags).desired_width(f32::INFINITY));
            let tags = parse_list(&form.remove_inbound_tags);
            if ui.add_enabled(!tags.is_empty(), egui::Button::new("Remove inbound(s)")).clicked() {
                open_removal_dialog(
                    ui,
                    format!("Remove {} live inbound(s): {}", tags.len(), tags.join(", ")),
                    remove_inbounds_request(tags),
                );
            }
        });
}

// ─── Outbounds (live) ─────────────────────────────────────────────────────

fn show_outbounds_section(ui: &mut Ui, service: &mut ApplicationService, form: &mut ApiConsoleForm) {
    egui::CollapsingHeader::new("Outbounds (live)")
        .default_open(false)
        .show(ui, |ui| {
            let list_request = list_outbounds_request();
            ui.horizontal(|ui| {
                super::help_button(ui, "Outbounds (live)", HELP_API_OUTBOUNDS);
                read_button(ui, service, "List live outbounds", list_request.clone());
            });
            show_read_result(ui, service, &list_request);

            ui.add_space(8.0);
            ui.label(RichText::new("Add — JSON body (`{\"outbounds\": [...]}`)").size(12.0));
            ui.add(
                egui::TextEdit::multiline(&mut form.add_outbound_json)
                    .desired_rows(5)
                    .desired_width(f32::INFINITY),
            );
            submit_mutation_button(
                ui,
                service,
                "Add outbound(s)",
                add_outbounds_request(form.add_outbound_json.as_bytes().to_vec()),
            );

            ui.add_space(8.0);
            ui.label(RichText::new("Remove — tags (comma/newline separated)").size(12.0));
            ui.add(egui::TextEdit::singleline(&mut form.remove_outbound_tags).desired_width(f32::INFINITY));
            let tags = parse_list(&form.remove_outbound_tags);
            if ui.add_enabled(!tags.is_empty(), egui::Button::new("Remove outbound(s)")).clicked() {
                open_removal_dialog(
                    ui,
                    format!("Remove {} live outbound(s): {}", tags.len(), tags.join(", ")),
                    remove_outbounds_request(tags),
                );
            }
        });
}

// ─── Inbound users (live) ─────────────────────────────────────────────────

fn show_users_section(ui: &mut Ui, service: &mut ApplicationService, form: &mut ApiConsoleForm) {
    egui::CollapsingHeader::new("Inbound users (live)")
        .default_open(false)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                super::help_button(ui, "Inbound users (live)", HELP_API_USERS);
                ui.label("Inbound tag:");
                ui.add(egui::TextEdit::singleline(&mut form.users_inbound_tag).desired_width(200.0));
            });
            ui.horizontal(|ui| {
                ui.label("Email filter (optional):");
                ui.add(egui::TextEdit::singleline(&mut form.users_email_filter).desired_width(200.0));
            });
            let tag = form.users_inbound_tag.trim().to_owned();
            ui.horizontal(|ui| {
                let list_request =
                    inbound_users_request(tag.clone(), non_empty(&form.users_email_filter));
                let count_request = inbound_user_count_request(tag.clone());
                let has_tag = !tag.is_empty();
                if ui
                    .add_enabled(
                        has_tag && !service.is_running_api_read(&list_request),
                        egui::Button::new("List users"),
                    )
                    .clicked()
                {
                    let _ = service.start_api_read(list_request);
                }
                if ui
                    .add_enabled(
                        has_tag && !service.is_running_api_read(&count_request),
                        egui::Button::new("Count users"),
                    )
                    .clicked()
                {
                    let _ = service.start_api_read(count_request);
                }
            });
            if !tag.is_empty() {
                show_read_result(
                    ui,
                    service,
                    &inbound_users_request(tag.clone(), non_empty(&form.users_email_filter)),
                );
                show_read_result(ui, service, &inbound_user_count_request(tag.clone()));
            }

            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "Add — JSON body (`{\"inbounds\": [...]}` with the whole inbound: tag, listen, \
                     port, protocol and `settings.clients`/`settings.users`; Xray adds its users \
                     that have an email to the running inbound with that tag)",
                )
                .size(12.0),
            );
            ui.add(
                egui::TextEdit::multiline(&mut form.add_user_json)
                    .desired_rows(5)
                    .desired_width(f32::INFINITY),
            );
            submit_mutation_button(
                ui,
                service,
                "Add user(s)",
                add_inbound_users_request(form.add_user_json.as_bytes().to_vec()),
            );

            ui.add_space(8.0);
            ui.label(RichText::new("Remove — inbound tag").size(12.0));
            ui.add(egui::TextEdit::singleline(&mut form.remove_user_tag).desired_width(200.0));
            ui.label(RichText::new("Emails (comma/newline separated)").size(12.0));
            ui.add(egui::TextEdit::singleline(&mut form.remove_user_emails).desired_width(f32::INFINITY));
            let remove_tag = form.remove_user_tag.trim().to_owned();
            let emails = parse_list(&form.remove_user_emails);
            if ui
                .add_enabled(
                    !remove_tag.is_empty() && !emails.is_empty(),
                    egui::Button::new("Remove user(s)"),
                )
                .clicked()
            {
                open_removal_dialog(
                    ui,
                    format!(
                        "Remove {} user(s) from live inbound «{}»: {}",
                        emails.len(),
                        remove_tag,
                        emails.join(", ")
                    ),
                    remove_inbound_users_request(remove_tag, emails),
                );
            }
        });
}

// ─── Routing rules (live) ─────────────────────────────────────────────────

fn show_rules_section(ui: &mut Ui, service: &mut ApplicationService, form: &mut ApiConsoleForm) {
    egui::CollapsingHeader::new("Routing rules (live)")
        .default_open(false)
        .show(ui, |ui| {
            let list_request = list_rules_request();
            ui.horizontal(|ui| {
                super::help_button(ui, "Routing rules (live)", HELP_API_RULES);
                read_button(ui, service, "List live routing rules", list_request.clone());
            });
            show_read_result(ui, service, &list_request);

            ui.add_space(8.0);
            ui.label(RichText::new("Add — JSON body (`{\"routing\": {\"rules\": [...]}}`)").size(12.0));
            ui.checkbox(
                &mut form.add_rules_replace,
                "Replace ALL live rules and balancers (instead of appending)",
            );
            if form.add_rules_replace {
                ui.label(
                    RichText::new(
                        "Every live routing rule and balancer, including those from the \
                         configuration, is dropped and only the body is installed.",
                    )
                    .size(12.0)
                    .color(WARN_COLOR),
                );
            }
            ui.add(
                egui::TextEdit::multiline(&mut form.add_rules_json)
                    .desired_rows(5)
                    .desired_width(f32::INFINITY),
            );
            submit_mutation_button(
                ui,
                service,
                "Add rule(s)",
                add_rules_request(form.add_rules_json.as_bytes().to_vec(), !form.add_rules_replace),
            );

            ui.add_space(8.0);
            ui.label(RichText::new("Remove — rule tags (comma/newline separated)").size(12.0));
            ui.add(egui::TextEdit::singleline(&mut form.remove_rule_tags).desired_width(f32::INFINITY));
            let rule_tags = parse_list(&form.remove_rule_tags);
            if ui.add_enabled(!rule_tags.is_empty(), egui::Button::new("Remove rule(s)")).clicked() {
                open_removal_dialog(
                    ui,
                    format!("Remove {} live routing rule(s): {}", rule_tags.len(), rule_tags.join(", ")),
                    remove_rules_request(rule_tags),
                );
            }
        });
}

// ─── Balancer ─────────────────────────────────────────────────────────────

fn show_balancer_section(ui: &mut Ui, service: &mut ApplicationService, form: &mut ApiConsoleForm) {
    egui::CollapsingHeader::new("Balancer")
        .default_open(false)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                super::help_button(ui, "Balancer", HELP_API_BALANCER);
                ui.label(
                    RichText::new("Requires `RoutingService` in `api.services`.")
                        .size(11.0)
                        .color(MUTED_COLOR),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Balancer tag:");
                ui.add(egui::TextEdit::singleline(&mut form.balancer_info_tag).desired_width(200.0));
            });
            let info_tag = form.balancer_info_tag.trim().to_owned();
            let info_request = balancer_info_request(info_tag.clone());
            if ui
                .add_enabled(
                    !info_tag.is_empty() && !service.is_running_api_read(&info_request),
                    egui::Button::new("Balancer info"),
                )
                .clicked()
            {
                let _ = service.start_api_read(info_request.clone());
            }
            if !info_tag.is_empty() {
                show_read_result(ui, service, &info_request);
            }

            ui.add_space(10.0);
            ui.label(RichText::new("Override live selection").size(12.0));
            ui.horizontal(|ui| {
                ui.label("Balancer tag:");
                ui.add(egui::TextEdit::singleline(&mut form.balancer_override_tag).desired_width(160.0));
            });
            ui.horizontal(|ui| {
                ui.label("Outbound tag:");
                ui.add(egui::TextEdit::singleline(&mut form.balancer_override_outbound).desired_width(160.0));
            });
            let balancer_tag = form.balancer_override_tag.trim().to_owned();
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!balancer_tag.is_empty() && !form.balancer_override_outbound.trim().is_empty(), egui::Button::new("Apply override"))
                    .clicked()
                {
                    let request = balancer_override_request(
                        balancer_tag.clone(),
                        non_empty(&form.balancer_override_outbound),
                        false,
                    );
                    let _ = service.start_api_mutation(request);
                }
                if ui.add_enabled(!balancer_tag.is_empty(), egui::Button::new("Remove override")).clicked() {
                    let request = balancer_override_request(balancer_tag.clone(), None, true);
                    let _ = service.start_api_mutation(request);
                }
            });
        });
}

// ─── Source IP block ──────────────────────────────────────────────────────

fn show_sib_section(ui: &mut Ui, service: &mut ApplicationService, form: &mut ApiConsoleForm) {
    egui::CollapsingHeader::new("Source IP block")
        .default_open(false)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                super::help_button(ui, "Source IP block", HELP_API_SIB);
                ui.label(
                    RichText::new(
                        "Emergency routing override for one or more source IPs. Requires \
                         `RoutingService` in `api.services`.",
                    )
                    .size(11.0)
                    .color(MUTED_COLOR),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Outbound tag (required):");
                ui.add(egui::TextEdit::singleline(&mut form.sib_outbound).desired_width(160.0));
            });
            ui.horizontal(|ui| {
                ui.label("Inbound tag (optional):");
                ui.add(egui::TextEdit::singleline(&mut form.sib_inbound).desired_width(160.0));
            });
            ui.horizontal(|ui| {
                ui.label("Rule tag (optional, default `sourceIpBlock`):");
                ui.add(egui::TextEdit::singleline(&mut form.sib_ruletag).desired_width(160.0));
            });
            ui.checkbox(
                &mut form.sib_reset,
                "Reset (replace the IP list of an existing rule with this tag)",
            );
            ui.label(RichText::new("Source IPs (comma/newline separated)").size(12.0));
            ui.add(egui::TextEdit::multiline(&mut form.sib_ips).desired_rows(3).desired_width(f32::INFINITY));

            let outbound = form.sib_outbound.trim().to_owned();
            let ips = parse_list(&form.sib_ips);
            // `sib` without IPs reads the literal `stdin:` as an address and fails — even with
            // Reset, before anything is removed (Xray 26.9.30).
            let can_apply = !outbound.is_empty() && !ips.is_empty();
            if ui.add_enabled(can_apply, egui::Button::new("Apply")).clicked() {
                let request = source_ip_block_request(
                    outbound,
                    non_empty(&form.sib_inbound),
                    non_empty(&form.sib_ruletag),
                    form.sib_reset,
                    ips,
                );
                let _ = service.start_api_mutation(request);
            }
        });
}

/// Opens the shared removal confirm dialog for `request` (used from within a
/// `CollapsingHeader::show` closure, where `ui` only borrows the outer `Ui`).
fn open_removal_dialog(ui: &mut Ui, description: String, request: ApiCallRequest) {
    set_pending_removal(
        ui,
        PendingLiveRemoval {
            description,
            request,
            error: None,
        },
    );
}
