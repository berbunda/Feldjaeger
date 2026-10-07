//! `streamSettings.sockopt` editor shared by every page with a `streamSettings` block
//! (Roadmap §2.6 stage 0.4; field set Roadmap §2.3:87).
//!
//! Direction-aware: a row is shown only when its key has an effect on that side of the
//! connection ([`sockopt_field_applies`]); fields without a row still round-trip losslessly
//! through [`SockoptDraft`]. The outbound-only rows (`dialerProxy`, `domainStrategy`, …,
//! `happyEyeballs`) are the Outbound Shell's "Socket options" section (Roadmap §4.2).

use std::str::FromStr;

use egui::{Color32, RichText, Ui};

use super::{HelpText, optional_string_combo, persistent_list_text_edit, resizable_multiline};
use crate::xray::{
    ADDRESS_PORT_STRATEGIES, DOMAIN_STRATEGIES, HappyEyeballsDraft, INBOUND_ONLY_SOCKOPT_FIELDS, SockoptDraft,
    StreamDirection, TCP_CONGESTION_PRESETS, TPROXY_MODES, TcpFastOpenDraft, sockopt_field_applies,
};

// Field help (Roadmap §3:124).
pub(crate) const HELP_SOCKOPT_TPROXY: HelpText = HelpText::new(
    "Enables OS-level transparent proxying via iptables (Linux only): \"redirect\" or \"tproxy\" \
     mode, or off. An alternative to Xray-level followRedirect — usually only one is needed.",
    "Включает прозрачное проксирование на уровне ОС через iptables (только Linux): режим \
     \"redirect\" или \"tproxy\", либо выключено. Альтернатива followRedirect на уровне Xray — \
     обычно нужно что-то одно.",
);

// Stream tab — Sockopt (streamSettings.sockopt; method-independent).
const HELP_SOCKOPT_TCP_FAST_OPEN: HelpText = HelpText::new(
    "Enables TCP Fast Open. `true`/`false`, or a positive integer to also set the accept queue \
     length. Availability depends on OS support.",
    "Включает TCP Fast Open. `true`/`false` или положительное целое — тогда оно задаёт ещё и \
     длину очереди приёма. Доступность зависит от поддержки в ОС.",
);
const HELP_SOCKOPT_ACCEPT_PROXY_PROTOCOL: HelpText = HelpText::new(
    "Inbound-only. When enabled, the peer must send a PROXY protocol v1/v2 header immediately \
     after the TCP connection is established, so Xray can see the real source IP/port.",
    "Только для inbound. Если включено, сразу после установки TCP-соединения клиент должен \
     отправить заголовок PROXY protocol v1/v2, чтобы Xray видел реальные IP и порт источника.",
);
const HELP_SOCKOPT_V6ONLY: HelpText = HelpText::new(
    "Linux only. When enabled, a listener bound to `::` accepts IPv6 connections only (no \
     IPv4-mapped addresses).",
    "Только Linux. Если включено, слушатель на `::` принимает только IPv6-подключения (без \
     IPv4-mapped адресов).",
);
const HELP_SOCKOPT_TCP_MAX_SEG: HelpText = HelpText::new(
    "Sets the maximum segment size (MSS) of TCP packets.",
    "Задаёт максимальный размер сегмента (MSS) TCP-пакетов.",
);
const HELP_SOCKOPT_TCP_KEEP_ALIVE_IDLE: HelpText = HelpText::new(
    "Seconds a TCP connection must be idle before Keep-Alive probes start.",
    "Сколько секунд TCP-соединение должно простаивать, прежде чем начнутся пробы Keep-Alive.",
);
const HELP_SOCKOPT_TCP_KEEP_ALIVE_INTERVAL: HelpText = HelpText::new(
    "Seconds between Keep-Alive probes once a TCP connection has entered the Keep-Alive state.",
    "Интервал в секундах между пробами Keep-Alive после того, как TCP-соединение перешло в \
     состояние Keep-Alive.",
);
const HELP_SOCKOPT_TCP_USER_TIMEOUT: HelpText = HelpText::new(
    "TCP user timeout in milliseconds (RFC 5482) — how long unacknowledged data may sit before \
     the connection is force-closed.",
    "TCP user timeout в миллисекундах (RFC 5482) — сколько неподтверждённые данные могут ждать, \
     прежде чем соединение будет принудительно закрыто.",
);
const HELP_SOCKOPT_TCP_WINDOW_CLAMP: HelpText = HelpText::new(
    "Caps the advertised TCP receive window size. The kernel uses the larger of this value and \
     its own minimum.",
    "Ограничивает объявляемый размер окна приёма TCP. Ядро использует большее из этого значения \
     и собственного минимума.",
);
const HELP_SOCKOPT_TRUSTED_X_FORWARDED_FOR: HelpText = HelpText::new(
    "For HTTP-based transports: source IP ranges allowed to set a trusted X-Forwarded-For \
     header (e.g. a reverse proxy in front of Xray). One CIDR/IP per line.",
    "Для транспортов на основе HTTP: диапазоны IP источников, которым разрешено задавать \
     доверенный заголовок X-Forwarded-For (например, обратный прокси перед Xray). Один CIDR или \
     IP на строку.",
);
const HELP_SOCKOPT_CUSTOM_SOCKOPT: HelpText = HelpText::new(
    "Escape hatch for socket options not exposed as dedicated fields above — a raw JSON array, \
     platform-specific (Linux/Windows/Darwin). Advanced use only.",
    "Обходной путь для параметров сокета, у которых нет отдельных полей выше, — JSON-массив как \
     есть, зависит от платформы (Linux/Windows/Darwin). Только для опытных пользователей.",
);

// Outbound-only fields (Roadmap §4.2), checked against `infra/conf/transport_sockopt.go` and
// `transport/internet/dialer.go` of XTLS/Xray-core.
const HELP_SOCKOPT_DIALER_PROXY: HelpText = HelpText::new(
    "Tag of another outbound that carries this outbound's connections — the way to chain \
     outbounds (e.g. through a local Tor SOCKS outbound); it replaced the removed proxySettings. \
     While it is set, sendThrough and happyEyeballs are not used.",
    "Тег другого outbound, через который идут подключения этого outbound, — способ строить \
     цепочки outbound (например, через локальный SOCKS outbound для Tor); заменил удалённый \
     proxySettings. Пока он задан, sendThrough и happyEyeballs не используются.",
);
const HELP_SOCKOPT_DOMAIN_STRATEGY: HelpText = HelpText::new(
    "How a domain target is resolved before dialing. AsIs (default): the operating system \
     resolves it. UseIP*: Xray's DNS, falling back to AsIs when the lookup fails. ForceIP*: \
     Xray's DNS, the connection fails when the lookup fails. v4 / v6 / v4v6 / v6v4 choose the \
     address family and its preference.",
    "Как разрешается доменный адрес назначения перед подключением. AsIs (по умолчанию) — \
     разрешает операционная система. UseIP* — DNS Xray, при неудачном запросе откат на AsIs. \
     ForceIP* — DNS Xray, при неудачном запросе подключение не устанавливается. v4 / v6 / v4v6 \
     / v6v4 выбирают семейство адресов и его приоритет.",
);
const HELP_SOCKOPT_INTERFACE: HelpText = HelpText::new(
    "Bind outgoing connections to this network interface (e.g. eth1, wg0). Linux and macOS.",
    "Привязать исходящие подключения к этому сетевому интерфейсу (например, eth1, wg0). Linux и \
     macOS.",
);
const HELP_SOCKOPT_MARK: HelpText = HelpText::new(
    "SO_MARK of outgoing packets, for policy routing with ip rule / iptables (Linux; needs \
     CAP_NET_ADMIN). A 32-bit integer.",
    "SO_MARK исходящих пакетов для маршрутизации по политикам с ip rule / iptables (Linux; \
     нужна CAP_NET_ADMIN). 32-битное целое.",
);
const HELP_SOCKOPT_TCP_CONGESTION: HelpText = HelpText::new(
    "TCP congestion control algorithm (Linux), e.g. bbr; the kernel must have it available.",
    "Алгоритм управления перегрузкой TCP (Linux), например bbr; он должен быть доступен в ядре.",
);
const HELP_SOCKOPT_TCP_MPTCP: HelpText = HelpText::new(
    "Multipath TCP (Linux 5.6+); the server has to support it too.",
    "Multipath TCP (Linux 5.6+); сервер тоже должен его поддерживать.",
);
const HELP_SOCKOPT_ADDRESS_PORT_STRATEGY: HelpText = HelpText::new(
    "Look up the real address and/or port of the target in DNS SRV or TXT records before \
     dialing. Freedom refuses it from Xray-core v26.9.8 (Save is blocked).",
    "Перед подключением искать реальный адрес и/или порт назначения в DNS-записях SRV или TXT. \
     Freedom отвергает этот параметр начиная с Xray-core v26.9.8 (Save блокируется).",
);
const HELP_SOCKOPT_HAPPY_EYEBALLS: HelpText = HelpText::new(
    "RFC 8305 connection racing over the resolved addresses. Used only for TCP, when \
     domainStrategy makes Xray resolve the domain (UseIP* / ForceIP*), the lookup returns at \
     least two addresses, tryDelayMs and maxConcurrentTry are above 0, and dialerProxy is empty.",
    "Параллельные попытки подключения к разрешённым адресам по RFC 8305. Используется только \
     для TCP, когда domainStrategy заставляет Xray разрешать домен (UseIP* / ForceIP*), запрос \
     вернул не меньше двух адресов, tryDelayMs и maxConcurrentTry больше 0, а dialerProxy пуст.",
);
const HELP_SOCKOPT_HE_TRY_DELAY: HelpText = HelpText::new(
    "Milliseconds before the next address is tried; 0 = racing off (default).",
    "Миллисекунды до попытки следующего адреса; 0 — параллельные попытки выключены (по \
     умолчанию).",
);
const HELP_SOCKOPT_HE_PRIORITIZE_IPV6: HelpText = HelpText::new(
    "Start with an IPv6 address (default: IPv4 first).",
    "Начинать с IPv6-адреса (по умолчанию сначала IPv4).",
);
const HELP_SOCKOPT_HE_INTERLEAVE: HelpText = HelpText::new(
    "How many addresses of one family are tried before switching to the other; default 1.",
    "Сколько адресов одного семейства пробуется перед переключением на другое; по умолчанию 1.",
);
const HELP_SOCKOPT_HE_MAX_CONCURRENT: HelpText = HelpText::new(
    "Maximum attempts in flight at once; default 4.",
    "Максимум одновременных попыток; по умолчанию 4.",
);

/// `sockopt.tproxy` combo (documented presets) + free-text fallback. Shared by the Stream tab's
/// full Sockopt editor and the Tunnel Protocol tab's narrow tproxy field (Roadmap §2.3:88).
/// Returns true when changed.
pub(crate) fn tproxy_combo_field(ui: &mut Ui, id_salt: &str, tproxy: &mut String) -> bool {
    let mut value = tproxy.clone();
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt(id_salt)
            .selected_text(if value.is_empty() {
                "(unset)"
            } else {
                value.as_str()
            })
            .show_ui(ui, |ui| {
                for &preset in TPROXY_MODES {
                    ui.selectable_value(&mut value, preset.to_owned(), preset);
                }
            });
        ui.text_edit_singleline(&mut value);
    });
    if value != *tproxy {
        *tproxy = value;
        true
    } else {
        false
    }
}

/// One-line explanation of which `sockopt` fields the editor offers for `direction`.
pub(crate) fn sockopt_scope_note(direction: StreamDirection) -> String {
    match direction {
        StreamDirection::Inbound => "streamSettings.sockopt — low-level socket options; applies \
             regardless of transport method. Outbound-only fields (dialerProxy, domainStrategy, \
             mark, …) are preserved but have no effect on a listener and are hidden."
            .to_owned(),
        StreamDirection::Outbound => format!(
            "streamSettings.sockopt — options of the socket this outbound dials; applies \
             regardless of transport method. Only changed keys are written. Inbound-only fields \
             ({}) have no effect on an outbound and are hidden.",
            INBOUND_ONLY_SOCKOPT_FIELDS.join(", ")
        ),
    }
}

/// Editor for `streamSettings.sockopt` (Roadmap §2.3:87, §4.2): the shared fields plus those that
/// apply to `direction` ([`sockopt_field_applies`]). `dialer_proxy_tags` are offered for
/// `dialerProxy` (outbound only). Returns true when any field changed.
pub(crate) fn show_sockopt_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    sockopt: &mut SockoptDraft,
    dialer_proxy_tags: &[String],
) -> bool {
    let applies = |field: &str| sockopt_field_applies(field, direction);
    let mut dirty = false;
    let mut tcp_max_seg = sockopt
        .tcp_max_seg
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mut tcp_keep_alive_idle = sockopt
        .tcp_keep_alive_idle
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mut tcp_keep_alive_interval = sockopt
        .tcp_keep_alive_interval
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mut tcp_user_timeout = sockopt
        .tcp_user_timeout
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mut tcp_window_clamp = sockopt
        .tcp_window_clamp
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mut custom_sockopt_text = sockopt
        .custom_sockopt
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
        .unwrap_or_default();

    egui::Grid::new("stream_sockopt_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            if applies("dialerProxy") {
                dirty |= show_outbound_only_rows(ui, sockopt, dialer_proxy_tags);
            }

            super::field_label(ui, "tproxy", HELP_SOCKOPT_TPROXY);
            if tproxy_combo_field(ui, "sockopt_tproxy", &mut sockopt.tproxy) {
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "tcpFastOpen", HELP_SOCKOPT_TCP_FAST_OPEN);
            if show_tcp_fast_open_edit(ui, &mut sockopt.tcp_fast_open) {
                dirty = true;
            }
            ui.end_row();

            if applies("acceptProxyProtocol") {
                super::field_label(ui, "acceptProxyProtocol", HELP_SOCKOPT_ACCEPT_PROXY_PROTOCOL);
                let mut accept_proxy_protocol = sockopt.accept_proxy_protocol;
                if ui.checkbox(&mut accept_proxy_protocol, "").changed() {
                    sockopt.accept_proxy_protocol = accept_proxy_protocol;
                    dirty = true;
                }
                ui.end_row();
            }

            if applies("V6Only") {
                super::field_label(ui, "V6Only", HELP_SOCKOPT_V6ONLY);
                let mut v6_only = sockopt.v6_only;
                if ui.checkbox(&mut v6_only, "").changed() {
                    sockopt.v6_only = v6_only;
                    dirty = true;
                }
                ui.end_row();
            }

            super::field_label(ui, "tcpMaxSeg", HELP_SOCKOPT_TCP_MAX_SEG);
            if ui
                .add(egui::TextEdit::singleline(&mut tcp_max_seg).hint_text("optional; integer"))
                .changed()
            {
                let trimmed = tcp_max_seg.trim();
                if trimmed.is_empty() {
                    sockopt.tcp_max_seg = None;
                    dirty = true;
                } else if let Ok(value) = trimmed.parse::<u64>() {
                    sockopt.tcp_max_seg = Some(value);
                    dirty = true;
                }
            }
            ui.end_row();

            super::field_label(ui, "tcpKeepAliveIdle (s)", HELP_SOCKOPT_TCP_KEEP_ALIVE_IDLE);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut tcp_keep_alive_idle)
                        .hint_text("optional; seconds"),
                )
                .changed()
            {
                let trimmed = tcp_keep_alive_idle.trim();
                if trimmed.is_empty() {
                    sockopt.tcp_keep_alive_idle = None;
                    dirty = true;
                } else if let Ok(value) = trimmed.parse::<i64>() {
                    sockopt.tcp_keep_alive_idle = Some(value);
                    dirty = true;
                }
            }
            ui.end_row();

            super::field_label(ui, "tcpKeepAliveInterval (s)", HELP_SOCKOPT_TCP_KEEP_ALIVE_INTERVAL);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut tcp_keep_alive_interval)
                        .hint_text("optional; seconds"),
                )
                .changed()
            {
                let trimmed = tcp_keep_alive_interval.trim();
                if trimmed.is_empty() {
                    sockopt.tcp_keep_alive_interval = None;
                    dirty = true;
                } else if let Ok(value) = trimmed.parse::<i64>() {
                    sockopt.tcp_keep_alive_interval = Some(value);
                    dirty = true;
                }
            }
            ui.end_row();

            super::field_label(ui, "tcpUserTimeout (ms)", HELP_SOCKOPT_TCP_USER_TIMEOUT);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut tcp_user_timeout)
                        .hint_text("optional; milliseconds"),
                )
                .changed()
            {
                let trimmed = tcp_user_timeout.trim();
                if trimmed.is_empty() {
                    sockopt.tcp_user_timeout = None;
                    dirty = true;
                } else if let Ok(value) = trimmed.parse::<u64>() {
                    sockopt.tcp_user_timeout = Some(value);
                    dirty = true;
                }
            }
            ui.end_row();

            super::field_label(ui, "tcpWindowClamp", HELP_SOCKOPT_TCP_WINDOW_CLAMP);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut tcp_window_clamp)
                        .hint_text("optional; integer"),
                )
                .changed()
            {
                let trimmed = tcp_window_clamp.trim();
                if trimmed.is_empty() {
                    sockopt.tcp_window_clamp = None;
                    dirty = true;
                } else if let Ok(value) = trimmed.parse::<u64>() {
                    sockopt.tcp_window_clamp = Some(value);
                    dirty = true;
                }
            }
            ui.end_row();

            if applies("trustedXForwardedFor") {
                super::field_label(
                    ui,
                    "trustedXForwardedFor (one per line)",
                    HELP_SOCKOPT_TRUSTED_X_FORWARDED_FOR,
                );
                if persistent_list_text_edit(
                    ui,
                    "sockopt_trusted_x_forwarded_for",
                    &mut sockopt.trusted_x_forwarded_for,
                    |ui, text| ui.add(egui::TextEdit::multiline(text).desired_rows(2)),
                ) {
                    dirty = true;
                }
                ui.end_row();
            }
        });

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        super::help_button(ui, "customSockopt", HELP_SOCKOPT_CUSTOM_SOCKOPT);
        ui.label(
            RichText::new("customSockopt (JSON array; advanced)")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    });
    if resizable_multiline(ui, &mut custom_sockopt_text, 3, "sockopt_custom_sockopt").changed() {
        let trimmed = custom_sockopt_text.trim();
        if trimmed.is_empty() {
            sockopt.custom_sockopt = None;
            dirty = true;
        } else if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
            && value.is_array()
        {
            sockopt.custom_sockopt = Some(value);
            dirty = true;
        }
    }

    if applies("happyEyeballs") {
        ui.add_space(6.0);
        dirty |= show_happy_eyeballs_edit(ui, &mut sockopt.happy_eyeballs);
    }

    dirty
}

/// Grid rows of the outbound-only fields (inside the editor's grid). Returns true when changed.
fn show_outbound_only_rows(ui: &mut Ui, sockopt: &mut SockoptDraft, dialer_proxy_tags: &[String]) -> bool {
    let mut dirty = false;
    let tags: Vec<&str> = dialer_proxy_tags.iter().map(String::as_str).collect();

    super::field_label(ui, "dialerProxy", HELP_SOCKOPT_DIALER_PROXY);
    ui.horizontal(|ui| {
        dirty |= optional_string_combo(ui, "sockopt_dialer_proxy", &mut sockopt.dialer_proxy, &tags);
    });
    ui.end_row();

    super::field_label(ui, "domainStrategy", HELP_SOCKOPT_DOMAIN_STRATEGY);
    ui.horizontal(|ui| {
        dirty |= optional_string_combo(ui, "sockopt_domain_strategy", &mut sockopt.domain_strategy, DOMAIN_STRATEGIES);
    });
    ui.end_row();

    super::field_label(ui, "interface", HELP_SOCKOPT_INTERFACE);
    dirty |= ui
        .add(egui::TextEdit::singleline(&mut sockopt.interface).hint_text("optional; e.g. eth1"))
        .changed();
    ui.end_row();

    super::field_label(ui, "mark", HELP_SOCKOPT_MARK);
    dirty |= optional_number_field(ui, &mut sockopt.mark, "optional; integer");
    ui.end_row();

    super::field_label(ui, "tcpCongestion", HELP_SOCKOPT_TCP_CONGESTION);
    ui.horizontal(|ui| {
        dirty |= optional_string_combo(ui, "sockopt_tcp_congestion", &mut sockopt.tcp_congestion, TCP_CONGESTION_PRESETS);
    });
    ui.end_row();

    super::field_label(ui, "tcpMptcp", HELP_SOCKOPT_TCP_MPTCP);
    dirty |= ui.checkbox(&mut sockopt.tcp_mptcp, "").changed();
    ui.end_row();

    super::field_label(ui, "addressPortStrategy", HELP_SOCKOPT_ADDRESS_PORT_STRATEGY);
    ui.horizontal(|ui| {
        dirty |= optional_string_combo(
            ui,
            "sockopt_address_port_strategy",
            &mut sockopt.address_port_strategy,
            ADDRESS_PORT_STRATEGIES,
        );
    });
    ui.end_row();
    dirty
}

/// `sockopt.happyEyeballs` (outbound only): a checkbox for the object, then its four fields.
/// Absent keys take the core defaults (`tryDelayMs` 0, `interleave` 1, `maxConcurrentTry` 4).
fn show_happy_eyeballs_edit(ui: &mut Ui, happy_eyeballs: &mut Option<HappyEyeballsDraft>) -> bool {
    let mut dirty = false;
    let mut enabled = happy_eyeballs.is_some();
    ui.horizontal(|ui| {
        super::help_button(ui, "happyEyeballs", HELP_SOCKOPT_HAPPY_EYEBALLS);
        if ui.checkbox(&mut enabled, "happyEyeballs").changed() {
            *happy_eyeballs = enabled.then(HappyEyeballsDraft::default);
            dirty = true;
        }
    });
    let Some(draft) = happy_eyeballs else {
        return dirty;
    };
    egui::Grid::new("stream_sockopt_happy_eyeballs_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "tryDelayMs", HELP_SOCKOPT_HE_TRY_DELAY);
            dirty |= optional_number_field(ui, &mut draft.try_delay_ms, "optional; ms, e.g. 250");
            ui.end_row();

            super::field_label(ui, "prioritizeIPv6", HELP_SOCKOPT_HE_PRIORITIZE_IPV6);
            let mut prioritize = draft.prioritize_ipv6.unwrap_or(false);
            if ui.checkbox(&mut prioritize, "").changed() {
                draft.prioritize_ipv6 = prioritize.then_some(true);
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "interleave", HELP_SOCKOPT_HE_INTERLEAVE);
            dirty |= optional_number_field(ui, &mut draft.interleave, "optional; default 1");
            ui.end_row();

            super::field_label(ui, "maxConcurrentTry", HELP_SOCKOPT_HE_MAX_CONCURRENT);
            dirty |= optional_number_field(ui, &mut draft.max_concurrent_try, "optional; default 4");
            ui.end_row();
        });
    dirty
}

/// Single-line editor for an optional number: empty = `None`; text that does not parse leaves the
/// value unchanged. Returns true when the value changed.
fn optional_number_field<T: Copy + PartialEq + FromStr + ToString>(
    ui: &mut Ui,
    value: &mut Option<T>,
    hint: &str,
) -> bool {
    let mut text = value.map(|v| v.to_string()).unwrap_or_default();
    if !ui.add(egui::TextEdit::singleline(&mut text).hint_text(hint)).changed() {
        return false;
    }
    let trimmed = text.trim();
    let parsed = if trimmed.is_empty() {
        None
    } else {
        match trimmed.parse::<T>() {
            Ok(parsed) => Some(parsed),
            Err(_) => return false,
        }
    };
    if parsed == *value {
        return false;
    }
    *value = parsed;
    true
}

/// `sockopt.tcpFastOpen` editor: `bool | number` union — unset / false / true / custom backlog.
fn show_tcp_fast_open_edit(ui: &mut Ui, value: &mut TcpFastOpenDraft) -> bool {
    let mut dirty = false;
    let label = match *value {
        TcpFastOpenDraft::Unset => "(unset)",
        TcpFastOpenDraft::Bool(false) => "false",
        TcpFastOpenDraft::Bool(true) => "true",
        TcpFastOpenDraft::Backlog(_) => "custom backlog",
    };
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt("sockopt_tcp_fast_open")
            .selected_text(label)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(matches!(value, TcpFastOpenDraft::Unset), "(unset)")
                    .clicked()
                    && !matches!(value, TcpFastOpenDraft::Unset)
                {
                    *value = TcpFastOpenDraft::Unset;
                    dirty = true;
                }
                if ui
                    .selectable_label(matches!(value, TcpFastOpenDraft::Bool(false)), "false")
                    .clicked()
                    && !matches!(value, TcpFastOpenDraft::Bool(false))
                {
                    *value = TcpFastOpenDraft::Bool(false);
                    dirty = true;
                }
                if ui
                    .selectable_label(matches!(value, TcpFastOpenDraft::Bool(true)), "true")
                    .clicked()
                    && !matches!(value, TcpFastOpenDraft::Bool(true))
                {
                    *value = TcpFastOpenDraft::Bool(true);
                    dirty = true;
                }
                if ui
                    .selectable_label(
                        matches!(value, TcpFastOpenDraft::Backlog(_)),
                        "custom backlog",
                    )
                    .clicked()
                    && !matches!(value, TcpFastOpenDraft::Backlog(_))
                {
                    *value = TcpFastOpenDraft::Backlog(0);
                    dirty = true;
                }
            });
        if let TcpFastOpenDraft::Backlog(n) = value {
            let mut text = n.to_string();
            if ui
                .add(egui::TextEdit::singleline(&mut text).desired_width(80.0))
                .changed()
                && let Ok(parsed) = text.trim().parse::<u64>()
            {
                *value = TcpFastOpenDraft::Backlog(parsed);
                dirty = true;
            }
        }
    });
    dirty
}

/// Compact read-only summary of populated `sockopt` fields — the same field set as
/// [`show_sockopt_edit`] offers for `direction`.
pub(crate) fn show_sockopt_readonly(ui: &mut Ui, direction: StreamDirection, sockopt: &SockoptDraft) {
    let applies = |field: &str| sockopt_field_applies(field, direction);
    let mut any = false;
    egui::Grid::new("stream_sockopt_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            if !sockopt.tproxy.is_empty() {
                ui.label("tproxy");
                ui.label(sockopt.tproxy.as_str());
                ui.end_row();
                any = true;
            }
            match sockopt.tcp_fast_open {
                TcpFastOpenDraft::Unset => {}
                TcpFastOpenDraft::Bool(b) => {
                    ui.label("tcpFastOpen");
                    ui.label(if b { "true" } else { "false" });
                    ui.end_row();
                    any = true;
                }
                TcpFastOpenDraft::Backlog(n) => {
                    ui.label("tcpFastOpen");
                    ui.label(format!("backlog {n}"));
                    ui.end_row();
                    any = true;
                }
            }
            if sockopt.accept_proxy_protocol && applies("acceptProxyProtocol") {
                ui.label("acceptProxyProtocol");
                ui.label("true");
                ui.end_row();
                any = true;
            }
            if sockopt.v6_only && applies("V6Only") {
                ui.label("V6Only");
                ui.label("true");
                ui.end_row();
                any = true;
            }
            if let Some(seg) = sockopt.tcp_max_seg {
                ui.label("tcpMaxSeg");
                ui.label(seg.to_string());
                ui.end_row();
                any = true;
            }
            if let Some(idle) = sockopt.tcp_keep_alive_idle {
                ui.label("tcpKeepAliveIdle");
                ui.label(format!("{idle} s"));
                ui.end_row();
                any = true;
            }
            if let Some(interval) = sockopt.tcp_keep_alive_interval {
                ui.label("tcpKeepAliveInterval");
                ui.label(format!("{interval} s"));
                ui.end_row();
                any = true;
            }
            if let Some(timeout) = sockopt.tcp_user_timeout {
                ui.label("tcpUserTimeout");
                ui.label(format!("{timeout} ms"));
                ui.end_row();
                any = true;
            }
            if let Some(clamp) = sockopt.tcp_window_clamp {
                ui.label("tcpWindowClamp");
                ui.label(clamp.to_string());
                ui.end_row();
                any = true;
            }
            if !sockopt.trusted_x_forwarded_for.is_empty() && applies("trustedXForwardedFor") {
                ui.label("trustedXForwardedFor");
                ui.label(sockopt.trusted_x_forwarded_for.join(", "));
                ui.end_row();
                any = true;
            }
            if sockopt.custom_sockopt.is_some() {
                ui.label("customSockopt");
                ui.label("set (see Edit / Preview diff)");
                ui.end_row();
                any = true;
            }
        });
    if !any {
        ui.label(
            RichText::new("No sockopt fields set.")
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}
