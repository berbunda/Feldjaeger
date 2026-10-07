//! Outbound Stream / Security editor (Roadmap §4.2): the client side of `streamSettings` —
//! transport (RAW, XHTTP, gRPC, WebSocket, HTTPUpgrade, mKCP, Hysteria) and client TLS /
//! REALITY — plus FinalMask and `quicParams` through the shared direction-aware editors with
//! [`StreamDirection::Outbound`] (Roadmap §2.6 stage 7.1). Shown in the Outbound Shell for
//! protocols that dial through a transport.
//!
//! Edits only the session draft ([`crate::app::OutboundEditorSession::stream`]); every change sets
//! `stream.write`, and Save writes `streamSettings` only then. Data flows through
//! [`ApplicationService`]; this page never reads JSON or opens SSH.

use egui::{Color32, RichText, Ui};

use crate::app::{ApplicationService, InboundSecurityMode, allowed_security_modes, coerce_security_mode_for_transport};
use crate::gui::pages::inbounds::{show_kcp_settings_edit, show_xhttp_settings_edit, string_tag_multi_select};
use crate::gui::pages::stream_finalmask::{
    show_finalmask_edit, show_foreign_finalmask_notice, show_quic_params_edit,
};
use crate::gui::pages::stream_sockopt::{show_sockopt_edit, sockopt_scope_note};
use crate::gui::pages::{HelpText, optional_string_combo, resizable_multiline};
use crate::xray::{
    ALPN_PRESETS, CURVE_PRESETS, DialerProxyProblem, FINGERPRINT_PRESETS, FinalMaskChain,
    HYSTERIA_TRANSPORT_VERSION, OutboundStreamDraft, OutboundTransport, SockoptDraft, StreamDirection,
    TLS_VERSION_PRESETS, outbound_transports_for_protocol,
};

const HELP_TRANSPORT: HelpText = HelpText::new(
    "streamSettings.network — how this outbound reaches the server. It must match the transport \
     of the server's inbound. Hysteria uses its own transport only.",
    "streamSettings.network — как этот outbound связывается с сервером. Должен совпадать с \
     транспортом inbound на сервере. Hysteria использует только собственный транспорт.",
);
const HELP_GRPC_AUTHORITY: HelpText = HelpText::new(
    "HTTP/2 :authority sent to the server; empty = the outbound's address.",
    "HTTP/2 :authority, отправляемый серверу; пусто — адрес outbound.",
);
const HELP_GRPC_SERVICE_NAME: HelpText = HelpText::new(
    "gRPC service name; must match the server's serviceName.",
    "Имя сервиса gRPC; должно совпадать с serviceName сервера.",
);
const HELP_GRPC_MULTI_MODE: HelpText = HelpText::new(
    "Multi mode (experimental); must match the server.",
    "Режим multi (экспериментальный); должен совпадать с сервером.",
);
const HELP_GRPC_USER_AGENT: HelpText = HelpText::new(
    "User-Agent header; empty = the gRPC library default.",
    "Заголовок User-Agent; пусто — значение библиотеки gRPC по умолчанию.",
);
const HELP_GRPC_IDLE_TIMEOUT: HelpText = HelpText::new(
    "idle_timeout — seconds without traffic before a health check ping; empty or ≤ 0 = off \
     (values below 10 are raised to 10 by gRPC).",
    "idle_timeout — сколько секунд без трафика проходит до проверочного ping; пусто или ≤ 0 — \
     выключено (значения меньше 10 gRPC поднимает до 10).",
);
const HELP_GRPC_HEALTH_CHECK_TIMEOUT: HelpText = HelpText::new(
    "health_check_timeout — seconds to wait for the ping answer; empty = 20.",
    "health_check_timeout — сколько секунд ждать ответа на ping; пусто — 20.",
);
const HELP_GRPC_PERMIT_WITHOUT_STREAM: HelpText = HelpText::new(
    "Send health check pings even without active streams.",
    "Отправлять проверочные ping даже без активных потоков.",
);
const HELP_GRPC_INITIAL_WINDOWS_SIZE: HelpText = HelpText::new(
    "initial_windows_size — HTTP/2 stream window in bytes; empty or 0 = default. 65536 helps \
     with some CDNs (e.g. Cloudflare).",
    "initial_windows_size — окно потока HTTP/2 в байтах; пусто или 0 — по умолчанию. 65536 \
     помогает с некоторыми CDN (например, Cloudflare).",
);
const HELP_WS_HOST: HelpText = HelpText::new(
    "Host header sent in the WebSocket handshake; empty = tlsSettings.serverName, then the address.",
    "Заголовок Host в рукопожатии WebSocket; пусто — tlsSettings.serverName, затем адрес.",
);
const HELP_WS_PATH: HelpText = HelpText::new(
    "HTTP path of the WebSocket endpoint; must match the server.",
    "HTTP-путь конечной точки WebSocket; должен совпадать с сервером.",
);
const HELP_WS_ED: HelpText = HelpText::new(
    "Early Data: up to this many bytes of the first payload ride in the handshake (written as \
     path?ed=N). The server must allow it too.",
    "Early Data: до стольких байт первых данных передаются в рукопожатии (записывается как \
     path?ed=N). Сервер тоже должен это разрешать.",
);
const HELP_WS_HEARTBEAT: HelpText = HelpText::new(
    "heartbeatPeriod — seconds between ping frames; empty = off.",
    "heartbeatPeriod — интервал в секундах между ping-кадрами; пусто — выключено.",
);
const HELP_HEADERS: HelpText = HelpText::new(
    "Extra HTTP headers of the handshake. Put the Host into the host field: a Host header is \
     deprecated on WebSocket and refused on HTTPUpgrade.",
    "Дополнительные HTTP-заголовки рукопожатия. Host указывайте в поле host: заголовок Host \
     устарел для WebSocket и отвергается для HTTPUpgrade.",
);
const HELP_HU_HOST: HelpText = HelpText::new(
    "Host header of the HTTP Upgrade request; empty = serverName, then the address.",
    "Заголовок Host запроса HTTP Upgrade; пусто — serverName, затем адрес.",
);
const HELP_HU_PATH: HelpText = HelpText::new(
    "HTTP path of the upgrade request; must match the server.",
    "HTTP-путь запроса upgrade; должен совпадать с сервером.",
);
const HELP_HY_AUTH: HelpText = HelpText::new(
    "Hysteria authentication — the auth of one of the server's users.",
    "Аутентификация Hysteria — auth одного из пользователей сервера.",
);
const HELP_HY_UDP_IDLE: HelpText = HelpText::new(
    "udpIdleTimeout — seconds a UDP session may stay idle (2–600); empty = 60.",
    "udpIdleTimeout — сколько секунд UDP-сессия может простаивать (2–600); пусто — 60.",
);
const HELP_SECURITY: HelpText = HelpText::new(
    "streamSettings.security of the client: TLS, or REALITY towards a REALITY server. REALITY \
     only works over RAW, XHTTP and gRPC; Hysteria needs TLS.",
    "streamSettings.security клиента: TLS или REALITY для REALITY-сервера. REALITY работает \
     только поверх RAW, XHTTP и gRPC; Hysteria требует TLS.",
);
const HELP_TLS_SERVER_NAME: HelpText = HelpText::new(
    "SNI sent to the server and the name its certificate must carry; empty = the address.",
    "SNI, отправляемый серверу, и имя, которое должно быть в его сертификате; пусто — адрес.",
);
const HELP_TLS_ALPN: HelpText = HelpText::new(
    "ALPN offered in the handshake (e.g. h2, http/1.1; exactly h3 for XHTTP/3).",
    "ALPN, предлагаемый при рукопожатии (например, h2, http/1.1; для XHTTP/3 — ровно h3).",
);
const HELP_TLS_FINGERPRINT: HelpText = HelpText::new(
    "uTLS ClientHello to imitate; empty = chrome. unsafe = Go's own hello (not recommended).",
    "uTLS ClientHello, который нужно имитировать; пусто — chrome. unsafe — собственный hello Go \
     (не рекомендуется).",
);
const HELP_TLS_PINNED: HelpText = HelpText::new(
    "pinnedPeerCertSha256 — SHA-256 of the server's certificate (hex, colons allowed, several \
     separated by commas). Pinning replaces the removed allowInsecure for self-signed servers.",
    "pinnedPeerCertSha256 — SHA-256 сертификата сервера (hex, двоеточия допускаются, несколько \
     через запятую). Закрепление заменяет удалённый allowInsecure для серверов с \
     самоподписанным сертификатом.",
);
const HELP_TLS_VERIFY_BY_NAME: HelpText = HelpText::new(
    "verifyPeerCertByName — names accepted in the server certificate instead of serverName \
     (comma-separated).",
    "verifyPeerCertByName — имена, принимаемые в сертификате сервера вместо serverName (через \
     запятую).",
);
const HELP_TLS_ECH: HelpText = HelpText::new(
    "echConfigList — the server's Encrypted Client Hello config (base64), or a DNS source as \
     documented by Xray.",
    "echConfigList — конфигурация Encrypted Client Hello сервера (base64) или DNS-источник, как \
     описано в документации Xray.",
);
const HELP_TLS_VERSION: HelpText = HelpText::new(
    "TLS version bound; empty = Xray default.",
    "Граница версии TLS; пусто — значение Xray по умолчанию.",
);
const HELP_TLS_CIPHERS: HelpText = HelpText::new(
    "cipherSuites — colon-separated list; empty = Go default.",
    "cipherSuites — список через двоеточие; пусто — значение Go по умолчанию.",
);
const HELP_TLS_CURVES: HelpText = HelpText::new(
    "curvePreferences — key exchange groups, in order.",
    "curvePreferences — группы обмена ключами, по порядку.",
);
const HELP_TLS_DISABLE_SYSTEM_ROOT: HelpText = HelpText::new(
    "Do not trust the operating system's CA store.",
    "Не доверять хранилищу корневых сертификатов операционной системы.",
);
const HELP_TLS_SESSION_RESUMPTION: HelpText = HelpText::new(
    "Allow TLS session resumption.",
    "Разрешить возобновление TLS-сессий.",
);
const HELP_TLS_MASTER_KEY_LOG: HelpText = HelpText::new(
    "Path of a TLS key log file (debugging only).",
    "Путь к файлу журнала ключей TLS (только для отладки).",
);
const HELP_REALITY_SERVER_NAME: HelpText = HelpText::new(
    "One of the server's serverNames.",
    "Одно из serverNames сервера.",
);
const HELP_REALITY_FINGERPRINT: HelpText = HelpText::new(
    "uTLS ClientHello to imitate; empty = chrome. REALITY refuses unsafe and hellogolang.",
    "uTLS ClientHello, который нужно имитировать; пусто — chrome. REALITY отвергает unsafe и \
     hellogolang.",
);
const HELP_REALITY_PUBLIC_KEY: HelpText = HelpText::new(
    "The server's X25519 public key (`xray x25519` prints it next to the private key), base64url.",
    "Открытый ключ X25519 сервера (`xray x25519` выводит его рядом с закрытым), base64url.",
);
const HELP_REALITY_SHORT_ID: HelpText = HelpText::new(
    "One of the server's shortIds (hex, up to 16 digits; may be empty if the server lists \"\").",
    "Одно из shortIds сервера (hex, до 16 цифр; может быть пустым, если сервер указывает \"\").",
);
const HELP_REALITY_SPIDER_X: HelpText = HelpText::new(
    "Initial path of the crawler that imitates a browser; empty = /.",
    "Начальный путь краулера, имитирующего браузер; пусто — /.",
);
const HELP_REALITY_MLDSA65_VERIFY: HelpText = HelpText::new(
    "The server's ML-DSA-65 public key (from mldsa65Seed); empty = no post-quantum signature check.",
    "Открытый ключ ML-DSA-65 сервера (из mldsa65Seed); пусто — без проверки постквантовой \
     подписи.",
);
const HELP_REALITY_SHOW: HelpText = HelpText::new(
    "Debug output of the REALITY handshake.",
    "Отладочный вывод рукопожатия REALITY.",
);

const GREY: Color32 = Color32::from_rgb(140, 140, 140);
const AMBER: Color32 = Color32::from_rgb(210, 170, 40);
const RED: Color32 = Color32::from_rgb(220, 80, 80);

/// Stream + Security sections of the Outbound Shell for `protocol`.
pub(super) fn show_outbound_stream_edit(ui: &mut Ui, service: &mut ApplicationService, protocol: &str) {
    // The outbound's warnings except `proxySettings` (shown in General): the Protocol section of a
    // transport protocol shows none, and the plaintext one (`settings.address`) is fixed by
    // choosing a security here.
    let warnings = super::outbounds::outbound_editor_warnings_below_general(service);
    let vision_hint = vision_hint(service);

    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let stream = &mut session.stream;

    ui.strong("Stream (streamSettings)");
    super::outbounds::show_outbound_compatibility_warnings(ui, &warnings);

    if let Some(other) = stream.other_transport.clone() {
        ui.label(
            RichText::new(format!(
                "Transport `{other}` is not editable here; streamSettings is preserved on save \
                 (Raw JSON remains available)."
            ))
            .color(GREY),
        );
        return;
    }

    show_transport_selector(ui, stream, protocol);
    ui.add_space(6.0);
    if show_transport_fields(ui, stream) {
        stream.write = true;
    }

    ui.add_space(8.0);
    ui.separator();
    ui.strong("Security");
    show_security_edit(ui, stream, protocol);
    if let Some(hint) = vision_hint {
        ui.label(RichText::new(hint).size(12.0).color(AMBER));
    }

    ui.add_space(8.0);
    ui.separator();
    let migrate_udp_hop = show_outbound_finalmask_edit(ui, stream);
    // Needs the service (installed core, diff preview), so it runs after the session borrow.
    if migrate_udp_hop {
        let message = match service.migrate_outbound_legacy_udp_hop() {
            Ok(message) => message,
            Err(error) => format!("udpHop migration refused: {error}"),
        };
        service.show_status_message(message);
    }
}

/// Socket options (`streamSettings.sockopt`) of the outbound — every protocol that dials
/// (Roadmap §4.2, "Outbound `sockopt` editor"). Only the keys the user changes are written.
pub(super) fn show_outbound_sockopt_edit(ui: &mut Ui, service: &mut ApplicationService) {
    // Computed before the mutable session borrow (a frame behind the typing, which is fine).
    let tags = service.outbound_dialer_proxy_candidates();
    let problem = service.outbound_dialer_proxy_problem();
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let stream = &mut session.stream;

    egui::CollapsingHeader::new(RichText::new("Socket options (streamSettings.sockopt)").strong())
        .id_salt("outbound_sockopt_section")
        .default_open(stream.sockopt != SockoptDraft::default())
        .show(ui, |ui| {
            if stream.sockopt_foreign {
                ui.label(
                    RichText::new(
                        "streamSettings.sockopt (or streamSettings) is not a JSON object; it is \
                         preserved on save — fix it on the Raw JSON tab to edit socket options.",
                    )
                    .color(GREY),
                );
                return;
            }
            ui.label(RichText::new(sockopt_scope_note(StreamDirection::Outbound)).size(12.0).color(GREY));
            ui.add_space(4.0);
            show_sockopt_edit(ui, StreamDirection::Outbound, &mut stream.sockopt, &tags);
            if let Some(problem) = problem {
                let (text, color) = dialer_proxy_problem_text(&problem);
                ui.label(RichText::new(text).size(12.0).color(color));
            }
        });
}

/// Hint under `dialerProxy` for a [`DialerProxyProblem`].
fn dialer_proxy_problem_text(problem: &DialerProxyProblem) -> (String, Color32) {
    match problem {
        DialerProxyProblem::SelfReference => (
            "dialerProxy is this outbound's own tag — Save refuses it (every connection would loop \
             back into this outbound)."
                .to_owned(),
            RED,
        ),
        DialerProxyProblem::UnknownTag => (
            "No outbound has this tag. Xray-core starts, but every connection of this outbound \
             fails (\"there is no outbound handler for dialerProxy\")."
                .to_owned(),
            AMBER,
        ),
        DialerProxyProblem::Cycle(path) => (
            format!(
                "dialerProxy chain loops back here: {}. Xray-core starts, but connections never \
                 leave the loop.",
                path.join(" → ")
            ),
            AMBER,
        ),
    }
}

/// FinalMask chains and `quicParams` of the outbound (client side). Returns true when "Migrate
/// udpHop" was clicked.
fn show_outbound_finalmask_edit(ui: &mut Ui, stream: &mut OutboundStreamDraft) -> bool {
    if stream.finalmask_foreign {
        show_foreign_finalmask_notice(ui);
        return false;
    }
    let mut migrate_udp_hop = false;
    match stream.quic_transport() {
        Some(transport) => {
            if show_quic_params_edit(ui, StreamDirection::Outbound, transport, &mut stream.quic_params) {
                stream.write_quic_params = true;
            }
            if stream.quic_params.has_legacy_udp_hop() {
                migrate_udp_hop = ui
                    .button("Migrate udpHop to a udphop layer")
                    .on_hover_text(
                        "Removes quicParams.udpHop and inserts the equivalent udphop layer at \
                         finalmask.udp[0], then shows the JSON diff. Nothing is written until Save.",
                    )
                    .clicked();
            }
            ui.add_space(8.0);
        }
        None if stream.transport == Some(OutboundTransport::Xhttp) => {
            ui.label(
                RichText::new(
                    "QUIC tuning (finalmask.quicParams) applies when XHTTP runs over HTTP/3: \
                     security tls with alpn exactly [\"h3\"].",
                )
                .size(12.0)
                .color(GREY),
            );
        }
        None => {}
    }

    // A chain the typed model cannot read is shown as a notice and never written.
    let mut unreadable_tcp = Vec::new();
    let mut unreadable_udp = Vec::new();
    for chain in [FinalMaskChain::Tcp, FinalMaskChain::Udp] {
        if !stream.finalmask_chain_editable(chain) {
            ui.label(
                RichText::new(format!(
                    "streamSettings.finalmask.{} on disk can't be read by the editor; it is kept as \
                     is — fix it on the Raw JSON tab to edit it here.",
                    chain.key()
                ))
                .color(AMBER),
            );
        }
    }
    let tcp_editable = stream.finalmask_chain_editable(FinalMaskChain::Tcp);
    let udp_editable = stream.finalmask_chain_editable(FinalMaskChain::Udp);
    let udp_only = stream.transport == Some(OutboundTransport::Hysteria);
    let edit = show_finalmask_edit(
        ui,
        StreamDirection::Outbound,
        if tcp_editable { &mut stream.finalmask_tcp } else { &mut unreadable_tcp },
        if udp_editable { &mut stream.finalmask_udp } else { &mut unreadable_udp },
        None,
        udp_only,
    );
    if edit.tcp && tcp_editable {
        stream.write_finalmask_tcp = true;
    }
    if edit.udp && udp_editable {
        stream.write_finalmask_udp = true;
    }
    migrate_udp_hop
}

/// Vision needs the bare TLS / REALITY connection under VLESS (`proxy/vless/outbound`): RAW with
/// TLS or REALITY, unless VLESS Encryption wraps the connection.
fn vision_hint(service: &ApplicationService) -> Option<&'static str> {
    let session = service.outbound_editor_session()?;
    let crate::app::OutboundSettingsDraft::Vless(settings) = &session.settings else {
        return None;
    };
    let vision = settings.flow.trim().starts_with("xtls-rprx-vision");
    let encryption = !matches!(settings.encryption.trim(), "" | "none");
    let stream = &session.stream;
    let direct = stream.transport == Some(OutboundTransport::Raw)
        && matches!(stream.security.mode, InboundSecurityMode::Tls | InboundSecurityMode::Reality);
    (vision && !encryption && !direct).then_some(
        "flow xtls-rprx-vision works only over RAW with TLS or REALITY (or with VLESS Encryption); \
         Xray-core refuses the connection otherwise.",
    )
}

fn show_transport_selector(ui: &mut Ui, stream: &mut OutboundStreamDraft, protocol: &str) {
    let allowed = outbound_transports_for_protocol(protocol);
    let current = stream.transport.unwrap_or(OutboundTransport::Raw);
    if !allowed.contains(&current) {
        ui.label(
            RichText::new(format!(
                "Transport `{}` is not used with {protocol}; pick one below.",
                current.label()
            ))
            .color(AMBER),
        );
    }
    let mut picked = None;
    ui.horizontal_wrapped(|ui| {
        super::help_button(ui, "network", HELP_TRANSPORT);
        ui.label("network");
        for transport in &allowed {
            if ui.selectable_label(current == *transport, transport.label()).clicked() && current != *transport {
                picked = Some(*transport);
            }
        }
    });
    if let Some(transport) = picked {
        stream.select_transport(transport);
        // Keep the security valid for the new transport (e.g. REALITY → TLS on WebSocket).
        if stream.security.is_editable() {
            stream.security.mode =
                coerce_security_mode_for_transport(protocol, transport.as_wire(), stream.security.mode);
        }
    }
}

/// Fields of the selected transport; returns whether anything changed.
fn show_transport_fields(ui: &mut Ui, stream: &mut OutboundStreamDraft) -> bool {
    let mut dirty = false;
    match stream.transport.unwrap_or(OutboundTransport::Raw) {
        OutboundTransport::Raw => {
            ui.label(RichText::new("RAW has no client fields.").size(12.0).color(GREY));
            if !stream.raw.extras.is_empty() {
                let keys: Vec<_> = stream.raw.extras.keys().map(String::as_str).collect();
                ui.label(
                    RichText::new(format!(
                        "Kept as is: {} (legacy header obfuscation / server-only) — edit on the Raw JSON tab.",
                        keys.join(", ")
                    ))
                    .size(12.0)
                    .color(GREY),
                );
            }
        }
        OutboundTransport::Xhttp => {
            dirty |= show_xhttp_settings_edit(ui, &mut stream.xhttp, "outbound_stream");
        }
        OutboundTransport::Grpc => {
            let grpc = &mut stream.grpc;
            egui::Grid::new("outbound_grpc_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                super::field_label(ui, "authority", HELP_GRPC_AUTHORITY);
                dirty |= ui.text_edit_singleline(&mut grpc.authority).changed();
                ui.end_row();
                super::field_label(ui, "serviceName", HELP_GRPC_SERVICE_NAME);
                dirty |= ui.text_edit_singleline(&mut grpc.service_name).changed();
                ui.end_row();
                super::field_label(ui, "multiMode", HELP_GRPC_MULTI_MODE);
                dirty |= ui.checkbox(&mut grpc.multi_mode, "").changed();
                ui.end_row();
                super::field_label(ui, "user_agent", HELP_GRPC_USER_AGENT);
                dirty |= ui.text_edit_singleline(&mut grpc.user_agent).changed();
                ui.end_row();
                super::field_label(ui, "idle_timeout (s)", HELP_GRPC_IDLE_TIMEOUT);
                dirty |= optional_int_field(ui, &mut grpc.idle_timeout);
                ui.end_row();
                super::field_label(ui, "health_check_timeout (s)", HELP_GRPC_HEALTH_CHECK_TIMEOUT);
                dirty |= optional_int_field(ui, &mut grpc.health_check_timeout);
                ui.end_row();
                super::field_label(ui, "permit_without_stream", HELP_GRPC_PERMIT_WITHOUT_STREAM);
                dirty |= ui.checkbox(&mut grpc.permit_without_stream, "").changed();
                ui.end_row();
                super::field_label(ui, "initial_windows_size", HELP_GRPC_INITIAL_WINDOWS_SIZE);
                dirty |= optional_int_field(ui, &mut grpc.initial_windows_size);
                ui.end_row();
            });
        }
        OutboundTransport::WebSocket => {
            let ws = &mut stream.ws;
            egui::Grid::new("outbound_ws_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                super::field_label(ui, "host", HELP_WS_HOST);
                dirty |= ui.text_edit_singleline(&mut ws.host).changed();
                ui.end_row();
                super::field_label(ui, "path", HELP_WS_PATH);
                dirty |= ui.text_edit_singleline(&mut ws.path).changed();
                ui.end_row();
                super::field_label(ui, "ed", HELP_WS_ED);
                dirty |= optional_uint_field(ui, &mut ws.ed);
                ui.end_row();
                super::field_label(ui, "heartbeatPeriod (s)", HELP_WS_HEARTBEAT);
                dirty |= optional_uint_field(ui, &mut ws.heartbeat_period);
                ui.end_row();
            });
            super::field_label(ui, "headers", HELP_HEADERS);
            dirty |= headers_edit(ui, &mut ws.headers, "outbound_ws_headers");
        }
        OutboundTransport::HttpUpgrade => {
            let hu = &mut stream.httpupgrade;
            egui::Grid::new("outbound_hu_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                super::field_label(ui, "host", HELP_HU_HOST);
                dirty |= ui.text_edit_singleline(&mut hu.host).changed();
                ui.end_row();
                super::field_label(ui, "path", HELP_HU_PATH);
                dirty |= ui.text_edit_singleline(&mut hu.path).changed();
                ui.end_row();
                super::field_label(ui, "ed", HELP_WS_ED);
                dirty |= optional_uint_field(ui, &mut hu.ed);
                ui.end_row();
            });
            super::field_label(ui, "headers", HELP_HEADERS);
            dirty |= headers_edit(ui, &mut hu.headers, "outbound_hu_headers");
        }
        OutboundTransport::Mkcp => {
            ui.label(
                RichText::new("mKCP runs over UDP; the values must match the server's.")
                    .size(12.0)
                    .color(GREY),
            );
            dirty |= show_kcp_settings_edit(ui, &mut stream.kcp, "outbound_stream");
        }
        OutboundTransport::Hysteria => {
            let hy = &mut stream.hysteria;
            egui::Grid::new("outbound_hy_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                ui.label("version");
                if hy.version == Some(HYSTERIA_TRANSPORT_VERSION) {
                    ui.label(HYSTERIA_TRANSPORT_VERSION.to_string());
                } else if ui.button(format!("Set {HYSTERIA_TRANSPORT_VERSION} (Xray-core accepts only 2)")).clicked() {
                    hy.version = Some(HYSTERIA_TRANSPORT_VERSION);
                    dirty = true;
                }
                ui.end_row();
                super::field_label(ui, "auth", HELP_HY_AUTH);
                dirty |= ui.add(egui::TextEdit::singleline(&mut hy.auth).password(true)).changed();
                ui.end_row();
                super::field_label(ui, "udpIdleTimeout (s)", HELP_HY_UDP_IDLE);
                dirty |= optional_uint_field(ui, &mut hy.udp_idle_timeout);
                ui.end_row();
            });
        }
    }
    dirty
}

fn show_security_edit(ui: &mut Ui, stream: &mut OutboundStreamDraft, protocol: &str) {
    if let Some(wire) = &stream.security.unknown_wire {
        ui.label(
            RichText::new(format!("security `{wire}` is not editable here; preserved on save."))
                .color(GREY),
        );
        return;
    }
    let transport = stream.transport.unwrap_or(OutboundTransport::Raw);
    let allowed = allowed_security_modes(protocol, transport.as_wire());
    let mut picked = None;
    ui.horizontal(|ui| {
        super::help_button(ui, "security", HELP_SECURITY);
        ui.label("security");
        for mode in &allowed {
            let selected = stream.security.mode == *mode;
            if ui.selectable_label(selected, mode.as_wire()).clicked() && !selected {
                picked = Some(*mode);
            }
        }
    });
    if let Some(mode) = picked {
        stream.security.mode = mode;
        stream.write = true;
    }
    if !allowed.contains(&stream.security.mode) {
        ui.label(
            RichText::new(format!(
                "security `{}` cannot be used with {}; pick one above.",
                stream.security.mode.as_wire(),
                transport.label()
            ))
            .color(AMBER),
        );
    }
    let dirty = match stream.security.mode {
        InboundSecurityMode::None => false,
        InboundSecurityMode::Tls => show_tls_client_edit(ui, stream),
        InboundSecurityMode::Reality => show_reality_client_edit(ui, stream),
    };
    if dirty {
        stream.write = true;
    }
}

fn show_tls_client_edit(ui: &mut Ui, stream: &mut OutboundStreamDraft) -> bool {
    let tls = &mut stream.security.tls;
    let mut dirty = false;
    if tls.allow_insecure {
        ui.label(
            RichText::new(
                "allowInsecure: true is a removed feature — Xray-core v26.1.31+ refuses to load \
                 the config. Pin the certificate (pinnedPeerCertSha256) instead.",
            )
            .color(AMBER),
        );
        if ui.button("Remove allowInsecure").clicked() {
            tls.allow_insecure = false;
            dirty = true;
        }
    }
    egui::Grid::new("outbound_tls_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
        super::field_label(ui, "serverName", HELP_TLS_SERVER_NAME);
        dirty |= ui.text_edit_singleline(&mut tls.server_name).changed();
        ui.end_row();
        super::field_label(ui, "alpn", HELP_TLS_ALPN);
        dirty |= string_tag_multi_select(ui, "outbound_tls_alpn", &mut tls.alpn, ALPN_PRESETS);
        ui.end_row();
        super::field_label(ui, "fingerprint", HELP_TLS_FINGERPRINT);
        ui.horizontal(|ui| {
            dirty |= optional_string_combo(ui, "outbound_tls_fp", &mut tls.fingerprint, FINGERPRINT_PRESETS);
        });
        ui.end_row();
        super::field_label(ui, "pinnedPeerCertSha256", HELP_TLS_PINNED);
        dirty |= ui.text_edit_singleline(&mut tls.pinned_peer_cert_sha256).changed();
        ui.end_row();
        super::field_label(ui, "verifyPeerCertByName", HELP_TLS_VERIFY_BY_NAME);
        dirty |= ui.text_edit_singleline(&mut tls.verify_peer_cert_by_name).changed();
        ui.end_row();
        super::field_label(ui, "echConfigList", HELP_TLS_ECH);
        dirty |= resizable_multiline(ui, &mut tls.ech_config_list, 2, "outbound_tls_ech").changed();
        ui.end_row();
    });
    egui::CollapsingHeader::new("Advanced TLS")
        .id_salt("outbound_tls_advanced")
        .default_open(false)
        .show(ui, |ui| {
            egui::Grid::new("outbound_tls_adv_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                super::field_label(ui, "minVersion", HELP_TLS_VERSION);
                ui.horizontal(|ui| {
                    dirty |= optional_string_combo(ui, "outbound_tls_min", &mut tls.min_version, TLS_VERSION_PRESETS);
                });
                ui.end_row();
                super::field_label(ui, "maxVersion", HELP_TLS_VERSION);
                ui.horizontal(|ui| {
                    dirty |= optional_string_combo(ui, "outbound_tls_max", &mut tls.max_version, TLS_VERSION_PRESETS);
                });
                ui.end_row();
                super::field_label(ui, "cipherSuites", HELP_TLS_CIPHERS);
                dirty |= ui.text_edit_singleline(&mut tls.cipher_suites).changed();
                ui.end_row();
                super::field_label(ui, "curvePreferences", HELP_TLS_CURVES);
                dirty |= string_tag_multi_select(ui, "outbound_tls_curves", &mut tls.curve_preferences, CURVE_PRESETS);
                ui.end_row();
                super::field_label(ui, "disableSystemRoot", HELP_TLS_DISABLE_SYSTEM_ROOT);
                dirty |= ui.checkbox(&mut tls.disable_system_root, "").changed();
                ui.end_row();
                super::field_label(ui, "enableSessionResumption", HELP_TLS_SESSION_RESUMPTION);
                dirty |= ui.checkbox(&mut tls.enable_session_resumption, "").changed();
                ui.end_row();
                super::field_label(ui, "masterKeyLog", HELP_TLS_MASTER_KEY_LOG);
                dirty |= ui.text_edit_singleline(&mut tls.master_key_log).changed();
                ui.end_row();
            });
        });
    show_preserved_keys(ui, "tlsSettings", tls.extras.keys());
    dirty
}

fn show_reality_client_edit(ui: &mut Ui, stream: &mut OutboundStreamDraft) -> bool {
    let reality = &mut stream.security.reality;
    let mut dirty = false;
    let presets: Vec<&str> = FINGERPRINT_PRESETS
        .iter()
        .copied()
        .filter(|name| !crate::xray::REALITY_REFUSED_FINGERPRINTS.contains(name))
        .collect();
    egui::Grid::new("outbound_reality_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
        super::field_label(ui, "serverName", HELP_REALITY_SERVER_NAME);
        dirty |= ui.text_edit_singleline(&mut reality.server_name).changed();
        ui.end_row();
        super::field_label(ui, "fingerprint", HELP_REALITY_FINGERPRINT);
        ui.horizontal(|ui| {
            dirty |= optional_string_combo(ui, "outbound_reality_fp", &mut reality.fingerprint, &presets);
        });
        ui.end_row();
        super::field_label(ui, "publicKey", HELP_REALITY_PUBLIC_KEY);
        dirty |= ui.text_edit_singleline(&mut reality.public_key).changed();
        ui.end_row();
        super::field_label(ui, "shortId", HELP_REALITY_SHORT_ID);
        dirty |= ui.text_edit_singleline(&mut reality.short_id).changed();
        ui.end_row();
        super::field_label(ui, "spiderX", HELP_REALITY_SPIDER_X);
        dirty |= ui.text_edit_singleline(&mut reality.spider_x).changed();
        ui.end_row();
        super::field_label(ui, "mldsa65Verify", HELP_REALITY_MLDSA65_VERIFY);
        dirty |= resizable_multiline(ui, &mut reality.mldsa65_verify, 2, "outbound_reality_mldsa").changed();
        ui.end_row();
        super::field_label(ui, "show", HELP_REALITY_SHOW);
        dirty |= ui.checkbox(&mut reality.show, "").changed();
        ui.end_row();
    });
    show_preserved_keys(ui, "realitySettings", reality.extras.keys());
    dirty
}

/// Grey note listing keys kept verbatim (no values — they may hold secrets).
fn show_preserved_keys<'a>(ui: &mut Ui, object: &str, keys: impl Iterator<Item = &'a String>) {
    let keys: Vec<&str> = keys.map(String::as_str).collect();
    if !keys.is_empty() {
        ui.label(
            RichText::new(format!("{object}: kept as is — {}", keys.join(", ")))
                .size(12.0)
                .color(GREY),
        );
    }
}

/// Key / value rows with remove buttons and "+ header"; returns whether anything changed.
fn headers_edit(ui: &mut Ui, headers: &mut Vec<(String, String)>, id: &str) -> bool {
    let mut dirty = false;
    let mut remove = None;
    for (index, (key, value)) in headers.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            dirty |= ui
                .add(egui::TextEdit::singleline(key).id_salt((id, index, "k")).desired_width(140.0).hint_text("name"))
                .changed();
            dirty |= ui
                .add(egui::TextEdit::singleline(value).id_salt((id, index, "v")).desired_width(220.0).hint_text("value"))
                .changed();
            if ui.button("−").clicked() {
                remove = Some(index);
            }
        });
    }
    if let Some(index) = remove {
        headers.remove(index);
        dirty = true;
    }
    if ui.button("+ header").clicked() {
        headers.push((String::new(), String::new()));
        dirty = true;
    }
    dirty
}

/// Optional signed integer text field: empty = `None`; text that does not parse is ignored.
fn optional_int_field(ui: &mut Ui, value: &mut Option<i64>) -> bool {
    let mut text = value.map(|v| v.to_string()).unwrap_or_default();
    if !ui.add(egui::TextEdit::singleline(&mut text).hint_text("default")).changed() {
        return false;
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        *value = None;
        return true;
    }
    match trimmed.parse() {
        Ok(parsed) => {
            *value = Some(parsed);
            true
        }
        Err(_) => false,
    }
}

/// Optional unsigned integer text field: empty = `None`; text that does not parse is ignored.
fn optional_uint_field(ui: &mut Ui, value: &mut Option<u64>) -> bool {
    let mut text = value.map(|v| v.to_string()).unwrap_or_default();
    if !ui.add(egui::TextEdit::singleline(&mut text).hint_text("default")).changed() {
        return false;
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        *value = None;
        return true;
    }
    match trimmed.parse() {
        Ok(parsed) => {
            *value = Some(parsed);
            true
        }
        Err(_) => false,
    }
}
