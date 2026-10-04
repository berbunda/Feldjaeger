//! `streamSettings.sockopt` editor shared by every page with a `streamSettings` block
//! (Roadmap §2.6 stage 0.4; field set Roadmap §2.3:87).
//!
//! Direction-aware: a row is shown only when its key has an effect on that side of the
//! connection ([`sockopt_field_applies`]); fields without a row still round-trip losslessly
//! through [`SockoptDraft`]. Outbound-only fields have no widgets yet (Tier 4 §4.2).

use egui::{Color32, RichText, Ui};

use super::{lines_to_vec, resizable_multiline};
use crate::xray::{
    INBOUND_ONLY_SOCKOPT_FIELDS, OUTBOUND_ONLY_SOCKOPT_FIELDS, SockoptDraft, StreamDirection, TPROXY_MODES, TcpFastOpenDraft,
    sockopt_field_applies,
};

// Field help (Roadmap §3:124).
pub(crate) const HELP_SOCKOPT_TPROXY: &str =
    "Enables OS-level transparent proxying via iptables (Linux only): \"redirect\" or \"tproxy\" \
     mode, or off. An alternative to Xray-level followRedirect — usually only one is needed.";

// Stream tab — Sockopt (streamSettings.sockopt; method-independent).
const HELP_SOCKOPT_TCP_FAST_OPEN: &str =
    "Enables TCP Fast Open. `true`/`false`, or a positive integer to also set the accept queue \
     length. Availability depends on OS support.";
const HELP_SOCKOPT_ACCEPT_PROXY_PROTOCOL: &str =
    "Inbound-only. When enabled, the peer must send a PROXY protocol v1/v2 header immediately \
     after the TCP connection is established, so Xray can see the real source IP/port.";
const HELP_SOCKOPT_V6ONLY: &str =
    "Linux only. When enabled, a listener bound to `::` accepts IPv6 connections only (no \
     IPv4-mapped addresses).";
const HELP_SOCKOPT_TCP_MAX_SEG: &str = "Sets the maximum segment size (MSS) of TCP packets.";
const HELP_SOCKOPT_TCP_KEEP_ALIVE_IDLE: &str =
    "Seconds a TCP connection must be idle before Keep-Alive probes start.";
const HELP_SOCKOPT_TCP_KEEP_ALIVE_INTERVAL: &str =
    "Seconds between Keep-Alive probes once a TCP connection has entered the Keep-Alive state.";
const HELP_SOCKOPT_TCP_USER_TIMEOUT: &str =
    "TCP user timeout in milliseconds (RFC 5482) — how long unacknowledged data may sit before \
     the connection is force-closed.";
const HELP_SOCKOPT_TCP_WINDOW_CLAMP: &str =
    "Caps the advertised TCP receive window size. The kernel uses the larger of this value and \
     its own minimum.";
const HELP_SOCKOPT_TRUSTED_X_FORWARDED_FOR: &str =
    "For HTTP-based transports: source IP ranges allowed to set a trusted X-Forwarded-For \
     header (e.g. a reverse proxy in front of Xray). One CIDR/IP per line.";
const HELP_SOCKOPT_CUSTOM_SOCKOPT: &str =
    "Escape hatch for socket options not exposed as dedicated fields above — a raw JSON array, \
     platform-specific (Linux/Windows/Darwin). Advanced use only.";

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
    let outbound_only = OUTBOUND_ONLY_SOCKOPT_FIELDS.join(", ");
    match direction {
        StreamDirection::Inbound => format!(
            "streamSettings.sockopt — low-level socket options; applies regardless of transport \
             method. Outbound-only fields ({outbound_only}) are preserved but not yet editable here."
        ),
        StreamDirection::Outbound => format!(
            "streamSettings.sockopt — low-level socket options; applies regardless of transport \
             method. Outbound-only fields ({outbound_only}) are preserved but not yet editable \
             here; inbound-only fields ({}) have no effect on an outbound and are hidden.",
            INBOUND_ONLY_SOCKOPT_FIELDS.join(", ")
        ),
    }
}

/// Editor for `streamSettings.sockopt` (Roadmap §2.3:87): the shared fields plus those that
/// apply to `direction` ([`sockopt_field_applies`]); outbound-only fields stay typed and
/// round-tripped with no widget yet. Returns true when any field changed.
pub(crate) fn show_sockopt_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    sockopt: &mut SockoptDraft,
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
    let mut trusted_x_forwarded_for = sockopt.trusted_x_forwarded_for.join("\n");
    let mut custom_sockopt_text = sockopt
        .custom_sockopt
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
        .unwrap_or_default();

    egui::Grid::new("stream_sockopt_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
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
                if ui
                    .add(egui::TextEdit::multiline(&mut trusted_x_forwarded_for).desired_rows(2))
                    .changed()
                {
                    sockopt.trusted_x_forwarded_for = lines_to_vec(&trusted_x_forwarded_for);
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

    dirty
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
