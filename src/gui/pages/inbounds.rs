//! Inbounds page — inbound table with 6-tab detail pane (IB-L1 + IB-L3 Stream).
//!
//! Tabs: General | Protocol | Stream | Security | Sniffing | Users
//! Data flows exclusively through [`ApplicationService`] → [`InboundSummary`].

use egui::{Color32, ComboBox, RichText, Sense, Ui};

use crate::app::{
    ApplicationService, ImportPreview, InboundClientProtocol, InboundEditorSession, InboundGeneral,
    InboundProtocolDraft, InboundShareMaterial, InboundsPageState, InboundsSortColumn,
    InboundSecurityMode, KNOWN_DEST_OVERRIDE, MISSING_FIELD,
    SniffingSettings, StreamMethod, allowed_security_modes,
    coerce_display_stream_method, coerce_security_mode_for_transport,
    selectable_stream_methods,
    inbound_row_display, parse_inbound_stream,
};
use crate::gui::pages::users;
use crate::gui::pages::stream_finalmask::{
    FinalMaskEdit, show_finalmask_edit, show_foreign_finalmask_notice, show_quic_params_edit,
};
use crate::gui::pages::stream_sockopt::{
    HELP_SOCKOPT_TPROXY, show_sockopt_edit, show_sockopt_readonly, sockopt_scope_note,
    tproxy_combo_field,
};
use crate::gui::pages::{
    danger_sign, danger_warning, lines_to_vec, optional_string_combo, persistent_multiline_list_row,
    resizable_multiline,
};
use crate::xray::{
    ALPN_PRESETS, CERT_USAGE_PRESETS, CURVE_PRESETS, CompatibilityWarning, FINGERPRINT_PRESETS, FallbackDest,
    FallbackDestKind, FallbackObject, InboundStreamDraft, InboundSummary,
    KCP_CWND_MULTIPLIER_MIN, KCP_DEFAULT_CWND_MULTIPLIER, KCP_DEFAULT_MAX_SENDING_WINDOW,
    KCP_IGNORED_FIELDS, KCP_MTU_MIN, KCP_TTI_MAX, KCP_TTI_MIN, KcpStreamSettings, ShareSecurity, ShareTransport, StreamDirection,
    TLS_VERSION_PRESETS, TUNNEL_NETWORKS, CertificateDraft,
    TlsSettingsDraft, XHTTP_DOWNLOAD_SECURITIES, XHTTP_MODES, XHTTP_MODE_DEFAULT, XHTTP_PADDING_METHODS,
    XHTTP_PATH_DEFAULT, XHTTP_PLACEMENTS, XHTTP_SESSION_ID_TABLES, XHTTP_UPLINK_METHODS,
    XhttpCoreSettings, XhttpDownloadDraft, XhttpRange, XhttpStreamSettings,
    QuicTransport, WarningSeverity, alpn_selects_http3, fallbacks_transport_compatible, finalmask_tcp_layer_faces_probes,
    parse_inbound_protocol,
    validate_port_map_target,
};

// ─── Field help text (Roadmap §3:124) ────────────────────────────────────────
//
// Condensed from the official Xray-core config docs (https://xtls.github.io/config/). Each
// constant backs one `super::field_label(...)` / `super::help_button(...)` call — see
// `gui::pages::help_button` for the pop-up mechanism.

// General tab.
const HELP_GENERAL_TAG: &str =
    "The identifier of this inbound connection, used to locate it in other parts of the \
     configuration — most importantly, routing rules reference it via `inboundTag`. Must be \
     unique across the whole config.";
const HELP_GENERAL_LISTEN: &str =
    "The listening address: an IP address or a Unix domain socket. Default is `0.0.0.0` (all \
     IPv4 interfaces); use `::` for all IPv6 interfaces, or a specific address to restrict \
     which interface accepts connections.";
const HELP_GENERAL_PORT: &str =
    "Port this inbound listens on. Accepts a single number, or — for protocols that support \
     port hopping/multiplexing (e.g. Hysteria2) — a range string (\"5000-6000\") or a \
     comma-separated list (\"443,5000-6000\"). Non-scalar shapes are preserved as-is and are \
     not editable from this shell (Roadmap §3:118); use the raw config file to change them.";

// Sniffing tab.
const HELP_SNIFFING_ENABLED: &str = "Whether to enable traffic sniffing.";
const HELP_SNIFFING_DEST_OVERRIDE: &str =
    "When sniffed traffic matches one of the checked types (http / tls / quic / fakedns / \
     fakedns+others), the connection's destination is reset to the domain name found inside \
     the traffic itself, instead of the original IP it was dialed to.";
const HELP_SNIFFING_METADATA_ONLY: &str =
    "When enabled, only connection metadata (e.g. SNI, HTTP Host header) is used to sniff the \
     destination address — Xray does not need to buffer/inspect payload bytes.";
const HELP_SNIFFING_ROUTE_ONLY: &str =
    "Use the sniffed domain only for routing decisions; the actual proxy destination address \
     stays the original IP instead of being replaced by the sniffed domain.";

// Protocol tab — VLESS.
const HELP_VLESS_DECRYPTION: &str =
    "VLESS Encryption settings (server-side \"decryption\"). Cannot be left empty; set to \
     \"none\" to disable it. Non-\"none\" values are generated with the remote `xray vlessenc` \
     command below.";
const HELP_VLESS_ENCRYPTION: &str =
    "The client-side half of VLESS Encryption produced by the last \"Generate vlessenc\" run — \
     shown here for copying into the client's config; never written into the inbound JSON \
     itself (only `decryption` is).";
const HELP_VLESSENC_AUTH: &str =
    "Key-exchange algorithm used by the remote `xray vlessenc` command when generating the \
     decryption/encryption pair: X25519 (classic) or ML-KEM-768 (post-quantum). Feldjäger UI \
     choice, not a field written to the config.";

// Protocol tab — fallbacks (VLESS / Trojan, TCP + TLS/Reality only).
const HELP_FALLBACK_NAME: &str =
    "Attempts to match TLS SNI (Server Name Indication) of the incoming connection. Empty \
     means any.";
const HELP_FALLBACK_ALPN: &str =
    "Attempts to match the negotiated TLS ALPN result of the incoming connection. Empty means \
     any. With REALITY no ALPN is ever negotiated, so only entries with an empty alpn are used.";
const HELP_FALLBACK_PATH: &str =
    "Attempts to match the HTTP PATH of the first packet. Empty means any; when set it must \
     start with `/` (h2c is not supported).";
const HELP_FALLBACK_DEST_KIND: &str =
    "Address type for where non-matching traffic is forwarded after TLS decryption: a local \
     port, a TCP host:port, or a Unix domain socket path.";
const HELP_FALLBACK_DEST: &str =
    "Destination for the fallback traffic after TLS decryption. Mandatory — Xray refuses to \
     start without it.";
const HELP_FALLBACK_XVER: &str =
    "Sends the PROXY protocol (v1 or v2) to the fallback destination so it can see the real \
     source IP/port. 0 (default) sends nothing; 1 and 2 behave identically, differing only in \
     wire format (text vs binary).";

// Protocol tab — Hysteria.
const HELP_HYSTERIA_VERSION: &str =
    "Hysteria transport version. Xray-core only implements Hysteria 2, so this is fixed and \
     not editable.";

// Protocol tab — Tunnel (successor to legacy dokodemo-door).
const HELP_TUNNEL_ALLOWED_NETWORK: &str =
    "Accepted network protocol types for this transparent-proxy inbound — e.g. \"tcp\" accepts \
     only TCP traffic. Default is \"tcp\".";
const HELP_TUNNEL_REWRITE_ADDRESS: &str =
    "Forwards traffic to this address — an IP (\"1.2.3.4\") or a domain name (\"xray.com\").";
const HELP_TUNNEL_REWRITE_PORT: &str =
    "Forwards traffic to this port on the rewrite address. If omitted or 0, the inbound's own \
     listening port is used instead.";
const HELP_TUNNEL_FOLLOW_REDIRECT: &str =
    "When enabled, Tunnel recognizes traffic redirected by iptables and forwards it to the \
     address it was originally destined for — an Xray-level alternative to OS-level tproxy.";
const HELP_TUNNEL_USER_LEVEL: &str =
    "User level for this inbound; connections use the Local Policy configured for this level \
     (defaults to 0).";
const HELP_TUNNEL_PORT_MAP: &str =
    "Maps a local port to a specific remote address/port, overriding rewriteAddress/rewritePort \
     for that one port. Ports not listed here fall back to the rewriteAddress/rewritePort above.";
// Stream tab — method selector + TCP.
const HELP_STREAM_METHOD: &str =
    "Transport carrying the proxy protocol on the wire (tcp/raw, WebSocket, mKCP, gRPC, XHTTP, \
     or the protocol-locked Hysteria transport). Which methods are selectable here depends on \
     the inbound's protocol and — for VLESS — whether Vision flow is in use.";
const HELP_TCP_ACCEPT_PROXY_PROTOCOL: &str =
    "Inbound-only. When enabled, the peer must send a PROXY protocol v1/v2 header immediately \
     after the TCP connection is established, so Xray can see the real source IP/port (e.g. \
     behind a load balancer).";

// Stream tab — XHTTP (basic fields; advanced knobs get section-level help further below).
const HELP_XHTTP_HOST: &str =
    "Host header the server checks (or the client sends). Empty means the value is not \
     verified server-side.";
const HELP_XHTTP_PATH: &str = "Request path for the XHTTP endpoint. Default is \"/\".";
const HELP_XHTTP_MODE: &str =
    "Framing mode: \"auto\" negotiates automatically, \"packet-up\" uses chunked POST requests \
     for uplink, \"stream-one\"/\"stream-up\" keep the uplink as a long-lived stream. Affects \
     latency/compatibility trade-offs, especially behind CDNs.";
const HELP_XHTTP_HEADERS_SECTION: &str =
    "Extra HTTP request headers sent with every XHTTP request — useful for CDN routing rules or \
     custom Host-like headers beyond the dedicated `host` field.";
const HELP_XHTTP_PADDING_SECTION: &str =
    "Padding, SSE, and gRPC-Content-Type knobs: `xPaddingBytes` adds random-length padding to \
     header requests (harder to fingerprint by size); `noSSEHeader`/`noGRPCHeader` drop the \
     Content-Type Xray would otherwise send for download/upload framing, useful when a CDN \
     mishandles those content types.";
const HELP_XHTTP_SC_SECTION: &str =
    "Packet-mode (\"packet-up\") tuning: max bytes per POST, minimum interval between POSTs, \
     how many POSTs the server buffers, and how long a stream-up connection is kept padded \
     before the server closes it. Mostly relevant when CDNs impose per-request limits.";
const HELP_XHTTP_PLACEMENT_SECTION: &str =
    "Where session id / sequence number / uplink data / padding are placed on the wire (query, \
     header, or cookie) and under what key names — plus the advanced padding obfuscation mode. \
     Used to blend XHTTP traffic in with ordinary HTTP requests.";
const HELP_XHTTP_XMUX_SECTION: &str =
    "Connection-pool / multiplexing limits for the client side of XHTTP (max concurrent \
     streams, max connections, connection reuse/lifetime caps, keep-alive period). Written into \
     the inbound only so it can be embedded in the generated client Share URI's `extra=` field \
     — Xray itself does not read xmux from inbound JSON.";
const HELP_XHTTP_DOWNLOAD_SECTION: &str =
    "Optional separate downlink connection (`downloadSettings`): dials out to a different \
     address/port — potentially a different XHTTP-capable node — instead of reusing the same \
     connection for both directions. Leave disabled unless you specifically split up/down \
     traffic.";

// Stream tab — gRPC.
const HELP_GRPC_SERVICE_NAME: &str =
    "gRPC service name, functioning similarly to a Path in HTTP/2 — the client uses this name \
     to open the stream, and the server verifies it matches.";
const HELP_GRPC_MULTI_MODE: &str =
    "Experimental client-side multiplexing mode that can improve throughput (~20% in Xray's own \
     benchmarks). Server just needs to accept it; the real effect depends on the client.";

// Stream tab — WebSocket.
const HELP_WS_PATH: &str =
    "HTTP path used by the WebSocket upgrade request. Default is \"/\". A client path containing \
     an `ed` query parameter (e.g. `/mypath?ed=2560`) enables Early Data to shave off a round trip.";
const HELP_WS_HOST: &str =
    "Host header expected in the WebSocket upgrade request. Empty means the server does not \
     verify whatever Host the client sends.";
const HELP_WS_ACCEPT_PROXY_PROTOCOL: &str =
    "Inbound-only. When enabled, the peer must send a PROXY protocol v1/v2 header immediately \
     after the TCP connection is established.";
const HELP_WS_ED: &str =
    "Early Data threshold appended to `path` as `?ed=N` — the first-packet length (in bytes) \
     that may be carried inside the WebSocket upgrade's `Sec-WebSocket-Protocol` header, saving \
     a round trip. Leave empty to disable.";

// Stream tab — mKCP.
const HELP_MKCP_MTU: &str =
    "Maximum Transmission Unit, in bytes. Default 1350. The docs recommend 576–1460; Xray-core \
     accepts any value from 21.";
const HELP_MKCP_TTI: &str =
    "Transmission Time Interval in milliseconds — how often mKCP sends data. Xray-core accepts \
     10–1000 ms, default 50 ms; smaller values lower latency at the cost of more overhead.";
const HELP_MKCP_UPLINK: &str =
    "Maximum uplink bandwidth this host will use, in MB/s. Default 5; 0 means unlimited.";
const HELP_MKCP_DOWNLINK: &str =
    "Maximum downlink bandwidth this host will use, in MB/s. Default 20; 0 means unlimited.";
const HELP_MKCP_CWND_MULTIPLIER: &str =
    "Congestion-window multiplier for mKCP sending. Leave empty for the Xray-core default (1); \
     must be at least 1.";
const HELP_MKCP_MAX_SENDING_WINDOW: &str =
    "Upper bound of the sending buffer, in bytes — the buffer holds maxSendingWindow / mtu \
     packets. Leave empty for the Xray-core default (2097152 = 2 MiB); must be at least mtu.";

// Security tab — mode selector.
const HELP_SECURITY_MODE: &str =
    "Transport security applied on top of the chosen Stream method: none (plaintext), tls \
     (standard TLS with your own certificate), or reality (camouflages the handshake as a real \
     site's TLS, no certificate of your own needed). Which modes are selectable depends on the \
     protocol and transport.";

// Security tab — TLS.
const HELP_TLS_ALPN: &str =
    "ALPN values offered during the TLS handshake. Default is [\"h2\", \"http/1.1\"]. Required \
     to be non-empty when fallbacks are configured on the Protocol tab: [\"http/1.1\"], or \
     [\"h2\", \"http/1.1\"] when a fallback matches alpn h2.";
const HELP_TLS_SERVER_NAME: &str =
    "Server name Xray presents/expects for SNI. The server certificate's SAN must cover this \
     value.";
const HELP_TLS_VERIFY_PEER_CERT_BY_NAME: &str =
    "Overrides the name used to verify the peer certificate, independent of the SNI/serverName \
     sent on the wire. Advanced use only — leave empty unless you specifically need this split.";
const HELP_TLS_REJECT_UNKNOWN_SNI: &str =
    "When enabled, the server rejects the TLS handshake if the client's SNI doesn't match any \
     configured certificate domain. Default false.";
const HELP_TLS_ALLOW_INSECURE: &str =
    "Skips TLS certificate verification. Only meaningful client-side; on a server inbound this \
     essentially never has any effect and should stay off.";
const HELP_TLS_MIN_VERSION: &str = "Minimum TLS version Xray will accept during the handshake.";
const HELP_TLS_MAX_VERSION: &str = "Maximum TLS version Xray will accept during the handshake.";
const HELP_TLS_CIPHER_SUITES: &str =
    "Colon-separated list of allowed cipher suites. Not normally needed — only for locking down \
     or working around a specific client/middlebox.";
const HELP_TLS_DISABLE_SYSTEM_ROOT: &str =
    "When enabled, Xray does not trust the OS's root CA store for outgoing verification — \
     irrelevant for a plain inbound listener, kept here since it lives on the same TLSObject.";
const HELP_TLS_ENABLE_SESSION_RESUMPTION: &str =
    "Enables TLS session resumption (session tickets), letting repeat clients skip a full \
     handshake.";
const HELP_TLS_FINGERPRINT: &str =
    "Client TLS fingerprint to emulate (e.g. chrome, firefox, safari) — a client-side setting \
     kept here for convenience when building Share URIs; the server itself does not use it.";
const HELP_TLS_PINNED_PEER_CERT_SHA256: &str =
    "Pins the expected peer certificate's SHA-256 fingerprint. Rarely used on a server inbound \
     (that's a client-side anti-MITM setting) — kept here since it's part of TLSObject.";
const HELP_TLS_CURVE_PREFERENCES: &str =
    "Preferred elliptic curves for the TLS key exchange, in priority order. Leave empty for \
     Xray's defaults; only override for compatibility with a specific client stack.";
const HELP_TLS_MASTER_KEY_LOG: &str =
    "Path to write the TLS master secret log for debugging with tools like Wireshark. Leave \
     empty in production — this weakens confidentiality of the traffic.";
const HELP_TLS_ENABLE_ECH: &str =
    "Enables Encrypted Client Hello (ECH), which hides the SNI from network observers. Requires \
     echServerKeys/echConfigList below.";
const HELP_TLS_ECH_SERVER_KEYS: &str =
    "Server-side ECH keys (matching the published echConfigList) used to decrypt the encrypted \
     ClientHello.";
const HELP_TLS_ECH_CONFIG_LIST: &str =
    "The ECHConfigList published for clients to use when constructing an encrypted ClientHello \
     for this server.";
const HELP_TLS_ECH_SOCKOPT: &str =
    "Advanced socket options specific to the ECH DNS/config-fetch path — raw JSON object. \
     Leave empty unless you need to tune this specifically.";

// Security tab — TLS certificate entries.
const HELP_CERT_CERTIFICATE_FILE: &str =
    "Path to the certificate file (e.g. a .crt). Takes precedence over the inline PEM \
     `certificate` field below when both are set.";
const HELP_CERT_KEY_FILE: &str =
    "Path to the private-key file (e.g. a .key). Password-protected keys are not supported. \
     Takes precedence over the inline PEM `key` field below when both are set.";
const HELP_CERT_CERTIFICATE_PEM: &str =
    "Certificate contents inline, as PEM text, instead of a file path. Ignored when \
     certificateFile is set. A full chain is recommended.";
const HELP_CERT_KEY_PEM: &str =
    "Private key contents inline, as PEM text, instead of a file path. Ignored when keyFile is \
     set.";
const HELP_CERT_USAGE: &str =
    "What this certificate is used for: \"encipherment\" (default; normal TLS termination), \
     \"verify\" (verify remote client certs — key optional), or \"issue\"/\"verifyClient\" for \
     the more advanced dynamic-issuance workflows.";
const HELP_CERT_BUILD_CHAIN: &str =
    "When usage is \"issue\", builds a full certificate chain automatically instead of using \
     only the leaf certificate as configured.";
const HELP_CERT_ONE_TIME_LOADING: &str =
    "Loads the certificate/key once at startup instead of watching the files for changes and \
     reloading — use when the files are static and you want to avoid the extra file-watch \
     overhead.";
const HELP_CERT_OCSP_STAPLING: &str =
    "Refresh interval, in seconds, for OCSP stapling. Leave empty to disable OCSP stapling for \
     this certificate.";

// Security tab — REALITY.
const HELP_REALITY_DEST: &str =
    "Required. The real TLS server REALITY connects to and camouflages as — same format as a \
     VLESS fallback `dest` (host:port). Should normally match one of `serverNames`.";
const HELP_REALITY_SHOW: &str = "When enabled, prints REALITY debug information to the log.";
const HELP_REALITY_XVER: &str =
    "Sends the PROXY protocol (v1 or v2) to the camouflaged destination on the fallback path — \
     same semantics as a VLESS fallback `xver`. 0 (default) sends nothing.";
const HELP_REALITY_SERVER_NAMES: &str =
    "Required. The SNI values REALITY accepts from clients (no wildcards). Should normally stay \
     consistent with `dest`.";
const HELP_REALITY_IGNORED_ALPN: &str =
    "realitySettings.alpn is not part of REALITY: neither the docs nor Xray-core's REALITYConfig \
     have it, and the REALITY server negotiates no ALPN (NextProtos is nil). The key on disk has no \
     effect; Feldjäger keeps it until you remove it.";
const HELP_REALITY_PRIVATE_KEY: &str =
    "Required. Server private key for REALITY's key exchange — generate with the \"Generate \
     x25519\" button (runs the remote `xray x25519`).";
const HELP_REALITY_PUBLIC_KEY: &str =
    "The client-side public key (`pbk`) derived from the private key above — copy this into \
     client configs / Share URIs. Never written into the inbound JSON itself.";
const HELP_REALITY_SHORT_IDS: &str =
    "Required. The `shortId` values clients may present, used to distinguish different clients \
     — each up to 16 hex characters (8 bytes).";
const HELP_REALITY_MLDSA65_SEED: &str =
    "Optional post-quantum signature seed (ML-DSA-65) added to the certificate REALITY presents \
     to clients — generate with the \"Generate mldsa65\" button.";
const HELP_REALITY_MLDSA65_VERIFY: &str =
    "The client-side verify string matching the seed above — copy into client configs. Never \
     written into the inbound JSON itself.";
const HELP_REALITY_MIN_CLIENT_VER: &str =
    "Optional minimum Xray client version (x.y.z) REALITY will accept.";
const HELP_REALITY_MAX_CLIENT_VER: &str =
    "Optional maximum Xray client version (x.y.z) REALITY will accept.";
const HELP_REALITY_MAX_TIME_DIFF: &str =
    "Optional maximum allowed clock difference between client and server, in milliseconds, \
     before REALITY rejects the connection.";
const HELP_REALITY_LIMIT_FALLBACK: &str =
    "Rate-limits connections that fail REALITY verification and get routed to the fallback \
     destination, using a token-bucket: an initial allowance (afterBytes), a sustained rate \
     (bytesPerSec), and a burst rate (burstBytesPerSec). Leave disabled unless you're seeing \
     fallback traffic used as an amplification/probing vector.";
const HELP_REALITY_LIMIT_AFTER_BYTES: &str =
    "Byte count after which rate limiting kicks in for this fallback direction.";
const HELP_REALITY_LIMIT_BYTES_PER_SEC: &str = "Sustained rate limit, in bytes/second.";
const HELP_REALITY_LIMIT_BURST_BYTES_PER_SEC: &str = "Burst rate limit, in bytes/second.";

// ─── Tab enum ────────────────────────────────────────────────────────────────

/// Detail pane tab under a selected inbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum InboundDetailTab {
    #[default]
    General,
    Protocol,
    /// Stream settings editor (IB-L3).
    Stream,
    Security,
    Sniffing,
    Users,
    /// Raw JSON escape hatch — any protocol, incl. unsupported ones (Roadmap §3:125).
    RawJson,
}

// ─── Protocol picker for Add mode ────────────────────────────────────────────

/// Allowed XHTTP `mode` values (Stream tab) — re-exported constants from xray.
const XHTTP_MODE_AUTO: &str = XHTTP_MODE_DEFAULT;

fn protocol_picker_id() -> egui::Id {
    egui::Id::new("inbounds_add_protocol_picker")
}

fn protocol_picker(ui: &Ui) -> InboundClientProtocol {
    ui.ctx()
        .data(|d| d.get_temp::<InboundClientProtocol>(protocol_picker_id()))
        .unwrap_or(InboundClientProtocol::Vless)
}

fn set_protocol_picker(ui: &Ui, protocol: InboundClientProtocol) {
    ui.ctx().data_mut(|d| d.insert_temp(protocol_picker_id(), protocol));
}

/// One-click "guided preset" (Roadmap §3:123): picks a protocol and its recommended security
/// mode, then kicks off remote key generation for modes that need it (Reality). Every field of
/// the resulting Add session remains freely editable afterward — this only saves the first few
/// clicks of the manual flow (protocol → Security tab → change mode → Generate x25519).
fn apply_inbound_preset(ui: &Ui, service: &mut ApplicationService, protocol: InboundClientProtocol) {
    set_protocol_picker(ui, protocol);
    if service.begin_add_inbound(protocol).is_err() {
        return;
    }
    if protocol == InboundClientProtocol::Vless {
        // begin_add_inbound defaults VLESS to security `none`; this preset wants Reality
        // (Trojan/Hysteria already default to Reality/TLS respectively — nothing to override).
        if let Some(session) = service.inbound_editor_session_mut()
            && let Some(security) = &mut session.security
        {
            security.mode = InboundSecurityMode::Reality;
        }
    }
    if matches!(
        protocol,
        InboundClientProtocol::Vless | InboundClientProtocol::Trojan
    ) {
        let _ = service.start_generate_x25519();
    }
}

// ─── Page entry point ────────────────────────────────────────────────────────

/// Renders the Inbounds page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    ui.heading("Inbounds");
    ui.add_space(8.0);

    let model = service.inbounds_page_model();

    match model.state {
        InboundsPageState::NoSshConnection
        | InboundsPageState::NoXrayInstallation
        | InboundsPageState::DiscoveryNotCompleted
        | InboundsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        InboundsPageState::NoInbounds => {
            // Configuration is loaded — the inbound list is just empty (e.g. a freshly
            // created config). Show the hint but fall through so the "Add Inbound" button
            // below stays reachable.
            show_state_message(ui, model.state);
            ui.add_space(8.0);
        }
        InboundsPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            for warning in &model.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(8.0);
            if model.rows.is_empty() {
                // Still fall through to the Add button — an empty list plus warnings
                // must not lock the user out of creating the first inbound.
                ui.label(RichText::new("No inbounds").size(14.0));
            }
        }
        InboundsPageState::ConfigurationLoaded => {}
    }

    // Table header with Add button.
    ui.horizontal(|ui| {
        ui.strong("Inbounds");
        ui.add_space(12.0);
        let busy = service.is_inbound_shell_mutation_busy();
        let adding = service
            .inbound_editor_session()
            .is_some_and(|s| s.is_add);
        if !adding
            && ui
                .add_enabled(!busy, egui::Button::new("Add Inbound"))
                .clicked()
        {
            let proto = protocol_picker(ui);
            if let Err(e) = service.begin_add_inbound(proto) {
                service.show_status_message(e);
            }
        }
        if !adding
            && ui
                .add_enabled(!busy, egui::Button::new("Import from Share URI"))
                .clicked()
        {
            set_pending_inbound_import(ui, PendingInboundImport::default());
        }
    });
    ui.add_space(4.0);

    show_table(ui, service, &model.rows);
    ui.add_space(12.0);

    // If we are in Add mode, show the Add form regardless of selection.
    if service
        .inbound_editor_session()
        .is_some_and(|s| s.is_add)
    {
        show_add_pane(ui, service);
    } else {
        show_detail_pane(ui, service, &model.rows);
    }

    show_delete_inbound_dialog(ui, service);
    show_duplicate_inbound_dialog(ui, service);
    show_import_dialog(ui, service);
    super::show_help_dialog(ui);
}

fn show_state_message(ui: &mut Ui, state: InboundsPageState) {
    let color = match state {
        InboundsPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        InboundsPageState::NoInbounds => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

// ─── Inbound table ───────────────────────────────────────────────────────────

fn show_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[InboundSummary]) {
    let sort = service.inbounds_sort();
    let selected = service.selected_users_inbound();

    egui::Grid::new("inbounds_table")
        .num_columns(6)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(72.0)
        .show(ui, |ui| {
            sortable_header(ui, service, "Tag", InboundsSortColumn::Tag, sort.column);
            sortable_header(
                ui,
                service,
                "Protocol",
                InboundsSortColumn::Protocol,
                sort.column,
            );
            ui.strong("Listen");
            sortable_header(ui, service, "Port", InboundsSortColumn::Port, sort.column);
            ui.strong("Clients");
            ui.strong("Source file");
            ui.end_row();

            for row in rows {
                let display = inbound_row_display(row);
                let is_selected = selected == Some(row.index);
                let tag_text = if is_selected {
                    format!("› {}", display.tag)
                } else {
                    display.tag.clone()
                };
                // Danger warnings (an open proxy) are flagged in the list, not only on selection.
                let danger = service
                    .inbound_warnings_at(row.index)
                    .into_iter()
                    .find(|warning| warning.id.severity() == WarningSeverity::Danger);
                let tag_clicked = ui
                    .horizontal(|ui| {
                        if let Some(warning) = danger {
                            danger_sign(ui, 14.0).on_hover_text(warning.text());
                        }
                        cell_with_menu(ui, service, row, &tag_text)
                    })
                    .inner;
                if tag_clicked {
                    service.set_selected_users_inbound(row.index);
                }
                cell_with_menu(ui, service, row, &display.protocol);
                cell_with_menu(ui, service, row, &display.listen);
                cell_with_menu(ui, service, row, &display.port);
                cell_with_menu(ui, service, row, &display.clients);
                cell_with_menu(ui, service, row, display.source_file);
                ui.end_row();
            }
        });
}

// ─── Add pane ────────────────────────────────────────────────────────────────

fn show_add_pane(ui: &mut Ui, service: &mut ApplicationService) {
    ui.separator();
    ui.add_space(4.0);
    ui.strong("Add New Inbound");
    ui.add_space(4.0);

    // Guided presets (Roadmap §3:123): one click for protocol + recommended security mode +
    // key generation where needed. Everything below remains a normal, freely-editable Add form.
    ui.horizontal(|ui| {
        ui.label("Presets:");
        if ui
            .button("VLESS + Reality")
            .on_hover_text("VLESS with Reality security; generates an x25519 key pair immediately")
            .clicked()
        {
            apply_inbound_preset(ui, service, InboundClientProtocol::Vless);
        }
        if ui
            .button("Trojan + Reality")
            .on_hover_text("Trojan with Reality security; generates an x25519 key pair immediately")
            .clicked()
        {
            apply_inbound_preset(ui, service, InboundClientProtocol::Trojan);
        }
        if ui
            .button("Hysteria2 (TLS)")
            .on_hover_text("Hysteria (protocol version 2) with TLS security")
            .clicked()
        {
            apply_inbound_preset(ui, service, InboundClientProtocol::Hysteria);
        }
    });
    ui.add_space(6.0);

    // Protocol picker at the top.
    let mut picker = protocol_picker(ui);
    ui.horizontal(|ui| {
        ui.label("Protocol:");
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Vless, "VLESS")
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Vless);
            let _ = service.begin_add_inbound(InboundClientProtocol::Vless);
        }
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Trojan, "Trojan")
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Trojan);
            let _ = service.begin_add_inbound(InboundClientProtocol::Trojan);
        }
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Hysteria, "Hysteria")
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Hysteria);
            let _ = service.begin_add_inbound(InboundClientProtocol::Hysteria);
        }
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Tunnel, "Tunnel")
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Tunnel);
            let _ = service.begin_add_inbound(InboundClientProtocol::Tunnel);
        }
        if ui
            .selectable_value(&mut picker, InboundClientProtocol::Tun, "TUN")
            .on_hover_text(
                "Local network-interface inbound — client-side use case; not recommended for \
                 server-side management (Roadmap §4.1)",
            )
            .changed()
        {
            set_protocol_picker(ui, InboundClientProtocol::Tun);
            let _ = service.begin_add_inbound(InboundClientProtocol::Tun);
        }
    });
    ui.add_space(6.0);

    let busy = service.is_inbound_shell_mutation_busy();
    let is_tun = service
        .inbound_editor_session()
        .is_some_and(|s| matches!(s.protocol, InboundProtocolDraft::Tun { .. }));

    // General fields.
    show_add_general(ui, service);
    ui.add_space(6.0);

    // Protocol tab (VLESS only, Trojan has no extra fields).
    if let Some(session) = service.inbound_editor_session() {
        match &session.protocol {
            crate::app::InboundProtocolDraft::Vless { .. } => {
                ui.strong("Protocol");
                show_protocol_edit(ui, service);
                ui.add_space(6.0);
            }
            crate::app::InboundProtocolDraft::Trojan { .. } => {
                ui.strong("Protocol");
                show_protocol_edit(ui, service);
                ui.add_space(6.0);
            }
            crate::app::InboundProtocolDraft::Hysteria { version } => {
                ui.strong("Protocol");
                ui.horizontal(|ui| {
                    super::help_button(ui, "Hysteria version", HELP_HYSTERIA_VERSION);
                    ui.label(format!("Hysteria version: {version} (fixed)"));
                });
                ui.add_space(6.0);
            }
            crate::app::InboundProtocolDraft::Tunnel { .. } => {
                ui.strong("Protocol");
                show_protocol_edit(ui, service);
                ui.add_space(6.0);
            }
            crate::app::InboundProtocolDraft::Tun { .. } => {
                ui.strong("Protocol");
                show_tun_protocol_edit(ui, service);
                ui.add_space(6.0);
            }
        }
    }

    // Stream (IB-L3) — not used for TUN (no streamSettings at all); Tunnel gets only FinalMask
    // (Roadmap §2.6 stage 4.2).
    if !is_tun {
        ui.strong("Stream");
        show_stream_edit(ui, service);
        ui.add_space(6.0);
    }

    // Security (VLESS: none|reality; Trojan: Reality required).
    if service
        .inbound_editor_session()
        .is_some_and(|s| s.security.is_some())
    {
        ui.strong("Security");
        ui.horizontal(|ui| {
            // Add flow: no remote certificate exists yet, so "Fetch cert pin" never applies.
            show_security_keygen_actions(ui, service, busy, None);
        });
        show_security_edit(ui, service);
        ui.add_space(6.0);
    }

    // Sniffing.
    ui.strong("Sniffing");
    show_sniffing_edit_session(ui, service);
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui
            .add_enabled(!busy, egui::Button::new("Add Inbound"))
            .clicked()
        {
            if let Err(e) = service.start_add_inbound() {
                service.show_status_message(e);
            }
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Preview changes"))
            .clicked()
        {
            if let Err(e) = service.preview_inbound_shell_diff() {
                service.show_status_message(e);
            }
        }
        if ui.button("Cancel").clicked() {
            service.cancel_inbound_editor_session();
        }
    });
    show_json_diff_preview(ui, service);
}

fn show_add_general(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    let general = &mut session.general;

    let mut tag = general.tag.clone().unwrap_or_default();
    let mut listen = general.listen.clone().unwrap_or_default();
    let mut port_text = general.port.map(|p| p.to_string()).unwrap_or_default();

    egui::Grid::new("add_general_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "Tag (required)", HELP_GENERAL_TAG);
            if ui.text_edit_singleline(&mut tag).changed() {
                general.tag = if tag.trim().is_empty() { None } else { Some(tag) };
                session.dirty = true;
            }
            ui.end_row();
            super::field_label(ui, "Listen", HELP_GENERAL_LISTEN);
            if ui.text_edit_singleline(&mut listen).changed() {
                general.listen = if listen.trim().is_empty() { None } else { Some(listen) };
                session.dirty = true;
            }
            ui.end_row();
            super::field_label(ui, "Port", HELP_GENERAL_PORT);
            if ui.text_edit_singleline(&mut port_text).changed() {
                if port_text.trim().is_empty() {
                    general.port = None;
                } else if let Ok(p) = port_text.trim().parse::<u64>() {
                    general.port = Some(p);
                }
                session.dirty = true;
            }
            ui.end_row();
        });
}

// ─── 6-tab detail pane ───────────────────────────────────────────────────────

fn show_detail_pane(ui: &mut Ui, service: &mut ApplicationService, rows: &[InboundSummary]) {
    let Some(selected_index) = service.selected_users_inbound() else {
        ui.label(
            RichText::new(
                "Select an inbound to view General | Protocol | Stream | Security | Sniffing | Users.",
            )
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    };
    let Some(row) = rows.iter().find(|r| r.index == selected_index) else {
        ui.label(
            RichText::new("Selected inbound is no longer in the loaded configuration.")
                .size(14.0)
                .color(Color32::from_rgb(200, 60, 60)),
        );
        return;
    };

    let protocol = row
        .protocol
        .as_deref()
        .and_then(InboundClientProtocol::from_wire);

    if take_focus_general(ui) {
        set_detail_tab(ui, InboundDetailTab::General);
    }

    // Danger warnings sit above the tabs: visible on every tab and for every protocol (Socks /
    // HTTP inbounds have no Stream tab, where the other warnings live).
    let danger: Vec<_> = service
        .inbound_warnings_at(row.index)
        .into_iter()
        .filter(|warning| warning.id.severity() == WarningSeverity::Danger)
        .collect();
    show_compatibility_warnings(ui, &danger);

    let mut tab = detail_tab(ui);
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let is_tunnel = matches!(protocol, Some(InboundClientProtocol::Tunnel));
    let has_stream_settings = protocol.is_none_or(InboundClientProtocol::has_stream_settings);
    let users_ok = protocol.is_some_and(|p| p.mutate_enabled());
    let is_security_proto = matches!(
        protocol,
        Some(
            InboundClientProtocol::Vless
                | InboundClientProtocol::Trojan
                | InboundClientProtocol::Hysteria
        )
    );

    ui.horizontal(|ui| {
        ui.selectable_value(&mut tab, InboundDetailTab::General, "General");
        ui.selectable_value(&mut tab, InboundDetailTab::Protocol, "Protocol");

        // Stream tab: shell-editable protocols with streamSettings — all but TUN. Tunnel's
        // transport is locked (tcp / none); it gets FinalMask there (Roadmap §2.6 stage 4.2).
        let stream_enabled = shell_ok && has_stream_settings;
        let stream_disabled_hint = if !has_stream_settings {
            "Stream is not used for TUN (no streamSettings)"
        } else {
            "Stream editing requires a shell-editable inbound"
        };
        if ui
            .add_enabled(
                stream_enabled,
                egui::Button::selectable(tab == InboundDetailTab::Stream, "Stream"),
            )
            .on_disabled_hover_text(stream_disabled_hint)
            .clicked()
            && stream_enabled
        {
            tab = InboundDetailTab::Stream;
        }

        // Security tab enabled for VLESS / Trojan / Hysteria when shell-editable.
        let security_enabled = is_security_proto && shell_ok;
        let security_disabled_hint = if is_tunnel {
            "Security is not used for Tunnel"
        } else if !shell_ok {
            "Security editing requires a shell-editable inbound"
        } else {
            "Security tab available for VLESS, Trojan, and Hysteria inbounds only"
        };
        if ui
            .add_enabled(
                security_enabled,
                egui::Button::selectable(tab == InboundDetailTab::Security, "Security"),
            )
            .on_disabled_hover_text(security_disabled_hint)
            .clicked()
            && security_enabled
        {
            tab = InboundDetailTab::Security;
        }

        ui.selectable_value(&mut tab, InboundDetailTab::Sniffing, "Sniffing");
        ui.selectable_value(&mut tab, InboundDetailTab::RawJson, "Raw JSON");
        if ui
            .add_enabled(
                users_ok,
                egui::Button::selectable(tab == InboundDetailTab::Users, "Users"),
            )
            .on_disabled_hover_text("Users are not available for Tunnel or TUN inbounds")
            .clicked()
            && users_ok
        {
            tab = InboundDetailTab::Users;
        } else if !users_ok && tab == InboundDetailTab::Users {
            tab = InboundDetailTab::General;
        }
        if (!has_stream_settings && tab == InboundDetailTab::Stream)
            || ((is_tunnel || !has_stream_settings) && tab == InboundDetailTab::Security)
        {
            tab = InboundDetailTab::Protocol;
        }
    });
    set_detail_tab(ui, tab);
    ui.add_space(8.0);

    match tab {
        InboundDetailTab::General => show_general(ui, service, row),
        InboundDetailTab::Protocol => show_protocol_tab(ui, service, row),
        InboundDetailTab::Stream => show_stream_tab(ui, service, row),
        InboundDetailTab::Security => show_security_tab(ui, service, row),
        InboundDetailTab::Sniffing => show_sniffing_tab(ui, service, row),
        InboundDetailTab::RawJson => show_inbound_raw_json_tab(ui, service, row),
        InboundDetailTab::Users => {
            if let Some(reason) = service.users_blocked_by_dirty_shell() {
                ui.label(
                    RichText::new(reason)
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            } else {
                users::show(ui, service);
            }
        }
    }

    if service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index)
    {
        ui.add_space(8.0);
        let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
        if ui
            .add_enabled(!busy, egui::Button::new("Preview changes"))
            .clicked()
        {
            if let Err(e) = service.preview_inbound_shell_diff() {
                service.show_status_message(e);
            }
        }
        show_json_diff_preview(ui, service);
    }
}

// ─── General tab ─────────────────────────────────────────────────────────────

fn show_general(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    let protocol = row
        .protocol
        .clone()
        .unwrap_or_else(|| MISSING_FIELD.to_owned());

    if !shell_ok {
        ui.label(
            RichText::new(
                "Shell editing is available for VLESS, Trojan, Hysteria, and Tunnel only.",
            )
            .size(14.0)
            .color(Color32::from_rgb(210, 170, 40)),
        );
        ui.add_space(6.0);
        show_general_readonly(ui, service, row, &protocol);
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!busy, egui::Button::new("Save"))
                .clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
        } else {
            if ui
                .add_enabled(!busy, egui::Button::new("Edit"))
                .clicked()
                && let Err(e) = service.begin_edit_inbound_shell(row.index)
            {
                service.show_status_message(e);
            }
        }
    });
    ui.add_space(8.0);

    if editing {
        show_general_edit_session(ui, service, row, &protocol);
    } else {
        show_general_readonly(ui, service, row, &protocol);
    }
}

fn show_general_readonly(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
    protocol: &str,
) {
    let general = service
        .inbound_general_view(row.index)
        .unwrap_or_else(|| InboundGeneral {
            tag: row.tag.clone(),
            listen: row.listen.clone(),
            port: row.port,
        });
    let display = inbound_row_display(row);
    egui::Grid::new("inbound_general_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("Tag");
            ui.label(general.tag.as_deref().unwrap_or(MISSING_FIELD));
            ui.end_row();
            ui.label("Protocol");
            ui.label(protocol);
            ui.end_row();
            ui.label("Listen");
            ui.label(general.listen.as_deref().unwrap_or(MISSING_FIELD));
            ui.end_row();
            ui.label("Port");
            match general.port {
                Some(port) => {
                    ui.label(port.to_string());
                }
                None => match service.inbound_port_raw_display(row.index) {
                    Some(raw) => {
                        ui.label(raw);
                    }
                    None => {
                        ui.label(MISSING_FIELD);
                    }
                },
            }
            ui.end_row();
            ui.label("Clients");
            ui.label(&display.clients);
            ui.end_row();
            ui.label("Source file");
            ui.label(display.source_file);
            ui.end_row();
        });
}

fn show_general_edit_session(
    ui: &mut Ui,
    service: &mut ApplicationService,
    row: &InboundSummary,
    protocol: &str,
) {
    let port_ok = service.inbound_port_shell_editable(row.index);
    let raw_port = service.inbound_port_raw_display(row.index);
    let tag_references = service.inbound_tag_reference_preview(row.index);
    let original_tag = row.tag.clone().unwrap_or_default();
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    let general = &mut session.general;

    let mut tag = general.tag.clone().unwrap_or_default();
    let mut listen = general.listen.clone().unwrap_or_default();
    let mut port_text = general.port.map(|p| p.to_string()).unwrap_or_default();

    egui::Grid::new("inbound_general_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "Tag", HELP_GENERAL_TAG);
            if ui.text_edit_singleline(&mut tag).changed() {
                general.tag = if tag.trim().is_empty() {
                    None
                } else {
                    Some(tag.clone())
                };
                session.dirty = true;
            }
            ui.end_row();

            ui.label("Protocol");
            ui.label(protocol);
            ui.end_row();

            super::field_label(ui, "Listen", HELP_GENERAL_LISTEN);
            if ui.text_edit_singleline(&mut listen).changed() {
                general.listen = if listen.trim().is_empty() { None } else { Some(listen) };
                session.dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "Port", HELP_GENERAL_PORT);
            if port_ok {
                if ui.text_edit_singleline(&mut port_text).changed() {
                    if port_text.trim().is_empty() {
                        general.port = None;
                    } else if let Ok(p) = port_text.trim().parse::<u64>() {
                        general.port = Some(p);
                    }
                    session.dirty = true;
                }
            } else {
                let note = match &raw_port {
                    Some(raw) => format!(
                        "{raw} — range/list port shape is preserved as-is; not editable in the shell"
                    ),
                    None => "Port shape is not editable (scalar only)".to_owned(),
                };
                ui.label(RichText::new(note).color(Color32::from_rgb(210, 170, 40)));
            }
            ui.end_row();

            ui.label("Source file");
            ui.label(row.source_file.as_str());
            ui.end_row();
        });

    let tag_changed = !tag.trim().is_empty() && tag.trim() != original_tag.trim();
    if tag_changed && !tag_references.is_empty() {
        ui.add_space(6.0);
        ui.label(
            RichText::new(format!(
                "Renaming will not update routing — still referenced by: {}",
                tag_references.join("; ")
            ))
            .size(13.0)
            .color(Color32::from_rgb(210, 170, 40)),
        );
    }
}

// ─── Protocol tab ────────────────────────────────────────────────────────────

// ─── Client-side crypto display (VLESS pairs) ────────────────────────────────

const CLIENT_FIELD_HINT: Color32 = Color32::from_rgb(140, 140, 140);

fn resolved_client_value(
    service: &ApplicationService,
    row: Option<&InboundSummary>,
    session_field: impl Fn(&InboundEditorSession) -> Option<String>,
    material_field: impl Fn(&InboundShareMaterial) -> Option<String>,
) -> Option<String> {
    if let Some(session) = service.inbound_editor_session() {
        let matches_row = row.is_none_or(|r| !session.is_add && session.inbound_index == r.index);
        if matches_row {
            if let Some(value) = session_field(session).filter(|s| !s.trim().is_empty()) {
                return Some(value);
            }
        }
    }
    row.and_then(|r| {
        service
            .inbound_share_material(r.tag.as_deref(), r.index)
            .and_then(material_field)
            .filter(|s| !s.trim().is_empty())
    })
}

fn show_client_field_value(ui: &mut Ui, value: Option<impl AsRef<str>>, generate_hint: &str) {
    if let Some(value) = value.filter(|s| !s.as_ref().trim().is_empty()) {
        ui.label(RichText::new(value.as_ref()).monospace());
    } else {
        ui.vertical(|ui| {
            ui.label(RichText::new(MISSING_FIELD).color(CLIENT_FIELD_HINT));
            ui.label(
                RichText::new(format!("Generate {generate_hint}"))
                    .size(13.0)
                    .color(CLIENT_FIELD_HINT),
            );
        });
    }
}

fn show_protocol_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    if !shell_ok {
        ui.label(
            RichText::new("Shell editing is not enabled for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!busy, egui::Button::new("Save"))
                .clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
            && let Err(e) = service.begin_edit_inbound_shell(row.index)
        {
            service.show_status_message(e);
        }
    });
    ui.add_space(8.0);

    if editing {
        show_protocol_edit(ui, service);
    } else {
        show_protocol_readonly(ui, service, row);
    }
}

fn show_protocol_readonly(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
) {
    let protocol = row.protocol.as_deref().unwrap_or(MISSING_FIELD);
    match protocol.to_ascii_lowercase().as_str() {
        "vless" => {
            // Show current decryption from loaded config.
            let decryption = service
                .loaded_config()
                .editable()
                .and_then(|e| e.sections().inbounds().get(row.index))
                .and_then(|inbound| inbound.value().get("settings"))
                .and_then(|s| s.get("decryption"))
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            let encryption = resolved_client_value(
                service,
                Some(row),
                |s| s.ephemeral_client_encryption.clone(),
                |m| m.client_encryption.clone(),
            );
            egui::Grid::new("protocol_view_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    ui.label("decryption");
                    ui.label(decryption);
                    ui.end_row();
                    ui.label("encryption");
                    show_client_field_value(ui, encryption, "vlessenc");
                    ui.end_row();
                });
            show_fallbacks_readonly_from_row(ui, service, row);
        }
        "trojan" => {
            show_fallbacks_readonly_from_row(ui, service, row);
        }
        "tunnel" => show_tunnel_protocol_readonly(ui, service, row),
        "tun" => show_tun_protocol_readonly(ui, service, row),
        _ => {
            ui.label(
                RichText::new("Protocol tab not available for this inbound type.")
                    .size(14.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
        }
    }
}

fn show_fallbacks_readonly_from_row(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
) {
    let fallbacks = service
        .loaded_config()
        .editable()
        .and_then(|e| e.sections().inbounds().get(row.index))
        .and_then(|inbound| parse_inbound_protocol(inbound.value()))
        .and_then(|draft| draft.fallbacks().map(|f| f.to_vec()))
        .unwrap_or_default();
    show_fallbacks_readonly(ui, &fallbacks);
}

fn show_fallbacks_readonly(ui: &mut Ui, fallbacks: &[FallbackObject]) {
    ui.add_space(6.0);
    ui.strong("fallbacks");
    if fallbacks.is_empty() {
        ui.label(
            RichText::new("(empty)")
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }
    egui::Grid::new("fallbacks_view_grid")
        .num_columns(5)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label(RichText::new("name").strong());
            ui.label(RichText::new("alpn").strong());
            ui.label(RichText::new("path").strong());
            ui.label(RichText::new("dest").strong());
            ui.label(RichText::new("xver").strong());
            ui.end_row();
            for entry in fallbacks {
                ui.label(if entry.name.is_empty() {
                    "—"
                } else {
                    entry.name.as_str()
                });
                ui.label(if entry.alpn.is_empty() {
                    "—"
                } else {
                    entry.alpn.as_str()
                });
                ui.label(if entry.path.is_empty() {
                    "—"
                } else {
                    entry.path.as_str()
                });
                ui.label(format!(
                    "{} ({})",
                    entry.dest.display(),
                    entry.dest.kind().label()
                ));
                ui.label(entry.xver.to_string());
                ui.end_row();
            }
        });
}

fn show_tunnel_protocol_readonly(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
) {
    let inbound_value = service
        .loaded_config()
        .editable()
        .and_then(|e| e.sections().inbounds().get(row.index))
        .map(|inbound| inbound.value());
    let draft = inbound_value.and_then(crate::xray::parse_inbound_protocol);
    let Some(InboundProtocolDraft::Tunnel {
        allowed_network,
        rewrite_address,
        rewrite_port,
        port_map,
        follow_redirect,
        user_level,
    }) = draft
    else {
        ui.label(
            RichText::new("Tunnel settings unavailable.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    };
    let tproxy = inbound_value
        .and_then(|v| v.get("streamSettings"))
        .and_then(|s| s.get("sockopt"))
        .and_then(|s| s.get("tproxy"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());

    egui::Grid::new("tunnel_protocol_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("allowedNetwork");
            ui.label(&allowed_network);
            ui.end_row();
            ui.label("rewriteAddress");
            ui.label(&rewrite_address);
            ui.end_row();
            ui.label("rewritePort");
            ui.label(
                rewrite_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "listen port".to_owned()),
            );
            ui.end_row();
            ui.label("followRedirect");
            ui.label(if follow_redirect { "true" } else { "false" });
            ui.end_row();
            ui.label("sockopt.tproxy");
            ui.label(tproxy.unwrap_or("(unset)"));
            ui.end_row();
            ui.label("userLevel");
            ui.label(user_level.to_string());
            ui.end_row();
        });

    ui.add_space(6.0);
    ui.strong("portMap");
    if port_map.is_empty() {
        ui.label(
            RichText::new("(empty)")
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    } else {
        egui::Grid::new("tunnel_portmap_view_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(RichText::new("local").strong());
                ui.label(RichText::new("target").strong());
                ui.end_row();
                for (local, target) in &port_map {
                    ui.label(local);
                    ui.label(target);
                    ui.end_row();
                }
            });
    }
}

fn show_tun_protocol_readonly(ui: &mut Ui, service: &ApplicationService, row: &InboundSummary) {
    let inbound_value = service
        .loaded_config()
        .editable()
        .and_then(|e| e.sections().inbounds().get(row.index))
        .map(|inbound| inbound.value());
    let draft = inbound_value.and_then(crate::xray::parse_inbound_protocol);
    let Some(InboundProtocolDraft::Tun {
        name,
        desc,
        mtu,
        gateway,
        dns,
        user_level,
        auto_system_routing_table,
        auto_outbounds_interface,
    }) = draft
    else {
        ui.label(
            RichText::new("TUN settings unavailable.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    };

    ui.label(
        RichText::new(
            "Local network-interface inbound (no port, no streamSettings/security). Client-side \
             use case — not recommended for server-side management (Roadmap §4.1).",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );

    egui::Grid::new("tun_protocol_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("name");
            ui.label(if name.is_empty() { "(unset)" } else { &name });
            ui.end_row();
            ui.label("desc");
            ui.label(if desc.is_empty() { "(unset)" } else { &desc });
            ui.end_row();
            ui.label("mtu");
            ui.label(if mtu == 0 { "(Xray default)".to_owned() } else { mtu.to_string() });
            ui.end_row();
            ui.label("userLevel");
            ui.label(user_level.to_string());
            ui.end_row();
            ui.label("autoOutboundsInterface");
            ui.label(if auto_outbounds_interface.is_empty() {
                "(unset)"
            } else {
                &auto_outbounds_interface
            });
            ui.end_row();
        });

    ui.add_space(6.0);
    ui.strong("gateway");
    ui.label(if gateway.is_empty() { "(empty)".to_owned() } else { gateway.join(", ") });
    ui.add_space(6.0);
    ui.strong("dns");
    ui.label(if dns.is_empty() { "(empty)".to_owned() } else { dns.join(", ") });
    ui.add_space(6.0);
    ui.strong("autoSystemRoutingTable");
    ui.label(if auto_system_routing_table.is_empty() {
        "(empty)".to_owned()
    } else {
        auto_system_routing_table.join(", ")
    });
}

fn show_protocol_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let protocol_kind = service
        .inbound_editor_session()
        .map(|s| match &s.protocol {
            InboundProtocolDraft::Vless { .. } => 0,
            InboundProtocolDraft::Trojan { .. } => 1,
            InboundProtocolDraft::Hysteria { .. } => 2,
            InboundProtocolDraft::Tunnel { .. } => 3,
            InboundProtocolDraft::Tun { .. } => 4,
        });

    let Some(kind) = protocol_kind else {
        return;
    };

    match kind {
        0 => {
            let Some(session) = service.inbound_editor_session_mut() else {
                return;
            };
            let InboundProtocolDraft::Vless { decryption, .. } = &mut session.protocol else {
                return;
            };
            let mut dec = decryption.clone();
            let mut auth = session.vlessenc_auth;
            egui::Grid::new("protocol_edit_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    super::field_label(ui, "decryption", HELP_VLESS_DECRYPTION);
                    if ui.text_edit_singleline(&mut dec).changed() {
                        *decryption = dec;
                        session.dirty = true;
                    }
                    ui.end_row();

                    super::field_label(ui, "encryption", HELP_VLESS_ENCRYPTION);
                    let encryption = session.ephemeral_client_encryption.clone();
                    show_client_field_value(ui, encryption, "vlessenc");
                    ui.end_row();

                    super::field_label(ui, "vlessenc auth", HELP_VLESSENC_AUTH);
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_value(
                                &mut auth,
                                crate::xray::VlessEncAuthKind::X25519,
                                "X25519",
                            )
                            .changed()
                        {
                            session.vlessenc_auth = auth;
                        }
                        if ui
                            .selectable_value(
                                &mut auth,
                                crate::xray::VlessEncAuthKind::MlKem768,
                                "ML-KEM-768",
                            )
                            .changed()
                        {
                            session.vlessenc_auth = auth;
                        }
                    });
                    ui.end_row();
                });

            ui.add_space(6.0);
            if ui
                .add_enabled(!busy, egui::Button::new("Generate vlessenc"))
                .on_hover_text(
                    "Runs remote xray vlessenc; fills decryption + encryption in the grid above",
                )
                .clicked()
                && let Err(e) = service.start_generate_vlessenc()
            {
                service.show_status_message(e);
            }
            show_fallbacks_edit(ui, service, busy);
        }
        1 => {
            show_fallbacks_edit(ui, service, busy);
        }
        2 => {
            let version = service
                .inbound_editor_session()
                .and_then(|s| match &s.protocol {
                    InboundProtocolDraft::Hysteria { version } => Some(*version),
                    _ => None,
                })
                .unwrap_or(2);
            ui.horizontal(|ui| {
                super::help_button(ui, "Hysteria version", HELP_HYSTERIA_VERSION);
                ui.label(format!("Hysteria version: {version} (fixed)"));
            });
        }
        3 => {
            let _ = busy;
            show_tunnel_protocol_edit(ui, service);
        }
        4 => {
            let _ = busy;
            show_tun_protocol_edit(ui, service);
        }
        _ => {}
    }
}

fn session_fallbacks_will_strip(session: &InboundEditorSession) -> bool {
    let Some(fallbacks) = session.protocol.fallbacks() else {
        return false;
    };
    if fallbacks.is_empty() {
        return false;
    }
    let transport = session
        .stream
        .method
        .unwrap_or(StreamMethod::Tcp)
        .as_wire();
    let security = session
        .security
        .as_ref()
        .map(|s| s.mode.as_wire())
        .unwrap_or("none");
    !fallbacks_transport_compatible(transport, security)
}

fn show_fallbacks_edit(ui: &mut Ui, service: &mut ApplicationService, busy: bool) {
    let will_strip = service
        .inbound_editor_session()
        .is_some_and(session_fallbacks_will_strip);

    ui.add_space(6.0);
    ui.strong("fallbacks");
    ui.label(
        RichText::new(
            "VLESS/Trojan · TCP + TLS/Reality only. TLS: a non-empty tlsSettings.alpn is required. \
             REALITY negotiates no ALPN — only fallbacks with an empty alpn are used.",
        )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );
    if will_strip {
        ui.label(
            RichText::new("Current Stream/Security is incompatible — fallbacks will be removed on Save.")
                .size(13.0)
                .color(Color32::from_rgb(200, 140, 40)),
        );
    }

    let mut dirty = false;
    {
        let Some(session) = service.inbound_editor_session_mut() else {
            return;
        };
        let reality = session
            .security
            .as_ref()
            .is_some_and(|security| security.mode == InboundSecurityMode::Reality);
        let Some(fallbacks) = session.protocol.fallbacks_mut() else {
            return;
        };

        let mut remove_idx: Option<usize> = None;
        for (idx, entry) in fallbacks.iter_mut().enumerate() {
            ui.add_space(4.0);
            ui.group(|ui| {
                egui::Grid::new(format!("fallback_edit_grid_{idx}"))
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        super::field_label(ui, "name (SNI)", HELP_FALLBACK_NAME);
                        if ui.text_edit_singleline(&mut entry.name).changed() {
                            dirty = true;
                        }
                        ui.end_row();

                        super::field_label(ui, "alpn", HELP_FALLBACK_ALPN);
                        ui.horizontal(|ui| {
                            if ui.text_edit_singleline(&mut entry.alpn).changed() {
                                dirty = true;
                            }
                            if reality && !entry.alpn.trim().is_empty() {
                                ui.label(
                                    RichText::new("never matches with REALITY (no ALPN negotiated)")
                                        .size(12.0)
                                        .color(Color32::from_rgb(220, 160, 60)),
                                );
                            }
                        });
                        ui.end_row();

                        super::field_label(ui, "path", HELP_FALLBACK_PATH);
                        if ui
                            .text_edit_singleline(&mut entry.path)
                            .on_hover_text("Empty or must start with /")
                            .changed()
                        {
                            dirty = true;
                        }
                        ui.end_row();

                        super::field_label(ui, "dest type", HELP_FALLBACK_DEST_KIND);
                        let mut kind = entry.dest.kind();
                        ComboBox::from_id_salt(format!("fallback_dest_kind_{idx}"))
                            .selected_text(kind.label())
                            .show_ui(ui, |ui| {
                                for option in [
                                    FallbackDestKind::Port,
                                    FallbackDestKind::TcpAddr,
                                    FallbackDestKind::UnixSocket,
                                ] {
                                    if ui
                                        .selectable_label(kind == option, option.label())
                                        .clicked()
                                        && kind != option
                                    {
                                        kind = option;
                                        entry.dest = FallbackDest::empty(option);
                                        dirty = true;
                                    }
                                }
                            });
                        ui.end_row();

                        super::field_label(ui, "dest", HELP_FALLBACK_DEST);
                        match &mut entry.dest {
                            FallbackDest::Port(port) => {
                                let mut value = i64::from(*port);
                                if ui
                                    .add(egui::DragValue::new(&mut value).range(1..=65535))
                                    .changed()
                                {
                                    *port = value as u16;
                                    dirty = true;
                                }
                            }
                            FallbackDest::TcpAddr(addr) => {
                                if ui
                                    .text_edit_singleline(addr)
                                    .on_hover_text("host:port")
                                    .changed()
                                {
                                    dirty = true;
                                }
                            }
                            FallbackDest::UnixSocket(path) => {
                                if ui
                                    .text_edit_singleline(path)
                                    .on_hover_text("Absolute path or @/@ abstract")
                                    .changed()
                                {
                                    dirty = true;
                                }
                            }
                        }
                        ui.end_row();

                        super::field_label(ui, "xver", HELP_FALLBACK_XVER);
                        let mut xver = entry.xver as i64;
                        ComboBox::from_id_salt(format!("fallback_xver_{idx}"))
                            .selected_text(xver.to_string())
                            .show_ui(ui, |ui| {
                                for option in [0_i64, 1, 2] {
                                    if ui
                                        .selectable_label(xver == option, option.to_string())
                                        .clicked()
                                        && xver != option
                                    {
                                        xver = option;
                                        entry.xver = option as u64;
                                        dirty = true;
                                    }
                                }
                            });
                        ui.end_row();
                    });

                if ui
                    .add_enabled(!busy, egui::Button::new("Remove"))
                    .clicked()
                {
                    remove_idx = Some(idx);
                }
            });
        }

        if let Some(idx) = remove_idx {
            fallbacks.remove(idx);
            dirty = true;
        }

        if ui
            .add_enabled(!busy, egui::Button::new("Add fallback"))
            .clicked()
        {
            fallbacks.push(FallbackObject::default());
            dirty = true;
        }
    }

    if dirty && let Some(session) = service.inbound_editor_session_mut() {
        session.dirty = true;
    }
}

fn show_tunnel_protocol_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    if !matches!(session.protocol, InboundProtocolDraft::Tunnel { .. }) {
        return;
    }

    let mut dirty = false;
    let mut tproxy = session.stream.sockopt.tproxy.clone();
    let tproxy_before = tproxy.clone();
    {
        let InboundProtocolDraft::Tunnel {
            allowed_network,
            rewrite_address,
            rewrite_port,
            port_map,
            follow_redirect,
            user_level,
        } = &mut session.protocol
        else {
            return;
        };

        let mut network = allowed_network.clone();
        let mut address = rewrite_address.clone();
        let mut port_text = rewrite_port.map(|p| p.to_string()).unwrap_or_default();
        let mut level = *user_level as i64;
        let mut follow = *follow_redirect;

        egui::Grid::new("tunnel_protocol_edit_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                super::field_label(ui, "allowedNetwork", HELP_TUNNEL_ALLOWED_NETWORK);
                ComboBox::from_id_salt("tunnel_allowed_network")
                    .selected_text(&network)
                    .show_ui(ui, |ui| {
                        for option in TUNNEL_NETWORKS {
                            if ui.selectable_label(network == *option, *option).clicked() {
                                network = (*option).to_owned();
                            }
                        }
                    });
                ui.end_row();

                super::field_label(ui, "rewriteAddress", HELP_TUNNEL_REWRITE_ADDRESS);
                if ui.text_edit_singleline(&mut address).changed() {
                    dirty = true;
                }
                ui.end_row();

                super::field_label(ui, "rewritePort", HELP_TUNNEL_REWRITE_PORT);
                if ui
                    .text_edit_singleline(&mut port_text)
                    .on_hover_text("Empty or 0 = use listen port")
                    .changed()
                {
                    dirty = true;
                }
                ui.end_row();

                super::field_label(ui, "followRedirect", HELP_TUNNEL_FOLLOW_REDIRECT);
                if ui.checkbox(&mut follow, "")
                    .on_hover_text("Xray-level fallback forwarding")
                    .changed()
                {
                    dirty = true;
                }
                ui.end_row();

                super::field_label(ui, "sockopt.tproxy", HELP_SOCKOPT_TPROXY);
                if tproxy_combo_field(ui, "tunnel_sockopt_tproxy", &mut tproxy) {
                    dirty = true;
                }
                ui.end_row();

                super::field_label(ui, "userLevel", HELP_TUNNEL_USER_LEVEL);
                if ui
                    .add(egui::DragValue::new(&mut level).range(0..=u32::MAX as i64))
                    .changed()
                {
                    dirty = true;
                }
                ui.end_row();
            });

        if network != *allowed_network {
            *allowed_network = network;
            dirty = true;
        }
        *rewrite_address = address;
        *rewrite_port = port_text.trim().parse::<u64>().ok().filter(|p| *p != 0);
        *follow_redirect = follow;
        *user_level = level.max(0) as u64;

        ui.label(
            RichText::new(
                "followRedirect is Xray-level fallback forwarding; sockopt.tproxy is OS-level \
                 transparent proxy integration (iptables REDIRECT/TPROXY) — usually only one is \
                 needed.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            super::help_button(ui, "portMap", HELP_TUNNEL_PORT_MAP);
            ui.strong("portMap");
        });
        ui.label(
            RichText::new("Target forms: host:port, :port, or host:")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );

        let mut remove_idx: Option<usize> = None;
        egui::Grid::new("tunnel_portmap_edit_grid")
            .num_columns(3)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                ui.label(RichText::new("local").strong());
                ui.label(RichText::new("target").strong());
                ui.label("");
                ui.end_row();

                for (idx, (local, target)) in port_map.iter_mut().enumerate() {
                    let mut local_edit = local.clone();
                    let mut target_edit = target.clone();
                    if ui.text_edit_singleline(&mut local_edit).changed() {
                        *local = local_edit;
                        dirty = true;
                    }
                    let target_resp = ui.text_edit_singleline(&mut target_edit);
                    if target_resp.changed() {
                        *target = target_edit.clone();
                        dirty = true;
                    }
                    if validate_port_map_target(target.trim()).is_err() && !target.trim().is_empty()
                    {
                        target_resp.on_hover_text("Expected host:port, :port, or host:");
                    }
                    if ui.small_button("Del").clicked() {
                        remove_idx = Some(idx);
                    }
                    ui.end_row();
                }
            });
        if let Some(idx) = remove_idx {
            port_map.remove(idx);
            dirty = true;
        }

        let new_id = egui::Id::new("tunnel_portmap_new");
        let (mut new_local, mut new_target) = ui.ctx().data(|d| {
            d.get_temp::<(String, String)>(new_id)
                .unwrap_or_default()
        });
        ui.horizontal(|ui| {
            ui.label("Add");
            ui.add(
                egui::TextEdit::singleline(&mut new_local)
                    .desired_width(80.0)
                    .hint_text("local"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut new_target)
                    .desired_width(160.0)
                    .hint_text("host:port"),
            );
            let can_add = !new_local.trim().is_empty()
                && validate_port_map_target(new_target.trim()).is_ok()
                && !port_map
                    .iter()
                    .any(|(local, _)| local.trim() == new_local.trim());
            if ui
                .add_enabled(can_add, egui::Button::new("Add mapping"))
                .clicked()
            {
                port_map.push((new_local.trim().to_owned(), new_target.trim().to_owned()));
                port_map.sort_by(|a, b| a.0.cmp(&b.0));
                dirty = true;
                new_local.clear();
                new_target.clear();
            }
        });
        ui.ctx()
            .data_mut(|d| d.insert_temp(new_id, (new_local, new_target)));
    }

    if tproxy != tproxy_before {
        session.stream.sockopt.tproxy = tproxy;
        session.stream.write_sockopt = true;
        dirty = true;
    }

    if dirty {
        session.dirty = true;
    }
}

fn show_tun_protocol_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    let InboundProtocolDraft::Tun {
        name,
        desc,
        mtu,
        gateway,
        dns,
        user_level,
        auto_system_routing_table,
        auto_outbounds_interface,
    } = &mut session.protocol
    else {
        return;
    };

    let mut dirty = false;
    let mut name_text = name.clone();
    let mut desc_text = desc.clone();
    let mut mtu_value = *mtu as i64;
    let mut level = *user_level as i64;
    let mut auto_outbounds_interface_text = auto_outbounds_interface.clone();

    ui.label(
        RichText::new(
            "Local network-interface inbound (no port, no streamSettings/security). Client-side \
             use case — not recommended for server-side management (Roadmap §4.1).",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );

    egui::Grid::new("tun_protocol_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("name");
            if ui.text_edit_singleline(&mut name_text).changed() {
                dirty = true;
            }
            ui.end_row();

            ui.label("desc");
            if ui.text_edit_singleline(&mut desc_text).changed() {
                dirty = true;
            }
            ui.end_row();

            ui.label("mtu");
            if ui
                .add(egui::DragValue::new(&mut mtu_value).range(0..=u32::MAX as i64))
                .on_hover_text("0 = Xray default")
                .changed()
            {
                dirty = true;
            }
            ui.end_row();

            ui.label("userLevel");
            if ui
                .add(egui::DragValue::new(&mut level).range(0..=u32::MAX as i64))
                .changed()
            {
                dirty = true;
            }
            ui.end_row();

            ui.label("autoOutboundsInterface");
            if ui.text_edit_singleline(&mut auto_outbounds_interface_text).changed() {
                dirty = true;
            }
            ui.end_row();
        });

    if persistent_multiline_list_row(ui, "gateway (one per line)", gateway, "tun_gateway") {
        dirty = true;
    }
    if persistent_multiline_list_row(ui, "dns (one per line)", dns, "tun_dns") {
        dirty = true;
    }
    if persistent_multiline_list_row(
        ui,
        "autoSystemRoutingTable (one per line, e.g. linux/windows/darwin/freebsd)",
        auto_system_routing_table,
        "tun_auto_system_routing_table",
    ) {
        dirty = true;
    }

    *name = name_text;
    *desc = desc_text;
    *mtu = mtu_value.clamp(0, u32::MAX as i64) as u32;
    *user_level = level.max(0) as u64;
    *auto_outbounds_interface = auto_outbounds_interface_text;

    if dirty {
        session.dirty = true;
    }
}

// ─── Stream tab (IB-L3) ──────────────────────────────────────────────────────

fn show_stream_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    if !shell_ok {
        ui.label(
            RichText::new("Shell editing is not enabled for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!busy, egui::Button::new("Save"))
                .clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
            && let Err(e) = service.begin_edit_inbound_shell(row.index)
        {
            service.show_status_message(e);
        }
    });
    ui.add_space(8.0);

    // Non-blocking warnings: for the draft while editing, for the saved inbound otherwise.
    // Danger ones are already shown above the tabs.
    let mut warnings = if editing {
        service.inbound_editor_warnings()
    } else {
        service.inbound_warnings_at(row.index)
    };
    warnings.retain(|warning| warning.id.severity() != WarningSeverity::Danger);
    show_compatibility_warnings(ui, &warnings);

    if editing {
        show_stream_edit(ui, service);
    } else {
        show_stream_readonly(ui, service, row);
    }
}

/// Non-blocking compatibility warnings (Roadmap §2.6 stage 0.3) — shown in yellow with their
/// JSON location, danger ones in red behind road sign 1.33; unlike gates they never block Save.
fn show_compatibility_warnings(ui: &mut Ui, warnings: &[CompatibilityWarning]) {
    if warnings.is_empty() {
        return;
    }
    for warning in warnings {
        match warning.id.severity() {
            WarningSeverity::Danger => danger_warning(ui, &warning.text()),
            WarningSeverity::Caution => {
                ui.label(
                    RichText::new(format!("Warning: {}", warning.text()))
                        .color(Color32::from_rgb(220, 160, 60)),
                );
            }
        }
    }
    ui.add_space(6.0);
}

fn show_stream_readonly(ui: &mut Ui, service: &ApplicationService, row: &InboundSummary) {
    let draft = service
        .loaded_config()
        .editable()
        .and_then(|e| e.sections().inbounds().get(row.index))
        .map(|inbound| parse_inbound_stream(inbound.value()))
        .unwrap_or_default();
    let protocol = row.protocol.as_deref().unwrap_or("").to_ascii_lowercase();

    if let Some(other) = draft.other_method.as_deref() {
        ui.label(
            RichText::new(format!(
                "Transport method `{other}` is not editable in IB-L3; preserved on save."
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    } else {
        show_stream_readonly_method_grid(ui, &draft);
    }

    // Sockopt is a streamSettings sibling (like security), not transport-specific, so it renders
    // regardless of whether the transport method above is editable.
    if matches!(protocol.as_str(), "vless" | "trojan" | "hysteria") {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        egui::CollapsingHeader::new("Sockopt")
            .default_open(false)
            .show(ui, |ui| {
                show_sockopt_readonly(ui, StreamDirection::Inbound, &draft.sockopt);
            });
    }
}

fn show_stream_readonly_method_grid(ui: &mut Ui, draft: &InboundStreamDraft) {
    let method = draft.method.unwrap_or(StreamMethod::Tcp);
    egui::Grid::new("stream_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("method");
            ui.label(method.label());
            ui.end_row();
            match method {
                StreamMethod::Tcp => {
                    ui.label("acceptProxyProtocol");
                    ui.label(bool_label(draft.tcp.accept_proxy_protocol));
                    ui.end_row();
                }
                StreamMethod::Xhttp => {
                    ui.label("path");
                    ui.label(if draft.xhttp.path().is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.xhttp.path()
                    });
                    ui.end_row();
                    ui.label("mode");
                    ui.label(if draft.xhttp.mode().is_empty() {
                        XHTTP_MODE_AUTO
                    } else {
                        draft.xhttp.mode()
                    });
                    ui.end_row();
                    ui.label("host");
                    ui.label(if draft.xhttp.host().is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.xhttp.host()
                    });
                    ui.end_row();
                    ui.label("xPaddingBytes");
                    ui.label(format_xhttp_range(draft.xhttp.core.x_padding_bytes));
                    ui.end_row();
                    ui.label("noSSEHeader");
                    ui.label(bool_label(draft.xhttp.core.no_sse_header));
                    ui.end_row();
                    ui.label("scMaxBufferedPosts");
                    ui.label(draft.xhttp.core.sc_max_buffered_posts.to_string());
                    ui.end_row();
                    ui.label("xmux");
                    ui.label(if draft.xhttp.core.xmux.is_some() {
                        "enabled"
                    } else {
                        "—"
                    });
                    ui.end_row();
                    ui.label("downloadSettings");
                    ui.label(if draft.xhttp.download.is_some() {
                        "enabled"
                    } else {
                        "—"
                    });
                    ui.end_row();
                }
                StreamMethod::Grpc => {
                    ui.label("serviceName");
                    ui.label(if draft.grpc.service_name.is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.grpc.service_name.as_str()
                    });
                    ui.end_row();
                    ui.label("multiMode");
                    ui.label(bool_label(draft.grpc.multi_mode));
                    ui.end_row();
                }
                StreamMethod::Ws => {
                    ui.label("path");
                    ui.label(if draft.ws.path.is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.ws.path.as_str()
                    });
                    ui.end_row();
                    ui.label("host");
                    ui.label(if draft.ws.host.is_empty() {
                        MISSING_FIELD
                    } else {
                        draft.ws.host.as_str()
                    });
                    ui.end_row();
                    ui.label("acceptProxyProtocol");
                    ui.label(bool_label(draft.ws.accept_proxy_protocol));
                    ui.end_row();
                    ui.label("ed");
                    ui.label(
                        draft
                            .ws
                            .ed
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    );
                    ui.end_row();
                }
                StreamMethod::Mkcp => {
                    ui.label("mtu");
                    ui.label(draft.kcp.mtu.to_string());
                    ui.end_row();
                    ui.label("tti");
                    ui.label(format!("{} ms", draft.kcp.tti));
                    ui.end_row();
                    ui.label("uplinkCapacity");
                    ui.label(format!("{} MB/s", draft.kcp.uplink_capacity));
                    ui.end_row();
                    ui.label("downlinkCapacity");
                    ui.label(format!("{} MB/s", draft.kcp.downlink_capacity));
                    ui.end_row();
                    ui.label("cwndMultiplier");
                    ui.label(
                        draft
                            .kcp
                            .cwnd_multiplier
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| format!("default ({KCP_DEFAULT_CWND_MULTIPLIER})")),
                    );
                    ui.end_row();
                    ui.label("maxSendingWindow");
                    ui.label(
                        draft
                            .kcp
                            .max_sending_window
                            .map(|v| format!("{v} bytes"))
                            .unwrap_or_else(|| {
                                format!("default ({KCP_DEFAULT_MAX_SENDING_WINDOW} bytes)")
                            }),
                    );
                    ui.end_row();
                }
                StreamMethod::Hysteria => {
                    ui.label("hysteria version");
                    ui.label(
                        draft
                            .hysteria
                            .version
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    );
                    ui.end_row();
                }
            }
        });
}

fn show_stream_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };

    let protocol = match &session.protocol {
        InboundProtocolDraft::Vless { .. } => "vless",
        InboundProtocolDraft::Trojan { .. } => "trojan",
        InboundProtocolDraft::Hysteria { .. } => "hysteria",
        InboundProtocolDraft::Tunnel { .. } => "tunnel",
        InboundProtocolDraft::Tun { .. } => "tun",
    };

    // Tunnel's transport is locked (tcp / none) and Tunnel Shell Save writes only sockopt and the
    // FinalMask chains (`apply_tunnel_stream`), so no transport fields are offered here.
    if protocol == "tunnel" {
        ui.label(
            RichText::new(
                "Tunnel transport: raw TCP / no security (locked). Only FinalMask is edited here; \
                 sockopt.tproxy is on the Protocol tab.",
            )
            .size(13.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    } else if !show_stream_transport_edit(ui, session, protocol) {
        return;
    }

    // mKCP legacy header/seed → `mkcp-legacy` layers (Roadmap §2.6 stage 5.2). Needs the
    // service (core version, diff preview), so the session borrow ends here and is taken again.
    if session.stream.method == Some(StreamMethod::Mkcp) && session.stream.kcp.has_legacy_obfuscation() {
        show_kcp_legacy_migration(ui, service);
    }
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };

    // FinalMask applies wherever the protocol has `streamSettings` (Roadmap §2.6 stage 4.2):
    // every listener Xray-core builds from them wraps its socket with the chains.
    let has_stream_settings = InboundClientProtocol::from_wire(protocol)
        .is_some_and(InboundClientProtocol::has_stream_settings);

    // Hysteria is QUIC over UDP: its FinalMask editor offers only `udp[]` (Roadmap §2.6 stage
    // 4.1). A foreign `finalmask` was already reported by the Hysteria branch above.
    let udp_only = protocol != "tunnel" && session.stream.method == Some(StreamMethod::Hysteria);
    if has_stream_settings && !(udp_only && session.stream.finalmask_foreign) {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        // Reality + a tcp layer that faces probers composes in Xray-core but weakens REALITY's
        // camouflage — a hint next to the chain, not a Save block (Roadmap §2.6 stage 5.1).
        let reality_probe_notice = matches!(
            session.security.as_ref().map(|s| s.mode),
            Some(InboundSecurityMode::Reality)
        ) && session
            .stream
            .finalmask_tcp
            .iter()
            .any(|layer| finalmask_tcp_layer_faces_probes(&layer.layer_type));
        let edit = if session.stream.finalmask_foreign {
            show_foreign_finalmask_notice(ui);
            FinalMaskEdit::default()
        } else {
            show_finalmask_edit(
                ui,
                StreamDirection::Inbound,
                &mut session.stream.finalmask_tcp,
                &mut session.stream.finalmask_udp,
                reality_probe_notice.then_some(
                    "REALITY + header-custom / sudoku / xmc in tcp: a scanner probing the port meets \
                     the mask instead of the REALITY target's real TLS site — camouflage is weakened \
                     (fragment is fine). Save is allowed.",
                ),
                udp_only,
            )
        };
        if edit.tcp {
            session.stream.write_finalmask_tcp = true;
            session.dirty = true;
        }
        if edit.udp {
            session.stream.write_finalmask_udp = true;
            session.dirty = true;
        }
    }

    // A hy2 link carries only a plain salamander `obfs`; when this chain needs more, Share is
    // disabled — say so next to the chain that causes it (Roadmap §2.6 stage 4.1). Asked after
    // this frame's edits, so the session borrow ends here and is taken again below.
    if udp_only && let Some(reason) = service.editor_hy2_share_blocked_reason() {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("Share links (hy2://) are disabled: {reason}"))
                .color(Color32::from_rgb(220, 160, 60)),
        );
    }
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };

    // Tunnel keeps its narrow tproxy editor on the Protocol tab (Roadmap §2.3:88).
    if matches!(protocol, "vless" | "trojan" | "hysteria") {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        egui::CollapsingHeader::new("Sockopt")
            .default_open(false)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(sockopt_scope_note(StreamDirection::Inbound))
                        .size(12.0)
                        .color(Color32::from_rgb(140, 140, 140)),
                );
                ui.add_space(4.0);
                if show_sockopt_edit(ui, StreamDirection::Inbound, &mut session.stream.sockopt, &[]) {
                    session.stream.write_sockopt = true;
                    session.dirty = true;
                }
            });
    }
}

/// Legacy mKCP `kcpSettings.header` / `seed` (Roadmap §2.6 stage 5.2): what is stored, what
/// the core does with it, and the explicit migration into `finalmask.udp`. The migration only
/// changes the draft and fills the JSON diff preview; Save writes it.
fn show_kcp_legacy_migration(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session() else {
        return;
    };
    let header = session.stream.kcp.extras.get("header").map(ToString::to_string);
    let has_seed = session.stream.kcp.extras.contains_key("seed");
    let blocked = service.editor_kcp_legacy_migration_blocked_reason();

    ui.add_space(6.0);
    ui.group(|ui| {
        ui.label(RichText::new("Legacy mKCP obfuscation").strong());
        if let Some(header) = &header {
            ui.label(RichText::new(format!("kcpSettings.header: {header}")).monospace().size(12.0));
        }
        if has_seed {
            // A password: never echoed.
            ui.label(RichText::new("kcpSettings.seed: (set, not shown)").monospace().size(12.0));
        }
        ui.label(
            RichText::new(
                "Xray-core v26.9.9+ ignores these keys, v26.1.31 – v26.9.8 refuses to load them. The \
                 same packets now come from mkcp-legacy layers in finalmask.udp: the cipher (seed → \
                 AES-128-GCM, no seed → the original obfuscation) and the header outside it. Clients \
                 on Xray-core up to v26.1.23 keep working with header/seed; newer clients need the \
                 same layers.",
            )
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
        if let Some(reason) = &blocked {
            ui.label(
                RichText::new(format!("Migration unavailable: {reason}"))
                    .color(Color32::from_rgb(220, 160, 60)),
            );
        }
        let clicked = ui
            .add_enabled(blocked.is_none(), egui::Button::new("Migrate header/seed to FinalMask"))
            .on_hover_text(
                "Removes kcpSettings.header/seed and adds the equivalent mkcp-legacy layers to \
                 finalmask.udp, then shows the JSON diff. Nothing is written until Save.",
            )
            .clicked();
        if clicked {
            let message = match service.migrate_editor_kcp_legacy_obfuscation() {
                Ok(message) => message,
                Err(error) => format!("mKCP migration refused: {error}"),
            };
            service.show_status_message(message);
        }
    });
}

/// Transport part of the Stream tab: method selector and the chosen method's fields. Returns
/// `false` for an exotic method on disk (read-only, preserved on save) — the rest of the tab is
/// then skipped.
fn show_stream_transport_edit(
    ui: &mut Ui,
    session: &mut InboundEditorSession,
    protocol: &str,
) -> bool {
    let vision_active = session.vision_active;
    let allowed = selectable_stream_methods(protocol, vision_active);

    if let Some(other) = session.stream.other_method.clone() {
        ui.label(
            RichText::new(format!(
                "Transport method `{other}` is not editable in IB-L3; preserved on save."
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
        return false;
    }

    let draft_method = session.stream.method;
    let display =
        coerce_display_stream_method(draft_method, &allowed).unwrap_or(StreamMethod::Tcp);
    if draft_method.is_some() && Some(display) != draft_method {
        ui.label(
            RichText::new(format!(
                "Current transport `{}` is not allowed with this protocol/Vision; showing `{}` until you pick an allowed method (draft unchanged until you edit).",
                draft_method.unwrap().as_wire(),
                display.as_wire()
            ))
            .size(13.0)
            .color(Color32::from_rgb(160, 120, 40)),
        );
        ui.add_space(4.0);
    }

    let mut selected_method: Option<StreamMethod> = None;
    ui.horizontal(|ui| {
        super::help_button(ui, "method", HELP_STREAM_METHOD);
        ui.label("method");
        for &method in &allowed {
            let mut selected = display;
            if ui
                .selectable_value(&mut selected, method, method.label())
                .changed()
            {
                selected_method = Some(method);
            }
        }
    });
    if let Some(method) = selected_method {
        let previous = session.stream.method;
        session.stream.method = Some(method);
        session.stream.other_method = None;
        if method == StreamMethod::Mkcp && previous != Some(StreamMethod::Mkcp) {
            session.stream.kcp = KcpStreamSettings::default();
        }
        if method == StreamMethod::Xhttp && previous != Some(StreamMethod::Xhttp) {
            session.stream.xhttp = XhttpStreamSettings::default();
        }
        if let Some(security) = session.security.as_mut() {
            let coerced =
                coerce_security_mode_for_transport(protocol, method.as_wire(), security.mode);
            if coerced != security.mode {
                security.mode = coerced;
            }
        }
        session.dirty = true;
    }
    ui.add_space(6.0);

    match session.stream.method.unwrap_or(StreamMethod::Tcp) {
        StreamMethod::Tcp => {
            let mut accept = session.stream.tcp.accept_proxy_protocol;
            ui.horizontal(|ui| {
                super::help_button(ui, "acceptProxyProtocol", HELP_TCP_ACCEPT_PROXY_PROTOCOL);
                if ui
                    .checkbox(&mut accept, "acceptProxyProtocol")
                    .changed()
                {
                    session.stream.tcp.accept_proxy_protocol = accept;
                    session.dirty = true;
                }
            });
        }
        StreamMethod::Xhttp => {
            let dirty = show_xhttp_settings_edit(ui, &mut session.stream.xhttp, "stream");
            if dirty {
                session.dirty = true;
            }
            // XHTTP runs over QUIC only with TLS ALPN exactly ["h3"] (Roadmap §2.6 stage 3.3).
            let http3 = session.security.as_ref().is_some_and(|security| {
                security.mode == InboundSecurityMode::Tls && alpn_selects_http3(&security.tls.alpn)
            });
            if http3 {
                ui.add_space(8.0);
                ui.separator();
                if session.stream.finalmask_foreign {
                    show_foreign_finalmask_notice(ui);
                } else if show_quic_params_edit(
                    ui,
                    StreamDirection::Inbound,
                    QuicTransport::XhttpH3,
                    &mut session.stream.quic_params,
                ) {
                    session.stream.write_quic_params = true;
                    session.dirty = true;
                }
            } else {
                ui.label(
                    RichText::new(
                        "QUIC tuning (finalmask.quicParams) applies when XHTTP runs over HTTP/3: \
                         security tls with alpn exactly [\"h3\"].",
                    )
                    .size(12.0)
                    .color(Color32::from_rgb(140, 140, 140)),
                );
            }
        }
        StreamMethod::Grpc => {
            let mut service_name = session.stream.grpc.service_name.clone();
            let mut multi = session.stream.grpc.multi_mode;
            egui::Grid::new("stream_grpc_edit_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    super::field_label(ui, "serviceName", HELP_GRPC_SERVICE_NAME);
                    if ui.text_edit_singleline(&mut service_name).changed() {
                        session.stream.grpc.service_name = service_name;
                        session.dirty = true;
                    }
                    ui.end_row();
                    super::field_label(ui, "multiMode", HELP_GRPC_MULTI_MODE);
                    if ui.checkbox(&mut multi, "").changed() {
                        session.stream.grpc.multi_mode = multi;
                        session.dirty = true;
                    }
                    ui.end_row();
                });
        }
        StreamMethod::Ws => {
            let mut path = session.stream.ws.path.clone();
            let mut host = session.stream.ws.host.clone();
            let mut accept = session.stream.ws.accept_proxy_protocol;
            let mut ed_text = session
                .stream
                .ws
                .ed
                .map(|v| v.to_string())
                .unwrap_or_default();
            egui::Grid::new("stream_ws_edit_grid")
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    super::field_label(ui, "path", HELP_WS_PATH);
                    if ui.text_edit_singleline(&mut path).changed() {
                        session.stream.ws.path = path;
                        session.dirty = true;
                    }
                    ui.end_row();
                    super::field_label(ui, "host", HELP_WS_HOST);
                    if ui.text_edit_singleline(&mut host).changed() {
                        session.stream.ws.host = host;
                        session.dirty = true;
                    }
                    ui.end_row();
                    super::field_label(ui, "acceptProxyProtocol", HELP_WS_ACCEPT_PROXY_PROTOCOL);
                    if ui.checkbox(&mut accept, "").changed() {
                        session.stream.ws.accept_proxy_protocol = accept;
                        session.dirty = true;
                    }
                    ui.end_row();
                    super::field_label(ui, "ed", HELP_WS_ED);
                    if ui.text_edit_singleline(&mut ed_text).changed() {
                        let trimmed = ed_text.trim();
                        session.stream.ws.ed = if trimmed.is_empty() {
                            None
                        } else {
                            trimmed.parse::<u64>().ok()
                        };
                        session.dirty = true;
                    }
                    ui.end_row();
                });
        }
        StreamMethod::Mkcp => {
            ui.label(
                RichText::new(format!(
                    "mKCP uses UDP — ensure firewall allows the listen port. Legacy header/seed are ignored by Xray-core; use FinalMask separately. Xray-core limits: mtu ≥ {KCP_MTU_MIN}, tti {KCP_TTI_MIN}–{KCP_TTI_MAX} ms, cwndMultiplier ≥ {KCP_CWND_MULTIPLIER_MIN}, maxSendingWindow ≥ mtu."
                ))
                .size(13.0)
                .color(Color32::from_rgb(140, 140, 140)),
            );
            ui.add_space(4.0);
            if show_kcp_settings_edit(ui, &mut session.stream.kcp, "stream") {
                session.dirty = true;
            }
            // Keys the core ignores stay on disk until removed explicitly (Roadmap §2.6 0.6);
            // the Stream-tab warnings above name each one. Legacy header/seed are kept for the
            // FinalMask migration (stage 5.2).
            if session.stream.kcp.has_ignored_fields() {
                ui.add_space(4.0);
                if ui
                    .button(format!("Remove ignored fields ({})", KCP_IGNORED_FIELDS.join(", ")))
                    .on_hover_text("Xray-core no longer reads these kcpSettings keys.")
                    .clicked()
                    && session.stream.kcp.remove_ignored_fields()
                {
                    session.dirty = true;
                }
            }
        }
        StreamMethod::Hysteria => {
            ui.label(
                RichText::new("Hysteria transport (locked). QUIC tuning via finalmask.quicParams.")
                    .size(13.0)
                    .color(Color32::from_rgb(140, 140, 140)),
            );
            if session.stream.finalmask_foreign {
                show_foreign_finalmask_notice(ui);
            } else if show_quic_params_edit(ui, StreamDirection::Inbound, QuicTransport::Hysteria, &mut session.stream.quic_params) {
                session.stream.write_quic_params = true;
                session.dirty = true;
            }
        }
    }
    true
}

// ─── Security tab (VLESS + Trojan; Reality keygen) ───────────────────────────

fn show_security_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    if !shell_ok {
        ui.label(
            RichText::new("Shell editing is not enabled for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        return;
    }

    let protocol = row.protocol.as_deref().and_then(InboundClientProtocol::from_wire);
    let is_security_proto = matches!(
        protocol,
        Some(
            InboundClientProtocol::Vless
                | InboundClientProtocol::Trojan
                | InboundClientProtocol::Hysteria
        )
    );
    if !is_security_proto {
        ui.label(
            RichText::new("Security tab is available for VLESS, Trojan, and Hysteria inbounds.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            let alpn_blocked = service
                .inbound_editor_session()
                .is_some_and(session_fallbacks_missing_alpn);
            let save = ui
                .add_enabled(!busy && !alpn_blocked, egui::Button::new("Save"))
                .on_disabled_hover_text(if alpn_blocked {
                    "Fallbacks on TLS require a non-empty ALPN list in the Security tab"
                } else {
                    ""
                });
            if save.clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
            ui.add_space(8.0);
            show_security_keygen_actions(ui, service, busy, protocol);
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
            && let Err(e) = service.begin_edit_inbound_shell(row.index)
        {
            service.show_status_message(e);
        }
    });
    ui.add_space(8.0);

    if editing {
        show_security_edit(ui, service);
    } else {
        show_security_readonly(ui, service, row);
    }
}

fn security_mode_is_reality(service: &ApplicationService) -> bool {
    service
        .inbound_editor_session()
        .and_then(|s| s.security.as_ref())
        .is_some_and(|sec| matches!(sec.mode, InboundSecurityMode::Reality))
}

fn security_mode_is_tls(service: &ApplicationService) -> bool {
    service
        .inbound_editor_session()
        .and_then(|s| s.security.as_ref())
        .is_some_and(|sec| matches!(sec.mode, InboundSecurityMode::Tls))
}

fn show_security_keygen_actions(
    ui: &mut Ui,
    service: &mut ApplicationService,
    busy: bool,
    protocol: Option<InboundClientProtocol>,
) {
    if security_mode_is_reality(service) {
        if ui
            .add_enabled(!busy, egui::Button::new("Generate x25519"))
            .on_hover_text("Run `xray x25519` on the remote host to generate a key pair")
            .clicked()
            && let Err(e) = service.start_generate_x25519()
        {
            service.show_status_message(e);
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Generate mldsa65"))
            .on_hover_text("Run `xray mldsa65` on the remote host to generate a seed/verify pair")
            .clicked()
            && let Err(e) = service.start_generate_mldsa65()
        {
            service.show_status_message(e);
        }
    }

    // hy2 `pinSHA256` (Roadmap §3:121): only meaningful for Hysteria + TLS with a cert path set.
    if matches!(protocol, Some(InboundClientProtocol::Hysteria)) && security_mode_is_tls(service) {
        let has_cert = service
            .inbound_editor_session()
            .and_then(|s| s.security.as_ref())
            .and_then(|sec| sec.tls.certificates.first())
            .is_some_and(|cert| !cert.certificate_file.trim().is_empty());
        if ui
            .add_enabled(!busy && has_cert, egui::Button::new("Fetch cert pin"))
            .on_hover_text(
                "Read the TLS certificate over SFTP and compute its SHA-256 pin for the hy2 share link",
            )
            .on_disabled_hover_text(if has_cert {
                ""
            } else {
                "Set a TLS certificateFile first"
            })
            .clicked()
            && let Err(e) = service.start_fetch_cert_pin()
        {
            service.show_status_message(e);
        }
    }
}

fn session_fallbacks_missing_alpn(session: &InboundEditorSession) -> bool {
    let has_fallbacks = session
        .protocol
        .fallbacks()
        .is_some_and(|f| !f.is_empty());
    if !has_fallbacks {
        return false;
    }
    let Some(security) = session.security.as_ref() else {
        return true;
    };
    if !matches!(
        security.mode,
        InboundSecurityMode::Tls | InboundSecurityMode::Reality
    ) {
        return true;
    }
    security.fallbacks_missing_alpn()
}

fn show_security_readonly(
    ui: &mut Ui,
    service: &ApplicationService,
    row: &InboundSummary,
) {
    let editable = service.loaded_config().editable();
    let security = editable
        .and_then(|e| e.sections().inbounds().get(row.index))
        .map(|inbound| crate::xray::parse_inbound_security(inbound.value()))
        .unwrap_or_default();

    if security.security_unknown {
        ui.label(
            RichText::new(format!(
                "Unknown security '{}': read-only. Choose none, tls, or reality before Save.",
                security
                    .unknown_security_wire
                    .as_deref()
                    .unwrap_or("?")
            ))
            .color(Color32::from_rgb(220, 160, 60)),
        );
        return;
    }

    let mode_label = match security.mode {
        InboundSecurityMode::None => "none",
        InboundSecurityMode::Tls => "tls",
        InboundSecurityMode::Reality => "reality",
    };

    let public_key = resolved_client_value(
        service,
        Some(row),
        |s| s.ephemeral_public_key.clone(),
        |m| m.public_key.clone(),
    );
    let mldsa65_verify = resolved_client_value(
        service,
        Some(row),
        |s| s.ephemeral_mldsa65_verify.clone(),
        |m| m.mldsa65_verify.clone(),
    );

    egui::Grid::new("security_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("security");
            ui.label(mode_label);
            ui.end_row();
            if matches!(security.mode, InboundSecurityMode::Tls) {
                let tls = &security.tls;
                for (idx, cert) in tls.certificates.iter().enumerate() {
                    ui.label(format!("certificate[{idx}]"));
                    let usage = if cert.usage.is_empty() {
                        "encipherment"
                    } else {
                        cert.usage.as_str()
                    };
                    let material = if !cert.certificate_file.trim().is_empty() {
                        format!("{} / {}", cert.certificate_file, cert.key_file)
                    } else if !cert.certificate.is_empty() {
                        "PEM".to_owned()
                    } else {
                        "—".to_owned()
                    };
                    ui.label(format!("{usage} · {material}"));
                    ui.end_row();
                }
                if !tls.alpn.is_empty() {
                    ui.label("alpn");
                    ui.label(tls.alpn.join(", "));
                    ui.end_row();
                }
                if !tls.server_name.is_empty() {
                    ui.label("serverName");
                    ui.label(&tls.server_name);
                    ui.end_row();
                }
                if !tls.min_version.is_empty() || !tls.max_version.is_empty() {
                    ui.label("TLS version");
                    ui.label(format!(
                        "{} .. {}",
                        if tls.min_version.is_empty() {
                            "—"
                        } else {
                            tls.min_version.as_str()
                        },
                        if tls.max_version.is_empty() {
                            "—"
                        } else {
                            tls.max_version.as_str()
                        }
                    ));
                    ui.end_row();
                }
                if !tls.fingerprint.is_empty() {
                    ui.label("fingerprint");
                    ui.label(&tls.fingerprint);
                    ui.end_row();
                }
                if tls.enable_ech {
                    ui.label("ECH");
                    ui.label("enabled");
                    ui.end_row();
                }
            }
            if matches!(security.mode, InboundSecurityMode::Reality) {
                ui.label("destination");
                ui.label(&security.reality.destination);
                ui.end_row();
                ui.label("serverNames");
                ui.label(security.reality.server_names.join(", "));
                ui.end_row();
                if security.reality.has_ignored_alpn() {
                    ui.label("alpn");
                    ui.label(
                        RichText::new("on disk — not a REALITY setting, ignored by Xray-core")
                            .color(Color32::from_rgb(220, 160, 60)),
                    );
                    ui.end_row();
                }
                ui.label("shortIds");
                ui.label(security.reality.short_ids.join(", "));
                ui.end_row();
                ui.label("privateKey");
                ui.label("••••••••");
                ui.end_row();
                ui.label("publicKey");
                show_client_field_value(ui, public_key, "x25519");
                ui.end_row();
                if security.reality.mldsa65_seed.is_some() || mldsa65_verify.is_some() {
                    ui.label("mldsa65Seed");
                    ui.label("••••••••");
                    ui.end_row();
                    ui.label("mldsa65Verify");
                    show_client_field_value(ui, mldsa65_verify, "mldsa65");
                    ui.end_row();
                }
                if security.reality.show {
                    ui.label("show");
                    ui.label("true");
                    ui.end_row();
                }
                if let Some(xver) = security.reality.xver {
                    ui.label("xver");
                    ui.label(xver.to_string());
                    ui.end_row();
                }
                if !security.reality.min_client_ver.is_empty()
                    || !security.reality.max_client_ver.is_empty()
                {
                    ui.label("client version");
                    ui.label(format!(
                        "{} .. {}",
                        if security.reality.min_client_ver.is_empty() {
                            "—"
                        } else {
                            security.reality.min_client_ver.as_str()
                        },
                        if security.reality.max_client_ver.is_empty() {
                            "—"
                        } else {
                            security.reality.max_client_ver.as_str()
                        }
                    ));
                    ui.end_row();
                }
                if let Some(max_time_diff) = security.reality.max_time_diff {
                    ui.label("maxTimeDiff");
                    ui.label(format!("{max_time_diff} ms"));
                    ui.end_row();
                }
                if security.reality.limit_fallback_upload.is_some()
                    || security.reality.limit_fallback_download.is_some()
                {
                    ui.label("rate limiting");
                    ui.label(format!(
                        "upload {} / download {}",
                        if security.reality.limit_fallback_upload.is_some() {
                            "on"
                        } else {
                            "off"
                        },
                        if security.reality.limit_fallback_download.is_some() {
                            "on"
                        } else {
                            "off"
                        }
                    ));
                    ui.end_row();
                }
            }
        });
}

fn show_security_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    if session.security.is_none() {
        ui.label(
            RichText::new("Security draft not available for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }

    let is_trojan = matches!(session.protocol, crate::app::InboundProtocolDraft::Trojan { .. });
    let is_hysteria = matches!(
        session.protocol,
        crate::app::InboundProtocolDraft::Hysteria { .. }
    );
    let method_wire = session
        .stream
        .method
        .map(|m| m.as_wire())
        .or(session.stream.other_method.as_deref())
        .unwrap_or("tcp")
        .to_owned();
    let protocol = if is_trojan {
        "trojan"
    } else if is_hysteria {
        "hysteria"
    } else {
        "vless"
    };
    let allowed_modes = allowed_security_modes(protocol, &method_wire);
    let has_fallbacks = session
        .protocol
        .fallbacks()
        .is_some_and(|f| !f.is_empty());
    let ephemeral_public_key = session.ephemeral_public_key.clone();
    let ephemeral_mldsa65_verify = session.ephemeral_mldsa65_verify.clone();

    let dirty = {
        let security = session.security.as_mut().expect("checked above");

        if security.security_unknown {
            ui.label(
                RichText::new(format!(
                    "Unknown security '{}'. Select a known mode to edit and Save.",
                    security
                        .unknown_security_wire
                        .as_deref()
                        .unwrap_or("?")
                ))
                .color(Color32::from_rgb(220, 160, 60)),
            );
            let mut applied = false;
            ui.horizontal(|ui| {
                ui.label("security");
                let mut mode = InboundSecurityMode::None;
                egui::ComboBox::from_id_salt("inbound_security_mode_unknown")
                    .selected_text("(pick mode)")
                    .show_ui(ui, |ui| {
                        for &allowed in &allowed_modes {
                            let label = match allowed {
                                InboundSecurityMode::None => "none",
                                InboundSecurityMode::Tls => "tls",
                                InboundSecurityMode::Reality => "reality",
                            };
                            ui.selectable_value(&mut mode, allowed, label);
                        }
                    });
                if ui.button("Apply mode").clicked() {
                    security.mode = mode;
                    security.security_unknown = false;
                    security.unknown_security_wire = None;
                    applied = true;
                }
            });
            applied
        } else {
            let mut dirty = false;
            ui.horizontal(|ui| {
                super::field_label(ui, "security", HELP_SECURITY_MODE);
                let mut mode = security.mode;
                if !allowed_modes.contains(&mode) {
                    if let Some(first) = allowed_modes.first() {
                        mode = *first;
                    }
                }
                egui::ComboBox::from_id_salt("inbound_security_mode")
                    .selected_text(match mode {
                        InboundSecurityMode::None => "none",
                        InboundSecurityMode::Tls => "tls",
                        InboundSecurityMode::Reality => "reality",
                    })
                    .show_ui(ui, |ui| {
                        for &allowed in &allowed_modes {
                            let label = match allowed {
                                InboundSecurityMode::None => "none",
                                InboundSecurityMode::Tls => "tls",
                                InboundSecurityMode::Reality => "reality",
                            };
                            ui.selectable_value(&mut mode, allowed, label);
                        }
                    });
                if mode != security.mode {
                    security.mode = mode;
                    dirty = true;
                }
            });
            ui.add_space(4.0);

            if has_fallbacks && security.fallbacks_missing_alpn() {
                ui.label(
                    RichText::new(
                        "Fallbacks on TLS require a non-empty ALPN list on this Security tab \
                         ([\"http/1.1\"], or [\"h2\", \"http/1.1\"] for h2 fallbacks). Save is blocked \
                         until ALPN is set.",
                    )
                    .color(Color32::from_rgb(220, 160, 60)),
                );
                ui.add_space(4.0);
            }

            match security.mode {
                InboundSecurityMode::None => {}
                InboundSecurityMode::Tls => {
                    dirty |= show_tls_settings_edit(ui, &mut security.tls);
                }
                InboundSecurityMode::Reality => {
                    dirty |= show_reality_settings_edit(
                        ui,
                        &mut security.reality,
                        ephemeral_public_key.as_deref(),
                        ephemeral_mldsa65_verify.as_deref(),
                    );
                }
            }
            dirty
        }
    };

    if dirty {
        session.dirty = true;
    }
}

fn show_tls_settings_edit(ui: &mut Ui, tls: &mut TlsSettingsDraft) -> bool {
    let mut dirty = false;
    let mut server_name = tls.server_name.clone();
    let mut verify_by_name = tls.verify_peer_cert_by_name.clone();
    let mut min_version = tls.min_version.clone();
    let mut max_version = tls.max_version.clone();
    let mut cipher_suites = tls.cipher_suites.clone();
    let mut fingerprint = tls.fingerprint.clone();
    let mut pinned = tls.pinned_peer_cert_sha256.clone();
    let mut master_key_log = tls.master_key_log.clone();
    let mut ech_server_keys = tls.ech_server_keys.clone();
    let mut ech_config_list = tls.ech_config_list.clone();
    let mut ech_sockopt_text = tls
        .ech_sockopt
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
        .unwrap_or_default();

    if tls.certificates.is_empty() {
        tls.certificates.push(CertificateDraft::default());
        dirty = true;
    }

    ui.strong("certificates");
    ui.label(
        RichText::new("Each entry needs file paths or PEM (key optional when usage is verify).")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );

    let mut remove_idx: Option<usize> = None;
    for idx in 0..tls.certificates.len() {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.label(RichText::new(format!("certificate[{idx}]")).strong());
            if show_certificate_draft_edit(ui, idx, &mut tls.certificates[idx]) {
                dirty = true;
            }
            let can_remove = tls.certificates.len() > 1;
            if ui
                .add_enabled(can_remove, egui::Button::new("Remove"))
                .on_hover_text(if can_remove {
                    "Remove this certificate entry"
                } else {
                    "At least one certificate entry is required"
                })
                .clicked()
            {
                remove_idx = Some(idx);
            }
        });
    }
    if let Some(idx) = remove_idx {
        if tls.certificates.len() > 1 {
            tls.certificates.remove(idx);
            dirty = true;
        }
    }
    if ui.button("Add certificate").clicked() {
        tls.certificates.push(CertificateDraft::default());
        dirty = true;
    }

    ui.add_space(8.0);
    ui.strong("tlsSettings");

    egui::Grid::new("tls_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "alpn", HELP_TLS_ALPN);
            if string_tag_multi_select(ui, "tls_alpn", &mut tls.alpn, ALPN_PRESETS) {
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "serverName", HELP_TLS_SERVER_NAME);
            if ui.text_edit_singleline(&mut server_name).changed() {
                tls.server_name = server_name.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "verifyPeerCertByName", HELP_TLS_VERIFY_PEER_CERT_BY_NAME);
            if ui.text_edit_singleline(&mut verify_by_name).changed() {
                tls.verify_peer_cert_by_name = verify_by_name.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "rejectUnknownSni", HELP_TLS_REJECT_UNKNOWN_SNI);
            if ui.checkbox(&mut tls.reject_unknown_sni, "").changed() {
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "allowInsecure", HELP_TLS_ALLOW_INSECURE);
            if ui.checkbox(&mut tls.allow_insecure, "").changed() {
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "minVersion", HELP_TLS_MIN_VERSION);
            {
                let before = min_version.clone();
                optional_string_combo(ui, "tls_min_ver", &mut min_version, TLS_VERSION_PRESETS);
                if min_version != before {
                    tls.min_version = min_version.clone();
                    dirty = true;
                }
            }
            ui.end_row();

            super::field_label(ui, "maxVersion", HELP_TLS_MAX_VERSION);
            {
                let before = max_version.clone();
                optional_string_combo(ui, "tls_max_ver", &mut max_version, TLS_VERSION_PRESETS);
                if max_version != before {
                    tls.max_version = max_version.clone();
                    dirty = true;
                }
            }
            ui.end_row();

            super::field_label(ui, "cipherSuites", HELP_TLS_CIPHER_SUITES);
            if resizable_multiline(ui, &mut cipher_suites, 2, "tls_ciphers").changed() {
                tls.cipher_suites = cipher_suites.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "disableSystemRoot", HELP_TLS_DISABLE_SYSTEM_ROOT);
            if ui.checkbox(&mut tls.disable_system_root, "").changed() {
                dirty = true;
            }
            ui.end_row();

            super::field_label(
                ui,
                "enableSessionResumption",
                HELP_TLS_ENABLE_SESSION_RESUMPTION,
            );
            if ui
                .checkbox(&mut tls.enable_session_resumption, "")
                .changed()
            {
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "fingerprint", HELP_TLS_FINGERPRINT);
            {
                let before = fingerprint.clone();
                optional_string_combo(ui, "tls_fp", &mut fingerprint, FINGERPRINT_PRESETS);
                if fingerprint != before {
                    tls.fingerprint = fingerprint.clone();
                    dirty = true;
                }
            }
            ui.end_row();

            super::field_label(ui, "pinnedPeerCertSha256", HELP_TLS_PINNED_PEER_CERT_SHA256);
            if ui.text_edit_singleline(&mut pinned).changed() {
                tls.pinned_peer_cert_sha256 = pinned.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "curvePreferences", HELP_TLS_CURVE_PREFERENCES);
            if string_tag_multi_select(ui, "tls_curves", &mut tls.curve_preferences, CURVE_PRESETS)
            {
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "masterKeyLog", HELP_TLS_MASTER_KEY_LOG);
            if resizable_multiline(ui, &mut master_key_log, 2, "tls_master_log").changed() {
                tls.master_key_log = master_key_log.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "Enable ECH", HELP_TLS_ENABLE_ECH);
            if ui.checkbox(&mut tls.enable_ech, "").changed() {
                if !tls.enable_ech {
                    tls.ech_server_keys.clear();
                    tls.ech_config_list.clear();
                    tls.ech_sockopt = None;
                    ech_server_keys.clear();
                    ech_config_list.clear();
                    ech_sockopt_text.clear();
                }
                dirty = true;
            }
            ui.end_row();
        });

    if tls.enable_ech {
        egui::CollapsingHeader::new("ECH settings")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("tls_ech_grid")
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        super::field_label(ui, "echServerKeys", HELP_TLS_ECH_SERVER_KEYS);
                        if resizable_multiline(ui, &mut ech_server_keys, 4, "tls_ech_server")
                            .changed()
                        {
                            tls.ech_server_keys = ech_server_keys.clone();
                            dirty = true;
                        }
                        ui.end_row();

                        super::field_label(ui, "echConfigList", HELP_TLS_ECH_CONFIG_LIST);
                        if resizable_multiline(ui, &mut ech_config_list, 4, "tls_ech_config")
                            .changed()
                        {
                            tls.ech_config_list = ech_config_list.clone();
                            dirty = true;
                        }
                        ui.end_row();

                        super::field_label(ui, "echSockopt (JSON object)", HELP_TLS_ECH_SOCKOPT);
                        if resizable_multiline(ui, &mut ech_sockopt_text, 5, "tls_ech_sockopt")
                            .changed()
                        {
                            let trimmed = ech_sockopt_text.trim();
                            if trimmed.is_empty() {
                                tls.ech_sockopt = None;
                                dirty = true;
                            } else if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
                            {
                                if value.is_object() {
                                    tls.ech_sockopt = Some(value);
                                    dirty = true;
                                }
                            }
                        }
                        ui.end_row();
                    });
            });
    }

    dirty
}

fn show_certificate_draft_edit(
    ui: &mut Ui,
    idx: usize,
    cert: &mut CertificateDraft,
) -> bool {
    let mut dirty = false;
    let mut cert_file = cert.certificate_file.clone();
    let mut key_file = cert.key_file.clone();
    let mut usage = if cert.usage.is_empty() {
        "encipherment".to_owned()
    } else {
        cert.usage.clone()
    };
    let mut ocsp_text = cert
        .ocsp_stapling
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mut cert_pem = cert.certificate.join("\n");
    let mut key_pem = cert.key.join("\n");

    egui::Grid::new(format!("tls_cert_edit_grid_{idx}"))
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "certificateFile", HELP_CERT_CERTIFICATE_FILE);
            if ui.text_edit_singleline(&mut cert_file).changed() {
                cert.certificate_file = cert_file.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "keyFile", HELP_CERT_KEY_FILE);
            if ui.text_edit_singleline(&mut key_file).changed() {
                cert.key_file = key_file.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "certificate (PEM)", HELP_CERT_CERTIFICATE_PEM);
            if resizable_multiline(
                ui,
                &mut cert_pem,
                6,
                &format!("tls_cert_pem_{idx}"),
            )
            .changed()
            {
                cert.certificate = lines_to_vec(&cert_pem);
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "key (PEM)", HELP_CERT_KEY_PEM);
            if resizable_multiline(ui, &mut key_pem, 6, &format!("tls_key_pem_{idx}")).changed()
            {
                cert.key = lines_to_vec(&key_pem);
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "usage", HELP_CERT_USAGE);
            {
                let before = usage.clone();
                egui::ComboBox::from_id_salt(format!("tls_cert_usage_{idx}"))
                    .selected_text(usage.as_str())
                    .show_ui(ui, |ui| {
                        for preset in CERT_USAGE_PRESETS {
                            ui.selectable_value(&mut usage, (*preset).to_owned(), *preset);
                        }
                    });
                if usage != before {
                    cert.usage = usage.clone();
                    if usage != "issue" {
                        cert.build_chain = false;
                    }
                    dirty = true;
                }
            }
            ui.end_row();

            if usage == "issue" {
                super::field_label(ui, "buildChain", HELP_CERT_BUILD_CHAIN);
                if ui.checkbox(&mut cert.build_chain, "").changed() {
                    dirty = true;
                }
                ui.end_row();
            }

            super::field_label(ui, "oneTimeLoading", HELP_CERT_ONE_TIME_LOADING);
            if ui.checkbox(&mut cert.one_time_loading, "").changed() {
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "ocspStapling (seconds)", HELP_CERT_OCSP_STAPLING);
            if ui.text_edit_singleline(&mut ocsp_text).changed() {
                cert.ocsp_stapling = ocsp_text.trim().parse().ok().filter(|&v| v != 0);
                dirty = true;
            }
            ui.end_row();
        });

    dirty
}

fn show_reality_settings_edit(
    ui: &mut Ui,
    reality: &mut crate::xray::RealitySettingsDraft,
    public_key: Option<&str>,
    mldsa65_verify: Option<&str>,
) -> bool {
    let mut dirty = false;
    let mut dest = reality.destination.clone();
    let mut server_names = reality.server_names.join("\n");
    let mut private_key = reality.private_key.clone();
    let mut short_ids = reality.short_ids.join("\n");
    let mut mldsa65_seed = reality.mldsa65_seed.clone().unwrap_or_default();
    let mut min_client_ver = reality.min_client_ver.clone();
    let mut max_client_ver = reality.max_client_ver.clone();
    let mut max_time_diff = reality
        .max_time_diff
        .map(|v| v.to_string())
        .unwrap_or_default();

    egui::Grid::new("reality_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "destination (host:port)", HELP_REALITY_DEST);
            if ui.text_edit_singleline(&mut dest).changed() {
                reality.destination = dest.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "show", HELP_REALITY_SHOW);
            if ui.checkbox(&mut reality.show, "").changed() {
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "xver", HELP_REALITY_XVER);
            let mut xver = reality.xver.unwrap_or(0);
            egui::ComboBox::from_id_salt("reality_xver")
                .selected_text(xver.to_string())
                .show_ui(ui, |ui| {
                    for option in [0u64, 1, 2] {
                        ui.selectable_value(&mut xver, option, option.to_string());
                    }
                });
            if xver != reality.xver.unwrap_or(0) {
                reality.xver = if xver == 0 { None } else { Some(xver) };
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "serverNames (one per line)", HELP_REALITY_SERVER_NAMES);
            if ui
                .add(egui::TextEdit::multiline(&mut server_names).desired_rows(3))
                .changed()
            {
                reality.server_names = lines_to_vec(&server_names);
                dirty = true;
            }
            ui.end_row();

            if reality.has_ignored_alpn() {
                super::field_label(ui, "alpn", HELP_REALITY_IGNORED_ALPN);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("not a REALITY setting — ignored by Xray-core")
                            .color(Color32::from_rgb(220, 160, 60)),
                    );
                    if ui
                        .button("Remove alpn")
                        .on_hover_text("Drops streamSettings.realitySettings.alpn on Save.")
                        .clicked()
                        && reality.remove_ignored_alpn()
                    {
                        dirty = true;
                    }
                });
                ui.end_row();
            }

            super::field_label(ui, "privateKey", HELP_REALITY_PRIVATE_KEY);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut private_key)
                        .password(true)
                        .hint_text("generated by x25519 or entered manually"),
                )
                .changed()
            {
                reality.private_key = private_key.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "publicKey", HELP_REALITY_PUBLIC_KEY);
            show_client_field_value(ui, public_key.map(str::to_owned), "x25519");
            ui.end_row();

            super::field_label(ui, "shortIds (one per line)", HELP_REALITY_SHORT_IDS);
            if ui
                .add(egui::TextEdit::multiline(&mut short_ids).desired_rows(3))
                .changed()
            {
                reality.short_ids = lines_to_vec(&short_ids);
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "mldsa65Seed", HELP_REALITY_MLDSA65_SEED);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut mldsa65_seed)
                        .password(true)
                        .hint_text("optional; generated by mldsa65"),
                )
                .changed()
            {
                reality.mldsa65_seed = if mldsa65_seed.trim().is_empty() {
                    None
                } else {
                    Some(mldsa65_seed.clone())
                };
                dirty = true;
            }
            ui.end_row();

            let show_mldsa65_verify = reality
                .mldsa65_seed
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
                || mldsa65_verify.is_some_and(|s| !s.trim().is_empty());
            if show_mldsa65_verify {
                super::field_label(ui, "mldsa65Verify", HELP_REALITY_MLDSA65_VERIFY);
                show_client_field_value(ui, mldsa65_verify.map(str::to_owned), "mldsa65");
                ui.end_row();
            }

            super::field_label(ui, "minClientVer", HELP_REALITY_MIN_CLIENT_VER);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut min_client_ver)
                        .hint_text("optional; x.y.z"),
                )
                .changed()
            {
                reality.min_client_ver = min_client_ver.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "maxClientVer", HELP_REALITY_MAX_CLIENT_VER);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut max_client_ver)
                        .hint_text("optional; x.y.z"),
                )
                .changed()
            {
                reality.max_client_ver = max_client_ver.clone();
                dirty = true;
            }
            ui.end_row();

            super::field_label(ui, "maxTimeDiff (ms)", HELP_REALITY_MAX_TIME_DIFF);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut max_time_diff)
                        .hint_text("optional; milliseconds"),
                )
                .changed()
            {
                let trimmed = max_time_diff.trim();
                if trimmed.is_empty() {
                    reality.max_time_diff = None;
                    dirty = true;
                } else if let Ok(value) = trimmed.parse::<u64>() {
                    reality.max_time_diff = Some(value);
                    dirty = true;
                }
            }
            ui.end_row();
        });

    if show_reality_limit_fallback_edit(ui, "upload", &mut reality.limit_fallback_upload) {
        dirty = true;
    }
    if show_reality_limit_fallback_edit(ui, "download", &mut reality.limit_fallback_download) {
        dirty = true;
    }

    dirty
}

/// Editor for one `limitFallbackUpload` / `limitFallbackDownload` sub-object; returns true when
/// the draft changed.
fn show_reality_limit_fallback_edit(
    ui: &mut Ui,
    label: &str,
    limit: &mut Option<crate::xray::RealityLimitFallbackDraft>,
) -> bool {
    let mut dirty = false;
    let mut enabled = limit.is_some();
    ui.horizontal(|ui| {
        super::help_button(ui, "limitFallback", HELP_REALITY_LIMIT_FALLBACK);
        if ui
            .checkbox(&mut enabled, format!("Limit fallback {label}"))
            .changed()
        {
            *limit = if enabled {
                Some(crate::xray::RealityLimitFallbackDraft::default())
            } else {
                None
            };
            dirty = true;
        }
    });

    if let Some(limit) = limit.as_mut() {
        let mut after_bytes = limit.after_bytes.map(|v| v.to_string()).unwrap_or_default();
        let mut bytes_per_sec = limit
            .bytes_per_sec
            .map(|v| v.to_string())
            .unwrap_or_default();
        let mut burst_bytes_per_sec = limit
            .burst_bytes_per_sec
            .map(|v| v.to_string())
            .unwrap_or_default();

        egui::Grid::new(format!("reality_limit_fallback_{label}_grid"))
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                super::field_label(ui, "afterBytes", HELP_REALITY_LIMIT_AFTER_BYTES);
                if ui.text_edit_singleline(&mut after_bytes).changed() {
                    limit.after_bytes = after_bytes.trim().parse::<u64>().ok();
                    dirty = true;
                }
                ui.end_row();

                super::field_label(ui, "bytesPerSec", HELP_REALITY_LIMIT_BYTES_PER_SEC);
                if ui.text_edit_singleline(&mut bytes_per_sec).changed() {
                    limit.bytes_per_sec = bytes_per_sec.trim().parse::<u64>().ok();
                    dirty = true;
                }
                ui.end_row();

                super::field_label(ui, "burstBytesPerSec", HELP_REALITY_LIMIT_BURST_BYTES_PER_SEC);
                if ui.text_edit_singleline(&mut burst_bytes_per_sec).changed() {
                    limit.burst_bytes_per_sec = burst_bytes_per_sec.trim().parse::<u64>().ok();
                    dirty = true;
                }
                ui.end_row();
            });
    }

    dirty
}

/// Multi-select from presets; selected values shown as removable tags.
pub(super) fn string_tag_multi_select(
    ui: &mut Ui,
    id: &str,
    selected: &mut Vec<String>,
    presets: &[&str],
) -> bool {
    let mut dirty = false;
    ui.vertical(|ui| {
        ui.horizontal_wrapped(|ui| {
            let mut remove_idx = None;
            for (idx, tag) in selected.iter().enumerate() {
                ui.horizontal(|ui| {
                    // Theme-aware: a fixed near-white read as greyed-out on the light theme.
                    ui.label(RichText::new(tag.as_str()).size(12.0).strong());
                    if ui.small_button("×").clicked() {
                        remove_idx = Some(idx);
                    }
                });
            }
            if let Some(idx) = remove_idx {
                selected.remove(idx);
                dirty = true;
            }
        });

        let available: Vec<&str> = presets
            .iter()
            .copied()
            .filter(|p| !selected.iter().any(|s| s == p))
            .collect();
        let mut to_add: Option<String> = None;
        egui::ComboBox::from_id_salt(id)
            .selected_text("Add…")
            .show_ui(ui, |ui| {
                for preset in &available {
                    if ui.selectable_label(false, *preset).clicked() {
                        to_add = Some((*preset).to_owned());
                    }
                }
                for tag in selected.iter() {
                    if !presets.contains(&tag.as_str()) {
                        ui.label(
                            RichText::new(format!("custom: {tag}"))
                                .size(11.0)
                                .color(Color32::from_rgb(140, 140, 140)),
                        );
                    }
                }
            });
        if let Some(value) = to_add {
            if !selected.iter().any(|s| s == &value) {
                selected.push(value);
                dirty = true;
            }
        }
    });
    dirty
}

// ─── Sniffing tab ─────────────────────────────────────────────────────────────

fn show_sniffing_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let shell_ok = service.inbound_shell_edit_enabled(row.index);
    let busy = service.is_inbound_shell_mutation_busy() || service.is_user_mutation_busy();
    let editing = service
        .inbound_editor_session()
        .is_some_and(|s| !s.is_add && s.inbound_index == row.index);

    if !shell_ok {
        ui.label(
            RichText::new("Shell editing is not available for this inbound.")
                .size(14.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
        return;
    }

    ui.horizontal(|ui| {
        if editing {
            if ui
                .add_enabled(!busy, egui::Button::new("Save"))
                .clicked()
                && let Err(e) = service.start_save_inbound_shell()
            {
                service.show_status_message(e);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                service.cancel_inbound_editor_session();
            }
        } else if ui
            .add_enabled(!busy, egui::Button::new("Edit"))
            .clicked()
            && let Err(e) = service.begin_edit_inbound_shell(row.index)
        {
            service.show_status_message(e);
        }
    });
    ui.add_space(8.0);

    if editing {
        show_sniffing_edit_session(ui, service);
    } else if let Some(settings) = service.inbound_sniffing_view(row.index) {
        show_sniffing_readonly(ui, &settings);
    }
}

// ─── Raw JSON escape hatch (Roadmap §3:125) ──────────────────────────────────

/// Local edit state for the Raw JSON tab — deliberately kept out of `InboundEditorSession`
/// (which is protocol-typed); this tab is a standalone action available for **any** protocol,
/// including ones with no structured editor at all.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawJsonEditState {
    inbound_index: usize,
    text: String,
    expected_fingerprint: String,
    error: Option<String>,
    /// Last redacted structural diff preview (Roadmap §3:126); cleared only by re-clicking
    /// Preview — same "stale until re-computed" semantics as Shell Save Preview (IB-L5).
    diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
}

fn raw_json_edit_id() -> egui::Id {
    egui::Id::new("inbound_raw_json_edit")
}

fn raw_json_edit_state(ui: &Ui) -> Option<RawJsonEditState> {
    ui.ctx()
        .data(|d| d.get_temp::<RawJsonEditState>(raw_json_edit_id()))
}

fn set_raw_json_edit_state(ui: &Ui, state: RawJsonEditState) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(raw_json_edit_id(), state));
}

fn clear_raw_json_edit_state(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<RawJsonEditState>(raw_json_edit_id()));
}

fn show_inbound_raw_json_tab(ui: &mut Ui, service: &mut ApplicationService, row: &InboundSummary) {
    let busy = service.is_inbound_shell_mutation_busy();
    let editing = raw_json_edit_state(ui).is_some_and(|s| s.inbound_index == row.index);

    ui.label(
        RichText::new(
            "Escape hatch: edits the entire inbound object as raw JSON — for fields the \
             structured tabs don't cover, or for protocols Feldjäger has no structured editor \
             for at all. Save replaces the whole object; invalid JSON or a stale fingerprint \
             (config changed underneath) is rejected before anything is written.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
    ui.add_space(6.0);

    ui.horizontal(|ui| {
        if editing {
            if ui.add_enabled(!busy, egui::Button::new("Save")).clicked()
                && let Some(state) = raw_json_edit_state(ui)
            {
                match service.start_replace_inbound_raw_json(
                    state.inbound_index,
                    &state.text,
                    state.expected_fingerprint.clone(),
                ) {
                    Ok(()) => clear_raw_json_edit_state(ui),
                    Err(message) => set_raw_json_edit_state(
                        ui,
                        RawJsonEditState {
                            error: Some(message),
                            ..state
                        },
                    ),
                }
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Preview changes"))
                .clicked()
                && let Some(state) = raw_json_edit_state(ui)
            {
                match service.preview_replace_inbound_raw_json_diff(
                    state.inbound_index,
                    &state.text,
                    state.expected_fingerprint.clone(),
                ) {
                    Ok(entries) => set_raw_json_edit_state(
                        ui,
                        RawJsonEditState {
                            diff_preview: Some(entries),
                            error: None,
                            ..state
                        },
                    ),
                    Err(message) => set_raw_json_edit_state(
                        ui,
                        RawJsonEditState {
                            error: Some(message),
                            ..state
                        },
                    ),
                }
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Cancel"))
                .clicked()
            {
                clear_raw_json_edit_state(ui);
            }
        } else if ui.add_enabled(!busy, egui::Button::new("Edit")).clicked()
            && let Some((text, expected_fingerprint)) = service.inbound_raw_json_view(row.index)
        {
            set_raw_json_edit_state(
                ui,
                RawJsonEditState {
                    inbound_index: row.index,
                    text,
                    expected_fingerprint,
                    error: None,
                    diff_preview: None,
                },
            );
        }
    });
    ui.add_space(6.0);

    // Re-read the temp store here rather than trusting the frame-start `editing`
    // snapshot: the button closure above may have cleared the state (Cancel, or a
    // successful Save), in which case `editing` is now stale and an `.expect()` here
    // would panic.
    if let Some(mut state) = raw_json_edit_state(ui).filter(|s| s.inbound_index == row.index) {
        if let Some(error) = &state.error {
            ui.label(
                RichText::new(error.clone())
                    .size(13.0)
                    .color(Color32::from_rgb(200, 60, 60)),
            );
            ui.add_space(4.0);
        }
        if let Some(entries) = state.diff_preview.clone() {
            super::json_diff_preview(ui, &entries);
            ui.add_space(4.0);
        }
        egui::ScrollArea::vertical()
            .max_height(480.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut state.text)
                        .desired_rows(24)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );
            });
        set_raw_json_edit_state(ui, state);
    } else if let Some((text, _)) = service.inbound_raw_json_view(row.index) {
        let mut text = text;
        egui::ScrollArea::vertical()
            .max_height(480.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut text)
                        .desired_rows(24)
                        .desired_width(f32::INFINITY)
                        .code_editor()
                        .interactive(false),
                );
            });
    }
}

fn show_sniffing_readonly(ui: &mut Ui, settings: &SniffingSettings) {
    egui::Grid::new("inbound_sniffing_view_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            ui.label("enabled");
            ui.label(bool_label(settings.enabled.unwrap_or(false)));
            ui.end_row();
            ui.label("destOverride");
            ui.label(format_dest_override(settings));
            ui.end_row();
            ui.label("metadataOnly");
            ui.label(bool_label(settings.metadata_only.unwrap_or(false)));
            ui.end_row();
            ui.label("routeOnly");
            ui.label(bool_label(settings.route_only.unwrap_or(false)));
            ui.end_row();
        });
    if !settings.unknown_dest_override.is_empty() {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!(
                "Preserved unknown destOverride: {}",
                settings.unknown_dest_override.join(", ")
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
    if !settings.extras.is_empty() {
        ui.label(
            RichText::new(format!(
                "Preserved sniffing extras: {}",
                settings.extras.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_sniffing_edit_session(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.inbound_editor_session_mut() else {
        return;
    };
    if show_sniffing_fields(ui, &mut session.sniffing) {
        session.dirty = true;
    }
}

/// Editor for a `SniffingConfig` — the inbound `sniffing` and the Loopback outbound's
/// `settings.sniffing` (Roadmap §4.2) share it. Returns true when a field changed.
pub(crate) fn show_sniffing_fields(ui: &mut Ui, settings: &mut SniffingSettings) -> bool {
    let mut dirty = false;
    let mut enabled = settings.enabled.unwrap_or(false);
    let mut metadata_only = settings.metadata_only.unwrap_or(false);
    let mut route_only = settings.route_only.unwrap_or(false);

    ui.horizontal(|ui| {
        super::help_button(ui, "enabled", HELP_SNIFFING_ENABLED);
        if ui.checkbox(&mut enabled, "enabled").changed() {
            settings.enabled = Some(enabled);
            dirty = true;
        }
    });

    super::field_label(ui, "destOverride", HELP_SNIFFING_DEST_OVERRIDE);
    ui.horizontal(|ui| {
        for token in KNOWN_DEST_OVERRIDE {
            let mut checked = settings.dest_override.iter().any(|t| t == *token);
            if ui.checkbox(&mut checked, *token).changed() {
                if checked {
                    if !settings.dest_override.iter().any(|t| t == *token) {
                        settings.dest_override.push((*token).to_owned());
                    }
                } else {
                    settings.dest_override.retain(|t| t != *token);
                }
                dirty = true;
            }
        }
    });
    if !settings.unknown_dest_override.is_empty() {
        ui.label(
            RichText::new(format!(
                "Preserved: {}",
                settings.unknown_dest_override.join(", ")
            ))
            .size(14.0)
            .color(Color32::from_rgb(140, 140, 140)),
        );
    }

    ui.horizontal(|ui| {
        super::help_button(ui, "metadataOnly", HELP_SNIFFING_METADATA_ONLY);
        if ui.checkbox(&mut metadata_only, "metadataOnly").changed() {
            settings.metadata_only = Some(metadata_only);
            dirty = true;
        }
    });
    ui.horizontal(|ui| {
        super::help_button(ui, "routeOnly", HELP_SNIFFING_ROUTE_ONLY);
        if ui.checkbox(&mut route_only, "routeOnly").changed() {
            settings.route_only = Some(route_only);
            dirty = true;
        }
    });
    dirty
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn bool_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn format_dest_override(settings: &SniffingSettings) -> String {
    let mut parts = settings.dest_override.clone();
    parts.extend(settings.unknown_dest_override.iter().cloned());
    if parts.is_empty() {
        MISSING_FIELD.to_owned()
    } else {
        parts.join(", ")
    }
}

fn detail_tab_id() -> egui::Id {
    egui::Id::new("inbounds_detail_tab")
}

fn focus_general_id() -> egui::Id {
    egui::Id::new("inbounds_focus_general")
}

fn detail_tab(ui: &Ui) -> InboundDetailTab {
    ui.ctx()
        .data(|data| data.get_temp::<InboundDetailTab>(detail_tab_id()))
        .unwrap_or_default()
}

fn set_detail_tab(ui: &Ui, tab: InboundDetailTab) {
    ui.ctx().data_mut(|data| {
        data.insert_temp(detail_tab_id(), tab);
    });
}

fn request_focus_general(ui: &Ui) {
    ui.ctx().data_mut(|data| {
        data.insert_temp(focus_general_id(), true);
    });
}

fn take_focus_general(ui: &Ui) -> bool {
    ui.ctx().data_mut(|data| {
        data.remove_temp::<bool>(focus_general_id()).unwrap_or(false)
    })
}

fn sortable_header(
    ui: &mut Ui,
    service: &mut ApplicationService,
    label: &str,
    column: InboundsSortColumn,
    active: InboundsSortColumn,
) {
    let sort = service.inbounds_sort();
    let marker = if active == column {
        if sort.ascending { " ▲" } else { " ▼" }
    } else {
        ""
    };
    let text = format!("{label}{marker}");
    if ui
        .add(egui::Label::new(RichText::new(text).strong()).sense(Sense::click()))
        .clicked()
    {
        service.set_inbounds_sort_column(column);
    }
}

fn cell_with_menu(
    ui: &mut Ui,
    service: &mut ApplicationService,
    row: &InboundSummary,
    text: &str,
) -> bool {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    let clicked = response.clicked();
    if clicked {
        service.set_selected_users_inbound(row.index);
    }
    show_inbound_context_menu(&response, service, row);
    clicked
}

/// IB-L5: redacted structural JSON diff stored on the editor session.
fn show_json_diff_preview(ui: &mut Ui, service: &ApplicationService) {
    let Some(entries) = service
        .inbound_editor_session()
        .and_then(|s| s.diff_preview.clone())
    else {
        return;
    };
    super::json_diff_preview(ui, &entries);
}

fn show_inbound_context_menu(
    response: &egui::Response,
    service: &mut ApplicationService,
    row: &InboundSummary,
) {
    response.context_menu(|ui| {
        if ui.button("Copy tag").clicked() {
            let text = row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }
        if ui.button("Copy port").clicked() {
            let text = row
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }
        if ui.button("Copy protocol").clicked() {
            let text = row
                .protocol
                .clone()
                .unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }

        ui.separator();

        let shell_ok = service.inbound_shell_edit_enabled(row.index);
        let busy = service.is_inbound_shell_mutation_busy();
        if ui
            .add_enabled(shell_ok && !busy, egui::Button::new("Edit"))
            .on_disabled_hover_text(
                "Shell edit is available for VLESS, Trojan, Hysteria, and Tunnel only",
            )
            .clicked()
        {
            request_focus_general(ui);
            if let Err(error) = service.begin_edit_inbound_shell(row.index) {
                service.show_status_message(error);
            }
            ui.close();
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Delete"))
            .on_disabled_hover_text("Delete requires an idle connection")
            .clicked()
        {
            set_pending_inbound_delete(
                ui,
                PendingInboundDelete {
                    index: row.index,
                    tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    unsupported: !shell_ok,
                    references: service.inbound_tag_reference_preview(row.index),
                    error: None,
                },
            );
            ui.close();
        }
        if ui
            .add_enabled(shell_ok && !busy, egui::Button::new("Duplicate"))
            .on_disabled_hover_text(
                "Duplicate is available for VLESS, Trojan, Hysteria, and Tunnel only",
            )
            .clicked()
        {
            set_pending_inbound_duplicate(
                ui,
                PendingInboundDuplicate {
                    index: row.index,
                    tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    error: None,
                    diff_preview: None,
                },
            );
            ui.close();
        }
    });
}

#[derive(Clone)]
struct PendingInboundDuplicate {
    index: usize,
    tag: String,
    error: Option<String>,
    /// Last redacted structural diff preview (Roadmap §3:126); stale until re-clicked.
    diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
}

fn pending_inbound_duplicate_id() -> egui::Id {
    egui::Id::new("inbounds_pending_duplicate")
}

fn pending_inbound_duplicate(ui: &Ui) -> Option<PendingInboundDuplicate> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingInboundDuplicate>(pending_inbound_duplicate_id()))
}

fn set_pending_inbound_duplicate(ui: &Ui, pending: PendingInboundDuplicate) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_inbound_duplicate_id(), pending));
}

fn clear_pending_inbound_duplicate(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingInboundDuplicate>(pending_inbound_duplicate_id()));
}

fn show_duplicate_inbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_inbound_duplicate(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Duplicate inbound")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(format!(
                    "Duplicate inbound «{}»? A copy with a unique tag is added to the same source file.",
                    pending.tag
                ))
                .size(14.0),
            );
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            if let Some(entries) = pending.diff_preview.clone() {
                ui.add_space(8.0);
                super::json_diff_preview(ui, &entries);
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_inbound_shell_mutation_busy();
                if ui
                    .add_enabled(!busy, egui::Button::new("Duplicate"))
                    .clicked()
                {
                    match service.start_duplicate_inbound(pending.index) {
                        Ok(()) => closed = true,
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("Preview changes"))
                    .clicked()
                {
                    match service.preview_duplicate_inbound_diff(pending.index) {
                        Ok(entries) => {
                            pending.diff_preview = Some(entries);
                            pending.error = None;
                        }
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui.button("Cancel").clicked() {
                    closed = true;
                }
            });
        });

    if closed || !open {
        clear_pending_inbound_duplicate(ui);
    } else {
        set_pending_inbound_duplicate(ui, pending);
    }
}

// ─── Import from Share URI (Roadmap §3:133) ─────────────────────────────────

#[derive(Clone, Default)]
struct PendingInboundImport {
    uri_text: String,
    preview: Option<ImportPreview>,
    error: Option<String>,
    /// Inbound index picked from the "add to existing" list, when that mode is used.
    target_inbound: Option<usize>,
}

fn pending_inbound_import_id() -> egui::Id {
    egui::Id::new("inbounds_pending_import")
}

fn pending_inbound_import(ui: &Ui) -> Option<PendingInboundImport> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingInboundImport>(pending_inbound_import_id()))
}

fn set_pending_inbound_import(ui: &Ui, pending: PendingInboundImport) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_inbound_import_id(), pending));
}

fn clear_pending_inbound_import(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingInboundImport>(pending_inbound_import_id()));
}

/// Wire `protocol` string matching [`InboundSummary::protocol`], for filtering the "add to
/// existing inbound" picker to inbounds the imported credential could actually work with.
fn import_protocol_wire(protocol: InboundClientProtocol) -> &'static str {
    match protocol {
        InboundClientProtocol::Vless => "vless",
        InboundClientProtocol::Trojan => "trojan",
        InboundClientProtocol::Hysteria => "hysteria",
        InboundClientProtocol::Tunnel => "tunnel",
        InboundClientProtocol::Tun => "tun",
    }
}

fn show_import_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_inbound_import(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Import from Share URI")
        .collapsible(false)
        .resizable(false)
        .default_width(480.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(
                    "Paste a vless:// / trojan:// / hy2:// (or hysteria2://) link. Only what the \
                     link actually carries can be imported — REALITY's private key and TLS \
                     certificates are never in a client link, so those still need to be \
                     generated/configured separately after import.",
                )
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
            );
            ui.add_space(6.0);
            ui.text_edit_multiline(&mut pending.uri_text);
            if let Some(error) = &pending.error {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(13.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(8.0);
            if ui.button("Parse").clicked() {
                match service.preview_inbound_import(pending.uri_text.trim()) {
                    Ok(preview) => {
                        pending.error = None;
                        pending.target_inbound = None;
                        pending.preview = Some(preview);
                    }
                    Err(message) => {
                        pending.error = Some(message);
                        pending.preview = None;
                    }
                }
            }

            let Some(preview) = pending.preview.clone() else {
                return;
            };

            ui.add_space(10.0);
            ui.separator();
            egui::Grid::new("inbound_import_preview_grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Protocol:");
                    ui.label(import_protocol_wire(preview.protocol));
                    ui.end_row();
                    ui.label("Port:");
                    ui.label(preview.port.map(|p| p.to_string()).unwrap_or_else(|| MISSING_FIELD.to_owned()));
                    ui.end_row();
                    ui.label("Security:");
                    ui.label(&preview.security_summary);
                    ui.end_row();
                    ui.label("Transport:");
                    ui.label(&preview.transport_summary);
                    ui.end_row();
                    ui.label("Credential:");
                    ui.label(&preview.user_id);
                    ui.end_row();
                    if let Some(flow) = &preview.flow {
                        ui.label("Flow:");
                        ui.label(flow);
                        ui.end_row();
                    }
                    if let Some(finalmask) = &preview.finalmask_summary {
                        ui.label("FinalMask:");
                        ui.label(finalmask).on_hover_text(
                            "Server layers from the link's fm / obfs — applied when creating a new \
                             inbound; adding a user to an existing inbound keeps its own chains.",
                        );
                        ui.end_row();
                    }
                });

            for warning in &preview.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(12.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }

            ui.add_space(10.0);
            ui.separator();
            ui.strong("Create new inbound");
            ui.label(
                RichText::new(
                    "Opens Add Inbound pre-filled from the link above. Add the client \
                     afterward via the Users tab (credential shown above).",
                )
                .size(11.0)
                .color(Color32::from_rgb(140, 140, 140)),
            );
            if ui.button("Create new inbound").clicked() {
                apply_import_to_new_inbound(ui, service, &preview);
                closed = true;
            }

            ui.add_space(10.0);
            ui.strong("Add user to existing inbound");
            let candidates: Vec<(usize, String)> = service
                .inbounds_page_model()
                .rows
                .iter()
                .filter(|row| row.protocol.as_deref() == Some(import_protocol_wire(preview.protocol)))
                .map(|row| (row.index, row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned())))
                .collect();
            if candidates.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "No existing {} inbounds to add this user to.",
                        import_protocol_wire(preview.protocol)
                    ))
                    .size(12.0)
                    .color(Color32::from_rgb(140, 140, 140)),
                );
            } else {
                ui.horizontal(|ui| {
                    let selected_label = pending
                        .target_inbound
                        .and_then(|idx| candidates.iter().find(|(i, _)| *i == idx))
                        .map(|(_, tag)| tag.clone())
                        .unwrap_or_else(|| "Choose inbound…".to_owned());
                    ComboBox::from_id_salt("inbound_import_target")
                        .selected_text(selected_label)
                        .show_ui(ui, |ui| {
                            for (index, tag) in &candidates {
                                ui.selectable_value(&mut pending.target_inbound, Some(*index), tag);
                            }
                        });
                    if ui
                        .add_enabled(pending.target_inbound.is_some(), egui::Button::new("Add user"))
                        .clicked()
                        && let Some(target) = pending.target_inbound
                    {
                        service.set_selected_users_inbound(target);
                        set_detail_tab(ui, InboundDetailTab::Users);
                        match preview.protocol {
                            InboundClientProtocol::Vless => users::open_add_dialog_prefilled(
                                ui,
                                target,
                                preview.email_hint.clone(),
                                preview.user_id.clone(),
                                preview.flow.as_deref(),
                            ),
                            InboundClientProtocol::Trojan => users::open_add_trojan_dialog_prefilled(
                                ui,
                                target,
                                preview.email_hint.clone(),
                                preview.user_id.clone(),
                            ),
                            InboundClientProtocol::Hysteria => users::open_add_hysteria_dialog_prefilled(
                                ui,
                                target,
                                preview.email_hint.clone(),
                                preview.user_id.clone(),
                            ),
                            InboundClientProtocol::Tunnel | InboundClientProtocol::Tun => {}
                        }
                        closed = true;
                    }
                });
            }

            ui.add_space(10.0);
            if ui.button("Cancel").clicked() {
                closed = true;
            }
        });

    if closed || !open {
        clear_pending_inbound_import(ui);
    } else {
        set_pending_inbound_import(ui, pending);
    }
}

/// Applies an import preview onto a fresh Add Inbound session — mirrors `apply_inbound_preset`
/// (Roadmap §3:123): every field stays freely editable afterward, nothing here is final until
/// the user clicks the form's own "Add Inbound" Save button.
fn apply_import_to_new_inbound(ui: &Ui, service: &mut ApplicationService, preview: &ImportPreview) {
    set_protocol_picker(ui, preview.protocol);
    if service.begin_add_inbound(preview.protocol).is_err() {
        return;
    }

    let parsed = &preview.parsed;
    let mut needs_x25519 = false;

    if let Some(session) = service.inbound_editor_session_mut() {
        if let Some(port) = parsed.port {
            session.general.port = Some(u64::from(port));
        }

        if let Some(security) = &mut session.security {
            match &parsed.security {
                ShareSecurity::None => {
                    security.mode = InboundSecurityMode::None;
                }
                ShareSecurity::Tls {
                    server_name,
                    insecure,
                    alpn,
                } => {
                    security.mode = InboundSecurityMode::Tls;
                    if let Some(sni) = server_name.as_deref().filter(|s| !s.is_empty()) {
                        security.tls.server_name = sni.to_owned();
                    }
                    security.tls.allow_insecure = *insecure;
                    if !alpn.is_empty() {
                        security.tls.alpn = alpn.clone();
                    }
                }
                ShareSecurity::Reality {
                    server_name,
                    short_id,
                    ..
                } => {
                    security.mode = InboundSecurityMode::Reality;
                    if !server_name.is_empty() {
                        security.reality.server_names = vec![server_name.clone()];
                    }
                    if !short_id.is_empty() {
                        security.reality.short_ids = vec![short_id.clone()];
                    }
                    needs_x25519 = true;
                }
            }
        }

        if preview.protocol != InboundClientProtocol::Hysteria {
            match &parsed.transport {
                ShareTransport::Tcp => {}
                ShareTransport::Xhttp { path, host, mode, .. } => {
                    session.stream.method = Some(StreamMethod::Xhttp);
                    session.stream.xhttp.core.path = path.clone();
                    if let Some(host) = host {
                        session.stream.xhttp.core.host = host.clone();
                    }
                    if let Some(mode) = mode {
                        session.stream.xhttp.core.mode = mode.clone();
                    }
                }
                ShareTransport::Grpc { service_name } => {
                    session.stream.method = Some(StreamMethod::Grpc);
                    session.stream.grpc.service_name = service_name.clone();
                }
                ShareTransport::Ws { path, host } => {
                    session.stream.method = Some(StreamMethod::Ws);
                    session.stream.ws.path = path.clone();
                    if let Some(host) = host {
                        session.stream.ws.host = host.clone();
                    }
                }
                ShareTransport::Kcp => {
                    session.stream.method = Some(StreamMethod::Mkcp);
                }
            }
        }
        // FinalMask from `fm` / hy2 `obfs`, already turned into server chains by the preview
        // (Roadmap §2.6 stage 6.2).
        if let Some(layers) = &preview.finalmask_tcp {
            session.stream.finalmask_tcp = layers.clone();
            session.stream.write_finalmask_tcp = true;
        }
        if let Some(layers) = &preview.finalmask_udp {
            session.stream.finalmask_udp = layers.clone();
            session.stream.write_finalmask_udp = true;
        }
    }

    if needs_x25519 {
        let _ = service.start_generate_x25519();
    }

    let credential_label = match preview.protocol {
        InboundClientProtocol::Vless => "UUID",
        InboundClientProtocol::Trojan => "password",
        InboundClientProtocol::Hysteria => "auth",
        InboundClientProtocol::Tunnel | InboundClientProtocol::Tun => "credential",
    };
    service.show_status_message(format!(
        "Inbound draft created from import. Save it, then add the user via the Users tab — \
         {credential_label}: {}",
        preview.user_id
    ));
}

#[derive(Clone)]
struct PendingInboundDelete {
    index: usize,
    tag: String,
    /// Protocol is not shell-editable (stronger confirm copy).
    unsupported: bool,
    /// Routing `inboundTag` rules referencing this tag (Roadmap §3:117); non-empty means the
    /// server-side hard-block in `delete_inbound` will refuse the delete until they are removed.
    references: Vec<String>,
    error: Option<String>,
}

fn pending_inbound_delete_id() -> egui::Id {
    egui::Id::new("inbounds_pending_delete")
}

fn pending_inbound_delete(ui: &Ui) -> Option<PendingInboundDelete> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingInboundDelete>(pending_inbound_delete_id()))
}

fn set_pending_inbound_delete(ui: &Ui, pending: PendingInboundDelete) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_inbound_delete_id(), pending));
}

fn clear_pending_inbound_delete(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingInboundDelete>(pending_inbound_delete_id()));
}

fn show_delete_inbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(pending) = pending_inbound_delete(ui) else {
        return;
    };
    let mut open = true;
    egui::Window::new("Delete inbound")
        .collapsible(false)
        .resizable(false)
        .default_width(380.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(format!(
                    "Delete inbound «{}»? This removes it from the remote configuration.",
                    pending.tag
                ))
                .size(14.0),
            );
            if pending.unsupported {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "This protocol is not editable in Feldjäger. Deletion cannot be undone from the UI (restore from backup if needed).",
                    )
                    .size(13.0)
                    .color(Color32::from_rgb(160, 120, 40)),
                );
            }
            if !pending.references.is_empty() {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "Still referenced in routing — remove these first: {}",
                        pending.references.join("; ")
                    ))
                    .size(13.0)
                    .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_inbound_shell_mutation_busy();
                let can_submit = !busy && pending.references.is_empty();
                if ui
                    .add_enabled(can_submit, egui::Button::new("Delete"))
                    .on_disabled_hover_text(if pending.references.is_empty() {
                        "Delete requires an idle connection"
                    } else {
                        "Remove the routing references above first"
                    })
                    .clicked()
                {
                    match service.start_delete_inbound(pending.index) {
                        Ok(()) => clear_pending_inbound_delete(ui),
                        Err(message) => {
                            set_pending_inbound_delete(
                                ui,
                                PendingInboundDelete {
                                    error: Some(message),
                                    ..pending.clone()
                                },
                            );
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    clear_pending_inbound_delete(ui);
                }
            });
        });

    if !open {
        clear_pending_inbound_delete(ui);
    }
}

/// mKCP `kcpSettings` grid (the same `KCPConfig` fields on both sides) — shared by the inbound
/// and outbound (Roadmap §4.2) Stream editors. Returns whether anything changed.
pub(super) fn show_kcp_settings_edit(ui: &mut Ui, kcp: &mut KcpStreamSettings, id_prefix: &str) -> bool {
    let mut dirty = false;
    let mut mtu = kcp.mtu.to_string();
    let mut tti = kcp.tti.to_string();
    let mut uplink = kcp.uplink_capacity.to_string();
    let mut downlink = kcp.downlink_capacity.to_string();
    let mut cwnd = kcp
        .cwnd_multiplier
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mut window = kcp
        .max_sending_window
        .map(|v| v.to_string())
        .unwrap_or_default();
    egui::Grid::new(format!("{id_prefix}_mkcp_edit_grid"))
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "mtu", HELP_MKCP_MTU);
            if ui.text_edit_singleline(&mut mtu).changed() {
                if let Ok(v) = mtu.trim().parse::<u64>() {
                    kcp.mtu = v;
                    dirty = true;
                }
            }
            ui.end_row();
            super::field_label(ui, "tti (ms)", HELP_MKCP_TTI);
            if ui.text_edit_singleline(&mut tti).changed() {
                if let Ok(v) = tti.trim().parse::<u64>() {
                    kcp.tti = v;
                    dirty = true;
                }
            }
            ui.end_row();
            super::field_label(ui, "uplinkCapacity (MB/s)", HELP_MKCP_UPLINK);
            if ui.text_edit_singleline(&mut uplink).changed() {
                if let Ok(v) = uplink.trim().parse::<u64>() {
                    kcp.uplink_capacity = v;
                    dirty = true;
                }
            }
            ui.end_row();
            super::field_label(ui, "downlinkCapacity (MB/s)", HELP_MKCP_DOWNLINK);
            if ui.text_edit_singleline(&mut downlink).changed() {
                if let Ok(v) = downlink.trim().parse::<u64>() {
                    kcp.downlink_capacity = v;
                    dirty = true;
                }
            }
            ui.end_row();
            super::field_label(ui, "cwndMultiplier", HELP_MKCP_CWND_MULTIPLIER);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut cwnd)
                        .hint_text(format!("default {KCP_DEFAULT_CWND_MULTIPLIER}")),
                )
                .changed()
            {
                let trimmed = cwnd.trim();
                if trimmed.is_empty() {
                    kcp.cwnd_multiplier = None;
                    dirty = true;
                } else if let Ok(v) = trimmed.parse::<u64>() {
                    kcp.cwnd_multiplier = Some(v);
                    dirty = true;
                }
            }
            ui.end_row();
            super::field_label(
                ui,
                "maxSendingWindow (bytes)",
                HELP_MKCP_MAX_SENDING_WINDOW,
            );
            if ui
                .add(
                    egui::TextEdit::singleline(&mut window)
                        .hint_text(format!("default {KCP_DEFAULT_MAX_SENDING_WINDOW}")),
                )
                .changed()
            {
                let trimmed = window.trim();
                if trimmed.is_empty() {
                    kcp.max_sending_window = None;
                    dirty = true;
                } else if let Ok(v) = trimmed.parse::<u64>() {
                    kcp.max_sending_window = Some(v);
                    dirty = true;
                }
            }
            ui.end_row();
        });
    dirty
}

// ─── XHTTP Stream helpers (Wave C3) ──────────────────────────────────────────

/// XHTTP fields (Basic, Headers, Padding, Packet knobs, Placement, XMUX, downloadSettings) —
/// one model for both sides, shared by the inbound and outbound (Roadmap §4.2) Stream editors.
/// `id_prefix` keeps the widget ids of the two editors apart. Returns whether anything changed.
pub(super) fn show_xhttp_settings_edit(ui: &mut Ui, xhttp: &mut XhttpStreamSettings, id_prefix: &str) -> bool {
    let mut dirty = false;
    egui::ScrollArea::vertical()
        .id_salt(format!("{id_prefix}_xhttp_scroll"))
        .show(ui, |ui| {
            ui.heading("Basic");
            egui::Grid::new(format!("{id_prefix}_xhttp_basic_grid"))
                .num_columns(2)
                .spacing([16.0, 6.0])
                .show(ui, |ui| {
                    dirty |= xhttp_edit_core_basic(ui, &mut xhttp.core, "main");
                });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                super::help_button(ui, "Headers", HELP_XHTTP_HEADERS_SECTION);
                ui.heading("Headers");
            });
            dirty |= xhttp_edit_headers(ui, &mut xhttp.core.headers, "main");
            ui.add_space(8.0);
            if xhttp_spoiler_header(
                ui,
                "padding",
                "Padding / SSE / gRPC",
                HELP_XHTTP_PADDING_SECTION,
                false,
            ) {
                egui::Grid::new(format!("{id_prefix}_xhttp_padding_grid"))
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        dirty |= xhttp_edit_core_padding(ui, &mut xhttp.core, "main");
                    });
            }
            ui.add_space(8.0);
            if xhttp_spoiler_header(
                ui,
                "sc",
                "Packet / stream knobs",
                HELP_XHTTP_SC_SECTION,
                false,
            ) {
                egui::Grid::new(format!("{id_prefix}_xhttp_sc_grid"))
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        dirty |= xhttp_edit_core_sc(ui, &mut xhttp.core, "main");
                    });
            }
            ui.add_space(8.0);
            if xhttp_spoiler_header(
                ui,
                "placement",
                "Placement / obfuscation",
                HELP_XHTTP_PLACEMENT_SECTION,
                false,
            ) {
                egui::Grid::new(format!("{id_prefix}_xhttp_place_grid"))
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        dirty |= xhttp_edit_core_placement(ui, &mut xhttp.core, "main");
                    });
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                super::help_button(ui, "xmux", HELP_XHTTP_XMUX_SECTION);
                ui.heading("XMUX");
            });
            let mut xmux_enabled = xhttp.core.xmux.is_some();
            if ui.checkbox(&mut xmux_enabled, "Enable XMUX").changed() {
                dirty = true;
                xhttp.core.xmux =
                    xmux_enabled.then(crate::xray::XmuxDraft::default);
            }
            if let Some(xmux) = xhttp.core.xmux.as_mut() {
                egui::Grid::new(format!("{id_prefix}_xhttp_xmux_grid"))
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        dirty |= xhttp_edit_xmux(ui, xmux, "main");
                    });
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                super::help_button(ui, "downloadSettings", HELP_XHTTP_DOWNLOAD_SECTION);
                ui.heading("downloadSettings");
            });
            let mut enabled = xhttp.download.is_some();
            if ui.checkbox(&mut enabled, "Enable downloadSettings").changed() {
                dirty = true;
                if enabled {
                    let mut dl = XhttpDownloadDraft::default();
                    dl.xhttp.path = xhttp.core.path.clone();
                    xhttp.download = Some(dl);
                } else {
                    xhttp.download = None;
                }
            }
            if let Some(download) = xhttp.download.as_mut() {
                egui::Grid::new(format!("{id_prefix}_xhttp_download_grid"))
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        dirty |= xhttp_edit_download(ui, download);
                    });
                ui.add_space(4.0);
                ui.label(RichText::new("Nested xhttp (download leg)").strong());
                egui::Grid::new(format!("{id_prefix}_xhttp_download_xhttp_grid"))
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        dirty |= xhttp_edit_core_basic(ui, &mut download.xhttp, "dl");
                        dirty |= xhttp_edit_core_padding(ui, &mut download.xhttp, "dl");
                        dirty |= xhttp_edit_core_sc(ui, &mut download.xhttp, "dl");
                    });
            }
        });
    dirty
}


/// Section heading with a spoiler-style disclosure arrow to the left of the title,
/// so long key/value content on following rows cannot push it out of view.
/// Returns whether the body should currently be drawn (open state).
fn xhttp_spoiler_header(
    ui: &mut Ui,
    id_salt: &str,
    title: &'static str,
    help_text: &'static str,
    default_open: bool,
) -> bool {
    let id = ui.make_persistent_id(("xhttp_spoiler", id_salt));
    let mut state =
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, default_open);
    let openness = state.openness(ui.ctx());

    ui.horizontal(|ui| {
        let size = egui::Vec2::splat(ui.spacing().icon_width);
        let (rect, _) = ui.allocate_exact_size(size, Sense::click());
        let response = ui.interact(rect, id, Sense::click());
        egui::collapsing_header::paint_default_icon(
            ui,
            openness,
            &response.clone().with_new_rect(rect),
        );
        if response.clicked() {
            state.toggle(ui);
        }
        super::help_button(ui, title, help_text);
        ui.heading(title);
    });

    state.store(ui.ctx());
    state.is_open()
}

fn format_xhttp_range(range: XhttpRange) -> String {
    if range.from == range.to {
        range.from.to_string()
    } else {
        format!("{}-{}", range.from, range.to)
    }
}

fn xhttp_edit_core_basic(ui: &mut Ui, core: &mut XhttpCoreSettings, salt: &str) -> bool {
    let mut dirty = false;
    super::field_label(ui, "host", HELP_XHTTP_HOST);
    let mut host = core.host.clone();
    if ui.text_edit_singleline(&mut host).changed() {
        core.host = host;
        dirty = true;
    }
    ui.end_row();

    super::field_label(ui, "path", HELP_XHTTP_PATH);
    let mut path = core.path.clone();
    if ui.text_edit_singleline(&mut path).changed() {
        core.path = if path.trim().is_empty() {
            XHTTP_PATH_DEFAULT.to_owned()
        } else {
            path
        };
        dirty = true;
    }
    ui.end_row();

    super::field_label(ui, "mode", HELP_XHTTP_MODE);
    dirty |= xhttp_string_combo(
        ui,
        &format!("stream_xhttp_mode_{salt}"),
        &mut core.mode,
        XHTTP_MODES,
        XHTTP_MODE_AUTO,
    );
    ui.end_row();
    dirty
}

fn xhttp_edit_core_padding(ui: &mut Ui, core: &mut XhttpCoreSettings, salt: &str) -> bool {
    let mut dirty = false;
    ui.label("xPaddingBytes");
    dirty |= xhttp_range_editors(ui, &mut core.x_padding_bytes, &format!("pad_{salt}"));
    ui.end_row();

    ui.label("noGRPCHeader");
    dirty |= xhttp_bool_combo(ui, &format!("no_grpc_{salt}"), &mut core.no_grpc_header);
    ui.end_row();

    ui.label("noSSEHeader");
    dirty |= xhttp_bool_combo(ui, &format!("no_sse_{salt}"), &mut core.no_sse_header);
    ui.end_row();
    dirty
}

fn xhttp_edit_core_sc(ui: &mut Ui, core: &mut XhttpCoreSettings, salt: &str) -> bool {
    let mut dirty = false;
    ui.label("scMaxEachPostBytes");
    dirty |= xhttp_range_editors(ui, &mut core.sc_max_each_post_bytes, &format!("sc_each_{salt}"));
    ui.end_row();

    ui.label("scMinPostsIntervalMs");
    dirty |= xhttp_range_editors(
        ui,
        &mut core.sc_min_posts_interval_ms,
        &format!("sc_min_{salt}"),
    );
    ui.end_row();

    ui.label("scMaxBufferedPosts");
    let mut buffered = core.sc_max_buffered_posts.to_string();
    if ui.text_edit_singleline(&mut buffered).changed() {
        if let Ok(v) = buffered.trim().parse::<i64>() {
            core.sc_max_buffered_posts = v;
            dirty = true;
        }
    }
    ui.end_row();

    ui.label("scStreamUpServerSecs");
    dirty |= xhttp_range_editors(
        ui,
        &mut core.sc_stream_up_server_secs,
        &format!("sc_stream_{salt}"),
    );
    ui.end_row();

    ui.label("serverMaxHeaderBytes");
    let mut header_bytes = core.server_max_header_bytes.to_string();
    if ui.text_edit_singleline(&mut header_bytes).changed() {
        if let Ok(v) = header_bytes.trim().parse::<i64>() {
            core.server_max_header_bytes = v;
            dirty = true;
        }
    }
    ui.end_row();
    dirty
}

fn xhttp_edit_core_placement(ui: &mut Ui, core: &mut XhttpCoreSettings, salt: &str) -> bool {
    let mut dirty = false;
    ui.label("xPaddingObfsMode");
    dirty |= xhttp_bool_combo(ui, &format!("obfs_{salt}"), &mut core.x_padding_obfs_mode);
    ui.end_row();

    ui.label("xPaddingPlacement");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("pad_place_{salt}"),
        &mut core.x_padding_placement,
        XHTTP_PLACEMENTS,
    );
    ui.end_row();

    ui.label("xPaddingMethod");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("pad_method_{salt}"),
        &mut core.x_padding_method,
        XHTTP_PADDING_METHODS,
    );
    ui.end_row();

    ui.label("xPaddingKey");
    let mut key = core.x_padding_key.clone();
    if ui.text_edit_singleline(&mut key).changed() {
        core.x_padding_key = key;
        dirty = true;
    }
    ui.end_row();

    ui.label("xPaddingHeader");
    let mut header = core.x_padding_header.clone();
    if ui.text_edit_singleline(&mut header).changed() {
        core.x_padding_header = header;
        dirty = true;
    }
    ui.end_row();

    ui.label("uplinkHTTPMethod");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("uplink_method_{salt}"),
        &mut core.uplink_http_method,
        XHTTP_UPLINK_METHODS,
    );
    ui.end_row();

    ui.label("sessionIDPlacement");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("sid_place_{salt}"),
        &mut core.session_id_placement,
        XHTTP_PLACEMENTS,
    );
    ui.end_row();

    ui.label("sessionIDKey");
    let mut sid_key = core.session_id_key.clone();
    if ui.text_edit_singleline(&mut sid_key).changed() {
        core.session_id_key = sid_key;
        dirty = true;
    }
    ui.end_row();

    ui.label("seqPlacement");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("seq_place_{salt}"),
        &mut core.seq_placement,
        XHTTP_PLACEMENTS,
    );
    ui.end_row();

    ui.label("seqKey");
    let mut seq_key = core.seq_key.clone();
    if ui.text_edit_singleline(&mut seq_key).changed() {
        core.seq_key = seq_key;
        dirty = true;
    }
    ui.end_row();

    ui.label("uplinkDataPlacement");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("up_place_{salt}"),
        &mut core.uplink_data_placement,
        XHTTP_PLACEMENTS,
    );
    ui.end_row();

    ui.label("uplinkDataKey");
    let mut up_key = core.uplink_data_key.clone();
    if ui.text_edit_singleline(&mut up_key).changed() {
        core.uplink_data_key = up_key;
        dirty = true;
    }
    ui.end_row();

    ui.label("uplinkChunkSize");
    dirty |= xhttp_range_editors(ui, &mut core.uplink_chunk_size, &format!("chunk_{salt}"));
    ui.end_row();

    ui.label("sessionIDTable");
    dirty |= xhttp_optional_string_combo(
        ui,
        &format!("sid_table_{salt}"),
        &mut core.session_id_table,
        XHTTP_SESSION_ID_TABLES,
    );
    ui.end_row();

    ui.label("sessionIDLength");
    dirty |= xhttp_range_editors(ui, &mut core.session_id_length, &format!("sid_len_{salt}"));
    ui.end_row();
    dirty
}

fn xhttp_edit_xmux(
    ui: &mut Ui,
    xmux: &mut crate::xray::XmuxDraft,
    salt: &str,
) -> bool {
    let mut dirty = false;
    ui.label("maxConcurrency");
    dirty |= xhttp_range_editors(ui, &mut xmux.max_concurrency, &format!("xmux_conc_{salt}"));
    ui.end_row();
    ui.label("maxConnections");
    dirty |= xhttp_range_editors(ui, &mut xmux.max_connections, &format!("xmux_conn_{salt}"));
    ui.end_row();
    ui.label("cMaxReuseTimes");
    dirty |= xhttp_range_editors(ui, &mut xmux.c_max_reuse_times, &format!("xmux_reuse_{salt}"));
    ui.end_row();
    ui.label("hMaxRequestTimes");
    dirty |= xhttp_range_editors(ui, &mut xmux.h_max_request_times, &format!("xmux_req_{salt}"));
    ui.end_row();
    ui.label("hMaxReusableSecs");
    dirty |= xhttp_range_editors(ui, &mut xmux.h_max_reusable_secs, &format!("xmux_secs_{salt}"));
    ui.end_row();
    ui.label("hKeepAlivePeriod");
    let mut keep = xmux.h_keep_alive_period.to_string();
    if ui.text_edit_singleline(&mut keep).changed() {
        if let Ok(v) = keep.trim().parse::<i64>() {
            xmux.h_keep_alive_period = v;
            dirty = true;
        }
    }
    ui.end_row();
    dirty
}

fn xhttp_edit_download(ui: &mut Ui, download: &mut XhttpDownloadDraft) -> bool {
    let mut dirty = false;
    ui.label("address");
    let mut address = download.address.clone();
    if ui.text_edit_singleline(&mut address).changed() {
        download.address = address;
        dirty = true;
    }
    ui.end_row();

    ui.label("port");
    let mut port = download.port.to_string();
    if ui.text_edit_singleline(&mut port).changed() {
        if let Ok(v) = port.trim().parse::<u64>() {
            download.port = v;
            dirty = true;
        }
    }
    ui.end_row();

    ui.label("network");
    ui.label("xhttp");
    ui.end_row();

    ui.label("security");
    dirty |= xhttp_string_combo(
        ui,
        "stream_xhttp_dl_security",
        &mut download.security,
        XHTTP_DOWNLOAD_SECURITIES,
        "tls",
    );
    ui.end_row();

    ui.label("serverName");
    let mut sni = download.server_name.clone();
    if ui.text_edit_singleline(&mut sni).changed() {
        download.server_name = sni;
        dirty = true;
    }
    ui.end_row();
    dirty
}

fn xhttp_edit_headers(ui: &mut Ui, headers: &mut Vec<(String, String)>, salt: &str) -> bool {
    let mut dirty = false;
    let mut remove_at = None;
    for (idx, (key, value)) in headers.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            let mut k = key.clone();
            let mut v = value.clone();
            if ui
                .add(egui::TextEdit::singleline(&mut k).desired_width(120.0).hint_text("key"))
                .changed()
            {
                *key = k;
                dirty = true;
            }
            if ui
                .add(egui::TextEdit::singleline(&mut v).desired_width(180.0).hint_text("value"))
                .changed()
            {
                *value = v;
                dirty = true;
            }
            if ui.button("−").clicked() {
                remove_at = Some(idx);
            }
        });
    }
    if let Some(idx) = remove_at {
        headers.remove(idx);
        dirty = true;
    }
    if ui
        .button(format!("+ header ({salt})"))
        .on_hover_text("Add header row")
        .clicked()
    {
        headers.push((String::new(), String::new()));
        dirty = true;
    }
    dirty
}

fn xhttp_range_editors(ui: &mut Ui, range: &mut XhttpRange, salt: &str) -> bool {
    let mut dirty = false;
    ui.horizontal(|ui| {
        ui.label("from");
        let mut from = range.from.to_string();
        if ui
            .add(egui::TextEdit::singleline(&mut from).id_salt(format!("{salt}_from")).desired_width(80.0))
            .changed()
        {
            if let Ok(v) = from.trim().parse::<i64>() {
                range.from = v;
                dirty = true;
            }
        }
        ui.label("to");
        let mut to = range.to.to_string();
        if ui
            .add(egui::TextEdit::singleline(&mut to).id_salt(format!("{salt}_to")).desired_width(80.0))
            .changed()
        {
            if let Ok(v) = to.trim().parse::<i64>() {
                range.to = v;
                dirty = true;
            }
        }
    });
    dirty
}

fn xhttp_bool_combo(ui: &mut Ui, id: &str, value: &mut bool) -> bool {
    let mut dirty = false;
    ComboBox::from_id_salt(id)
        .selected_text(if *value { "true" } else { "false" })
        .width(100.0)
        .show_ui(ui, |ui| {
            for option in [false, true] {
                let label = if option { "true" } else { "false" };
                if ui.selectable_label(*value == option, label).clicked() && *value != option {
                    *value = option;
                    dirty = true;
                }
            }
        });
    dirty
}

fn xhttp_string_combo(
    ui: &mut Ui,
    id: &str,
    value: &mut String,
    options: &[&str],
    default_label: &str,
) -> bool {
    let mut dirty = false;
    let current = value.clone();
    let selected_label = if current.trim().is_empty() {
        default_label
    } else {
        current.as_str()
    };
    ComboBox::from_id_salt(id)
        .selected_text(selected_label)
        .width(200.0)
        .show_ui(ui, |ui| {
            for option in options {
                let selected = current.trim() == *option
                    || (current.trim().is_empty() && *option == default_label);
                if ui.selectable_label(selected, *option).clicked() && current.trim() != *option {
                    *value = (*option).to_owned();
                    dirty = true;
                }
            }
            let trimmed = current.trim();
            if !trimmed.is_empty() && !options.contains(&trimmed) {
                ui.separator();
                let _ = ui.selectable_label(true, format!("{trimmed} (preserved)"));
            }
        });
    dirty
}

fn xhttp_optional_string_combo(
    ui: &mut Ui,
    id: &str,
    value: &mut String,
    options: &[&str],
) -> bool {
    let mut dirty = false;
    let current = value.clone();
    let selected_label = if current.trim().is_empty() {
        "(default)"
    } else {
        current.as_str()
    };
    ComboBox::from_id_salt(id)
        .selected_text(selected_label)
        .width(200.0)
        .show_ui(ui, |ui| {
            if ui
                .selectable_label(current.trim().is_empty(), "(default)")
                .clicked()
                && !current.trim().is_empty()
            {
                value.clear();
                dirty = true;
            }
            for option in options {
                let selected = current.trim() == *option;
                if ui.selectable_label(selected, *option).clicked() && current.trim() != *option {
                    *value = (*option).to_owned();
                    dirty = true;
                }
            }
            let trimmed = current.trim();
            if !trimmed.is_empty() && !options.contains(&trimmed) {
                ui.separator();
                let _ = ui.selectable_label(true, format!("{trimmed} (preserved)"));
            }
        });
    dirty
}
