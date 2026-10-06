//! `streamSettings.finalmask` editors — `tcp[]` / `udp[]` layer chains, typed layer forms and
//! `quicParams` — shared by every page with a `streamSettings` block (Roadmap §2.6 stage 0.4).
//!
//! The editors only change the drafts they are given and report whether they did; the caller
//! owns its session state (`write_*` flags, dirty marker). [`StreamDirection`] decides which
//! layer types are offered and flags layers that do not work on that side (client-only `udphop`
//! on an inbound, Roadmap §2.6 stage 1.1).

use egui::{Color32, RichText, Ui};

use super::{
    load_text_buffer, persistent_multiline_list_row, resizable_multiline, store_text_buffer,
};
use crate::xray::{
    FinalMaskChain, FinalMaskLayerDraft, NoiseMaskItem, QuicParamsDraft, REALM_IP_MODES,
    RangeValue, RealmPortMapping, RealmScheme, RealmUrl, StreamDirection, UdpHopModes,
    MKCP_LEGACY_DEFAULT_DNS_DOMAIN, MKCP_LEGACY_HEADERS, MkcpLegacyMode,
    finalmask_layer_type_applies, fragment_mask_settings_to_value, mkcp_legacy_settings_to_value,
    noise_mask_settings_to_value, parse_mkcp_legacy_settings,
    parse_fragment_mask_settings, parse_noise_mask_settings, parse_realm_settings,
    parse_realm_url, parse_salamander_settings, parse_sudoku_settings, parse_udphop_mode,
    parse_udphop_settings, parse_xdns_settings, parse_xicmp_settings, range_values_from_lines,
    range_values_to_lines, realm_ip_mode_is_known, realm_settings_to_value,
    salamander_settings_to_value, sudoku_settings_to_value, udphop_settings_to_value,
    validate_finalmask_layer, xdns_settings_to_value, xicmp_settings_to_value,
    XDNS_RECORD_TYPES, XDNS_RESOLVER_KINDS, XdnsDomain, XdnsResolver, migrate_legacy_xdns_settings,
    xdns_has_legacy_fields, xdns_record_type_name,
    HeaderCustomItem, HeaderCustomItemKind, HeaderCustomSequences, HeaderCustomTcpGroup,
    PacketValue, escape_packet_text, header_custom_tcp_settings_to_value,
    parse_header_custom_tcp_settings, unescape_packet_text,
    HEADER_CUSTOM_UDP_DEFAULT_MODE, HEADER_CUSTOM_UDP_MODES, HeaderCustomUdpGroup,
    header_custom_udp_settings_to_value, parse_header_custom_udp_settings,
    XMC_LEGACY_DEFAULT_USERNAME, XMC_MAX_PASSWORD_BYTES, XmcProfile, XmcSettings,
    migrate_legacy_xmc_usernames, parse_xmc_settings, xmc_settings_to_value, xmc_username_is_valid,
    FRAGMENT_PACKETS_TLSHELLO, FragmentMaskSettings, FragmentPackets, fragment_packets_mode, NOISE_EXP_KIND, NoiseItemPayload,
    SALAMANDER_MIN_PASSWORD_BYTES, SUDOKU_ASCII_MODES, SUDOKU_MAX_PADDING, SudokuSettings,
    validate_sudoku_custom_table,
    QUIC_BBR_PROFILES, QUIC_MIN_BRUTAL_BYTES_PER_SEC, QuicTransport,
    quic_bandwidth_bytes_per_sec, quic_params_field_applies, validate_quic_params_for_transport,
    LegacyUdpHopMigration, QUIC_PARAMS_LEGACY_UDP_HOP_KEY, migrate_legacy_udp_hop,
};

// Field help (Roadmap §3:124).
// Stream tab — finalmask.quicParams (Roadmap §2.6 stage 3.1; `QuicParamsConfig` of the core).
const HELP_QUIC_SECTION: &str =
    "QUIC tuning for QUIC-based transports (Hysteria; XHTTP over HTTP/3). Every field is \
     optional — an empty field or 0 means the core's default.";
const HELP_QUIC_CONGESTION: &str =
    "Congestion control. bbr — adapts to measured bandwidth (bbrProfile tunes it). reno — \
     classic loss-based. brutal (the default) — sends at a fixed rate regardless of loss: on the \
     server at min(brutalUp, the client's brutalDown), falling back to bbr when either is 0. \
     force-brutal — always brutalUp, whatever the peer advertises; requires brutalUp. Case does \
     not matter.";
const HELP_QUIC_BBR_PROFILE: &str =
    "How aggressively bbr probes for bandwidth: conservative, standard (the default) or \
     aggressive. Also used when brutal falls back to bbr.";
const HELP_QUIC_BRUTAL_UP: &str =
    "This side's sending rate for brutal / force-brutal: a number with an optional unit — bps, \
     kbps, mbps, gbps, tbps (or b, k, m, g, t), bits per second in powers of 1024, e.g. \
     \"100 mbps\". Must be at least 512 kbps (65536 bytes/s) when set. Must be a JSON string — \
     a bare number fails the config.";
const HELP_QUIC_BRUTAL_DOWN: &str =
    "This side's receiving rate, advertised to the peer during the Hysteria handshake so its \
     brutal sender does not exceed it. Same format and minimum as brutalUp.";
const HELP_QUIC_BRUTAL_LOSS: &str =
    "Brutal normally raises its send rate to make up for measured packet loss. When on, it keeps \
     the configured rate exactly.";
const HELP_QUIC_DEBUG: &str =
    "Sets HYSTERIA_BBR_DEBUG and HYSTERIA_BRUTAL_DEBUG for the whole Xray process: every QUIC \
     connection then logs congestion-control internals. Diagnostics only.";
const HELP_QUIC_STREAM_WINDOWS: &str =
    "Per-stream flow-control window in bytes: the initial value and the ceiling it may grow to. \
     At least 16384 when set; the default is 8 MiB (8388608).";
const HELP_QUIC_CONN_WINDOWS: &str =
    "Per-connection flow-control window in bytes (all streams together): the initial value and \
     the ceiling. At least 16384 when set; the default is 20 MiB (20971520).";
const HELP_QUIC_MAX_IDLE_TIMEOUT: &str =
    "Seconds without any traffic before the connection is closed: 4–120, or 0 for the default \
     (30).";
const HELP_QUIC_KEEP_ALIVE: &str =
    "Client-only: seconds between keep-alive pings that hold the connection (and NAT mappings) \
     open: 2–60, or 0 for the transport's default.";
const HELP_QUIC_MAX_INCOMING_STREAMS: &str =
    "How many concurrent streams the peer may open on one connection: at least 8, or 0 for the \
     default (1024). The Hysteria client ignores it.";
const HELP_QUIC_DISABLE_PMTUD: &str =
    "Turns off path-MTU discovery, so packets stay at the minimal QUIC size. Always off on \
     platforms other than Linux, Windows and macOS.";
const HELP_QUIC_DISABLE_CHROME_PARROT: &str =
    "Client-only: by default the client shapes its QUIC handshake like Chrome's. When on, it \
     uses the plain QUIC library handshake.";
const HELP_QUIC_DISABLE_GSO: &str =
    "Turns off UDP generic segmentation offload (batching packets in the kernel). Try it when a \
     NIC or virtual network driver mishandles GSO.";
const HELP_QUIC_DISABLE_STATELESS_RESET: &str =
    "Server-only: by default the listener generates a random stateless-reset key so clients \
     learn quickly that a connection is gone after a restart. When on, no key is used.";

// Stream tab — FinalMask (streamSettings.finalmask; VLESS/Trojan: tcp + udp, Hysteria: udp).
const HELP_FINALMASK_SECTION: &str =
    "The final layer of traffic camouflage, applied after transport-layer encryption (TLS/\
     REALITY) has already been processed. `tcp[]` and `udp[]` are ordered chains of masking \
     layers — the first entry is the innermost. Hysteria runs over UDP, so only `udp[]` applies \
     to it. A Tunnel uses `tcp[]` for its TCP listener and `udp[]` for its UDP listener \
     (settings.allowedNetwork). `salamander` (udp) is the same obfuscation algorithm as Hysteria2's \
     `obfs=salamander`: a Hysteria share link carries it as obfs when it is the only layer the \
     client must mirror (`noise` needs no client layer) and has no packetSize (Gecko).";

// What each FinalMask layer type does (help next to the layer's type, Roadmap §2.6 stage 2.5).
const HELP_TYPE_FRAGMENT: &str =
    "Splits what this side writes into smaller pieces, so DPI that needs a whole message (the TLS \
     ClientHello with its SNI) sees only fragments. packets picks the writes: tlshello — the \
     first TLS handshake record, re-cut into several TLS records; FROM-TO — writes FROM to TO, \
     cut into separate TCP writes; empty — every write. Works on either side; the peer needs no \
     matching layer.";
const HELP_TYPE_SUDOKU: &str =
    "Re-encodes every byte as Sudoku-grid clue patterns keyed by password, so the stream looks \
     like random bytes (entropy) or printable text (ascii), with optional random padding. Both \
     sides need the identical layer. Available in tcp and udp.";
const HELP_TYPE_XMC: &str =
    "Disguises the connection as a Minecraft online-mode login: handshake, encryption request \
     and a signed profile, then the data inside the encrypted game stream. Both sides need the \
     same password and profiles.";
const HELP_TYPE_HEADER_CUSTOM_TCP: &str =
    "A scripted handshake before the data: client and server exchange the byte sequences defined \
     here (fixed bytes, random bytes, echoed values) and check what they receive. Both sides need \
     the identical layer.";
const HELP_TYPE_HEADER_CUSTOM_UDP: &str =
    "A custom header in front of every UDP packet (prefix) or a one-time handshake packet per \
     destination (standalone), built from fixed, random and echoed bytes. Both sides need the \
     identical layer.";
const HELP_TYPE_MKCP_LEGACY: &str =
    "The former mKCP obfuscation (kcpSettings.header / seed) as a mask: a fake packet header \
     (DNS, DTLS, SRTP, uTP, WeChat video, WireGuard) or AES-128-GCM with a password. Both sides \
     need the same layer.";
const HELP_TYPE_NOISE: &str =
    "Sends junk datagrams before the first packet to each destination address, and again every \
     reset seconds, to confuse UDP DPI. Only the sending side acts — the peer needs no matching \
     layer.";
const HELP_TYPE_SALAMANDER: &str =
    "Hysteria2's obfuscation: every UDP packet is XORed with a BLAKE2b-256 keystream from the \
     password and a random 8-byte salt, so nothing in it is recognizable. With packetSize it is \
     Gecko: QUIC handshake packets are also split and padded to random sizes. Both sides need \
     the same password and mode.";
const HELP_TYPE_XDNS: &str =
    "Tunnels the UDP traffic through DNS queries and answers for a domain the server is \
     authoritative for — for networks where only DNS gets out.";
const HELP_TYPE_XICMP: &str =
    "Carries the UDP traffic inside ICMP echo (ping) packets — for networks that let ping \
     through. The server needs raw ICMP sockets (root or CAP_NET_RAW).";
const HELP_TYPE_REALM: &str =
    "NAT hole punching: both peers register with a realm server, learn their public addresses \
     via STUN and then connect directly — a server behind NAT without an open port.";
const HELP_TYPE_UDPHOP: &str =
    "Client-only UDP port hopping: the client switches its local socket or the server port / \
     address on a timer or per connection, so a single blocked port does not stop the traffic.";

// FinalMask `fragment` layer (Roadmap §2.6 stage 2.5, `fragment/conn.go`).
const HELP_FRAGMENT_PACKETS: &str =
    "Which writes to split. tlshello — only the first write, and only if it is a whole TLS \
     handshake record (the ClientHello on the client, the server's first record on the server); \
     its body is re-cut into several TLS records. FROM-TO or N — the writes numbered FROM to TO \
     since the connection opened (1 = the first), each cut into separate TCP writes; FROM must \
     not be 0. Empty — every write.";
const HELP_FRAGMENT_LENGTHS: &str =
    "Piece sizes in bytes, by position: lengths[0] for the first piece, lengths[1] for the \
     second, …; the last entry repeats for the rest. Each N or MIN-MAX (a random value in it). \
     The last entry must not start at 0. length is the single form, used only while lengths is \
     empty.";
const HELP_FRAGMENT_DELAYS: &str =
    "Pause in milliseconds after each piece, by position like lengths (the last repeats); 0 = \
     none. delay is the single form, used only while delays is empty. With tlshello, a single \
     delay of 0 (or none at all) sends the re-cut records together in one write — TLS records \
     are split, TCP writes are not.";
const HELP_FRAGMENT_MAX_SPLIT: &str =
    "Most pieces per write: the piece that reaches this count takes the rest. N or MIN-MAX (a \
     random value per write); empty or 0 = no limit.";

// FinalMask `salamander` layer.
const HELP_SALAMANDER_PASSWORD: &str =
    "Pre-shared key, identical on both sides — the obfs-password of a Hysteria2 share link. At \
     least 4 bytes: a shorter one fails when the layer starts, and xray run -test does not catch \
     it.";
const HELP_SALAMANDER_PACKET_SIZE: &str =
    "Empty — plain Salamander. N or MIN-MAX within 1–2048 — Gecko: every QUIC long-header \
     (handshake) packet is split into 2–8 fragments, each padded so the datagram size falls in \
     this range where it can; data packets are only obfuscated. Both sides must use the same \
     mode.";

// FinalMask `sudoku` layer (`sudoku/table.go`).
const HELP_SUDOKU_PASSWORD: &str =
    "Key that shuffles the encoding tables; identical on both sides. Empty is allowed.";
const HELP_SUDOKU_ASCII: &str =
    "Output layout. entropy (default, also prefer_entropy) — bytes look random; ascii (also \
     prefer_ascii) — printable characters only, custom tables are not used. Any other value \
     fails every connection, and xray run -test does not catch it.";
const HELP_SUDOKU_CUSTOM_TABLE: &str =
    "Bit layout of each output byte, highest bit first: 8 characters, exactly 2 x, 2 p and 4 v \
     (case and spaces ignored), e.g. xpxvvpvv. Empty = the built-in layout. customTables — several layouts, one \
     per line, used instead of customTable. A wrong pattern fails every connection, and xray \
     run -test does not catch it.";
const HELP_SUDOKU_PADDING: &str =
    "Random padding, in percent: every connection picks a chance between paddingMin and \
     paddingMax, then pads each encoded unit with that chance. Values above 100 count as 100; a \
     paddingMax below paddingMin is raised to it. Empty = 0.";

// FinalMask `noise` layer (`noise/conn.go`).
const HELP_NOISE_RESET: &str =
    "Seconds after which the junk is sent again to the same address, before its next packet: N \
     or MIN-MAX (random). Empty or 0 = only once per address.";
const HELP_NOISE_PACKET: &str =
    "The datagram's content, decoded by type: array (default) — byte list \"22, 3, 1\"; str — \
     the text (written here with escapes \\r \\n \\t \\\\ \\xHH); hex; base64; exp — an \
     expression of segments: <b HEX> bytes, <r N> random, <rc N> random letters, <rd N> random \
     digits (N or MIN-MAX, 0–65535), <t> 4-byte Unix time, <c> 4-byte counter, <n> 8-byte \
     nonce. exp needs Xray-core v26.9.30+. Set either packet or rand.";
const HELP_NOISE_RAND: &str =
    "rand — a datagram of N or MIN-MAX random bytes, instead of packet. randRange — FROM-TO for \
     the byte values, within 0–255 (empty = 0-255). Not used with type exp.";
const HELP_NOISE_DELAY: &str =
    "Pause in milliseconds after this datagram, before the next one (or the real packet): N or \
     MIN-MAX (random).";

/// `type` presets for a `noise` item: the `packet` encodings plus the `exp` expression.
const NOISE_PACKET_KINDS: &[&str] = &["array", "str", "hex", "base64", NOISE_EXP_KIND];

// FinalMask `xicmp` layer (`xicmp/client.go`, `server.go`).
const HELP_XICMP_DGRAM: &str =
    "Client side: send the pings through unprivileged ICMP sockets (Linux ping_group_range) \
     instead of raw ones that need root or CAP_NET_RAW. The server always uses raw sockets and \
     ignores it.";
const HELP_XICMP_IPS: &str =
    "Plain IP addresses, one per line (no CIDR). Client: the server addresses to ping, one \
     picked at random — empty = the outbound's address, which then must be an IP. Server: only \
     pings from these addresses are accepted — empty = from anyone.";

// FinalMask `udphop` layer (client-only UDP port hopping, XTLS/Xray-core#6327).
const HELP_UDPHOP_MODE: &str =
    "Required, at least one. intervalLocal — every interval, dial a fresh local socket (new local \
     port). intervalRemote — every interval, switch to a random IP/port from remoteIPs / \
     remotePorts. perConnRemote — pick a random IP/port from remoteIPs / remotePorts once, when \
     the connection opens. Written comma-separated without spaces.";
const HELP_UDPHOP_INTERVAL: &str =
    "Seconds between hops: a number or a FROM-TO range (a random value in it each time). Empty or \
     0 = 30; the lower bound must be at least 5.";
const HELP_UDPHOP_REMOTE_PORTS: &str =
    "Ports to hop between: a port, a FROM-TO range or a comma list (\"20000-50000\", \
     \"443,8443\"). Empty = keep the outbound's port.";
const HELP_UDPHOP_REMOTE_IPS: &str =
    "Addresses to hop between: IPs or CIDR prefixes (a random address inside the prefix is used). \
     Empty = keep the outbound's address.";

// FinalMask `realm` layer (NAT hole punching through a realm server, both sides).
const HELP_REALM_URL: &str =
    "Realm server both peers register with: realm://TOKEN@HOST[:PORT]/ID over HTTPS (default port \
     443) or realm+http://… over plain HTTP (port 80). TOKEN authorizes with the server, ID names \
     the realm — both sides must use the same one. Edit the URL or the fields below.";
const HELP_REALM_STUN: &str =
    "STUN servers used to discover the public address, one host:port per line (at least one; \
     IPv6 in brackets). An entry whose port is not a number is skipped by Xray-core.";
const HELP_REALM_IP_MODE: &str =
    "Address family for STUN and hole punching: dual (default), v4 or v6. Any other value also \
     means dual.";
const HELP_REALM_PORT_MAPPING: &str =
    "Map the local UDP port on the home gateway via UPnP / NAT-PMP. timeout — seconds for gateway \
     discovery and each request (empty/0 = 10); lifetime — mapping lease in seconds (empty/0 = \
     600). A failed mapping is only logged.";
const HELP_REALM_TLS: &str =
    "Client TLS settings for the HTTPS connection to the realm server (a tlsSettings-style object: \
     serverName, fingerprint, pinnedPeerCertSha256, …). Absent = system defaults.";

// FinalMask `xdns` layer (DNS tunnelling, v26.9.30 schema).
const HELP_XDNS_DOMAINS: &str =
    "Tunnel domains, needed on both sides. name — a domain the server is authoritative for; types \
     — DNS record types to carry data (TXT holds the most); lenLimit / labelLimit — maximum query \
     name / label length (empty = 255 / 63; the name must leave at least 17 payload bytes); edns0 \
     — EDNS0 UDP payload size, 0 = off, 512–4096.";
const HELP_XDNS_RESOLVERS: &str =
    "DNS resolvers the client sends its queries through: udp or tcp, address host:port (IPv6 in \
     brackets). Required on the client (outbound) side, ignored by the server.";
const HELP_XDNS_EXTRA_POLL: &str =
    "Additional polling queries the client keeps in flight, 0–3 (empty = 0).";

// FinalMask `mkcp-legacy` layer (the former kcpSettings.header / seed, Roadmap §2.6 stage 2.1).
const HELP_MKCP_LEGACY_HEADER: &str =
    "Fake packet header prepended to every UDP packet: dns, dtls, srtp, utp, wechat or wireguard \
     (case-insensitive). Empty = no header — then value selects the obfuscation: empty = the \
     original mKCP obfuscation, set = AES-128-GCM with value as the password. The old \
     kcpSettings names \"none\" and \"wechat-video\" are not accepted here.";
const HELP_MKCP_LEGACY_VALUE: &str =
    "Meaning depends on header: no header — AES-128-GCM password (empty = original obfuscation); \
     dns — the domain written into the fake DNS query (empty = www.baidu.com); any other header \
     ignores it. Used byte for byte (spaces count). Both sides need the same layer and value.";

// FinalMask `xmc` layer (the connection disguised as a Minecraft login, Roadmap §2.6 stage 2.4).
const HELP_XMC_PASSWORD: &str =
    "Required pre-shared secret, identical on both sides. Both derive the same RSA key from it \
     (the fake online-mode encryption); the client sends the password inside the encrypted login \
     and the server compares it. Used byte for byte; at most 113 bytes fit the RSA block — a \
     longer one fails every connection, and xray run -test does not catch it.";
const HELP_XMC_HOSTNAME: &str =
    "Server address the client writes into the Minecraft handshake, like a real client joining \
     mc.example.com (empty = the IP it dials). Client side only: the server reads and ignores it.";
const HELP_XMC_PROFILES: &str =
    "Signed Minecraft profiles. The client picks one at random for every connection and logs in \
     with its username and UUID; the server accepts only a listed profile and answers with its \
     stored textures, which the client compares — both sides need the identical list. To get a \
     profile: look up the UUID by username (api.mojang.com/users/profiles/minecraft/NAME), then \
     fetch sessionserver.mojang.com/session/minecraft/profile/UUID?unsigned=false and copy the \
     value and signature of its \"textures\" property.";
const HELP_XMC_USERNAME: &str = "Minecraft username of the profile: 3–16 letters, digits or _.";
const HELP_XMC_UUID: &str = "The profile's UUID, with or without hyphens.";
const HELP_XMC_TEXTURES: &str =
    "value and signature of the \"textures\" property of the signed session profile \
     (unsigned=false), copied as they are. Both are required, at most 4096 bytes each.";

// FinalMask `header-custom` TCP layer (scripted handshake, Roadmap §2.6 stage 2.2).
const HELP_HC_CLIENTS: &str =
    "Sequences the client sends. The client writes clients[0], reads servers[0], writes clients[1], \
     … The server reads each one and checks it item by item; a mismatch refuses the connection \
     (after sending errors[i], if set). Both sides need the identical layer.";
const HELP_HC_SERVERS: &str =
    "Sequences the server answers with: servers[i] follows clients[i]; extra ones are sent after \
     the last client sequence. The client checks them like the server checks clients.";
const HELP_HC_ERRORS: &str =
    "Sent by the server when clients[i] does not match, just before it refuses the connection \
     (errors[i] belongs to clients[i]). Only the server side uses errors.";
const HELP_HC_DELAY: &str =
    "Pause in milliseconds before this item is written: a number or a FROM-TO range (a random \
     value in it). Earlier items are flushed first. Ignored when the sequence is received.";
const HELP_HC_PACKET: &str =
    "Fixed bytes, decoded by type: array (default) — byte list \"22, 3, 1\"; str — the text itself \
     (written here with escapes: \\r \\n \\t \\\\ \\xHH); hex — even-length hex; base64. When \
     received, the bytes must match exactly.";
const HELP_HC_RAND: &str =
    "rand — number of random bytes (only > 0 makes this a rand item). randRange — FROM-TO for \
     the byte values, 0–255 (empty = 0-255). When received, rand bytes of any content are \
     accepted.";
const HELP_HC_REUSE: &str =
    "This item is the bytes saved earlier under this name (capture). When received, they must \
     match. Letters, digits and _, not starting with a digit.";
const HELP_HC_CAPTURE: &str =
    "Save this item's bytes (sent or received) under a name, for a later reuse or transform — \
     e.g. echo back a random nonce. Needs a kind (packet, rand, reuse or transform).";
const HELP_HC_TRANSFORM: &str =
    "Computed bytes: {\"op\": NAME, \"args\": [...]}, each argument exactly one of bytes (+ type), \
     u64, reuse, metadata or a nested transform. Ops include concat, slice, xor16/xor32, \
     be16/be32, le16/le32/le64, pad, truncate, add, sub, and, or, shl, shr.";

/// `type` presets for a `header-custom` packet (empty = `array`).
const HEADER_CUSTOM_PACKET_KINDS: &[&str] = &["array", "str", "hex", "base64"];

// FinalMask `header-custom` UDP layer (Roadmap §2.6 stage 2.3).
const HELP_HC_UDP_MODE: &str =
    "prefix (default) — client and server are a header in front of every packet the respective \
     side sends; the receiver checks and strips it, a packet that does not match is dropped. \
     standalone — client is a separate handshake packet the client sends once per destination \
     (and waits for), server is the reply; data packets then travel unchanged. Lower-case only. \
     Xray-core works out the header size when the listener (inbound) or dialer (outbound) is \
     created: every reuse must name an earlier capture — in client, or in client or server for \
     server — and a transform must have a fixed size (no metadata, no u64 inside concat). \
     Otherwise it fails to start, and xray run -test does not catch it.";
const HELP_HC_UDP_CLIENT: &str =
    "Items the client sends: the header of each of its packets (prefix) or its one-time \
     handshake packet (standalone). The server checks them item by item. A capture here can be \
     reused in server.";
const HELP_HC_UDP_SERVER: &str =
    "Items the server sends: the header of each of its packets (prefix) or its reply to the \
     handshake (standalone). The client checks them item by item; it may reuse what client \
     captured.";

/// Orange text for problems Save will reject or the user should act on.
const WARNING_COLOR: Color32 = Color32::from_rgb(220, 160, 60);
/// Grey text for hints.
const HINT_COLOR: Color32 = Color32::from_rgb(140, 140, 140);

/// `finalmask.quicParams` editor — every `QuicParamsConfig` field (Roadmap §2.6 stage 3.1).
/// A field that has no effect on `direction` gets a row only while it is set, marked as
/// ignored, so it can be seen and cleared. Problems Save would reject are listed under the grid.
/// Returns true when the draft changed.
pub(crate) fn show_quic_params_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    transport: QuicTransport,
    quic_params: &mut QuicParamsDraft,
) -> bool {
    let mut changed = false;
    // Number-field text buffers hang off the editor's root id, not the nested grid cells'.
    let buffer_base = ui.make_persistent_id("quic_params_number");
    let ignored_note = |ui: &mut Ui, field: &str| {
        if !quic_params_field_applies(field, direction) {
            let side = match direction {
                StreamDirection::Inbound => "client-only — ignored on an inbound",
                StreamDirection::Outbound => "server-only — ignored on an outbound",
            };
            ui.label(RichText::new(side).size(12.0).color(WARNING_COLOR));
        }
    };
    ui.horizontal(|ui| {
        super::help_button(ui, "quicParams", HELP_QUIC_SECTION);
        ui.strong("quicParams");
        ui.label(RichText::new(format!("({})", transport.label())).color(HINT_COLOR));
    });
    // What differs per transport (Roadmap §2.6 stage 3.3).
    let transport_note = match transport {
        QuicTransport::Hysteria => {
            "Empty congestion = brutal (bbr while brutalUp or the client's brutalDown is 0)."
        }
        QuicTransport::XhttpH3 => {
            "XHTTP over HTTP/3: empty congestion = bbr; brutal is not supported (Xray-core fails \
             every connection with it) — use force-brutal; brutalDown is not used."
        }
    };
    ui.label(RichText::new(transport_note).size(12.0).color(HINT_COLOR));
    egui::Grid::new("stream_quic_params_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "congestion", HELP_QUIC_CONGESTION);
            ui.horizontal(|ui| {
                changed |= super::optional_string_combo(
                    ui,
                    "quic_params_congestion",
                    &mut quic_params.congestion,
                    transport.congestion_modes(),
                );
            });
            ui.end_row();
            super::field_label(ui, "bbrProfile", HELP_QUIC_BBR_PROFILE);
            ui.horizontal(|ui| {
                changed |= super::optional_string_combo(
                    ui,
                    "quic_params_bbr_profile",
                    &mut quic_params.bbr_profile,
                    QUIC_BBR_PROFILES,
                );
            });
            ui.end_row();
            for (label, help, value) in [
                ("brutalUp", HELP_QUIC_BRUTAL_UP, &mut quic_params.brutal_up),
                ("brutalDown", HELP_QUIC_BRUTAL_DOWN, &mut quic_params.brutal_down),
            ] {
                let read = transport.reads_field(label);
                if !read && value.trim().is_empty() {
                    continue;
                }
                super::field_label(ui, label, help);
                ui.horizontal(|ui| {
                    if !read {
                        ui.label(
                            RichText::new(format!("not used on {}", transport.label()))
                                .size(12.0)
                                .color(WARNING_COLOR),
                        );
                    }
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(value)
                                .desired_width(140.0)
                                .hint_text("e.g. 100 mbps"),
                        )
                        .changed();
                    match quic_bandwidth_bytes_per_sec(value) {
                        Ok(0) => {}
                        Ok(bytes) => {
                            let color = if bytes < QUIC_MIN_BRUTAL_BYTES_PER_SEC {
                                WARNING_COLOR
                            } else {
                                HINT_COLOR
                            };
                            ui.label(RichText::new(format_bytes_per_sec(bytes)).size(12.0).color(color));
                        }
                        Err(error) => {
                            ui.label(RichText::new(error).size(12.0).color(WARNING_COLOR));
                        }
                    }
                });
                ui.end_row();
            }
            super::field_label(ui, "brutalDisableLossCompensation", HELP_QUIC_BRUTAL_LOSS);
            changed |= optional_flag_combo(
                ui,
                "quic_params_brutal_loss",
                &mut quic_params.brutal_disable_loss_compensation,
            );
            ui.end_row();

            for (key, help, value) in [
                ("initStreamReceiveWindow", HELP_QUIC_STREAM_WINDOWS,
                 &mut quic_params.init_stream_receive_window),
                ("maxStreamReceiveWindow", HELP_QUIC_STREAM_WINDOWS,
                 &mut quic_params.max_stream_receive_window),
                ("initConnectionReceiveWindow", HELP_QUIC_CONN_WINDOWS,
                 &mut quic_params.init_connection_receive_window),
                ("maxConnectionReceiveWindow", HELP_QUIC_CONN_WINDOWS,
                 &mut quic_params.max_connection_receive_window),
            ] {
                super::field_label(ui, key, help);
                changed |= optional_number_field(ui, buffer_base.with(key), value, "bytes; ≥ 16384");
                ui.end_row();
            }
            for (key, label, help, value, hint) in [
                ("maxIdleTimeout", "maxIdleTimeout (s)", HELP_QUIC_MAX_IDLE_TIMEOUT,
                 &mut quic_params.max_idle_timeout, "4–120; default 30"),
                ("keepAlivePeriod", "keepAlivePeriod (s)", HELP_QUIC_KEEP_ALIVE,
                 &mut quic_params.keep_alive_period, "2–60"),
                ("maxIncomingStreams", "maxIncomingStreams", HELP_QUIC_MAX_INCOMING_STREAMS,
                 &mut quic_params.max_incoming_streams, "≥ 8; default 1024"),
            ] {
                if quic_params_field_applies(key, direction) || value.is_some() {
                    super::field_label(ui, label, help);
                    ui.horizontal(|ui| {
                        changed |= optional_number_field(ui, buffer_base.with(key), value, hint);
                        ignored_note(ui, key);
                    });
                    ui.end_row();
                }
            }
            for (key, help, value) in [
                ("disablePathMTUDiscovery", HELP_QUIC_DISABLE_PMTUD,
                 &mut quic_params.disable_path_mtu_discovery),
                ("disableGSO", HELP_QUIC_DISABLE_GSO, &mut quic_params.disable_gso),
                ("disableChromeParrot", HELP_QUIC_DISABLE_CHROME_PARROT,
                 &mut quic_params.disable_chrome_parrot),
                ("disableStatelessReset", HELP_QUIC_DISABLE_STATELESS_RESET,
                 &mut quic_params.disable_stateless_reset),
                ("debug", HELP_QUIC_DEBUG, &mut quic_params.debug),
            ] {
                if quic_params_field_applies(key, direction) || value.is_some() {
                    super::field_label(ui, key, help);
                    ui.horizontal(|ui| {
                        changed |= optional_flag_combo(ui, key, value);
                        ignored_note(ui, key);
                    });
                    ui.end_row();
                }
            }
        });

    changed |= show_legacy_udp_hop(ui, direction, quic_params);

    let mistyped = quic_params.mistyped_keys();
    if !mistyped.is_empty() {
        ui.label(
            RichText::new(format!(
                "On disk with a JSON type Xray rejects: {} — set the field above to replace it, or \
                 remove the value.",
                mistyped.join(", ")
            ))
            .color(WARNING_COLOR),
        );
        if ui.button("Remove invalid values").clicked() && quic_params.remove_mistyped() {
            changed = true;
        }
    } else if let Err(error) = validate_quic_params_for_transport(quic_params, transport) {
        ui.label(RichText::new(format!("Save will be rejected: {error}")).color(WARNING_COLOR));
    }
    changed
}

/// The removed `quicParams.udpHop` (Roadmap §2.6 stage 3.2), shown as stored. On an inbound the
/// key never had an effect, so the action is "Remove udpHop" (`migrate_legacy_udp_hop` with
/// `Inbound`); on an outbound the action converts it to a `udphop` layer, which needs the
/// `finalmask.udp` chain and the installed core — the Outbound Stream editor shows that button
/// right below (stage 7.1). Returns true when the draft changed.
fn show_legacy_udp_hop(ui: &mut Ui, direction: StreamDirection, quic_params: &mut QuicParamsDraft) -> bool {
    let Some(legacy) = quic_params.extras.get(QUIC_PARAMS_LEGACY_UDP_HOP_KEY) else {
        return false;
    };
    ui.add_space(4.0);
    ui.label(
        RichText::new(format!("quicParams.udpHop: {legacy}"))
            .monospace()
            .size(12.0)
            .color(HINT_COLOR),
    );
    match direction {
        StreamDirection::Inbound => {
            ui.label(
                RichText::new(
                    "Port hopping is client-side: only the Hysteria dialer ever read udpHop, so it \
                     never had an effect on an inbound (and Xray-core v26.9.9+ ignores it \
                     everywhere). Clients hop with their own `udphop` layer.",
                )
                .color(WARNING_COLOR),
            );
            let clicked = ui
                .button("Remove udpHop")
                .on_hover_text("Drops streamSettings.finalmask.quicParams.udpHop on Save.")
                .clicked();
            clicked
                && migrate_legacy_udp_hop(quic_params, &mut Vec::new(), direction)
                    == Ok(LegacyUdpHopMigration::RemovedServerSide)
        }
        StreamDirection::Outbound => {
            ui.label(
                RichText::new(
                    "Ignored by Xray-core v26.9.9+: port hopping is a `udphop` layer at \
                     finalmask.udp[0] now (mode intervalLocal,intervalRemote, remotePorts = ports).",
                )
                .color(WARNING_COLOR),
            );
            false
        }
    }
}

/// Bytes per second as the exact value plus a rounded MiB/s or KiB/s reading.
fn format_bytes_per_sec(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value >= KIB * KIB {
        format!("= {bytes} B/s (≈ {:.1} MiB/s)", value / (KIB * KIB))
    } else if value >= KIB {
        format!("= {bytes} B/s (≈ {:.1} KiB/s)", value / KIB)
    } else {
        format!("= {bytes} B/s")
    }
}

/// Unset / false / true for an optional JSON bool. Returns true when changed.
fn optional_flag_combo(ui: &mut Ui, id: &str, value: &mut Option<bool>) -> bool {
    let label = |value: Option<bool>| match value {
        None => "(default: false)",
        Some(false) => "false",
        Some(true) => "true",
    };
    let before = *value;
    egui::ComboBox::from_id_salt(("quic_params_flag", id))
        .selected_text(label(*value))
        .show_ui(ui, |ui| {
            for option in [None, Some(false), Some(true)] {
                ui.selectable_value(value, option, label(option));
            }
        });
    *value != before
}

/// Optional integer as a text field (empty = unset). The typed text lives in a frame-persistent
/// buffer (Roadmap §2.6 stage 0.2), so a half-typed value such as `-` is not lost; text that
/// does not parse leaves the model unchanged and is flagged inline. Returns true when changed.
fn optional_number_field<T>(ui: &mut Ui, buffer_id: egui::Id, value: &mut Option<T>, hint: &str) -> bool
where
    T: Copy + PartialEq + ToString + std::str::FromStr + Send + Sync + 'static,
{
    let mut text = load_text_buffer(ui, buffer_id, value, || {
        value.map(|number| number.to_string()).unwrap_or_default()
    });
    let mut changed = false;
    ui.horizontal(|ui| {
        let response = ui.add(
            egui::TextEdit::singleline(&mut text)
                .desired_width(140.0)
                .hint_text(hint),
        );
        let trimmed = text.trim();
        let parsed = if trimmed.is_empty() {
            Some(None)
        } else {
            trimmed.parse::<T>().ok().map(Some)
        };
        if response.changed()
            && let Some(parsed) = parsed
            && parsed != *value
        {
            *value = parsed;
            changed = true;
        }
        if parsed.is_none() {
            ui.label(RichText::new("not a valid integer").size(12.0).color(WARNING_COLOR));
        }
    });
    store_text_buffer(ui, buffer_id, *value, text);
    changed
}

/// Shown instead of the FinalMask / `quicParams` editors when `streamSettings.finalmask` on disk
/// is neither an object nor `null` (Roadmap §2.6 stage 0.5): Feldjäger does not own such a value
/// and leaves it untouched, so offering editors would only lead to a rejected Save.
pub(crate) fn show_foreign_finalmask_notice(ui: &mut Ui) {
    ui.horizontal(|ui| {
        super::help_button(ui, "FinalMask", HELP_FINALMASK_SECTION);
        ui.strong("FinalMask");
    });
    ui.label(
        RichText::new(
            "streamSettings.finalmask on disk is not a JSON object, so it can't be edited here. It is \
             kept exactly as it is on save — fix or remove it on the Raw JSON tab to edit FinalMask \
             or quicParams.",
        )
        .color(Color32::from_rgb(220, 160, 60)),
    );
}

/// Which FinalMask chains an edit changed; the caller sets its matching `write_*` flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FinalMaskEdit {
    /// `finalmask.tcp` changed.
    pub(crate) tcp: bool,
    /// `finalmask.udp` changed.
    pub(crate) udp: bool,
}

/// The FinalMask section: heading, optional `notice` (e.g. a non-blocking REALITY hint), and
/// the `tcp[]` / `udp[]` layer chains.
///
/// `udp_only`: the transport is QUIC over UDP (Hysteria, Roadmap §2.6 stage 4.1), so a `tcp[]`
/// layer is never used. The `tcp` chain is then left out while empty; a chain already on disk
/// stays visible, flagged, so it can be removed (the GUI never hides configuration).
pub(crate) fn show_finalmask_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    tcp: &mut Vec<FinalMaskLayerDraft>,
    udp: &mut Vec<FinalMaskLayerDraft>,
    notice: Option<&str>,
    udp_only: bool,
) -> FinalMaskEdit {
    ui.horizontal(|ui| {
        super::help_button(ui, "FinalMask", HELP_FINALMASK_SECTION);
        ui.strong("FinalMask");
    });
    ui.label(
        RichText::new(
            "Advanced streamSettings.finalmask masking layers. Order matters — the first entry is the innermost layer.",
        )
        .size(12.0)
        .color(Color32::from_rgb(140, 140, 140)),
    );
    if let Some(notice) = notice {
        ui.label(RichText::new(notice).color(Color32::from_rgb(220, 160, 60)));
    }
    ui.add_space(4.0);
    let tcp = if udp_only && tcp.is_empty() {
        false
    } else {
        ui.label(RichText::new("tcp").strong());
        if udp_only {
            ui.label(
                RichText::new(
                    "This transport runs over UDP only: Xray-core never applies finalmask.tcp \
                     layers to it. They are kept as they are — remove them if they are leftovers.",
                )
                .color(WARNING_COLOR),
            );
        }
        let edited = show_finalmask_layers_edit(ui, direction, FinalMaskChain::Tcp, tcp);
        ui.add_space(6.0);
        edited
    };
    ui.label(RichText::new("udp").strong());
    let udp = show_finalmask_layers_edit(ui, direction, FinalMaskChain::Udp, udp);
    FinalMaskEdit { tcp, udp }
}

/// Editor for one `finalmask.tcp` / `finalmask.udp` layer chain; returns true when the layer
/// list changed. Only layer types that work on the `direction` side are offered as presets; an
/// on-disk layer that doesn't is flagged (Save of the chain is refused until it is removed).
fn show_finalmask_layers_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    chain: FinalMaskChain,
    layers: &mut Vec<FinalMaskLayerDraft>,
) -> bool {
    let id_suffix = chain.key();
    let type_presets: Vec<&str> = chain
        .types()
        .iter()
        .copied()
        .filter(|preset| finalmask_layer_type_applies(preset, chain, direction))
        .collect();
    let mut dirty = false;
    let mut remove_idx: Option<usize> = None;
    let mut move_up_idx: Option<usize> = None;
    let mut move_down_idx: Option<usize> = None;

    for idx in 0..layers.len() {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(format!("layer[{idx}]"));
                let mut layer_type = layers[idx].layer_type.clone();
                egui::ComboBox::from_id_salt(format!("finalmask_{id_suffix}_type_{idx}"))
                    .selected_text(if layer_type.is_empty() {
                        "(pick type)"
                    } else {
                        layer_type.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in &type_presets {
                            ui.selectable_value(&mut layer_type, preset.to_owned(), preset);
                        }
                    });
                if ui.text_edit_singleline(&mut layer_type).changed() {
                    layers[idx].layer_type = layer_type.clone();
                    dirty = true;
                } else if layer_type != layers[idx].layer_type {
                    layers[idx].layer_type = layer_type;
                    dirty = true;
                }
                if let Some((title, help)) = finalmask_type_help(chain, &layers[idx].layer_type) {
                    super::help_button(ui, title, help);
                }
                if ui.small_button("Up").on_hover_text("Move up").clicked() && idx > 0 {
                    move_up_idx = Some(idx);
                }
                if ui.small_button("Down").on_hover_text("Move down").clicked() && idx + 1 < layers.len() {
                    move_down_idx = Some(idx);
                }
                if ui.button("Remove").clicked() {
                    remove_idx = Some(idx);
                }
            });

            if !finalmask_layer_type_applies(&layers[idx].layer_type, chain, direction) {
                ui.label(
                    RichText::new(format!(
                        "`{}` is a client-only mask: Xray-core cannot listen with it, so this {} \
                         would not start (`xray run -test` does not catch it). Saving this chain is \
                         refused until the layer is removed — it belongs in the client's outbound.",
                        layers[idx].layer_type.trim(),
                        direction.as_str()
                    ))
                    .color(WARNING_COLOR),
                );
            }

            if show_finalmask_settings_edit(
                ui,
                direction,
                chain,
                &layers[idx].layer_type.clone(),
                &mut layers[idx].settings,
                id_suffix,
                idx,
            ) {
                dirty = true;
            }
            // The same per-type `Build()` checks Save runs (Roadmap §2.6 stage 1.4), for typed
            // and raw-JSON layers alike.
            if let Err(error) = validate_finalmask_layer(chain, direction, &layers[idx].layer_type, &layers[idx].settings) {
                ui.colored_label(WARNING_COLOR, format!("Save will be refused: {error}"));
            }
        });
    }

    if let Some(idx) = remove_idx {
        layers.remove(idx);
        dirty = true;
    } else if let Some(idx) = move_up_idx {
        layers.swap(idx, idx - 1);
        dirty = true;
    } else if let Some(idx) = move_down_idx {
        layers.swap(idx, idx + 1);
        dirty = true;
    }

    ui.add_space(4.0);
    if ui.button(format!("Add {id_suffix} layer")).clicked() {
        layers.push(FinalMaskLayerDraft::default());
        dirty = true;
    }

    dirty
}

/// Help for a layer type of `chain` (title, text); `None` for a type the chain does not know.
fn finalmask_type_help(chain: FinalMaskChain, layer_type: &str) -> Option<(&'static str, &'static str)> {
    let help = match (chain, layer_type.trim().to_ascii_lowercase().as_str()) {
        (FinalMaskChain::Tcp, "fragment") => ("fragment", HELP_TYPE_FRAGMENT),
        (FinalMaskChain::Tcp, "header-custom") => ("header-custom (tcp)", HELP_TYPE_HEADER_CUSTOM_TCP),
        (FinalMaskChain::Tcp, "xmc") => ("xmc", HELP_TYPE_XMC),
        (_, "sudoku") => ("sudoku", HELP_TYPE_SUDOKU),
        (FinalMaskChain::Udp, "header-custom") => ("header-custom (udp)", HELP_TYPE_HEADER_CUSTOM_UDP),
        (FinalMaskChain::Udp, "mkcp-legacy") => ("mkcp-legacy", HELP_TYPE_MKCP_LEGACY),
        (FinalMaskChain::Udp, "noise") => ("noise", HELP_TYPE_NOISE),
        (FinalMaskChain::Udp, "salamander") => ("salamander", HELP_TYPE_SALAMANDER),
        (FinalMaskChain::Udp, "xdns") => ("xdns", HELP_TYPE_XDNS),
        (FinalMaskChain::Udp, "xicmp") => ("xicmp", HELP_TYPE_XICMP),
        (FinalMaskChain::Udp, "realm") => ("realm", HELP_TYPE_REALM),
        (FinalMaskChain::Udp, "udphop") => ("udphop", HELP_TYPE_UDPHOP),
        _ => return None,
    };
    Some(help)
}

/// Dispatches to a typed form for the FinalMask layer types that have one; falls back to the
/// raw-JSON editor for the rest (unknown types, a type in the wrong chain). The chain matters: `header-custom` has a
/// different schema in `tcp[]` and `udp[]`. Returns true when `settings` changed.
fn show_finalmask_settings_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    chain: FinalMaskChain,
    layer_type: &str,
    settings: &mut serde_json::Value,
    id_suffix: &str,
    idx: usize,
) -> bool {
    match layer_type.trim().to_ascii_lowercase().as_str() {
        "header-custom" => match chain {
            FinalMaskChain::Tcp => show_header_custom_tcp_settings_edit(ui, direction, settings, id_suffix, idx),
            FinalMaskChain::Udp => show_header_custom_udp_settings_edit(ui, direction, settings, id_suffix, idx),
        },
        "fragment" => show_fragment_mask_settings_edit(ui, direction, settings, id_suffix, idx),
        "salamander" => show_salamander_settings_edit(ui, settings, id_suffix, idx),
        "sudoku" => show_sudoku_settings_edit(ui, settings, id_suffix, idx),
        "realm" => show_realm_settings_edit(ui, settings, id_suffix, idx),
        "udphop" => show_udphop_settings_edit(ui, settings, id_suffix, idx),
        "noise" => show_noise_mask_settings_edit(ui, settings, id_suffix, idx),
        "xdns" => show_xdns_settings_edit(ui, direction, settings, id_suffix, idx),
        "xicmp" => show_xicmp_settings_edit(ui, direction, settings, id_suffix, idx),
        "mkcp-legacy" => show_mkcp_legacy_settings_edit(ui, settings, id_suffix, idx),
        // `xmc` is a `tcp[]` mask; in `udp[]` the layer is an error, shown as it is.
        "xmc" if chain == FinalMaskChain::Tcp => show_xmc_settings_edit(ui, direction, settings, id_suffix, idx),
        _ => show_finalmask_raw_json_edit(ui, settings, id_suffix, idx),
    }
}

// ─── FinalMask form state across frames (Roadmap §2.6 stage 0.2) ───────────────────────────
//
// egui is immediate-mode: every frame the forms below are rebuilt from the model. Re-deriving
// the editable state from `settings` each frame has two failure modes:
// 1. merely *showing* a form rewrote `settings` with the normalized `*_to_value` output (legacy
//    `sudoku` aliases → camelCase, dropped `"dgram": false`, …), marking the inbound dirty;
// 2. text the user is typing was normalized away on the next frame (`"1,"` in a byte-array
//    `packet` became `[1]` → `"1"`; a trailing Enter in a one-per-line list vanished; a raw-JSON
//    edit that is not yet valid JSON was reverted).
// So each editor keeps its draft/text buffer in egui temp memory together with the `settings`
// snapshot (`source`) it belongs to. The buffer is reused while `settings` still equals that
// snapshot, and re-derived as soon as something else changed it (Raw JSON, Move up/down, Cancel,
// another inbound). `settings` is written only when the user changed a widget **and** the
// resulting JSON differs.

/// A typed FinalMask form's draft as stored between frames.
#[derive(Clone)]
struct FinalMaskFormState<D> {
    /// `settings` exactly as last parsed or written by this form.
    source: serde_json::Value,
    draft: D,
}

/// One frame of a typed FinalMask form: [`Self::begin`] → edit `draft` → [`Self::finish`].
struct FinalMaskForm<D> {
    state_id: egui::Id,
    /// The draft at the start of the frame; `finish` writes only when `draft` differs from it.
    before: D,
    draft: D,
}

impl<D: Clone + PartialEq + Send + Sync + 'static> FinalMaskForm<D> {
    /// Reuses the stored draft while `settings` is unchanged, otherwise parses `settings`.
    /// `None` when `settings` can't be represented by the typed form (caller shows raw JSON).
    fn begin(
        ui: &Ui,
        settings: &serde_json::Value,
        id_suffix: &str,
        idx: usize,
        parse: fn(&serde_json::Value) -> Option<D>,
    ) -> Option<Self> {
        let state_id = ui.make_persistent_id(("finalmask_form", id_suffix, idx));
        let stored = ui
            .ctx()
            .data(|d| d.get_temp::<FinalMaskFormState<D>>(state_id))
            .filter(|state| state.source == *settings)
            .map(|state| state.draft);
        let draft = match stored {
            Some(draft) => draft,
            None => parse(settings)?,
        };
        Some(Self {
            state_id,
            before: draft.clone(),
            draft,
        })
    }

    /// Writes `settings` only if the user changed the draft this frame and the JSON differs;
    /// stores the draft for the next frame. Returns true when `settings` changed.
    fn finish(self, ui: &Ui, settings: &mut serde_json::Value, to_value: fn(&D) -> serde_json::Value) -> bool {
        let mut changed = false;
        if self.draft != self.before {
            let value = to_value(&self.draft);
            if value != *settings {
                *settings = value;
                changed = true;
            }
        }
        let state = FinalMaskFormState {
            source: settings.clone(),
            draft: self.draft,
        };
        ui.ctx().data_mut(|d| d.insert_temp(self.state_id, state));
        changed
    }
}

/// Raw-JSON `settings` editor — the fallback for FinalMask layer types with no typed form
/// (the packet-scripting DSL types), and the safety net when a typed parse fails because the
/// on-disk shape doesn't match what Feldjäger expects. Text that is not (yet) a JSON object is
/// kept in the buffer and flagged instead of being reverted on the next frame.
fn show_finalmask_raw_json_edit(ui: &mut Ui, settings: &mut serde_json::Value, id_suffix: &str, idx: usize) -> bool {
    let mut dirty = false;
    let buffer_id = ui.make_persistent_id(("finalmask_raw", id_suffix, idx));
    let mut settings_text = load_text_buffer(ui, buffer_id, settings, || {
        serde_json::to_string_pretty(settings).unwrap_or_default()
    });
    ui.label(
        RichText::new("settings (JSON object)")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );
    let edited = resizable_multiline(
        ui,
        &mut settings_text,
        4,
        &format!("finalmask_{id_suffix}_settings_{idx}"),
    )
    .changed();
    match serde_json::from_str::<serde_json::Value>(&settings_text) {
        Ok(value) if value.is_object() => {
            if edited && value != *settings {
                *settings = value;
                dirty = true;
            }
        }
        Ok(_) => {
            ui.colored_label(Color32::from_rgb(220, 160, 60), "Not applied: settings must be a JSON object");
        }
        Err(error) => {
            ui.colored_label(Color32::from_rgb(220, 160, 60), format!("Not applied: {error}"));
        }
    }
    store_text_buffer(ui, buffer_id, settings.clone(), settings_text);
    dirty
}

/// Newline-separated `Int32Range` list (`fragment.lengths[]`/`delays[]`); each line keeps the
/// JSON shape (number vs string) it was read in, by position.
fn finalmask_range_list_row(
    ui: &mut Ui,
    label: &str,
    values: &mut Vec<RangeValue>,
    id: impl std::hash::Hash + std::fmt::Debug,
) -> bool {
    let mut lines = range_values_to_lines(values);
    let changed = persistent_multiline_list_row(ui, label, &mut lines, id);
    if changed {
        *values = range_values_from_lines(values, lines);
    }
    changed
}

/// `fragment` form (Roadmap §2.6 stage 2.5): `packets` as a preset picker (every write /
/// `tlshello` / a range), piece sizes and delays with help, and a line on what the layer does.
fn show_fragment_mask_settings_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    settings: &mut serde_json::Value,
    id_suffix: &str,
    idx: usize,
) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_fragment_mask_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_fragment", id_suffix, idx), |ui| {
        egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "packets", HELP_FRAGMENT_PACKETS);
            ui.horizontal(|ui| {
                fragment_packets_combo(ui, &mut draft.packets);
                if !matches!(draft.packets_mode(), Some(FragmentPackets::All | FragmentPackets::TlsHello)) {
                    ui.add(egui::TextEdit::singleline(&mut draft.packets).hint_text("FROM-TO, e.g. 1-3").desired_width(100.0));
                }
            });
            ui.end_row();
            super::field_label(ui, "length", HELP_FRAGMENT_LENGTHS);
            ui.add(egui::TextEdit::singleline(&mut draft.length.text).hint_text("bytes: N or MIN-MAX"));
            ui.end_row();
            super::field_label(ui, "delay", HELP_FRAGMENT_DELAYS);
            ui.add(egui::TextEdit::singleline(&mut draft.delay.text).hint_text("ms: N or MIN-MAX"));
            ui.end_row();
            super::field_label(ui, "maxSplit", HELP_FRAGMENT_MAX_SPLIT);
            ui.add(egui::TextEdit::singleline(&mut draft.max_split.text).hint_text("empty = no limit"));
            ui.end_row();
        });
        ui.horizontal(|ui| {
            super::help_button(ui, "lengths", HELP_FRAGMENT_LENGTHS);
            finalmask_range_list_row(ui, "lengths (one per line)", &mut draft.lengths, "lengths");
        });
        ui.horizontal(|ui| {
            super::help_button(ui, "delays", HELP_FRAGMENT_DELAYS);
            finalmask_range_list_row(ui, "delays (one per line)", &mut draft.delays, "delays");
        });
        for (note, color) in fragment_notes(draft, direction) {
            ui.label(RichText::new(note).size(11.0).color(color));
        }
    });
    form.finish(ui, settings, fragment_mask_settings_to_value)
}

/// `packets` picker: every write (empty), `tlshello`, or a range edited in the text box next to
/// it. Picking "range" starts from `1-3`; a value from disk (`TLSHello`) is kept verbatim until
/// another entry is picked.
fn fragment_packets_combo(ui: &mut Ui, packets: &mut String) {
    let mode = fragment_packets_mode(packets);
    let selected = match mode {
        Some(FragmentPackets::All) => "(every write)".to_owned(),
        Some(FragmentPackets::TlsHello) => packets.clone(),
        _ => "range".to_owned(),
    };
    egui::ComboBox::from_id_salt("packets").selected_text(selected).show_ui(ui, |ui| {
        if ui.selectable_label(mode == Some(FragmentPackets::All), "(every write)").clicked() {
            packets.clear();
        }
        if ui.selectable_label(mode == Some(FragmentPackets::TlsHello), FRAGMENT_PACKETS_TLSHELLO).clicked()
            && mode != Some(FragmentPackets::TlsHello)
        {
            *packets = FRAGMENT_PACKETS_TLSHELLO.to_owned();
        }
        let is_range = !matches!(mode, Some(FragmentPackets::All | FragmentPackets::TlsHello));
        if ui.selectable_label(is_range, "range").clicked() && !is_range {
            *packets = "1-3".to_owned();
        }
    });
}

/// What the layer does on this side, plus the fields it will not read (`fragment/conn.go`).
fn fragment_notes(draft: &FragmentMaskSettings, direction: StreamDirection) -> Vec<(String, Color32)> {
    let side = direction.as_str();
    let mut notes = Vec::new();
    match draft.packets_mode() {
        Some(FragmentPackets::All) => notes.push((format!("Splits every write of this {side} into TCP pieces."), HINT_COLOR)),
        Some(FragmentPackets::TlsHello) if draft.merges_tls_records() => notes.push((
            format!(
                "Re-cuts the first TLS handshake record this {side} writes into several records, sent together \
                 in one write (no delay)."
            ),
            HINT_COLOR,
        )),
        Some(FragmentPackets::TlsHello) => notes.push((
            format!(
                "Re-cuts the first TLS handshake record this {side} writes into several records, each its own \
                 write with the delays between them."
            ),
            HINT_COLOR,
        )),
        Some(FragmentPackets::Range { from, to }) if from > to => notes.push((
            format!("packets {from}-{to}: FROM is greater than TO, so no write matches — the layer does nothing."),
            WARNING_COLOR,
        )),
        Some(FragmentPackets::Range { from, to }) if from == to => {
            notes.push((format!("Splits write {from} of this {side} into TCP pieces."), HINT_COLOR));
        }
        Some(FragmentPackets::Range { from, to }) => {
            notes.push((format!("Splits writes {from}–{to} of this {side} into TCP pieces."), HINT_COLOR));
        }
        None => {}
    }
    if !draft.lengths.is_empty() && !draft.length.text.trim().is_empty() {
        notes.push(("length is not used while lengths is set — kept as it is.".to_owned(), WARNING_COLOR));
    }
    if !draft.delays.is_empty() && !draft.delay.text.trim().is_empty() {
        notes.push(("delay is not used while delays is set — kept as it is.".to_owned(), WARNING_COLOR));
    }
    notes
}

fn show_salamander_settings_edit(ui: &mut Ui, settings: &mut serde_json::Value, id_suffix: &str, idx: usize) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_salamander_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_salamander", id_suffix, idx), |ui| {
        egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "password", HELP_SALAMANDER_PASSWORD);
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut draft.password);
                let len = draft.password.len();
                let color = if len < SALAMANDER_MIN_PASSWORD_BYTES { WARNING_COLOR } else { HINT_COLOR };
                ui.label(
                    RichText::new(format!("{len} bytes · at least {SALAMANDER_MIN_PASSWORD_BYTES}"))
                        .size(11.0)
                        .color(color),
                );
            });
            ui.end_row();
            super::field_label(ui, "packetSize", HELP_SALAMANDER_PACKET_SIZE);
            ui.add(egui::TextEdit::singleline(&mut draft.packet_size.text).hint_text("empty = Salamander · 512-1200 = Gecko"));
            ui.end_row();
        });
        let note = match draft.packet_size.bounds() {
            Ok(Some((from, to))) if to > 0 => {
                format!("Gecko: QUIC handshake packets are split and padded to {from}–{to} bytes; the peer needs the same mode.")
            }
            Ok(_) => "Plain Salamander: every packet is obfuscated, sizes stay as they are.".to_owned(),
            Err(_) => String::new(),
        };
        if !note.is_empty() {
            ui.label(RichText::new(note).size(11.0).color(HINT_COLOR));
        }
    });
    form.finish(ui, settings, salamander_settings_to_value)
}

/// `sudoku` form (Roadmap §2.6 stage 2.5): `ascii` as a layout picker, custom tables checked as
/// the core reads them (only in the entropy layout), padding with the values the core uses.
fn show_sudoku_settings_edit(ui: &mut Ui, settings: &mut serde_json::Value, id_suffix: &str, idx: usize) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_sudoku_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_sudoku", id_suffix, idx), |ui| {
        let ascii = draft.prefers_ascii() == Some(true);
        egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "password", HELP_SUDOKU_PASSWORD);
            ui.text_edit_singleline(&mut draft.password);
            ui.end_row();
            super::field_label(ui, "ascii", HELP_SUDOKU_ASCII);
            sudoku_ascii_combo(ui, &mut draft.ascii);
            ui.end_row();
            super::field_label(ui, "customTable", HELP_SUDOKU_CUSTOM_TABLE);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut draft.custom_table).hint_text("xpxvvpvv").desired_width(100.0));
                if let Err(error) = validate_sudoku_custom_table(&draft.custom_table)
                    && !ascii
                {
                    ui.colored_label(WARNING_COLOR, error);
                }
            });
            ui.end_row();
            super::field_label(ui, "paddingMin", HELP_SUDOKU_PADDING);
            optional_u32_field(ui, &mut draft.padding_min);
            ui.end_row();
            super::field_label(ui, "paddingMax", HELP_SUDOKU_PADDING);
            optional_u32_field(ui, &mut draft.padding_max);
            ui.end_row();
        });
        ui.horizontal(|ui| {
            super::help_button(ui, "customTables", HELP_SUDOKU_CUSTOM_TABLE);
            persistent_multiline_list_row(ui, "customTables (one per line)", &mut draft.custom_tables, "custom_tables");
        });
        for (note, color) in sudoku_notes(draft) {
            ui.label(RichText::new(note).size(11.0).color(color));
        }
    });
    form.finish(ui, settings, sudoku_settings_to_value)
}

/// `ascii` picker: "(entropy)" + the core's layouts; a value from disk that is not one of them
/// verbatim (`prefer_ascii`, `ASCII`) is shown as it is until another one is picked.
fn sudoku_ascii_combo(ui: &mut Ui, ascii: &mut String) {
    let selected = if ascii.is_empty() { "(entropy)".to_owned() } else { ascii.clone() };
    egui::ComboBox::from_id_salt("ascii").selected_text(selected).show_ui(ui, |ui| {
        if ui.selectable_label(ascii.is_empty(), "(entropy)").clicked() {
            ascii.clear();
        }
        for &preset in SUDOKU_ASCII_MODES {
            if ui.selectable_label(ascii == preset, preset).clicked() {
                *ascii = preset.to_owned();
            }
        }
    });
}

/// The fields the core does not read as written: custom tables in the ASCII layout, a
/// `customTable` hidden by `customTables`, padding it caps or raises.
fn sudoku_notes(draft: &SudokuSettings) -> Vec<(String, Color32)> {
    let mut notes = Vec::new();
    let has_table = !draft.custom_table.trim().is_empty();
    let has_tables = draft.custom_tables.iter().any(|table| !table.trim().is_empty());
    if draft.prefers_ascii() == Some(true) && (has_table || has_tables) {
        notes.push(("The ascii layout uses no custom table — kept as it is.".to_owned(), WARNING_COLOR));
    } else if has_table && !draft.custom_tables.is_empty() {
        notes.push(("customTable is not used while customTables is set — kept as it is.".to_owned(), WARNING_COLOR));
    }
    let (min, max) = draft.effective_padding();
    let written = (draft.padding_min.unwrap_or(0), draft.padding_max.unwrap_or(0));
    if written != (min, max) {
        notes.push((
            format!("Padding is used as {min}–{max}% (at most {SUDOKU_MAX_PADDING}, paddingMax not below paddingMin)."),
            HINT_COLOR,
        ));
    }
    notes
}

/// `realm` form (Roadmap §2.6 stage 1.2): `url` as text and as fields, `stunServers`, `ipMode`,
/// typed `portMapping`, `tlsConfig` as a JSON object. The core's `Build()` checks are shown under
/// the layer.
fn show_realm_settings_edit(ui: &mut Ui, settings: &mut serde_json::Value, id_suffix: &str, idx: usize) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_realm_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_realm", id_suffix, idx), |ui| {
        egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "url", HELP_REALM_URL);
            ui.add(
                egui::TextEdit::singleline(&mut draft.url)
                    .desired_width(320.0)
                    .hint_text("realm://TOKEN@realm.example.com/ID"),
            );
            ui.end_row();
        });
        realm_url_fields_edit(ui, &mut draft.url);

        ui.horizontal(|ui| {
            super::help_button(ui, "stunServers", HELP_REALM_STUN);
            persistent_multiline_list_row(ui, "stunServers (one host:port per line)", &mut draft.stun_servers, "stun_servers");
        });
        egui::Grid::new("options").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "ipMode", HELP_REALM_IP_MODE);
            ui.horizontal(|ui| {
                super::optional_string_combo(ui, "realm_ip_mode", &mut draft.ip_mode, REALM_IP_MODES);
                if !realm_ip_mode_is_known(&draft.ip_mode) {
                    ui.colored_label(WARNING_COLOR, "unknown — Xray-core uses dual");
                }
            });
            ui.end_row();
        });
        realm_port_mapping_edit(ui, &mut draft.port_mapping);
        ui.horizontal(|ui| {
            super::help_button(ui, "tlsConfig", HELP_REALM_TLS);
            optional_json_object_edit(ui, "tlsConfig (client TLS to the realm server)", &mut draft.tls_config, "tls_config");
        });
    });
    form.finish(ui, settings, realm_settings_to_value)
}

/// The fields of a realm `url`. Editing one rewrites `url` (token and id percent-encoded); a URL
/// that doesn't parse is reported instead, and is edited as text. Host and port inputs drop the
/// characters that would make the composed URL unparsable.
fn realm_url_fields_edit(ui: &mut Ui, url_text: &mut String) {
    let parsed = if url_text.is_empty() { Ok(RealmUrl::default()) } else { parse_realm_url(url_text) };
    let mut url = match parsed {
        Ok(url) => url,
        Err(error) => {
            ui.colored_label(WARNING_COLOR, format!("url: {error} — fix the URL text to edit it by fields"));
            return;
        }
    };
    let mut changed = false;
    ui.indent("realm_url_fields", |ui| {
        egui::Grid::new("realm_url_grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            ui.label("scheme");
            ui.horizontal(|ui| {
                for (scheme, text) in [(RealmScheme::Https, "realm (HTTPS)"), (RealmScheme::Http, "realm+http (HTTP)")] {
                    changed |= ui.radio_value(&mut url.scheme, scheme, text).changed();
                }
            });
            ui.end_row();
            ui.label("token");
            changed |= ui.text_edit_singleline(&mut url.token).changed();
            ui.end_row();
            ui.label("host");
            if ui.text_edit_singleline(&mut url.host).changed() {
                url.host.retain(|c| !c.is_whitespace() && !c.is_control() && !"/?#@[]".contains(c));
                changed = true;
            }
            ui.end_row();
            ui.label("port");
            let default_port = url.scheme.default_port().to_string();
            if ui.add(egui::TextEdit::singleline(&mut url.port).hint_text(default_port)).changed() {
                url.port.retain(|c| c.is_ascii_digit());
                changed = true;
            }
            ui.end_row();
            ui.label("id");
            changed |= ui.text_edit_singleline(&mut url.id).changed();
            ui.end_row();
        });
    });
    if changed {
        *url_text = url.to_url_text();
    }
}

/// `portMapping`: the checkbox drives `enabled`; unticking a mapping that has nothing else set
/// removes the key.
fn realm_port_mapping_edit(ui: &mut Ui, port_mapping: &mut Option<RealmPortMapping>) {
    let mut enabled = port_mapping.as_ref().is_some_and(RealmPortMapping::is_enabled);
    ui.horizontal(|ui| {
        super::help_button(ui, "portMapping", HELP_REALM_PORT_MAPPING);
        if ui.checkbox(&mut enabled, "portMapping (UPnP / NAT-PMP)").changed() {
            let mapping = port_mapping.get_or_insert_with(RealmPortMapping::default);
            if enabled || !mapping.is_bare() {
                mapping.enabled = Some(enabled);
            } else {
                *port_mapping = None;
            }
        }
    });
    if let Some(mapping) = port_mapping {
        ui.indent("realm_port_mapping", |ui| {
            egui::Grid::new("realm_port_mapping_grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
                ui.label("timeout (s)");
                optional_i64_field(ui, &mut mapping.timeout, "10");
                ui.end_row();
                ui.label("lifetime (s)");
                optional_i64_field(ui, &mut mapping.lifetime, "600");
                ui.end_row();
            });
        });
    }
}

/// An optional nested JSON object (`realm.tlsConfig`): a checkbox adds / removes the key, the
/// text keeps what is being typed until it is a JSON object.
fn optional_json_object_edit(ui: &mut Ui, label: &str, value: &mut Option<serde_json::Value>, id: &str) {
    ui.vertical(|ui| {
        let mut present = value.is_some();
        if ui.checkbox(&mut present, label).changed() {
            *value = present.then(|| serde_json::Value::Object(serde_json::Map::new()));
        }
        let Some(object) = value else {
            return;
        };
        let buffer_id = ui.make_persistent_id(id);
        let mut text = load_text_buffer(ui, buffer_id, object, || {
            serde_json::to_string_pretty(object).unwrap_or_default()
        });
        let edited = resizable_multiline(ui, &mut text, 3, id).changed();
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(parsed) if parsed.is_object() => {
                if edited && parsed != *object {
                    *object = parsed;
                }
            }
            Ok(_) => {
                ui.colored_label(WARNING_COLOR, "Not applied: must be a JSON object");
            }
            Err(error) => {
                ui.colored_label(WARNING_COLOR, format!("Not applied: {error}"));
            }
        }
        store_text_buffer(ui, buffer_id, object.clone(), text);
    });
}

/// `udphop` form (Roadmap §2.6 stage 1.1): `mode` as checkboxes, `interval` / `remotePorts` /
/// `remoteIPs`, and an explicit removal of the legacy `sockopt` (kept verbatim otherwise). The
/// core's `Build()` checks are shown under the layer.
fn show_udphop_settings_edit(ui: &mut Ui, settings: &mut serde_json::Value, id_suffix: &str, idx: usize) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_udphop_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_udphop", id_suffix, idx), |ui| {
        let mut modes = lenient_udphop_modes(&draft.mode);
        egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "mode", HELP_UDPHOP_MODE);
            ui.horizontal(|ui| {
                let mut toggled = ui.checkbox(&mut modes.interval_local, "intervalLocal").changed();
                toggled |= ui.checkbox(&mut modes.interval_remote, "intervalRemote").changed();
                toggled |= ui.checkbox(&mut modes.per_conn_remote, "perConnRemote").changed();
                if toggled {
                    draft.mode = modes.to_mode_text();
                }
            });
            ui.end_row();
            super::field_label(ui, "interval", HELP_UDPHOP_INTERVAL);
            ui.add(egui::TextEdit::singleline(&mut draft.interval.text).hint_text("30 · N or FROM-TO, ≥ 5"));
            ui.end_row();
            super::field_label(ui, "remotePorts", HELP_UDPHOP_REMOTE_PORTS);
            ui.add(egui::TextEdit::singleline(&mut draft.remote_ports.text).hint_text("20000-50000"));
            ui.end_row();
        });
        ui.horizontal(|ui| {
            super::help_button(ui, "remoteIPs", HELP_UDPHOP_REMOTE_IPS);
            persistent_multiline_list_row(ui, "remoteIPs (one per line)", &mut draft.remote_ips, "remote_ips");
        });

        if modes.picks_remote() && draft.remote_ports.text.trim().is_empty() && draft.remote_ips.is_empty() {
            ui.label(
                RichText::new(
                    "intervalRemote / perConnRemote pick from remoteIPs / remotePorts — with both \
                     empty the remote address never changes.",
                )
                .size(11.0)
                .color(HINT_COLOR),
            );
        }
        if draft.has_legacy_sockopt() {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    WARNING_COLOR,
                    "sockopt: removed from the mask in Xray-core v26.9.30 (XTLS/Xray-core#6754); \
                     older cores still read it. Kept as is.",
                );
                if ui.button("Remove sockopt").clicked() {
                    draft.remove_legacy_sockopt();
                }
            });
        }
    });
    form.finish(ui, settings, udphop_settings_to_value)
}

/// The modes a possibly invalid `mode` text already names (tokens trimmed), so the checkboxes
/// reflect what the user meant; toggling one rewrites `mode` in the canonical form.
fn lenient_udphop_modes(text: &str) -> UdpHopModes {
    text.split(',')
        .filter_map(|token| parse_udphop_mode(token.trim()).ok())
        .fold(UdpHopModes::default(), |all, one| UdpHopModes {
            interval_local: all.interval_local || one.interval_local,
            interval_remote: all.interval_remote || one.interval_remote,
            per_conn_remote: all.per_conn_remote || one.per_conn_remote,
        })
}

fn show_noise_mask_settings_edit(ui: &mut Ui, settings: &mut serde_json::Value, id_suffix: &str, idx: usize) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_noise_mask_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_noise", id_suffix, idx), |ui| {
        ui.horizontal(|ui| {
            super::field_label(ui, "reset", HELP_NOISE_RESET);
            ui.add(egui::TextEdit::singleline(&mut draft.reset.text).hint_text("s: empty = once per address"));
        });
        ui.add_space(4.0);
        ui.label(RichText::new("noise[]").strong());
        let len = draft.noise.len();
        let mut item_edit = None;
        for (item_idx, item) in draft.noise.iter_mut().enumerate() {
            ui.push_id(("item", item_idx), |ui| {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("noise[{item_idx}]"));
                        list_edit_buttons(ui, item_idx, len, &mut item_edit);
                    });
                    noise_item_edit(ui, item);
                    if let Some(note) = noise_item_note(item) {
                        ui.label(RichText::new(note).size(11.0).color(HINT_COLOR));
                    }
                });
            });
        }
        apply_list_edit(&mut draft.noise, item_edit);
        if ui.button("Add noise item").clicked() {
            draft.noise.push(NoiseMaskItem::default());
        }
    });
    form.finish(ui, settings, noise_mask_settings_to_value)
}

fn noise_item_edit(ui: &mut Ui, item: &mut NoiseMaskItem) {
    egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        super::field_label(ui, "packet", HELP_NOISE_PACKET);
        ui.vertical(|ui| {
            packet_kind_combo(ui, NOISE_PACKET_KINDS, &mut item.kind, &mut item.packet);
            packet_text_edit(ui, &item.kind, &mut item.packet);
        });
        ui.end_row();
        super::field_label(ui, "rand", HELP_NOISE_RAND);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut item.rand.text).hint_text("bytes: N or MIN-MAX").desired_width(110.0));
            ui.label("randRange");
            ui.add(egui::TextEdit::singleline(&mut item.rand_range.text).hint_text("0-255").desired_width(80.0));
        });
        ui.end_row();
        super::field_label(ui, "delay", HELP_NOISE_DELAY);
        ui.add(egui::TextEdit::singleline(&mut item.delay.text).hint_text("ms: N or MIN-MAX"));
        ui.end_row();
    });
}

/// What the item sends (`noise/conn.go` `buildPacket`); `None` when it sets both `packet` and
/// `rand` (the `Build()` error under the layer says it).
fn noise_item_note(item: &NoiseMaskItem) -> Option<String> {
    let range = match item.rand_range.text.trim() {
        "" => "0-255",
        range => range,
    };
    let mut note = match item.payload()? {
        NoiseItemPayload::Exp => "Sends the bytes the expression builds, fresh for every datagram".to_owned(),
        NoiseItemPayload::Rand => format!("Sends {} random bytes, values {range}", item.rand.text.trim()),
        NoiseItemPayload::Packet => "Sends these bytes".to_owned(),
        NoiseItemPayload::Empty => "Sends an empty datagram (no packet, no rand)".to_owned(),
    };
    if item.payload() == Some(NoiseItemPayload::Exp)
        && (!item.rand.text.trim().is_empty() || !item.rand_range.text.trim().is_empty())
    {
        note.push_str(" · rand / randRange are not used with exp");
    }
    match item.delay.text.trim() {
        "" => {}
        delay => note.push_str(&format!(" · then waits {delay} ms")),
    }
    Some(note)
}

/// `xdns` form (Roadmap §2.6 stage 1.3, v26.9.30 schema): domains with record-type checkboxes and
/// limits, resolvers (client side), `extraPoll`. Settings in the pre-v26.9.30 schema stay on the
/// raw-JSON editor with an explicit "Migrate" button.
fn show_xdns_settings_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    settings: &mut serde_json::Value,
    id_suffix: &str,
    idx: usize,
) -> bool {
    if xdns_has_legacy_fields(settings) {
        return show_legacy_xdns_edit(ui, settings, id_suffix, idx);
    }
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_xdns_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_xdns", id_suffix, idx), |ui| {
        ui.horizontal(|ui| {
            super::help_button(ui, "xdns domains", HELP_XDNS_DOMAINS);
            ui.label(RichText::new("domains[]").strong());
        });
        let mut remove_domain = None;
        for (domain_idx, domain) in draft.domains.iter_mut().enumerate() {
            ui.push_id(("domain", domain_idx), |ui| {
                ui.group(|ui| {
                    egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
                        ui.label("name");
                        ui.add(egui::TextEdit::singleline(&mut domain.name).hint_text("t.example.com"));
                        ui.end_row();
                        ui.label("types");
                        xdns_types_edit(ui, &mut domain.types);
                        ui.end_row();
                        ui.label("lenLimit");
                        optional_i64_field(ui, &mut domain.len_limit, "255");
                        ui.end_row();
                        ui.label("labelLimit");
                        optional_i64_field(ui, &mut domain.label_limit, "63");
                        ui.end_row();
                        ui.label("edns0");
                        optional_i64_field(ui, &mut domain.edns0, "0 = off · 512–4096");
                        ui.end_row();
                    });
                    if ui.button("Remove domain").clicked() {
                        remove_domain = Some(domain_idx);
                    }
                });
            });
        }
        if let Some(domain_idx) = remove_domain {
            draft.domains.remove(domain_idx);
        }
        if ui.button("Add domain").clicked() {
            draft.domains.push(XdnsDomain { types: vec![16], ..XdnsDomain::default() });
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            super::help_button(ui, "xdns resolvers", HELP_XDNS_RESOLVERS);
            ui.label(RichText::new("resolvers[]").strong());
        });
        if direction == StreamDirection::Inbound {
            ui.label(
                RichText::new("Client side only — an inbound (server) ignores resolvers.")
                    .size(11.0)
                    .color(HINT_COLOR),
            );
        }
        let mut remove_resolver = None;
        for (resolver_idx, resolver) in draft.resolvers.iter_mut().enumerate() {
            ui.push_id(("resolver", resolver_idx), |ui| {
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("type")
                        .selected_text(if resolver.kind.is_empty() { "(type)" } else { resolver.kind.as_str() })
                        .show_ui(ui, |ui| {
                            for kind in XDNS_RESOLVER_KINDS {
                                ui.selectable_value(&mut resolver.kind, (*kind).to_owned(), *kind);
                            }
                        });
                    if ui.add(egui::TextEdit::singleline(&mut resolver.addr).hint_text("1.1.1.1:53")).changed() {
                        resolver.has_settings = true;
                    }
                    if ui.button("Remove").clicked() {
                        remove_resolver = Some(resolver_idx);
                    }
                });
            });
        }
        if let Some(resolver_idx) = remove_resolver {
            draft.resolvers.remove(resolver_idx);
        }
        if ui.button("Add resolver").clicked() {
            draft.resolvers.push(XdnsResolver { kind: "udp".to_owned(), has_settings: true, ..XdnsResolver::default() });
        }

        ui.add_space(4.0);
        egui::Grid::new("options").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "extraPoll", HELP_XDNS_EXTRA_POLL);
            optional_i64_field(ui, &mut draft.extra_poll, "0 · 0–3");
            ui.end_row();
        });
    });
    form.finish(ui, settings, xdns_settings_to_value)
}

/// Record-type checkboxes (A, CNAME, TXT, AAAA). A box is ticked when any entry casts to its
/// code (the core's `uint16` cast); unticking removes those entries, other codes are kept and
/// shown.
fn xdns_types_edit(ui: &mut Ui, types: &mut Vec<i64>) {
    ui.horizontal(|ui| {
        for &(code, name) in XDNS_RECORD_TYPES {
            let mut on = types.iter().any(|kind| xdns_record_type_name(*kind) == Some(name));
            if ui.checkbox(&mut on, name).changed() {
                if on {
                    types.push(code);
                } else {
                    types.retain(|kind| xdns_record_type_name(*kind) != Some(name));
                }
            }
        }
        let others: Vec<String> = types
            .iter()
            .filter(|kind| xdns_record_type_name(**kind).is_none())
            .map(i64::to_string)
            .collect();
        if !others.is_empty() {
            ui.colored_label(WARNING_COLOR, format!("unsupported: {}", others.join(", ")));
        }
    });
}

/// Pre-v26.9.30 `xdns` settings: explanation, a "Migrate" button (enabled when the conversion is
/// unambiguous) and the raw-JSON editor.
fn show_legacy_xdns_edit(ui: &mut Ui, settings: &mut serde_json::Value, id_suffix: &str, idx: usize) -> bool {
    let mut changed = false;
    ui.label(
        RichText::new(
            "Pre-v26.9.30 xdns schema (string domains / resolvers or `domain`). Xray-core v26.9.30+ \
             reads only the object form (XTLS/Xray-core#6718) — migrate once the server runs it.",
        )
        .color(WARNING_COLOR),
    );
    match migrate_legacy_xdns_settings(settings) {
        Ok(migrated) => {
            if ui
                .button("Migrate to the v26.9.30 schema")
                .on_hover_text("Converts the strings to domains[] / resolvers[] objects; review the result before Save.")
                .clicked()
                && migrated != *settings
            {
                *settings = migrated;
                changed = true;
            }
        }
        Err(error) => {
            ui.colored_label(WARNING_COLOR, format!("Can't migrate automatically: {error}"));
        }
    }
    changed | show_finalmask_raw_json_edit(ui, settings, id_suffix, idx)
}

/// `xicmp` form: `dgram` (client side only) and `ips`, whose meaning depends on the side
/// (`xicmp/client.go`: server addresses to ping; `server.go`: accepted client addresses).
fn show_xicmp_settings_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    settings: &mut serde_json::Value,
    id_suffix: &str,
    idx: usize,
) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_xicmp_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_xicmp", id_suffix, idx), |ui| {
        ui.horizontal(|ui| {
            super::help_button(ui, "dgram", HELP_XICMP_DGRAM);
            ui.checkbox(&mut draft.dgram, "dgram");
            if direction == StreamDirection::Inbound && draft.dgram {
                ui.colored_label(WARNING_COLOR, "ignored on the inbound side (the server uses raw sockets) — kept as it is");
            }
        });
        ui.horizontal(|ui| {
            super::help_button(ui, "ips", HELP_XICMP_IPS);
            persistent_multiline_list_row(ui, "ips (one per line)", &mut draft.ips, "ips");
        });
        let note = match (direction, draft.ips.is_empty()) {
            (StreamDirection::Inbound, true) => "Accepts pings from any address.",
            (StreamDirection::Inbound, false) => "Accepts pings only from these addresses.",
            (StreamDirection::Outbound, true) => "Pings the outbound's address — it must be an IP, not a domain.",
            (StreamDirection::Outbound, false) => "Pings one of these addresses, picked at random.",
        };
        ui.label(RichText::new(note).size(11.0).color(HINT_COLOR));
    });
    form.finish(ui, settings, xicmp_settings_to_value)
}

/// `mkcp-legacy` form (Roadmap §2.6 stage 2.1): `header` ComboBox + `value` whose hint follows
/// what `MkcpLegacy.Build()` makes of the pair.
fn show_mkcp_legacy_settings_edit(ui: &mut Ui, settings: &mut serde_json::Value, id_suffix: &str, idx: usize) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_mkcp_legacy_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_mkcp_legacy", id_suffix, idx), |ui| {
        let mode = draft.mode();
        egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "header", HELP_MKCP_LEGACY_HEADER);
            mkcp_legacy_header_combo(ui, &mut draft.header);
            ui.end_row();
            super::field_label(ui, "value", HELP_MKCP_LEGACY_VALUE);
            let value_hint = match &mode {
                Some(MkcpLegacyMode::Original | MkcpLegacyMode::Aes128Gcm) => "AES-128-GCM password",
                Some(MkcpLegacyMode::Dns { .. }) => MKCP_LEGACY_DEFAULT_DNS_DOMAIN,
                Some(MkcpLegacyMode::Header(_)) | None => "(not used)",
            };
            ui.add(egui::TextEdit::singleline(&mut draft.value).hint_text(value_hint));
            ui.end_row();
        });
        let (note, color) = mkcp_legacy_mode_note(mode.as_ref(), !draft.value.is_empty());
        if !note.is_empty() {
            ui.label(RichText::new(note).size(11.0).color(color));
        }
    });
    form.finish(ui, settings, mkcp_legacy_settings_to_value)
}

/// `mkcp-legacy` `header` picker: "(none)" + the core's headers. A value from disk that is not
/// one of them verbatim (`DNS`, an invalid `none`) is shown as it is until another one is picked.
fn mkcp_legacy_header_combo(ui: &mut Ui, header: &mut String) {
    let selected = if header.is_empty() { "(none)" } else { header.as_str() };
    egui::ComboBox::from_id_salt("header")
        .selected_text(selected.to_owned())
        .show_ui(ui, |ui| {
            if ui.selectable_label(header.is_empty(), "(none)").clicked() {
                header.clear();
            }
            for &preset in MKCP_LEGACY_HEADERS {
                if ui.selectable_label(header == preset, preset).clicked() {
                    *header = preset.to_owned();
                }
            }
        });
}

/// One line on what the core does with the layer; empty when the `Build()` error under the layer
/// already says it. Warning colour when a set `value` is ignored.
fn mkcp_legacy_mode_note(mode: Option<&MkcpLegacyMode>, value_set: bool) -> (String, Color32) {
    match mode {
        None => (String::new(), HINT_COLOR),
        Some(MkcpLegacyMode::Original) => (
            "Original mKCP obfuscation. Enter a value to use AES-128-GCM with that password instead."
                .to_owned(),
            HINT_COLOR,
        ),
        Some(MkcpLegacyMode::Aes128Gcm) => (
            "AES-128-GCM obfuscation with value as the password — the other side needs the same one."
                .to_owned(),
            HINT_COLOR,
        ),
        Some(MkcpLegacyMode::Dns { domain }) => (
            format!(
                "Fake DNS query for {domain}. The other side must use the same domain: the header \
                 length depends on it."
            ),
            HINT_COLOR,
        ),
        Some(MkcpLegacyMode::Header(name)) if value_set => (
            format!("value is ignored by Xray-core with header {name} — it is kept as it is."),
            WARNING_COLOR,
        ),
        Some(MkcpLegacyMode::Header(name)) => (format!("Fake {name} header; value is not used."), HINT_COLOR),
    }
}

/// `xmc` form (Roadmap §2.6 stage 2.4): `password` with its RSA byte limit, `hostname` (client
/// side) and the signed `profiles` with Up / Down / Remove. The pre-v26.7.28 `usernames` key gets
/// a notice and an explicit way out ("Start profiles from usernames" / "Remove usernames").
fn show_xmc_settings_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    settings: &mut serde_json::Value,
    id_suffix: &str,
    idx: usize,
) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_xmc_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_xmc", id_suffix, idx), |ui| {
        xmc_legacy_usernames_edit(ui, draft);
        egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            super::field_label(ui, "password", HELP_XMC_PASSWORD);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut draft.password).hint_text("same on both sides"));
                let len = draft.password.len();
                let color = if len > XMC_MAX_PASSWORD_BYTES { WARNING_COLOR } else { HINT_COLOR };
                ui.label(RichText::new(format!("{len}/{XMC_MAX_PASSWORD_BYTES} bytes")).size(11.0).color(color));
            });
            ui.end_row();
            super::field_label(ui, "hostname", HELP_XMC_HOSTNAME);
            let hint = match direction {
                StreamDirection::Inbound => "(not used by the server)",
                StreamDirection::Outbound => "(the dialed IP)",
            };
            ui.add(egui::TextEdit::singleline(&mut draft.hostname).hint_text(hint));
            ui.end_row();
        });
        if let Some(note) = xmc_hostname_note(direction, !draft.hostname.is_empty()) {
            ui.label(RichText::new(note).size(11.0).color(WARNING_COLOR));
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            super::help_button(ui, "profiles", HELP_XMC_PROFILES);
            ui.strong("profiles");
        });
        ui.label(RichText::new(xmc_profiles_note(direction)).size(11.0).color(HINT_COLOR));
        let len = draft.profiles.len();
        let mut profile_edit = None;
        for (profile_idx, profile) in draft.profiles.iter_mut().enumerate() {
            ui.push_id(("profile", profile_idx), |ui| {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("profiles[{profile_idx}]")).strong());
                        list_edit_buttons(ui, profile_idx, len, &mut profile_edit);
                    });
                    xmc_profile_edit(ui, profile);
                });
            });
        }
        apply_list_edit(&mut draft.profiles, profile_edit);
        if ui.button("Add profile").clicked() {
            draft.profiles.push(XmcProfile::default());
        }
    });
    form.finish(ui, settings, xmc_settings_to_value)
}

fn xmc_profile_edit(ui: &mut Ui, profile: &mut XmcProfile) {
    egui::Grid::new("profile").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        super::field_label(ui, "username", HELP_XMC_USERNAME);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut profile.username).hint_text("Steve").desired_width(160.0));
            if !profile.username.is_empty() && !xmc_username_is_valid(&profile.username) {
                ui.colored_label(WARNING_COLOR, "3–16 letters, digits, _");
            }
        });
        ui.end_row();
        super::field_label(ui, "uuid", HELP_XMC_UUID);
        ui.add(
            egui::TextEdit::singleline(&mut profile.uuid)
                .hint_text("8667ba71-b85a-4004-af54-457a9734eed7")
                .desired_width(320.0),
        );
        ui.end_row();
        super::field_label(ui, "texturesValue", HELP_XMC_TEXTURES);
        resizable_multiline(ui, &mut profile.textures_value, 2, "textures_value");
        ui.end_row();
        super::field_label(ui, "texturesSignature", HELP_XMC_TEXTURES);
        resizable_multiline(ui, &mut profile.textures_signature, 2, "textures_signature");
        ui.end_row();
    });
}

/// What this side does with `profiles`.
fn xmc_profiles_note(direction: StreamDirection) -> &'static str {
    match direction {
        StreamDirection::Inbound => {
            "This inbound accepts only these profiles and answers with their textures — the client \
             needs the identical list."
        }
        StreamDirection::Outbound => {
            "This outbound logs in with one of these profiles, picked at random per connection, and \
             checks the server's answer — the server needs the identical list."
        }
    }
}

/// Warning for a `hostname` the inbound side ignores; `None` when there is nothing to say.
fn xmc_hostname_note(direction: StreamDirection, hostname_set: bool) -> Option<&'static str> {
    (direction == StreamDirection::Inbound && hostname_set)
        .then_some("hostname is ignored on the inbound side (only the client sends it) — kept as it is.")
}

/// Notice for the pre-v26.7.28 `usernames` key with the action that applies: start `profiles`
/// from it (no profiles yet) or drop it (profiles already replace it). Nothing without the key.
fn xmc_legacy_usernames_edit(ui: &mut Ui, draft: &mut XmcSettings) {
    if draft.legacy_usernames().is_none() {
        return;
    }
    if !draft.profiles.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(
                WARNING_COLOR,
                "usernames is the pre-v26.7.28 schema; profiles replaces it, and Xray-core ignores it.",
            );
            if ui.small_button("Remove usernames").clicked() {
                draft.remove_legacy_usernames();
            }
        });
        return;
    }
    ui.colored_label(
        WARNING_COLOR,
        "usernames is the pre-v26.7.28 schema: Xray-core v26.7.28+ ignores it and refuses the layer \
         without profiles (signed Minecraft profiles); older cores ignore profiles.",
    );
    let mut migrated = draft.clone();
    match migrate_legacy_xmc_usernames(&mut migrated) {
        Ok(()) => {
            let clicked = ui
                .button("Start profiles from usernames")
                .on_hover_text(format!(
                    "One profile per username ({XMC_LEGACY_DEFAULT_USERNAME} for an empty list) and \
                     usernames removed; then fill in each UUID and the textures."
                ))
                .clicked();
            if clicked {
                *draft = migrated;
            }
        }
        Err(error) => {
            ui.colored_label(WARNING_COLOR, format!("Cannot start profiles from usernames: {error}"));
        }
    }
}

/// `header-custom` TCP form (Roadmap §2.6 stage 2.2): `clients` / `servers` / `errors` as lists
/// of sequences, each a list of items with Up / Down / Remove. `transform` stays a JSON object.
fn show_header_custom_tcp_settings_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    settings: &mut serde_json::Value,
    id_suffix: &str,
    idx: usize,
) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_header_custom_tcp_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_header_custom", id_suffix, idx), |ui| {
        for group in HeaderCustomTcpGroup::ALL {
            ui.push_id(group.key(), |ui| {
                header_custom_group_edit(ui, direction, group, draft.group_mut(group));
            });
        }
    });
    form.finish(ui, settings, header_custom_tcp_settings_to_value)
}

/// A list edit requested by an item's Up / Down / Remove buttons, applied after the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListEdit {
    Up(usize),
    Down(usize),
    Remove(usize),
}

/// Up / Down / Remove for entry `idx` of `len`; Up and Down are disabled at the ends.
fn list_edit_buttons(ui: &mut Ui, idx: usize, len: usize, edit: &mut Option<ListEdit>) {
    if ui.add_enabled(idx > 0, egui::Button::new("Up").small()).on_hover_text("Move up").clicked() {
        *edit = Some(ListEdit::Up(idx));
    }
    if ui.add_enabled(idx + 1 < len, egui::Button::new("Down").small()).on_hover_text("Move down").clicked() {
        *edit = Some(ListEdit::Down(idx));
    }
    if ui.small_button("Remove").clicked() {
        *edit = Some(ListEdit::Remove(idx));
    }
}

fn apply_list_edit<T>(items: &mut Vec<T>, edit: Option<ListEdit>) {
    match edit {
        Some(ListEdit::Up(idx)) if idx > 0 => items.swap(idx, idx - 1),
        Some(ListEdit::Down(idx)) if idx + 1 < items.len() => items.swap(idx, idx + 1),
        Some(ListEdit::Remove(idx)) if idx < items.len() => {
            items.remove(idx);
        }
        _ => {}
    }
}

/// Whether this side writes (`true`) or receives and checks (`false`) the sequences of `group`;
/// `None` when it does not use them at all (`errors` on the client).
fn header_custom_group_writes(group: HeaderCustomTcpGroup, direction: StreamDirection) -> Option<bool> {
    match (group, direction) {
        (HeaderCustomTcpGroup::Clients, StreamDirection::Inbound) => Some(false),
        (HeaderCustomTcpGroup::Clients, StreamDirection::Outbound) => Some(true),
        (HeaderCustomTcpGroup::Servers, StreamDirection::Inbound) => Some(true),
        (HeaderCustomTcpGroup::Servers, StreamDirection::Outbound) => Some(false),
        (HeaderCustomTcpGroup::Errors, StreamDirection::Inbound) => Some(true),
        (HeaderCustomTcpGroup::Errors, StreamDirection::Outbound) => None,
    }
}

/// One line on what this side does with `group`; warning colour when it is set but unused.
fn header_custom_group_note(group: HeaderCustomTcpGroup, direction: StreamDirection, used: bool) -> (String, Color32) {
    let side = direction.as_str();
    match header_custom_group_writes(group, direction) {
        None if used => (
            format!("errors is ignored on the {side} side (only the server sends it) — kept as it is."),
            WARNING_COLOR,
        ),
        None => (format!("Not used on the {side} side — only the server sends errors."), HINT_COLOR),
        Some(true) => (format!("This {side} sends these sequences."), HINT_COLOR),
        Some(false) => (
            format!("This {side} receives these sequences and refuses the connection on a mismatch."),
            HINT_COLOR,
        ),
    }
}

fn header_custom_group_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    group: HeaderCustomTcpGroup,
    sequences: &mut HeaderCustomSequences,
) {
    let help = match group {
        HeaderCustomTcpGroup::Clients => HELP_HC_CLIENTS,
        HeaderCustomTcpGroup::Servers => HELP_HC_SERVERS,
        HeaderCustomTcpGroup::Errors => HELP_HC_ERRORS,
    };
    let key = group.key();
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        super::help_button(ui, key, help);
        ui.strong(key);
    });
    let (note, color) = header_custom_group_note(group, direction, !sequences.sequences.is_empty());
    ui.label(RichText::new(note).size(11.0).color(color));
    let writes = header_custom_group_writes(group, direction);

    let len = sequences.sequences.len();
    let mut sequence_edit = None;
    for (sequence_idx, sequence) in sequences.sequences.iter_mut().enumerate() {
        ui.push_id(sequence_idx, |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{key}[{sequence_idx}]")).strong());
                    list_edit_buttons(ui, sequence_idx, len, &mut sequence_edit);
                });
                header_custom_items_edit(ui, &format!("{key}[{sequence_idx}]"), sequence, writes, true);
            });
        });
    }
    apply_list_edit(&mut sequences.sequences, sequence_edit);
    if ui.button(format!("Add {key} sequence")).clicked() {
        sequences.sequences.push(vec![HeaderCustomItem::default()]);
    }
}

/// An ordered `header-custom` item list: a TCP sequence (`path` = `clients[0]`, items with
/// `delay`) or a UDP group (`path` = `client`, no `delay`). `writes` = this side sends the items
/// (`None`: it does not use them).
fn header_custom_items_edit(
    ui: &mut Ui,
    path: &str,
    items: &mut Vec<HeaderCustomItem>,
    writes: Option<bool>,
    with_delay: bool,
) {
    let len = items.len();
    let mut item_edit = None;
    for (item_idx, item) in items.iter_mut().enumerate() {
        ui.push_id(("item", item_idx), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(format!("{path}[{item_idx}]"));
                    list_edit_buttons(ui, item_idx, len, &mut item_edit);
                });
                header_custom_item_edit(ui, item, with_delay);
                if let Some(writes) = writes
                    && let Some(note) = header_custom_item_note(item, writes)
                {
                    ui.label(RichText::new(note).size(11.0).color(HINT_COLOR));
                }
            });
        });
    }
    apply_list_edit(items, item_edit);
    if ui.small_button("Add item").clicked() {
        items.push(HeaderCustomItem::default());
    }
}

fn header_custom_item_edit(ui: &mut Ui, item: &mut HeaderCustomItem, with_delay: bool) {
    egui::Grid::new("grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        if with_delay {
            super::field_label(ui, "delay", HELP_HC_DELAY);
            ui.add(egui::TextEdit::singleline(&mut item.delay.text).hint_text("ms: N or FROM-TO"));
            ui.end_row();
        }
        super::field_label(ui, "packet", HELP_HC_PACKET);
        ui.vertical(|ui| {
            packet_kind_combo(ui, HEADER_CUSTOM_PACKET_KINDS, &mut item.kind, &mut item.packet);
            packet_text_edit(ui, &item.kind, &mut item.packet);
        });
        ui.end_row();
        super::field_label(ui, "rand", HELP_HC_RAND);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut item.rand).hint_text("bytes").desired_width(60.0));
            ui.label("randRange");
            ui.add(egui::TextEdit::singleline(&mut item.rand_range.text).hint_text("0-255").desired_width(80.0));
        });
        ui.end_row();
        super::field_label(ui, "reuse", HELP_HC_REUSE);
        ui.add(egui::TextEdit::singleline(&mut item.reuse).hint_text("variable name"));
        ui.end_row();
        super::field_label(ui, "capture", HELP_HC_CAPTURE);
        ui.add(egui::TextEdit::singleline(&mut item.capture).hint_text("save as variable"));
        ui.end_row();
    });
    ui.horizontal(|ui| {
        super::help_button(ui, "transform", HELP_HC_TRANSFORM);
        optional_json_object_edit(ui, "transform", &mut item.transform, "transform");
    });
}

/// `type` picker for a `packet` (`header-custom` item, `noise` item): "(array)" + `kinds`; a
/// value from disk that is not one of them verbatim is shown as it is. Picking another type
/// re-reads the text in the new encoding (a byte list read from disk is no longer forced to stay
/// a list).
fn packet_kind_combo(ui: &mut Ui, kinds: &[&str], kind: &mut String, packet: &mut PacketValue) {
    let before = kind.clone();
    let selected = if kind.is_empty() { "(array)" } else { kind.as_str() };
    egui::ComboBox::from_id_salt("packet_type")
        .selected_text(format!("type: {selected}"))
        .show_ui(ui, |ui| {
            if ui.selectable_label(kind.is_empty(), "(array)").clicked() {
                kind.clear();
            }
            for &preset in kinds {
                if ui.selectable_label(*kind == preset, preset).clicked() {
                    *kind = preset.to_owned();
                }
            }
        });
    if *kind != before {
        *packet = PacketValue::new(packet.text.clone());
    }
}

/// The `packet` text box for the sibling `kind`. A `str` packet is edited with escapes
/// ([`escape_packet_text`]) so CR / LF are visible; text with a broken escape is kept in the box
/// and not applied. An `exp` (noise) packet is the expression text itself.
fn packet_text_edit(ui: &mut Ui, kind: &str, packet: &mut PacketValue) {
    let kind = kind.trim().to_ascii_lowercase();
    if kind != "str" {
        let hint = match kind.as_str() {
            "hex" => "16030100",
            "base64" => "FgMBAA==",
            NOISE_EXP_KIND => "<b 0x1603> <r 8-16> <t>",
            _ => "22, 3, 1",
        };
        ui.add(egui::TextEdit::singleline(&mut packet.text).hint_text(hint));
        return;
    }
    let buffer_id = ui.make_persistent_id("packet_str");
    let mut text = load_text_buffer(ui, buffer_id, &packet.text, || escape_packet_text(&packet.text));
    let edited = ui
        .add(egui::TextEdit::singleline(&mut text).hint_text("GET / HTTP/1.1\\r\\n\\r\\n"))
        .changed();
    match unescape_packet_text(&text) {
        Ok(plain) => {
            if edited && plain != packet.text {
                packet.text = plain;
            }
        }
        Err(error) => {
            ui.colored_label(WARNING_COLOR, format!("Not applied: {error}"));
        }
    }
    store_text_buffer(ui, buffer_id, packet.text.clone(), text);
}

/// What the item does on this side (`writes` = this side sends the sequence); `None` when the
/// item sets several kinds (the `Build()` error under the layer says it).
fn header_custom_item_note(item: &HeaderCustomItem, writes: bool) -> Option<String> {
    let rand = item.rand.trim();
    let range = match item.rand_range.text.trim() {
        "" => "0-255",
        range => range,
    };
    let var = |name: &str| format!("`{name}`");
    let mut note = match (item.kind()?, writes) {
        (HeaderCustomItemKind::Empty, _) => "No bytes".to_owned(),
        (HeaderCustomItemKind::Packet, true) => "Sends these bytes".to_owned(),
        (HeaderCustomItemKind::Packet, false) => "Expects exactly these bytes".to_owned(),
        (HeaderCustomItemKind::Rand, true) => format!("Sends {rand} random bytes, values {range}"),
        (HeaderCustomItemKind::Rand, false) => format!("Accepts any {rand} bytes"),
        (HeaderCustomItemKind::Reuse, true) => format!("Sends the bytes saved as {}", var(&item.reuse)),
        (HeaderCustomItemKind::Reuse, false) => format!("Expects the bytes saved as {}", var(&item.reuse)),
        (HeaderCustomItemKind::Transform, true) => "Sends the transform result".to_owned(),
        (HeaderCustomItemKind::Transform, false) => "Expects the transform result".to_owned(),
    };
    if !item.capture.is_empty() {
        note.push_str(&format!(" · saved as {}", var(&item.capture)));
    }
    match item.delay.text.trim() {
        "" => {}
        delay if writes => note.push_str(&format!(" · after a {delay} ms pause")),
        _ => note.push_str(" · delay is not used when receiving"),
    }
    Some(note)
}

/// `header-custom` UDP form (Roadmap §2.6 stage 2.3): `mode` ComboBox, then `client` / `server`
/// item lists with Up / Down / Remove (`UDPItem` has no `delay`).
fn show_header_custom_udp_settings_edit(
    ui: &mut Ui,
    direction: StreamDirection,
    settings: &mut serde_json::Value,
    id_suffix: &str,
    idx: usize,
) -> bool {
    let Some(mut form) = FinalMaskForm::begin(ui, settings, id_suffix, idx, parse_header_custom_udp_settings) else {
        return show_finalmask_raw_json_edit(ui, settings, id_suffix, idx);
    };
    let draft = &mut form.draft;
    ui.push_id(("finalmask_header_custom_udp", id_suffix, idx), |ui| {
        ui.horizontal(|ui| {
            super::field_label(ui, "mode", HELP_HC_UDP_MODE);
            header_custom_udp_mode_combo(ui, &mut draft.mode);
        });
        if let Some(note) = header_custom_udp_mode_note(&draft.mode) {
            ui.label(RichText::new(note).size(11.0).color(HINT_COLOR));
        }
        let standalone = draft.is_standalone();
        for group in HeaderCustomUdpGroup::ALL {
            let key = group.key();
            let help = match group {
                HeaderCustomUdpGroup::Client => HELP_HC_UDP_CLIENT,
                HeaderCustomUdpGroup::Server => HELP_HC_UDP_SERVER,
            };
            let writes = header_custom_udp_group_writes(group, direction);
            ui.push_id(key, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    super::help_button(ui, key, help);
                    ui.strong(key);
                });
                let note = header_custom_udp_group_note(group, direction, standalone);
                ui.label(RichText::new(note).size(11.0).color(HINT_COLOR));
                header_custom_items_edit(ui, key, &mut draft.group_mut(group).items, Some(writes), false);
            });
        }
    });
    form.finish(ui, settings, header_custom_udp_settings_to_value)
}

/// `mode` picker: "(prefix)" + the core's modes. A value from disk that is not one of them
/// verbatim (`Prefix` — the core is case-sensitive) is shown as it is until another one is picked.
fn header_custom_udp_mode_combo(ui: &mut Ui, mode: &mut String) {
    let default = format!("({HEADER_CUSTOM_UDP_DEFAULT_MODE})");
    let selected = if mode.is_empty() { default.clone() } else { mode.clone() };
    egui::ComboBox::from_id_salt("mode").selected_text(selected).show_ui(ui, |ui| {
        if ui.selectable_label(mode.is_empty(), default).clicked() {
            mode.clear();
        }
        for &preset in HEADER_CUSTOM_UDP_MODES {
            if ui.selectable_label(mode == preset, preset).clicked() {
                *mode = preset.to_owned();
            }
        }
    });
}

/// What `HeaderCustomUDP.Build()` makes of `mode`; `None` for an unknown one (the error under the
/// layer says it).
fn header_custom_udp_mode_note(mode: &str) -> Option<&'static str> {
    match mode {
        "" | "prefix" => Some("Every packet carries the header in front of its payload; headers have a fixed size."),
        "standalone" => Some("One handshake packet per destination, then data packets travel unchanged."),
        _ => None,
    }
}

/// Whether this side sends `group`: the client sends `client`, the server sends `server`.
fn header_custom_udp_group_writes(group: HeaderCustomUdpGroup, direction: StreamDirection) -> bool {
    matches!(
        (group, direction),
        (HeaderCustomUdpGroup::Client, StreamDirection::Outbound) | (HeaderCustomUdpGroup::Server, StreamDirection::Inbound)
    )
}

/// One line on what this side does with `group` in the current mode (`udp.go`).
fn header_custom_udp_group_note(group: HeaderCustomUdpGroup, direction: StreamDirection, standalone: bool) -> String {
    let side = direction.as_str();
    let writes = header_custom_udp_group_writes(group, direction);
    match (standalone, group, writes) {
        (false, _, true) => format!("Put in front of every packet this {side} sends."),
        (false, _, false) => {
            format!("Expected in front of every packet this {side} receives; a packet without it is dropped.")
        }
        (true, HeaderCustomUdpGroup::Client, true) => {
            format!("Sent once per destination as a separate packet; this {side} waits for the server reply before data.")
        }
        (true, HeaderCustomUdpGroup::Client, false) => format!(
            "The client handshake: a packet of exactly this size that matches is answered with server; \
             other packets reach this {side} as data."
        ),
        (true, HeaderCustomUdpGroup::Server, true) => {
            format!("Sent by this {side} as the reply to a matching client handshake.")
        }
        (true, HeaderCustomUdpGroup::Server, false) => {
            format!("The reply this {side} waits for before it sends data.")
        }
    }
}

/// `Option<i64>` field as a text box (empty = `None`); non-numeric text is ignored.
fn optional_i64_field(ui: &mut Ui, value: &mut Option<i64>, hint: &str) {
    let mut text = value.map(|v| v.to_string()).unwrap_or_default();
    if ui.add(egui::TextEdit::singleline(&mut text).hint_text(hint)).changed() {
        let trimmed = text.trim();
        *value = if trimmed.is_empty() {
            None
        } else {
            trimmed.parse::<i64>().ok().or(*value)
        };
    }
}

/// `Option<u32>` field as a text box (empty = `None`); non-numeric text is ignored.
fn optional_u32_field(ui: &mut Ui, value: &mut Option<u32>) {
    let mut text = value.map(|v| v.to_string()).unwrap_or_default();
    if ui.text_edit_singleline(&mut text).changed() {
        let trimmed = text.trim();
        *value = if trimmed.is_empty() {
            None
        } else {
            trimmed.parse::<u32>().ok().or(*value)
        };
    }
}


#[cfg(test)]
mod finalmask_form_tests {
    //! Roadmap §2.6 stage 0.2: FinalMask editors must not rewrite `settings` on their own, and
    //! text being typed must survive the next frame. Driven through real egui frames (`run_ui`).

    use super::*;
    use crate::gui::pages::SourcedTextBuffer;
    use crate::xray::{
        HeaderCustomTcpSettings, HeaderCustomUdpSettings, NoiseMaskSettings, noise_mask_settings_to_value,
        parse_quic_params,
        parse_noise_mask_settings,
    };
    use serde_json::json;

    /// One egui frame of the FinalMask settings editor for layer `udp[0]`; returns its "changed".
    fn frame(ctx: &egui::Context, layer_type: &str, settings: &mut serde_json::Value) -> bool {
        frame_on(ctx, FinalMaskChain::Udp, layer_type, settings)
    }

    /// [`frame`] for layer `0` of `chain`.
    fn frame_on(ctx: &egui::Context, chain: FinalMaskChain, layer_type: &str, settings: &mut serde_json::Value) -> bool {
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            changed =
                show_finalmask_settings_edit(ui, StreamDirection::Inbound, chain, layer_type, settings, chain.key(), 0);
        })
        .drop_without_applying_deltas();
        changed
    }

    /// The persistent id an editor derives from the root `Ui` via `make_persistent_id(salt)`.
    fn root_id(ctx: &egui::Context, salt: impl std::hash::Hash + std::fmt::Debug + Copy) -> egui::Id {
        let mut id = egui::Id::NULL;
        ctx.run_ui(egui::RawInput::default(), |ui| id = ui.make_persistent_id(salt))
            .drop_without_applying_deltas();
        id
    }

    #[test]
    fn showing_an_editor_never_rewrites_settings() {
        // Each value is one `*_to_value` would normalize (legacy alias, trimmed text, dropped
        // default, blank list entry) — before stage 0.2 merely rendering the form rewrote it.
        let cases = [
            ("sudoku", json!({"padding_min": 10, "custom_table": "t"})),
            ("xicmp", json!({"dgram": false, "ips": ["1.1.1.1"]})),
            ("fragment", json!({"packets": " tlshello ", "maxSplit": 3})),
            ("xdns", json!({"domains": ["t.example.com", ""]})),
            ("xdns", json!({"domains": [{"name": "t.example.com", "types": [16, 65552], "edns0": 1232}],
                            "resolvers": [{"type": "UDP", "settings": {"addr": "1.1.1.1:53"}}]})),
            ("noise", json!({"reset": 0, "noise": [{"packet": [1, 2]}]})),
            ("salamander", json!({"password": "p", "packetSize": "512-1200"})),
            ("header-custom", json!({"client": [{"rand": 4}]})),
            // Stage 2.1: non-canonical case, a padded value, an empty header, an invalid header.
            ("mkcp-legacy", json!({"header": "DNS", "value": " a.example ", "x": 1})),
            ("mkcp-legacy", json!({"header": "", "value": null})),
            ("mkcp-legacy", json!({"header": "none"})),
            ("mkcp-legacy", json!({"header": 1})),
            // Stage 1.1: invalid mode text and the legacy `sockopt` are shown, not "fixed".
            ("udphop", json!({"mode": "intervalLocal, perConnRemote", "interval": 30, "sockopt": {"mark": 1}})),
            // Stage 1.2: a non-canonical URL (unescaped `:` token, upper-case scheme) and an
            // invalid one are shown as they are.
            ("realm", json!({"url": "REALM://a:b@h/id", "stunServers": ["s:1"], "portMapping": {"enabled": false},
                             "tlsConfig": {"serverName": "h"}, "ipMode": "V4"})),
            ("realm", json!({"url": "https://nope", "portMapping": {}})),
            // Stage 2.5: non-canonical `packets` / `type` / `ascii`, fields the core does not read
            // (`delay` beside `delays`, `randRange` with `exp`, tables in the ascii layout), a
            // short salamander password — shown and flagged, never "fixed".
            ("fragment", json!({"packets": "TLSHello", "delay": 0, "delays": [5]})),
            ("fragment", json!({"packets": "3-1", "length": "5"})),
            ("noise", json!({"noise": [{"type": "EXP", "packet": "<b 0x01> <r 4>", "randRange": "1-2", "delay": 5},
                                       {"type": "str", "packet": "hi\r\n"}, {}]})),
            ("sudoku", json!({"ascii": "Prefer_ASCII", "customTables": ["bad", ""], "paddingMin": 200})),
            ("xicmp", json!({"dgram": true})),
            ("salamander", json!({"password": "p"})),
        ];
        for (layer_type, original) in cases {
            let ctx = egui::Context::default();
            let mut settings = original.clone();
            for _ in 0..3 {
                assert!(!frame(&ctx, layer_type, &mut settings), "{layer_type} reported a change");
            }
            assert_eq!(settings, original, "{layer_type} settings were rewritten");
        }
    }

    /// Stage 2.5: every documented layer type has help next to its type, in its own chain only.
    #[test]
    fn every_documented_type_has_type_help() {
        for chain in [FinalMaskChain::Tcp, FinalMaskChain::Udp] {
            for &kind in chain.types() {
                assert!(finalmask_type_help(chain, kind).is_some(), "{kind} in {}", chain.key());
                assert!(finalmask_type_help(chain, &kind.to_ascii_uppercase()).is_some(), "{kind}");
            }
        }
        assert_eq!(finalmask_type_help(FinalMaskChain::Udp, "fragment"), None);
        assert_eq!(finalmask_type_help(FinalMaskChain::Tcp, "noise"), None);
        assert_ne!(
            finalmask_type_help(FinalMaskChain::Tcp, "header-custom"),
            finalmask_type_help(FinalMaskChain::Udp, "header-custom")
        );
    }

    /// Stage 2.5: the `fragment` line says which writes are split, how `tlshello` sends its
    /// records, and which single-value fields the lists hide.
    #[test]
    fn fragment_notes_follow_packets_and_the_lists() {
        let notes = |settings: serde_json::Value| -> Vec<String> {
            let draft = parse_fragment_mask_settings(&settings).expect("parsed");
            fragment_notes(&draft, StreamDirection::Inbound).into_iter().map(|(note, _)| note).collect()
        };
        assert!(notes(json!({"length": 5}))[0].contains("every write of this inbound"));
        assert!(notes(json!({"packets": "tlshello"}))[0].contains("together in one write"));
        assert!(notes(json!({"packets": "tlshello", "delays": ["5-10"]}))[0].contains("each its own write"));
        assert!(notes(json!({"packets": "2"}))[0].contains("write 2 "));
        assert!(notes(json!({"packets": "1-3"}))[0].contains("writes 1–3"));
        assert!(notes(json!({"packets": "3-1"}))[0].contains("no write matches"));
        assert!(notes(json!({"packets": "tls"})).is_empty());
        let hidden = notes(json!({"length": 5, "lengths": [6], "delay": 1, "delays": [2]}));
        assert!(hidden.iter().any(|note| note.starts_with("length is not used")), "{hidden:?}");
        assert!(hidden.iter().any(|note| note.starts_with("delay is not used")), "{hidden:?}");
    }

    /// Stage 2.5: the `noise` item line follows `buildPacket`.
    #[test]
    fn noise_item_note_follows_what_is_sent() {
        let note = |item: serde_json::Value| {
            let settings = json!({"noise": [item]});
            noise_item_note(&parse_noise_mask_settings(&settings).expect("parsed").noise[0])
        };
        assert_eq!(note(json!({"rand": "8-16"})).as_deref(), Some("Sends 8-16 random bytes, values 0-255"));
        assert_eq!(note(json!({"packet": [1], "delay": "5-10"})).as_deref(), Some("Sends these bytes · then waits 5-10 ms"));
        assert!(note(json!({})).is_some_and(|note| note.contains("empty datagram")));
        assert!(note(json!({"type": "exp", "packet": "<t>", "randRange": "1-2"}))
            .is_some_and(|note| note.contains("not used with exp")));
        assert_eq!(note(json!({"packet": [1], "rand": 2})), None);
    }

    /// Stage 2.5: the `sudoku` notes name what the core does not read as written.
    #[test]
    fn sudoku_notes_name_unused_and_adjusted_fields() {
        let notes = |settings: serde_json::Value| -> Vec<String> {
            sudoku_notes(&parse_sudoku_settings(&settings).expect("parsed")).into_iter().map(|(note, _)| note).collect()
        };
        assert!(notes(json!({})).is_empty());
        assert!(notes(json!({"ascii": "ascii", "customTable": "xpxvvpvv"}))[0].contains("ascii layout"));
        assert!(notes(json!({"customTable": "xpxvvpvv", "customTables": ["xpxvvpvv"]}))[0].contains("customTable is not used"));
        assert!(notes(json!({"paddingMin": 50, "paddingMax": 10}))[0].contains("50–50%"));
        assert!(notes(json!({"paddingMax": 150}))[0].contains("0–100%"));
    }

    /// Stage 2.4: the `xmc` form shows settings as they are — a padded password, an empty profile,
    /// the legacy `usernames`, unknown keys — and falls back to raw JSON for shapes it can't hold
    /// and for a misplaced `xmc` in `udp[]`.
    #[test]
    fn xmc_form_never_rewrites_settings() {
        let profile = json!({"username": "Steve", "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
                             "texturesValue": "dmFsdWU=", "texturesSignature": "c2ln", "x": 1});
        for (original, is_typed) in [
            (json!({"password": " p ", "hostname": "mc.example.com", "profiles": [profile], "future": true}), true),
            (json!({"password": "", "profiles": [{}]}), true),
            (json!({"password": "p", "usernames": ["Notch"]}), true),
            (json!({"password": "p", "usernames": "Notch", "profiles": [{"username": "ab"}]}), true),
            // Not representable losslessly: raw JSON.
            (json!({"password": 1}), false),
            (json!({"profiles": [null]}), false),
        ] {
            for direction in [StreamDirection::Inbound, StreamDirection::Outbound] {
                let ctx = egui::Context::default();
                let mut settings = original.clone();
                for _ in 0..3 {
                    let mut changed = false;
                    ctx.run_ui(egui::RawInput::default(), |ui| {
                        changed = show_finalmask_settings_edit(ui, direction, FinalMaskChain::Tcp, "xmc", &mut settings, "tcp", 0);
                    })
                    .drop_without_applying_deltas();
                    assert!(!changed, "{original}");
                }
                assert_eq!(settings, original);
                let state_id = root_id(&ctx, ("finalmask_form", "tcp", 0usize));
                let stored = ctx.data(|d| d.get_temp::<FinalMaskFormState<XmcSettings>>(state_id));
                assert_eq!(stored.is_some(), is_typed, "{original}");
            }
        }
        // `xmc` in `udp[]` is an error the layer row reports; the settings stay raw JSON.
        let ctx = egui::Context::default();
        let mut settings = json!({"password": "p"});
        assert!(!frame(&ctx, "xmc", &mut settings));
        let state_id = root_id(&ctx, ("finalmask_form", "udp", 0usize));
        assert!(ctx.data(|d| d.get_temp::<FinalMaskFormState<XmcSettings>>(state_id)).is_none());
    }

    /// Stage 2.4: a real edit of the `xmc` draft is written; the per-side notes.
    #[test]
    fn xmc_form_writes_edits_and_explains_each_side() {
        let ctx = egui::Context::default();
        let mut settings = json!({"password": "p", "usernames": ["Notch"]});
        assert!(!frame_on(&ctx, FinalMaskChain::Tcp, "xmc", &mut settings));
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            let mut form = FinalMaskForm::begin(ui, &settings, "tcp", 0, parse_xmc_settings).expect("typed");
            // What "Start profiles from usernames" does, then the user fills in the UUID.
            migrate_legacy_xmc_usernames(&mut form.draft).expect("migrated");
            form.draft.profiles[0].uuid = "069a79f444e94726a5befca90e38aaf5".to_owned();
            changed = form.finish(ui, &mut settings, xmc_settings_to_value);
        })
        .drop_without_applying_deltas();
        assert!(changed);
        assert_eq!(
            settings,
            json!({"password": "p", "profiles": [{"username": "Notch", "uuid": "069a79f444e94726a5befca90e38aaf5"}]})
        );

        assert!(xmc_hostname_note(StreamDirection::Inbound, true).is_some_and(|note| note.contains("ignored")));
        assert_eq!(xmc_hostname_note(StreamDirection::Inbound, false), None);
        assert_eq!(xmc_hostname_note(StreamDirection::Outbound, true), None);
        assert!(xmc_profiles_note(StreamDirection::Inbound).contains("accepts only"));
        assert!(xmc_profiles_note(StreamDirection::Outbound).contains("at random"));
    }

    /// Stage 2.2: the typed `header-custom` TCP form — and its raw-JSON fallback — show settings
    /// without rewriting them (CRLF in a `str` packet, empty groups, non-canonical `type`).
    #[test]
    fn header_custom_tcp_form_never_rewrites_settings() {
        let typed = json!({
            "clients": [[{"type": "str", "packet": " GET / HTTP/1.1\r\n\r\n"}, {"rand": 4, "capture": "n"}]],
            "servers": [[{"reuse": "n", "delay": "5-10"}], []],
            "errors": [],
            "x": 1
        });
        for (original, is_typed) in [
            (typed, true),
            (json!({"clients": [[{"type": "STR", "packet": "\u{1}"}]]}), true),
            // Shown as they are, Save reports them.
            (json!({"servers": [[{"packet": [1], "rand": 2}]]}), true),
            // Not representable losslessly: raw JSON.
            (json!({"clients": [[{"rand": "4"}]]}), false),
            (json!({"clients": [[{"packet": null}]]}), false),
        ] {
            let ctx = egui::Context::default();
            let mut settings = original.clone();
            for _ in 0..3 {
                assert!(!frame_on(&ctx, FinalMaskChain::Tcp, "header-custom", &mut settings), "{original}");
            }
            assert_eq!(settings, original);
            let state_id = root_id(&ctx, ("finalmask_form", "tcp", 0usize));
            let stored = ctx.data(|d| d.get_temp::<FinalMaskFormState<HeaderCustomTcpSettings>>(state_id));
            assert_eq!(stored.is_some(), is_typed, "{original}");
        }
        // `header-custom` in `udp[]` has another schema: the UDP form, never the TCP one.
        let ctx = egui::Context::default();
        let mut settings = json!({"client": [{"rand": 4}]});
        assert!(!frame(&ctx, "header-custom", &mut settings));
        let state_id = root_id(&ctx, ("finalmask_form", "udp", 0usize));
        assert!(ctx.data(|d| d.get_temp::<FinalMaskFormState<HeaderCustomTcpSettings>>(state_id)).is_none());
        assert!(ctx.data(|d| d.get_temp::<FinalMaskFormState<HeaderCustomUdpSettings>>(state_id)).is_some());
    }

    /// Stage 2.3: the UDP form shows settings as they are — a non-canonical `mode`, a `delay`
    /// the core does not read in UDP items, an empty group — and falls back to raw JSON for shapes
    /// it can't hold.
    #[test]
    fn header_custom_udp_form_never_rewrites_settings() {
        for (original, is_typed) in [
            (json!({"mode": "standalone", "client": [{"type": "str", "packet": "hi\r\n", "capture": "h"}],
                    "server": [{"reuse": "h"}], "x": 1}), true),
            (json!({"mode": "Prefix", "client": [{"rand": 2, "delay": 5}], "server": []}), true),
            (json!({"server": [{"reuse": "unknown"}]}), true),
            (json!({"mode": 1}), false),
            (json!({"client": [{"packet": null}]}), false),
        ] {
            let ctx = egui::Context::default();
            let mut settings = original.clone();
            for _ in 0..3 {
                assert!(!frame(&ctx, "header-custom", &mut settings), "{original}");
            }
            assert_eq!(settings, original);
            let state_id = root_id(&ctx, ("finalmask_form", "udp", 0usize));
            let stored = ctx.data(|d| d.get_temp::<FinalMaskFormState<HeaderCustomUdpSettings>>(state_id));
            assert_eq!(stored.is_some(), is_typed, "{original}");
        }
    }

    #[test]
    fn header_custom_udp_mode_pick_keeps_items_verbatim() {
        let ctx = egui::Context::default();
        let mut settings = json!({"client": [{"type": "str", "packet": " A\r\n", "delay": 5}]});
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            let mut form =
                FinalMaskForm::begin(ui, &settings, "udp", 0, parse_header_custom_udp_settings).expect("typed");
            form.draft.mode = "standalone".to_owned();
            changed = form.finish(ui, &mut settings, header_custom_udp_settings_to_value);
        })
        .drop_without_applying_deltas();
        assert!(changed);
        assert_eq!(
            settings,
            json!({"mode": "standalone", "client": [{"type": "str", "packet": " A\r\n", "delay": 5}]})
        );
    }

    #[test]
    fn header_custom_udp_notes_follow_mode_and_side() {
        use HeaderCustomUdpGroup::{Client, Server};
        use StreamDirection::{Inbound, Outbound};
        assert!(header_custom_udp_group_writes(Server, Inbound) && header_custom_udp_group_writes(Client, Outbound));
        assert!(!header_custom_udp_group_writes(Client, Inbound) && !header_custom_udp_group_writes(Server, Outbound));
        assert!(header_custom_udp_group_note(Client, Inbound, false).contains("dropped"));
        assert!(header_custom_udp_group_note(Server, Inbound, false).starts_with("Put in front"));
        assert!(header_custom_udp_group_note(Client, Inbound, true).contains("exactly this size"));
        assert!(header_custom_udp_group_note(Server, Outbound, true).contains("waits for"));
        assert!(header_custom_udp_mode_note("").is_some_and(|note| note.contains("Every packet")));
        assert!(header_custom_udp_mode_note("standalone").is_some_and(|note| note.contains("handshake")));
        // Case-sensitive like the core: the `Build()` error under the layer says it.
        assert_eq!(header_custom_udp_mode_note("Prefix"), None);
    }

    #[test]
    fn header_custom_tcp_edit_keeps_other_items_verbatim() {
        let ctx = egui::Context::default();
        let mut settings = json!({"clients": [[{"type": "str", "packet": "A\r\n\r\n"}, {"rand": 4}]], "errors": []});
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            let mut form =
                FinalMaskForm::begin(ui, &settings, "tcp", 0, parse_header_custom_tcp_settings).expect("typed");
            form.draft.clients.sequences[0][1].rand = "8".to_owned();
            form.draft.clients.sequences[0].swap(0, 1);
            changed = form.finish(ui, &mut settings, header_custom_tcp_settings_to_value);
        })
        .drop_without_applying_deltas();
        assert!(changed);
        assert_eq!(
            settings,
            json!({"clients": [[{"rand": 8}, {"type": "str", "packet": "A\r\n\r\n"}]], "errors": []})
        );
    }

    #[test]
    fn header_custom_notes_follow_the_side() {
        use HeaderCustomTcpGroup::{Clients, Errors, Servers};
        use StreamDirection::{Inbound, Outbound};
        let item = |value: serde_json::Value| {
            parse_header_custom_tcp_settings(&json!({"clients": [[value]]})).expect("typed").clients.sequences[0][0].clone()
        };
        assert_eq!(header_custom_item_note(&item(json!({"rand": 8})), true).as_deref(), Some("Sends 8 random bytes, values 0-255"));
        assert_eq!(
            header_custom_item_note(&item(json!({"rand": 8, "delay": 5})), false).as_deref(),
            Some("Accepts any 8 bytes · delay is not used when receiving")
        );
        assert_eq!(
            header_custom_item_note(&item(json!({"reuse": "n", "delay": "5-10"})), true).as_deref(),
            Some("Sends the bytes saved as `n` · after a 5-10 ms pause")
        );
        assert!(header_custom_item_note(&item(json!({"packet": [1], "capture": "h"})), false).unwrap().ends_with("saved as `h`"));
        // Several kinds: the `Build()` error under the layer says it.
        assert_eq!(header_custom_item_note(&item(json!({"packet": [1], "rand": 1})), true), None);

        // `tcp.go`: the server reads clients and writes servers / errors; the client never uses errors.
        assert_eq!(header_custom_group_writes(Clients, Inbound), Some(false));
        assert_eq!(header_custom_group_writes(Servers, Inbound), Some(true));
        assert_eq!(header_custom_group_writes(Clients, Outbound), Some(true));
        assert_eq!(header_custom_group_writes(Errors, Outbound), None);
        assert_eq!(header_custom_group_note(Errors, Outbound, true).1, WARNING_COLOR);
        assert_eq!(header_custom_group_note(Errors, Outbound, false).1, HINT_COLOR);
        assert_eq!(header_custom_group_note(Errors, Inbound, true).1, HINT_COLOR);
    }

    #[test]
    fn list_edits_ignore_out_of_range_requests() {
        let mut items = vec![1, 2, 3];
        apply_list_edit(&mut items, Some(ListEdit::Down(0)));
        assert_eq!(items, [2, 1, 3]);
        apply_list_edit(&mut items, Some(ListEdit::Up(2)));
        assert_eq!(items, [2, 3, 1]);
        for edit in [ListEdit::Up(0), ListEdit::Down(2), ListEdit::Remove(3)] {
            apply_list_edit(&mut items, Some(edit));
        }
        assert_eq!(items, [2, 3, 1]);
        apply_list_edit(&mut items, Some(ListEdit::Remove(1)));
        assert_eq!(items, [2, 1]);
    }

    #[test]
    fn udphop_checkboxes_read_what_the_mode_text_means() {
        let modes = lenient_udphop_modes("intervalLocal, PerConnRemote,bogus");
        assert_eq!(
            modes,
            UdpHopModes { interval_local: true, interval_remote: false, per_conn_remote: true }
        );
        // Toggling rewrites it in the core's form.
        assert_eq!(modes.to_mode_text(), "intervalLocal,perConnRemote");
        assert_eq!(lenient_udphop_modes(""), UdpHopModes::default());
    }

    #[test]
    fn realm_url_field_edit_rewrites_the_url() {
        let ctx = egui::Context::default();
        let mut settings = json!({"url": "realm://a:b@h/room", "stunServers": ["s:3478"]});
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            let mut form =
                FinalMaskForm::begin(ui, &settings, "udp", 0, parse_realm_settings).expect("typed");
            let mut url = parse_realm_url(&form.draft.url).expect("parses");
            url.host = "realm.example.com".to_owned();
            url.port = "8443".to_owned();
            form.draft.url = url.to_url_text();
            changed = form.finish(ui, &mut settings, realm_settings_to_value);
        })
        .drop_without_applying_deltas();
        assert!(changed);
        // The token keeps its meaning; `:` is now percent-encoded.
        assert_eq!(settings["url"], "realm://a%3Ab@realm.example.com:8443/room");
        assert_eq!(parse_realm_url(settings["url"].as_str().unwrap()).unwrap().token, "a:b");
    }

    /// Stage 2.1: picking a header rewrites only `header`; `value` and unknown keys stay as typed.
    #[test]
    fn mkcp_legacy_header_pick_keeps_value_and_extras() {
        let ctx = egui::Context::default();
        let mut settings = json!({"value": " pw ", "future": true});
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            let mut form =
                FinalMaskForm::begin(ui, &settings, "udp", 0, parse_mkcp_legacy_settings).expect("typed");
            form.draft.header = "dns".to_owned();
            changed = form.finish(ui, &mut settings, mkcp_legacy_settings_to_value);
        })
        .drop_without_applying_deltas();
        assert!(changed);
        assert_eq!(settings, json!({"header": "dns", "value": " pw ", "future": true}));
    }

    #[test]
    fn mkcp_legacy_note_follows_the_mode() {
        let (note, color) = mkcp_legacy_mode_note(Some(&MkcpLegacyMode::Header("utp")), true);
        assert!(note.contains("ignored") && color == WARNING_COLOR, "{note}");
        let (note, color) = mkcp_legacy_mode_note(Some(&MkcpLegacyMode::Header("utp")), false);
        assert!(!note.contains("ignored") && color == HINT_COLOR, "{note}");
        let dns = MkcpLegacyMode::Dns { domain: MKCP_LEGACY_DEFAULT_DNS_DOMAIN.to_owned() };
        assert!(mkcp_legacy_mode_note(Some(&dns), false).0.contains("www.baidu.com"));
        assert!(mkcp_legacy_mode_note(Some(&MkcpLegacyMode::Aes128Gcm), true).0.contains("password"));
        // An invalid header: the `Build()` error under the layer says it, no second line.
        assert!(mkcp_legacy_mode_note(None, true).0.is_empty());
    }

    #[test]
    fn edit_is_written_and_equivalent_typing_is_kept_unwritten() {
        let ctx = egui::Context::default();
        let mut settings = json!({"noise": [{"packet": [1]}]});

        // A real edit is written.
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            let mut form =
                FinalMaskForm::begin(ui, &settings, "udp", 0, parse_noise_mask_settings).expect("typed");
            form.draft.reset.text = "5".to_owned();
            changed = form.finish(ui, &mut settings, noise_mask_settings_to_value);
        })
        .drop_without_applying_deltas();
        assert!(changed);
        assert_eq!(settings, json!({"reset": 5, "noise": [{"packet": [1]}]}));

        // Typing "1," into a byte-array packet yields the same JSON: nothing is written, but the
        // typed text is kept for the next keystroke instead of collapsing back to "1".
        let written = settings.clone();
        ctx.run_ui(egui::RawInput::default(), |ui| {
            let mut form =
                FinalMaskForm::begin(ui, &settings, "udp", 0, parse_noise_mask_settings).expect("typed");
            form.draft.noise[0].packet.text = "1,".to_owned();
            changed = form.finish(ui, &mut settings, noise_mask_settings_to_value);
        })
        .drop_without_applying_deltas();
        assert!(!changed);
        assert_eq!(settings, written);
        assert!(!frame(&ctx, "noise", &mut settings));
        let state_id = root_id(&ctx, ("finalmask_form", "udp", 0usize));
        let stored = ctx
            .data(|d| d.get_temp::<FinalMaskFormState<NoiseMaskSettings>>(state_id))
            .expect("stored draft");
        assert_eq!(stored.draft.noise[0].packet.text, "1,");
    }

    #[test]
    fn external_change_replaces_the_stored_draft() {
        let ctx = egui::Context::default();
        let mut settings = json!({"reset": 1});
        assert!(!frame(&ctx, "noise", &mut settings));

        settings = json!({"reset": 2}); // e.g. Raw JSON, Move up/down, Cancel
        assert!(!frame(&ctx, "noise", &mut settings));
        let state_id = root_id(&ctx, ("finalmask_form", "udp", 0usize));
        let stored = ctx
            .data(|d| d.get_temp::<FinalMaskFormState<NoiseMaskSettings>>(state_id))
            .expect("stored draft");
        assert_eq!(stored.draft.reset.text, "2");
        assert_eq!(settings, json!({"reset": 2}));
    }

    #[test]
    fn raw_json_editor_keeps_text_that_is_not_valid_yet() {
        let ctx = egui::Context::default();
        let original = json!({"profiles": []});
        let mut settings = original.clone();
        assert!(!frame(&ctx, "future-mask", &mut settings));

        let buffer_id = root_id(&ctx, ("finalmask_raw", "udp", 0usize));
        let half_typed = "{\"profiles\": [".to_owned();
        ctx.data_mut(|d| {
            d.insert_temp(
                buffer_id,
                SourcedTextBuffer {
                    source: settings.clone(),
                    text: half_typed.clone(),
                },
            );
        });
        assert!(!frame(&ctx, "future-mask", &mut settings));
        assert_eq!(settings, original);
        let stored = ctx
            .data(|d| d.get_temp::<SourcedTextBuffer<serde_json::Value>>(buffer_id))
            .expect("buffer");
        assert_eq!(stored.text, half_typed);
    }

    /// One egui frame of the `quicParams` editor; returns its "changed".
    fn quic_frame(ctx: &egui::Context, direction: StreamDirection, draft: &mut QuicParamsDraft) -> bool {
        quic_frame_on(ctx, direction, QuicTransport::Hysteria, draft)
    }

    /// [`quic_frame`] for a given QUIC transport.
    fn quic_frame_on(
        ctx: &egui::Context,
        direction: StreamDirection,
        transport: QuicTransport,
        draft: &mut QuicParamsDraft,
    ) -> bool {
        let mut changed = false;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            changed = show_quic_params_edit(ui, direction, transport, draft);
        })
        .drop_without_applying_deltas();
        changed
    }

    /// Roadmap §2.6 stage 3.1: rendering the full `quicParams` form — including invalid,
    /// mistyped and wrong-side values — never changes the draft.
    #[test]
    fn showing_the_quic_params_editor_never_rewrites_the_draft() {
        let cases = [
            json!({}),
            json!({"congestion": "BBR", "bbrProfile": "turbo", "brutalUp": "10 mib", "brutalDown": "1 kbps",
                   "maxIdleTimeout": 3, "keepAlivePeriod": 0, "disableChromeParrot": false,
                   "initStreamReceiveWindow": 1, "debug": true, "disableStatelessReset": true}),
            json!({"brutalUp": 1000000, "maxStreamReceiveWindow": -1, "disableGSO": null, "x": [1]}),
            // Stage 3.2: the removed udpHop is shown, never dropped by rendering alone.
            json!({"congestion": "bbr", "udpHop": {"ports": "20000-50000", "interval": 30}}),
            json!({"udpHop": "broken"}),
            json!({"congestion": "brutal", "brutalUp": "100 mbps", "brutalDown": "50 mbps"}),
        ];
        for value in cases {
            for direction in [StreamDirection::Inbound, StreamDirection::Outbound] {
                // Stage 3.3: XHTTP/3 hides an empty brutalDown and flags brutal — still no rewrite.
                for transport in [QuicTransport::Hysteria, QuicTransport::XhttpH3] {
                    let ctx = egui::Context::default();
                    let original = parse_quic_params(value.as_object().expect("object"));
                    let mut draft = original.clone();
                    for _ in 0..3 {
                        assert!(!quic_frame_on(&ctx, direction, transport, &mut draft), "{value} reported a change");
                    }
                    assert_eq!(draft, original, "{value} was rewritten");
                }
            }
        }
    }

    /// A half-typed number survives the next frame without touching the model.
    #[test]
    fn quic_params_number_buffer_keeps_half_typed_text() {
        let ctx = egui::Context::default();
        let mut draft = QuicParamsDraft {
            max_idle_timeout: Some(30),
            ..QuicParamsDraft::default()
        };
        assert!(!quic_frame(&ctx, StreamDirection::Inbound, &mut draft));
        let id = root_id(&ctx, "quic_params_number").with("maxIdleTimeout");
        assert!(
            ctx.data(|d| d.get_temp::<SourcedTextBuffer<Option<i64>>>(id)).is_some(),
            "the field stores its buffer under the editor's root id"
        );
        ctx.data_mut(|d| {
            d.insert_temp(id, SourcedTextBuffer { source: Some(30_i64), text: "-".to_owned() });
        });
        assert!(!quic_frame(&ctx, StreamDirection::Inbound, &mut draft));
        assert_eq!(draft.max_idle_timeout, Some(30));
        let stored = ctx
            .data(|d| d.get_temp::<SourcedTextBuffer<Option<i64>>>(id))
            .expect("buffer");
        assert_eq!(stored.text, "-");
    }
}

