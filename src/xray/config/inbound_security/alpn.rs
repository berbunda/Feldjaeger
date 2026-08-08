//! ALPN protocol ID presets (IANA registry + Xray `FromMitM`).

/// IANA TLS ALPN Protocol IDs (excluding reserved / `h2c`) plus Xray `FromMitM`.
pub const ALPN_PRESETS: &[&str] = &[
    "http/0.9",
    "http/1.0",
    "http/1.1",
    "spdy/1",
    "spdy/2",
    "spdy/3",
    "stun.turn",
    "stun.nat-discovery",
    "h2",
    "h3",
    "webrtc",
    "c-webrtc",
    "ftp",
    "imap",
    "pop3",
    "managesieve",
    "coap",
    "co",
    "xmpp-client",
    "xmpp-server",
    "acme-tls/1",
    "mqtt",
    "dot",
    "ntske/1",
    "sunrpc",
    "smb",
    "irc",
    "nntp",
    "nnsp",
    "doq",
    "sip/2",
    "tds/8.0",
    "dicom",
    "postgresql",
    "radius/1.0",
    "radius/1.1",
    "netperfmeter/control",
    "netperfmeter/data",
    "n-pamp/2",
    "EoQ",
    "FromMitM",
];

/// ECDHE curve preferences from Xray TLS docs.
pub const CURVE_PRESETS: &[&str] = &[
    "CurveP256",
    "CurveP384",
    "CurveP521",
    "X25519",
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
];

/// TLS version combo values.
pub const TLS_VERSION_PRESETS: &[&str] = &["1.0", "1.1", "1.2", "1.3"];

/// uTLS fingerprint presets (+ free-text allowed in UI).
pub const FINGERPRINT_PRESETS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
    "unsafe",
];

/// Certificate `usage` values.
pub const CERT_USAGE_PRESETS: &[&str] = &["encipherment", "verify", "issue"];
