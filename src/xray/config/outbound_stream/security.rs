//! Outbound `streamSettings.security` — the client form of TLS and REALITY (Roadmap §4.2).
//!
//! Verified against `XTLS/Xray-core@main` (`infra/conf/transport_security.go`): one `TLSConfig`
//! and one `REALITYConfig` struct serve both sides, and the side is decided by the fields. A
//! REALITY config without `target`/`dest` is a client: `fingerprint` must be a known uTLS
//! fingerprint (not `unsafe`/`hellogolang`), `publicKey` (alias `password`) is a 32-byte
//! base64url key, `shortId` is up to 16 hex digits, `spiderX` starts with `/`, `mldsa65Verify` is
//! a 1952-byte base64url key, and the server lists `serverNames`/`shortIds` must be empty. A
//! client TLS config has no certificate of its own; `allowInsecure` is a removed feature (the
//! core refuses to load it — `pinnedPeerCertSha256` / `verifyPeerCertByName` replace it).
//!
//! Server-only keys found on disk (`certificates`, `rejectUnknownSni`, `echServerKeys`,
//! REALITY `target`/`privateKey`/…) are not edited here; they stay in `extras`, unchanged.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};

use crate::xray::config::inbound_security::{InboundSecurityMode, insert_string_list, string_list};
use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Every fingerprint name Xray-core's `tls.GetFingerprint` knows (`PresetFingerprints`,
/// `ModernFingerprints`, `OtherFingerprints` in `transport/internet/tls/tls.go`); the core
/// lowercases the configured value first. `""` means the default (`chrome`).
pub const TLS_KNOWN_FINGERPRINTS: &[&str] = &[
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized",
    "randomizednoalpn", "unsafe", "hellofirefox_120", "hellofirefox_148", "hellochrome_120",
    "hellochrome_131", "hellochrome_133", "helloios_13", "helloios_14", "helloedge_106",
    "hellosafari_26_3", "hello360_11_0", "helloqq_11_1", "hellogolang", "hellorandomized",
    "hellorandomizedalpn", "hellorandomizednoalpn", "hellofirefox_auto", "hellofirefox_55",
    "hellofirefox_56", "hellofirefox_63", "hellofirefox_65", "hellofirefox_99",
    "hellofirefox_102", "hellofirefox_105", "hellochrome_auto", "hellochrome_58",
    "hellochrome_62", "hellochrome_70", "hellochrome_72", "hellochrome_83", "hellochrome_87",
    "hellochrome_96", "hellochrome_100", "hellochrome_102", "hellochrome_106_shuffle",
    "helloios_auto", "helloios_11_1", "helloios_12_1", "helloandroid_11_okhttp", "helloedge_85",
    "helloedge_auto", "hellosafari_16_0", "hellosafari_auto", "hello360_auto", "hello360_7_5",
    "helloqq_auto", "hellochrome_100_psk", "hellochrome_112_psk_shuf",
    "hellochrome_114_padding_psk_shuf", "hellochrome_115_pq", "hellochrome_115_pq_psk",
    "hellochrome_120_pq",
];

/// Fingerprints REALITY refuses (`REALITYConfig.Build()`): neither leaks a browser-like hello.
pub const REALITY_REFUSED_FINGERPRINTS: &[&str] = &["unsafe", "hellogolang"];

/// Decoded length of a REALITY `publicKey` (X25519).
const REALITY_PUBLIC_KEY_LEN: usize = 32;
/// Decoded length of a REALITY `mldsa65Verify` (ML-DSA-65 public key).
const REALITY_MLDSA65_VERIFY_LEN: usize = 1952;
/// Maximum `shortId` length in hex digits (8 bytes).
const REALITY_SHORT_ID_MAX_HEX: usize = 16;
/// Decoded length of one `pinnedPeerCertSha256` entry (SHA-256).
const PINNED_SHA256_LEN: usize = 32;

/// `tlsSettings` keys typed by [`TlsClientDraft`]; everything else stays in its extras.
const TLS_CLIENT_KEYS: &[&str] = &[
    "serverName",
    "alpn",
    "fingerprint",
    "pinnedPeerCertSha256",
    "verifyPeerCertByName",
    "echConfigList",
    "minVersion",
    "maxVersion",
    "cipherSuites",
    "curvePreferences",
    "disableSystemRoot",
    "enableSessionResumption",
    "masterKeyLog",
    "allowInsecure",
];

/// `realitySettings` keys typed by [`RealityClientDraft`].
const REALITY_CLIENT_KEYS: &[&str] = &[
    "serverName",
    "fingerprint",
    "publicKey",
    "password",
    "shortId",
    "spiderX",
    "mldsa65Verify",
    "show",
];

/// Client `tlsSettings` of an outbound.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsClientDraft {
    /// `serverName` — SNI and the name the certificate is verified against; empty = the
    /// outbound's address.
    pub server_name: String,
    /// `alpn` (`StringList`; the on-disk string/array form survives an unchanged Save).
    pub alpn: Vec<String>,
    /// `fingerprint` (uTLS ClientHello); empty = `chrome`.
    pub fingerprint: String,
    /// `pinnedPeerCertSha256` — comma-separated SHA-256 hashes (hex, colons allowed).
    pub pinned_peer_cert_sha256: String,
    /// `verifyPeerCertByName` — comma-separated names accepted in the peer certificate.
    pub verify_peer_cert_by_name: String,
    /// `echConfigList` — Encrypted Client Hello config (client side).
    pub ech_config_list: String,
    /// `minVersion` (`1.0`…`1.3`); empty = default.
    pub min_version: String,
    /// `maxVersion`; empty = default.
    pub max_version: String,
    /// `cipherSuites` (`:`-separated); empty = default.
    pub cipher_suites: String,
    /// `curvePreferences` (`StringList`).
    pub curve_preferences: Vec<String>,
    /// `disableSystemRoot`.
    pub disable_system_root: bool,
    /// `enableSessionResumption`.
    pub enable_session_resumption: bool,
    /// `masterKeyLog` — path for TLS key logging (debugging).
    pub master_key_log: String,
    /// `allowInsecure` as found on disk — a removed feature; never set by the editor, only
    /// cleared by an explicit "Remove allowInsecure".
    pub allow_insecure: bool,
    /// Other `tlsSettings` keys (`certificates`, `echSockopt`, server-only keys, unknown keys),
    /// preserved verbatim.
    pub extras: Map<String, Value>,
}

/// Which key holds the REALITY client's public key on disk (`password` is the core's alias).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RealityPublicKeyField {
    /// `publicKey` (documented; written for new configs).
    #[default]
    PublicKey,
    /// `password` (alias read by `REALITYConfig.Build()`; kept when it is the one on disk).
    Password,
}

impl RealityPublicKeyField {
    fn key(self) -> &'static str {
        match self {
            Self::PublicKey => "publicKey",
            Self::Password => "password",
        }
    }
}

/// Client `realitySettings` of an outbound.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityClientDraft {
    /// `serverName` — one of the server's `serverNames`.
    pub server_name: String,
    /// `fingerprint` (uTLS ClientHello); empty = `chrome`.
    pub fingerprint: String,
    /// The server's X25519 public key (`xray x25519` "Password"/public key), base64url.
    pub public_key: String,
    /// Key the public key is written under.
    pub public_key_field: RealityPublicKeyField,
    /// `shortId` — one of the server's `shortIds` (hex, up to 16 digits; empty allowed when the
    /// server lists `""`).
    pub short_id: String,
    /// `spiderX` — initial crawler path (starts with `/`); empty = `/`.
    pub spider_x: String,
    /// `mldsa65Verify` — the server's ML-DSA-65 public key (base64url); empty = not verified.
    pub mldsa65_verify: String,
    /// `show` — debug output.
    pub show: bool,
    /// Other `realitySettings` keys (`masterKeyLog`, server keys found on disk, unknown keys),
    /// preserved verbatim.
    pub extras: Map<String, Value>,
}

/// Outbound Security draft: `streamSettings.security` with the client TLS / REALITY forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSecurityDraft {
    /// `none` | `tls` | `reality` (meaningless when [`Self::unknown_wire`] is set).
    pub mode: InboundSecurityMode,
    /// TLS form (kept while another mode is selected, so switching back restores it).
    pub tls: TlsClientDraft,
    /// REALITY form.
    pub reality: RealityClientDraft,
    /// A `security` value this editor does not know: the security keys stay untouched.
    pub unknown_wire: Option<String>,
}

impl Default for OutboundSecurityDraft {
    fn default() -> Self {
        Self {
            mode: InboundSecurityMode::None,
            tls: TlsClientDraft::default(),
            reality: RealityClientDraft::default(),
            unknown_wire: None,
        }
    }
}

impl OutboundSecurityDraft {
    /// Whether the security part can be edited (the wire value is `none`/`tls`/`reality`).
    pub fn is_editable(&self) -> bool {
        self.unknown_wire.is_none()
    }
}

/// Reads the security part of an outbound `streamSettings` object.
pub(super) fn parse_outbound_security(stream: &Map<String, Value>) -> OutboundSecurityDraft {
    let mut draft = OutboundSecurityDraft::default();
    match stream.get("security") {
        None | Some(Value::Null) => {}
        Some(Value::String(wire)) => match InboundSecurityMode::from_wire(wire) {
            Some(mode) => draft.mode = mode,
            None => draft.unknown_wire = Some(wire.trim().to_owned()),
        },
        Some(other) => draft.unknown_wire = Some(other.to_string()),
    }
    if let Some(tls) = stream.get("tlsSettings").and_then(Value::as_object) {
        draft.tls = parse_tls_client(tls);
    }
    if let Some(reality) = stream.get("realitySettings").and_then(Value::as_object) {
        draft.reality = parse_reality_client(reality);
    }
    draft
}

fn parse_tls_client(tls: &Map<String, Value>) -> TlsClientDraft {
    TlsClientDraft {
        server_name: string_field(tls.get("serverName")),
        alpn: string_list(tls.get("alpn")),
        fingerprint: string_field(tls.get("fingerprint")),
        pinned_peer_cert_sha256: string_field(tls.get("pinnedPeerCertSha256")),
        verify_peer_cert_by_name: string_field(tls.get("verifyPeerCertByName")),
        ech_config_list: string_field(tls.get("echConfigList")),
        min_version: string_field(tls.get("minVersion")),
        max_version: string_field(tls.get("maxVersion")),
        cipher_suites: string_field(tls.get("cipherSuites")),
        curve_preferences: string_list(tls.get("curvePreferences")),
        disable_system_root: bool_field(tls.get("disableSystemRoot")),
        enable_session_resumption: bool_field(tls.get("enableSessionResumption")),
        master_key_log: string_field(tls.get("masterKeyLog")),
        allow_insecure: bool_field(tls.get("allowInsecure")),
        extras: extras_without(tls, TLS_CLIENT_KEYS),
    }
}

fn parse_reality_client(reality: &Map<String, Value>) -> RealityClientDraft {
    // `REALITYConfig.Build()`: a non-empty `password` replaces `publicKey`.
    let password = string_field(reality.get("password"));
    let (public_key, public_key_field) = if password.is_empty() {
        (string_field(reality.get("publicKey")), RealityPublicKeyField::PublicKey)
    } else {
        (password, RealityPublicKeyField::Password)
    };
    let mut extras = extras_without(reality, REALITY_CLIENT_KEYS);
    // The key that lost to `password` is kept as it was.
    if public_key_field == RealityPublicKeyField::Password
        && let Some(shadowed) = reality.get("publicKey")
    {
        extras.insert("publicKey".to_owned(), shadowed.clone());
    }
    RealityClientDraft {
        server_name: string_field(reality.get("serverName")),
        fingerprint: string_field(reality.get("fingerprint")),
        public_key,
        public_key_field,
        short_id: string_field(reality.get("shortId")),
        spider_x: string_field(reality.get("spiderX")),
        mldsa65_verify: string_field(reality.get("mldsa65Verify")),
        show: bool_field(reality.get("show")),
        extras,
    }
}

/// Validates the selected security form like the client branch of the core's `Build()`.
pub(super) fn validate_outbound_security(draft: &OutboundSecurityDraft) -> ConfigModifyResult<()> {
    match draft.mode {
        _ if !draft.is_editable() => Ok(()),
        InboundSecurityMode::None => Ok(()),
        InboundSecurityMode::Tls => validate_tls_client(&draft.tls),
        InboundSecurityMode::Reality => validate_reality_client(&draft.reality),
    }
}

fn validate_tls_client(tls: &TlsClientDraft) -> ConfigModifyResult<()> {
    validate_fingerprint("tlsSettings", &tls.fingerprint, &[])?;
    for entry in tls.pinned_peer_cert_sha256.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // The core accepts the OpenSSL `AA:BB:…` form by dropping the colons.
        let hex = entry.replace(':', "");
        match decode_hex(&hex) {
            Some(bytes) if bytes.len() == PINNED_SHA256_LEN => {}
            _ => {
                return invalid(format!(
                    "tlsSettings.pinnedPeerCertSha256: \"{entry}\" is not a SHA-256 hash (64 hex \
                     digits, colons allowed)"
                ));
            }
        }
    }
    Ok(())
}

fn validate_reality_client(reality: &RealityClientDraft) -> ConfigModifyResult<()> {
    validate_fingerprint("realitySettings", &reality.fingerprint, REALITY_REFUSED_FINGERPRINTS)?;
    for (key, what) in [("serverNames", "serverName"), ("shortIds", "shortId")] {
        let non_empty = reality
            .extras
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty());
        if non_empty {
            return invalid(format!(
                "realitySettings.{key} is a server field; a client uses \"{what}\" — remove it on \
                 the Raw JSON tab"
            ));
        }
    }
    let public_key = reality.public_key.trim();
    if public_key.is_empty() {
        return invalid("realitySettings.publicKey must not be empty (the server's X25519 public key)");
    }
    if !decodes_to(public_key, REALITY_PUBLIC_KEY_LEN) {
        return invalid(
            "realitySettings.publicKey must be a 32-byte key in base64url without padding",
        );
    }
    let short_id = reality.short_id.trim();
    if short_id.len() > REALITY_SHORT_ID_MAX_HEX {
        return invalid(format!(
            "realitySettings.shortId is longer than {REALITY_SHORT_ID_MAX_HEX} hex digits"
        ));
    }
    if decode_hex(short_id).is_none() {
        return invalid("realitySettings.shortId must be hex digits (an even number of them)");
    }
    let mldsa = reality.mldsa65_verify.trim();
    if !mldsa.is_empty() && !decodes_to(mldsa, REALITY_MLDSA65_VERIFY_LEN) {
        return invalid(
            "realitySettings.mldsa65Verify must be the server's 1952-byte ML-DSA-65 public key in \
             base64url without padding",
        );
    }
    let spider_x = reality.spider_x.trim();
    if !spider_x.is_empty() && !spider_x.starts_with('/') {
        return invalid("realitySettings.spiderX must start with \"/\"");
    }
    Ok(())
}

fn validate_fingerprint(object: &str, value: &str, refused: &[&str]) -> ConfigModifyResult<()> {
    let name = value.trim().to_ascii_lowercase();
    if name.is_empty() {
        return Ok(());
    }
    if refused.contains(&name.as_str()) {
        return invalid(format!("{object}.fingerprint \"{name}\" is refused by Xray-core here"));
    }
    if !TLS_KNOWN_FINGERPRINTS.contains(&name.as_str()) {
        return invalid(format!("{object}.fingerprint \"{name}\" is not a fingerprint Xray-core knows"));
    }
    Ok(())
}

/// Writes the security part into `stream`; an unknown wire `security` leaves every security key
/// as it is. Validate first ([`validate_outbound_security`]).
pub(super) fn apply_outbound_security(stream: &mut Map<String, Value>, draft: &OutboundSecurityDraft) {
    if !draft.is_editable() {
        return;
    }
    stream.insert("security".to_owned(), Value::String(draft.mode.as_wire().to_owned()));
    match draft.mode {
        InboundSecurityMode::None => {
            stream.remove("tlsSettings");
            stream.remove("realitySettings");
        }
        InboundSecurityMode::Tls => {
            stream.remove("realitySettings");
            let previous = stream.get("tlsSettings").and_then(Value::as_object).cloned().unwrap_or_default();
            stream.insert("tlsSettings".to_owned(), Value::Object(tls_client_to_object(&draft.tls, &previous)));
        }
        InboundSecurityMode::Reality => {
            stream.remove("tlsSettings");
            stream.insert("realitySettings".to_owned(), Value::Object(reality_client_to_object(&draft.reality)));
        }
    }
}

fn tls_client_to_object(tls: &TlsClientDraft, previous: &Map<String, Value>) -> Map<String, Value> {
    let mut object = Map::new();
    insert_non_empty(&mut object, "serverName", &tls.server_name);
    insert_string_list(&mut object, "alpn", &tls.alpn, previous.get("alpn"));
    insert_non_empty(&mut object, "fingerprint", &tls.fingerprint);
    insert_non_empty(&mut object, "pinnedPeerCertSha256", &tls.pinned_peer_cert_sha256);
    insert_non_empty(&mut object, "verifyPeerCertByName", &tls.verify_peer_cert_by_name);
    insert_non_empty(&mut object, "echConfigList", &tls.ech_config_list);
    insert_non_empty(&mut object, "minVersion", &tls.min_version);
    insert_non_empty(&mut object, "maxVersion", &tls.max_version);
    insert_non_empty(&mut object, "cipherSuites", &tls.cipher_suites);
    insert_string_list(&mut object, "curvePreferences", &tls.curve_preferences, previous.get("curvePreferences"));
    insert_true(&mut object, "disableSystemRoot", tls.disable_system_root);
    insert_true(&mut object, "enableSessionResumption", tls.enable_session_resumption);
    insert_non_empty(&mut object, "masterKeyLog", &tls.master_key_log);
    insert_true(&mut object, "allowInsecure", tls.allow_insecure);
    append_extras(&mut object, &tls.extras);
    object
}

fn reality_client_to_object(reality: &RealityClientDraft) -> Map<String, Value> {
    let mut object = Map::new();
    insert_non_empty(&mut object, "serverName", &reality.server_name);
    insert_non_empty(&mut object, "fingerprint", &reality.fingerprint);
    insert_non_empty(&mut object, reality.public_key_field.key(), &reality.public_key);
    // An empty `shortId` is a valid choice (the server may list `""`), so it is always written.
    object.insert("shortId".to_owned(), Value::String(reality.short_id.trim().to_owned()));
    insert_non_empty(&mut object, "spiderX", &reality.spider_x);
    insert_non_empty(&mut object, "mldsa65Verify", &reality.mldsa65_verify);
    insert_true(&mut object, "show", reality.show);
    append_extras(&mut object, &reality.extras);
    object
}

fn invalid(message: impl Into<String>) -> ConfigModifyResult<()> {
    Err(ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message.into()))
}

/// Strict base64url (no padding, like Go's `RawURLEncoding`) of exactly `len` bytes.
fn decodes_to(text: &str, len: usize) -> bool {
    URL_SAFE_NO_PAD.decode(text).is_ok_and(|bytes| bytes.len() == len)
}

/// Lower/upper-case hex of an even length, like Go's `hex.DecodeString`.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

pub(super) fn string_field(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").trim().to_owned()
}

pub(super) fn bool_field(value: Option<&Value>) -> bool {
    value.and_then(Value::as_bool).unwrap_or(false)
}

pub(super) fn extras_without(object: &Map<String, Value>, known: &[&str]) -> Map<String, Value> {
    object
        .iter()
        .filter(|(key, _)| !known.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub(super) fn insert_non_empty(object: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        object.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

pub(super) fn insert_true(object: &mut Map<String, Value>, key: &str, value: bool) {
    if value {
        object.insert(key.to_owned(), Value::Bool(true));
    }
}

pub(super) fn append_extras(object: &mut Map<String, Value>, extras: &Map<String, Value>) {
    for (key, value) in extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stream(value: Value) -> Map<String, Value> {
        value.as_object().cloned().expect("object")
    }

    const PUBLIC_KEY: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

    #[test]
    fn tls_client_round_trips_and_keeps_extras() {
        let mut s = stream(json!({
            "security": "tls",
            "tlsSettings": {
                "serverName": "example.com", "alpn": "h2,http/1.1", "fingerprint": "chrome",
                "pinnedPeerCertSha256": "ab", "certificates": [{"usage": "verify"}],
                "echSockopt": {"mark": 1}, "future": 1
            }
        }));
        let draft = parse_outbound_security(&s);
        assert_eq!(draft.mode, InboundSecurityMode::Tls);
        assert_eq!(draft.tls.alpn, ["h2", "http/1.1"]);
        assert!(draft.tls.extras.contains_key("certificates"));
        apply_outbound_security(&mut s, &draft);
        // Unchanged StringList keeps its string form; extras survive.
        assert_eq!(s["tlsSettings"]["alpn"], "h2,http/1.1");
        assert_eq!(s["tlsSettings"]["certificates"][0]["usage"], "verify");
        assert_eq!(s["tlsSettings"]["future"], 1);
    }

    #[test]
    fn tls_pinned_hash_and_fingerprint_validation() {
        let mut draft = OutboundSecurityDraft { mode: InboundSecurityMode::Tls, ..Default::default() };
        draft.tls.pinned_peer_cert_sha256 = "ab".to_owned();
        assert!(validate_outbound_security(&draft).is_err());
        draft.tls.pinned_peer_cert_sha256 = format!("{}, {}", "0a".repeat(32), "0A:".repeat(31) + "0A");
        validate_outbound_security(&draft).expect("two valid hashes");
        draft.tls.fingerprint = "Chrome".to_owned();
        validate_outbound_security(&draft).expect("case-insensitive");
        draft.tls.fingerprint = "unsafe".to_owned();
        validate_outbound_security(&draft).expect("unsafe is allowed for TLS");
        draft.tls.fingerprint = "netscape".to_owned();
        assert!(validate_outbound_security(&draft).is_err());
    }

    #[test]
    fn reality_client_validation_mirrors_core() {
        let mut draft = OutboundSecurityDraft { mode: InboundSecurityMode::Reality, ..Default::default() };
        assert!(validate_outbound_security(&draft).is_err(), "public key required");
        draft.reality.public_key = PUBLIC_KEY.to_owned();
        draft.reality.short_id = "6ba85179e30d4fc2".to_owned();
        validate_outbound_security(&draft).expect("valid");
        draft.reality.short_id = "abc".to_owned();
        assert!(validate_outbound_security(&draft).is_err(), "odd hex length");
        draft.reality.short_id = String::new();
        validate_outbound_security(&draft).expect("empty shortId");
        draft.reality.fingerprint = "unsafe".to_owned();
        assert!(validate_outbound_security(&draft).is_err());
        draft.reality.fingerprint = String::new();
        draft.reality.spider_x = "x".to_owned();
        assert!(validate_outbound_security(&draft).is_err());
        draft.reality.spider_x = "/?p=1".to_owned();
        draft.reality.extras.insert("shortIds".to_owned(), json!(["aa"]));
        assert!(validate_outbound_security(&draft).is_err(), "server list on a client");
    }

    #[test]
    fn reality_password_alias_is_kept() {
        let mut s = stream(json!({
            "security": "reality",
            "realitySettings": {"password": PUBLIC_KEY, "serverName": "a.com", "shortId": ""}
        }));
        let draft = parse_outbound_security(&s);
        assert_eq!(draft.reality.public_key_field, RealityPublicKeyField::Password);
        apply_outbound_security(&mut s, &draft);
        assert_eq!(s["realitySettings"]["password"], PUBLIC_KEY);
        assert!(s["realitySettings"].get("publicKey").is_none());
        assert_eq!(s["realitySettings"]["shortId"], "");
    }

    #[test]
    fn switching_modes_strips_the_other_settings_and_unknown_is_untouched() {
        let mut s = stream(json!({"security": "tls", "tlsSettings": {"serverName": "a"}}));
        let mut draft = parse_outbound_security(&s);
        draft.mode = InboundSecurityMode::Reality;
        draft.reality.public_key = PUBLIC_KEY.to_owned();
        apply_outbound_security(&mut s, &draft);
        assert!(s.get("tlsSettings").is_none());
        assert_eq!(s["security"], "reality");

        let mut odd = stream(json!({"security": "xtls", "xtlsSettings": {}}));
        let before = odd.clone();
        let draft = parse_outbound_security(&odd);
        assert!(!draft.is_editable());
        apply_outbound_security(&mut odd, &draft);
        assert_eq!(odd, before);
    }
}
