//! VLESS outbound Protocol tab — bridge side of VLESS-native reverse proxy (Roadmap §2.1:58),
//! plus a plain forward VLESS outbound.
//!
//! <https://xtls.github.io/en/document/level-2/vless_reverse.html> documents this outbound with a
//! **flat** `settings` object — `address`/`port`/`id`/`encryption`/`flow` sit directly on
//! `settings`, not nested under `vnext[]`/`users[]` as the general VLESS outbound schema allows.
//! Feldjäger only writes this flat form.
//!
//! The legacy `vnext[]` form is not edited in place. `VLessOutboundConfig.Build()`
//! (`infra/conf/vless.go`) turns the flat keys into a one-element `vnext` internally and accepts
//! exactly one server with exactly one user, so a `vnext[0]`/`users[0]` outbound whose keys all
//! have flat equivalents ([`VNEXT_SERVER_KEYS`], [`VNEXT_USER_KEYS`]) loads into the same draft
//! with [`VlessOutboundSettings::legacy_vnext`] set, and Save rewrites it into the flat form
//! (Roadmap §4.2). Every other `vnext[]` shape — several servers/users (refused by the core, see
//! `CompatibilityWarningId::VlessVnextNotSingle`), keys without a flat equivalent, a mix with flat
//! keys — stays Raw JSON only; [`legacy_vnext_blocker`] says why.
//!
//! Flat `seed` is declared by the core but never applied (`//account.Seed = c.Seed`), and
//! `testpre`/`testseed` are experimental Vision knobs: none of them is edited, all are preserved.
//!
//! `streamSettings`/`mux` are untouched siblings, same as the other three outbound Shells —
//! `apply_vless_settings` only ever touches keys under `settings`.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::config::reverse_proxy::{ReverseTagDraft, parse_reverse, reverse_to_value, validate_reverse};

/// Keys of the flat form — the fields of `VLessOutboundConfig` besides `vnext`.
const FLAT_KEYS: &[&str] = &[
    "address", "port", "level", "email", "id", "flow", "seed", "encryption", "reverse", "testpre",
    "testseed",
];

/// `vnext[0]` keys a conversion to the flat form carries over.
pub const VNEXT_SERVER_KEYS: &[&str] = &["address", "port", "users"];

/// `vnext[0].users[0]` keys a conversion to the flat form carries over. Others the core would
/// read there (e.g. `testpre`) are not converted — the outbound stays Raw JSON only.
pub const VNEXT_USER_KEYS: &[&str] = &["id", "flow", "encryption", "level", "email"];

/// `true` when `settings.vnext` is an array — the legacy VLESS outbound form (see the module
/// docs for which of these the editor can still open).
pub fn is_legacy_vnext_form(outbound: &Value) -> bool {
    outbound
        .get("settings")
        .and_then(|s| s.get("vnext"))
        .is_some_and(Value::is_array)
}

/// Why a legacy `vnext[]` outbound cannot be converted to the flat form (and so is Raw JSON only);
/// `None` when it can, or when it is not in the legacy form at all.
pub fn legacy_vnext_blocker(outbound: &Value) -> Option<String> {
    if !is_legacy_vnext_form(outbound) {
        return None;
    }
    legacy_vnext_entry(outbound).err()
}

/// `vnext[0]` and its `users[0]`, as returned by [`legacy_vnext_entry`].
type LegacyVnextEntry<'a> = (&'a Map<String, Value>, &'a Map<String, Value>);

/// The single `vnext[0]` server and its single `users[0]` entry, when every key has a flat-form
/// equivalent. `Err` carries the user-facing reason otherwise.
fn legacy_vnext_entry(outbound: &Value) -> Result<LegacyVnextEntry<'_>, String> {
    let settings = outbound
        .get("settings")
        .and_then(Value::as_object)
        .ok_or_else(|| "settings is not a JSON object".to_owned())?;
    // `"address": null` decodes to a nil pointer, so the core still reads `vnext`; any other
    // flat key next to `vnext[]` would silently become active after a conversion.
    if let Some(key) = FLAT_KEYS
        .iter()
        .find(|key| settings.get(**key).is_some_and(|value| !value.is_null()))
    {
        return Err(format!(
            "settings mixes vnext[] with the flat key `{key}` — Xray-core reads only one of the \
             two forms"
        ));
    }
    let servers = settings.get("vnext").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    let [server] = servers else {
        return Err(format!(
            "Xray-core requires exactly one vnext[] server (found {}) — use one outbound per \
             server and a balancer",
            servers.len()
        ));
    };
    let server = server
        .as_object()
        .ok_or_else(|| "vnext[0] is not a JSON object".to_owned())?;
    if let Some(key) = server.keys().find(|key| !VNEXT_SERVER_KEYS.contains(&key.as_str())) {
        return Err(format!("vnext[0].{key} has no flat-form equivalent"));
    }
    let users = server.get("users").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    let [user] = users else {
        return Err(format!(
            "Xray-core requires exactly one vnext[0].users[] entry (found {}) — use one outbound \
             per user and a balancer",
            users.len()
        ));
    };
    let user = user
        .as_object()
        .ok_or_else(|| "vnext[0].users[0] is not a JSON object".to_owned())?;
    if let Some(key) = user.keys().find(|key| !VNEXT_USER_KEYS.contains(&key.as_str())) {
        return Err(format!("vnext[0].users[0].{key} has no flat-form equivalent"));
    }
    // A non-string value would read as empty and be lost on Save.
    if let Some(key) = ["id", "flow", "encryption", "email"]
        .iter()
        .find(|key| user.get(**key).is_some_and(|value| !value.is_string()))
    {
        return Err(format!("vnext[0].users[0].{key} is not a string"));
    }
    Ok((server, user))
}

/// VLESS outbound Protocol-tab draft (flat `settings` form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessOutboundSettings {
    /// `settings.address` — the server this outbound dials. Required.
    pub address: String,
    /// `settings.port`, kept as free text and validated as 1-65535 on apply. Required.
    pub port: String,
    /// `settings.id` — client UUID matching a `clients[]` entry on the far end. Required.
    pub id: String,
    /// `settings.encryption` — `"none"` (no VLESS Encryption, matches inbound
    /// `decryption: "none"`) or the client string of `xray vlessenc`. Required: Xray-core refuses
    /// an absent or empty one (`please add/set "encryption":"none" for every user`).
    pub encryption: String,
    /// `settings.flow`; empty = key absent.
    pub flow: String,
    /// `settings.level` — index into `policy.levels` (timeouts, buffer size), kept as free text
    /// and validated as a `uint32` on apply; empty = key absent (level 0).
    pub level: String,
    /// `settings.email` — user label in logs and statistics; empty = key absent.
    pub email: String,
    /// `settings.reverse` — bridge-side registration (Roadmap §2.1:58); `None` = plain forward
    /// VLESS outbound.
    pub reverse: Option<ReverseTagDraft>,
    /// The draft was read from the legacy `vnext[0]`/`users[0]` form; apply removes
    /// `settings.vnext` and writes the flat keys instead.
    pub legacy_vnext: bool,
}

impl VlessOutboundSettings {
    /// Default for Add VLESS outbound: blank except `encryption: "none"`, no reverse. The GUI is
    /// expected to offer a "Generate UUID" action for `id`, same as the inbound Users Add dialog.
    pub fn default_draft() -> Self {
        Self {
            address: String::new(),
            port: String::new(),
            id: String::new(),
            encryption: "none".to_owned(),
            flow: String::new(),
            level: String::new(),
            email: String::new(),
            reverse: None,
            legacy_vnext: false,
        }
    }
}

/// Parses a VLESS outbound's `settings` into a draft: the flat form, or a convertible legacy
/// `vnext[]` form. Returns `None` for any other `vnext[]` shape — see [`legacy_vnext_blocker`].
pub fn parse_vless_outbound_settings(outbound: &Value) -> Option<VlessOutboundSettings> {
    if is_legacy_vnext_form(outbound) {
        let (server, user) = legacy_vnext_entry(outbound).ok()?;
        return Some(VlessOutboundSettings {
            address: string_field(server.get("address")),
            port: numeric_or_string_field(server.get("port")),
            id: string_field(user.get("id")),
            encryption: string_field(user.get("encryption")),
            flow: string_field(user.get("flow")),
            level: numeric_or_string_field(user.get("level")),
            email: string_field(user.get("email")),
            reverse: None,
            legacy_vnext: true,
        });
    }
    let settings = outbound.get("settings").and_then(Value::as_object);
    Some(VlessOutboundSettings {
        address: string_field(settings.and_then(|s| s.get("address"))),
        port: numeric_or_string_field(settings.and_then(|s| s.get("port"))),
        id: string_field(settings.and_then(|s| s.get("id"))),
        encryption: string_field(settings.and_then(|s| s.get("encryption"))),
        flow: string_field(settings.and_then(|s| s.get("flow"))),
        level: numeric_or_string_field(settings.and_then(|s| s.get("level"))),
        email: string_field(settings.and_then(|s| s.get("email"))),
        reverse: parse_reverse(settings.and_then(|s| s.get("reverse"))),
        legacy_vnext: false,
    })
}

/// Applies a VLESS outbound draft onto `settings` in place — only `address`/`port`/`id`/
/// `encryption`/`flow`/`level`/`email`/`reverse` are touched (plus `vnext`, removed when
/// [`VlessOutboundSettings::legacy_vnext`] converts the outbound); any other existing `settings`
/// keys (and outbound siblings like `streamSettings`/`mux`/`proxySettings`) are preserved
/// untouched.
pub fn apply_vless_outbound_settings(
    outbound: &mut Value,
    draft: &VlessOutboundSettings,
) -> ConfigModifyResult<()> {
    let address = draft.address.trim();
    if address.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound address must not be empty".to_owned(),
        ));
    }
    let id = draft.id.trim();
    if id.is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound id must not be empty".to_owned(),
        ));
    }
    if draft.encryption.trim().is_empty() {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound encryption must be set: \"none\" (no VLESS Encryption) or the client \
             string from xray vlessenc — Xray-core refuses an empty one"
                .to_owned(),
        ));
    }
    let port_trimmed = draft.port.trim();
    let port: u32 = port_trimmed.parse().map_err(|_| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound port must be a valid port number (1-65535)".to_owned(),
        )
    })?;
    if port == 0 || port > 65535 {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "VLESS outbound port must be between 1 and 65535".to_owned(),
        ));
    }
    let level_trimmed = draft.level.trim();
    let level: Option<u32> = if level_trimmed.is_empty() {
        None
    } else {
        Some(level_trimmed.parse().map_err(|_| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "VLESS outbound level must be a non-negative integer (0-4294967295)".to_owned(),
            )
        })?)
    };
    if let Some(reverse) = &draft.reverse {
        validate_reverse(reverse)?;
    }

    let object = outbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound must be a JSON object".to_owned(),
        )
    })?;
    if !object.contains_key("settings") || object.get("settings").is_some_and(Value::is_null) {
        object.insert("settings".to_owned(), Value::Object(Map::new()));
    }
    let settings = object
        .get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "settings must be a JSON object".to_owned(),
            )
        })?;

    settings.insert("address".to_owned(), Value::String(address.to_owned()));
    settings.insert("port".to_owned(), Value::Number(port.into()));
    settings.insert("id".to_owned(), Value::String(id.to_owned()));
    apply_optional_string(settings, "encryption", &draft.encryption);
    apply_optional_string(settings, "flow", &draft.flow);
    match level {
        Some(level) => {
            settings.insert("level".to_owned(), Value::Number(level.into()));
        }
        None => {
            settings.remove("level");
        }
    }
    apply_optional_string(settings, "email", &draft.email);
    if draft.legacy_vnext {
        // Every `vnext[0]`/`users[0]` key was carried into the flat keys above
        // (`legacy_vnext_entry` refuses any other), so nothing is lost.
        settings.remove("vnext");
    }
    match &draft.reverse {
        Some(reverse) => {
            settings.insert("reverse".to_owned(), reverse_to_value(reverse));
        }
        None => {
            settings.remove("reverse");
        }
    }

    Ok(())
}

fn apply_optional_string(settings: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        settings.remove(key);
    } else {
        settings.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

fn string_field(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").trim().to_owned()
}

fn numeric_or_string_field(value: Option<&Value>) -> String {
    match value {
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(text)) => text.trim().to_owned(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "protocol": "vless",
            "settings": {
                "address": "yourserver.com",
                "port": 8443,
                "id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
                "flow": "xtls-rprx-vision",
                "encryption": "mlkem768x25519plus.native.0rtt.2PcBa3Yz0zBdt4p8-PkJMzx9hIj2Ve-UmrnmZRPnpRk",
                "reverse": {"tag": "reverse-in"}
            }
        })
    }

    #[test]
    fn parses_flat_form_with_reverse() {
        let draft = parse_vless_outbound_settings(&sample()).expect("parsed");
        assert_eq!(draft.address, "yourserver.com");
        assert_eq!(draft.port, "8443");
        assert_eq!(draft.id, "ac04551d-6ebf-4685-86e2-17c12491f7f4");
        assert_eq!(draft.flow, "xtls-rprx-vision");
        assert!(draft.encryption.starts_with("mlkem768x25519plus"));
        assert_eq!(draft.reverse.expect("reverse").tag, "reverse-in");
    }

    fn legacy_sample() -> Value {
        json!({
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "a.example",
                    "port": 443,
                    "users": [{
                        "id": "u",
                        "encryption": "none",
                        "flow": "xtls-rprx-vision",
                        "level": 1,
                        "email": "bridge@example"
                    }]
                }],
                "futureField": "keep"
            },
            "streamSettings": {"network": "tcp"}
        })
    }

    #[test]
    fn single_vnext_parses_as_convertible_draft() {
        let outbound = legacy_sample();
        assert!(is_legacy_vnext_form(&outbound));
        assert_eq!(legacy_vnext_blocker(&outbound), None);
        let draft = parse_vless_outbound_settings(&outbound).expect("convertible");
        assert!(draft.legacy_vnext);
        assert_eq!(draft.address, "a.example");
        assert_eq!(draft.port, "443");
        assert_eq!(draft.id, "u");
        assert_eq!(draft.encryption, "none");
        assert_eq!(draft.flow, "xtls-rprx-vision");
        assert_eq!(draft.level, "1");
        assert_eq!(draft.email, "bridge@example");
        assert_eq!(draft.reverse, None);
    }

    #[test]
    fn apply_converts_vnext_to_flat_form() {
        let mut outbound = legacy_sample();
        let draft = parse_vless_outbound_settings(&outbound).expect("convertible");
        apply_vless_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(
            outbound["settings"],
            json!({
                "futureField": "keep",
                "address": "a.example",
                "port": 443,
                "id": "u",
                "encryption": "none",
                "flow": "xtls-rprx-vision",
                "level": 1,
                "email": "bridge@example"
            })
        );
        assert_eq!(outbound["streamSettings"]["network"], "tcp");
        // Converted once; the result reads back as the plain flat form.
        let reparsed = parse_vless_outbound_settings(&outbound).expect("flat");
        assert!(!reparsed.legacy_vnext);
        assert_eq!(reparsed.level, "1");
    }

    #[test]
    fn vnext_blockers_keep_outbound_raw_json_only() {
        let cases = [
            (json!({"vnext": []}), "exactly one vnext[] server (found 0)"),
            (
                json!({"vnext": [{"address": "a", "port": 1, "users": [{"id": "u"}]}, {"address": "b"}]}),
                "exactly one vnext[] server (found 2)",
            ),
            (
                json!({"vnext": [{"address": "a", "port": 1, "users": [{"id": "u"}, {"id": "v"}]}]}),
                "exactly one vnext[0].users[] entry (found 2)",
            ),
            (
                json!({"vnext": [{"address": "a", "port": 1, "users": [{"id": "u", "testpre": 2}]}]}),
                "vnext[0].users[0].testpre has no flat-form equivalent",
            ),
            (
                json!({"vnext": [{"address": "a", "port": 1, "extra": 1, "users": [{"id": "u"}]}]}),
                "vnext[0].extra has no flat-form equivalent",
            ),
            (
                json!({"vnext": [{"address": "a", "port": 1, "users": [{"id": "u", "email": 5}]}]}),
                "vnext[0].users[0].email is not a string",
            ),
            (
                json!({"flow": "x", "vnext": [{"address": "a", "port": 1, "users": [{"id": "u"}]}]}),
                "flat key `flow`",
            ),
        ];
        for (settings, reason) in cases {
            let outbound = json!({"protocol": "vless", "settings": settings});
            let blocker = legacy_vnext_blocker(&outbound).expect("blocked");
            assert!(blocker.contains(reason), "{blocker}");
            assert!(parse_vless_outbound_settings(&outbound).is_none());
        }
    }

    #[test]
    fn null_flat_address_does_not_block_conversion() {
        let outbound = json!({
            "protocol": "vless",
            "settings": {"address": null, "vnext": [{"address": "a", "port": 1, "users": [{"id": "u"}]}]}
        });
        assert_eq!(legacy_vnext_blocker(&outbound), None);
        assert!(parse_vless_outbound_settings(&outbound).expect("convertible").legacy_vnext);
    }

    #[test]
    fn apply_writes_and_removes_level_and_email() {
        let mut outbound = json!({"protocol": "vless", "settings": {"level": 3, "email": "old", "encryption": "none"}});
        let mut draft = parse_vless_outbound_settings(&outbound).expect("flat");
        assert_eq!((draft.level.as_str(), draft.email.as_str()), ("3", "old"));
        draft.address = "host.example".to_owned();
        draft.port = "443".to_owned();
        draft.id = "u".to_owned();
        draft.level = " 7 ".to_owned();
        draft.email = String::new();
        apply_vless_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["level"], 7);
        assert!(outbound["settings"].get("email").is_none());
        draft.level = String::new();
        apply_vless_outbound_settings(&mut outbound, &draft).expect("apply");
        assert!(outbound["settings"].get("level").is_none());
    }

    #[test]
    fn apply_rejects_invalid_level() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.address = "host.example".to_owned();
        draft.id = "u".to_owned();
        draft.port = "443".to_owned();
        for level in ["-1", "4294967296", "high"] {
            draft.level = level.to_owned();
            let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
            assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
        }
    }

    #[test]
    fn flat_seed_and_test_knobs_are_preserved() {
        let mut outbound = json!({
            "protocol": "vless",
            "settings": {"address": "a", "port": 1, "id": "u", "encryption": "none", "seed": "s", "testpre": 2, "testseed": [1, 2]}
        });
        let draft = parse_vless_outbound_settings(&outbound).expect("flat");
        apply_vless_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["seed"], "s");
        assert_eq!(outbound["settings"]["testpre"], 2);
        assert_eq!(outbound["settings"]["testseed"], json!([1, 2]));
    }

    #[test]
    fn apply_roundtrip_preserves_unknown_and_siblings() {
        let mut outbound = json!({
            "protocol": "vless",
            "settings": {"futureField": "keep"},
            "streamSettings": {"network": "tcp"},
            "mux": {"enabled": true}
        });
        let draft = VlessOutboundSettings {
            address: "host.example".to_owned(),
            port: "443".to_owned(),
            id: "11111111-1111-1111-1111-111111111111".to_owned(),
            encryption: "none".to_owned(),
            flow: String::new(),
            level: String::new(),
            email: String::new(),
            reverse: None,
            legacy_vnext: false,
        };
        apply_vless_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["address"], "host.example");
        assert_eq!(outbound["settings"]["port"], 443);
        assert_eq!(outbound["settings"]["id"], "11111111-1111-1111-1111-111111111111");
        assert_eq!(outbound["settings"]["encryption"], "none");
        assert!(outbound["settings"].get("flow").is_none());
        assert!(outbound["settings"].get("reverse").is_none());
        assert_eq!(outbound["settings"]["futureField"], "keep");
        assert_eq!(outbound["streamSettings"]["network"], "tcp");
        assert_eq!(outbound["mux"]["enabled"], true);
    }

    #[test]
    fn apply_writes_reverse_with_sniffing() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let draft = VlessOutboundSettings {
            address: "host.example".to_owned(),
            port: "443".to_owned(),
            id: "11111111-1111-1111-1111-111111111111".to_owned(),
            encryption: "none".to_owned(),
            flow: String::new(),
            level: String::new(),
            email: String::new(),
            reverse: Some(ReverseTagDraft {
                tag: "reverse-in".to_owned(),
                sniffing: None,
                extras: Map::new(),
            }),
            legacy_vnext: false,
        };
        apply_vless_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["reverse"]["tag"], "reverse-in");
    }

    #[test]
    fn default_draft_has_encryption_none_and_empty_encryption_is_refused() {
        // Xray-core v26.9.30: `please add/set "encryption":"none" for every user` for an absent
        // or empty value (checked with `xray run -test`).
        assert_eq!(VlessOutboundSettings::default_draft().encryption, "none");
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.address = "host.example".to_owned();
        draft.port = "443".to_owned();
        draft.id = "11111111-1111-1111-1111-111111111111".to_owned();
        draft.encryption = "  ".to_owned();
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert!(err.to_string().contains("encryption"), "{err}");
        assert_eq!(outbound, json!({"protocol": "vless", "settings": {}}), "nothing written");
    }

    #[test]
    fn apply_rejects_empty_address() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.id = "11111111-1111-1111-1111-111111111111".to_owned();
        draft.port = "443".to_owned();
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn apply_rejects_empty_id() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.address = "host.example".to_owned();
        draft.port = "443".to_owned();
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn apply_rejects_invalid_port() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.address = "host.example".to_owned();
        draft.id = "11111111-1111-1111-1111-111111111111".to_owned();
        draft.port = "70000".to_owned();
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }

    #[test]
    fn apply_rejects_reverse_with_empty_tag() {
        let mut outbound = json!({"protocol": "vless", "settings": {}});
        let mut draft = VlessOutboundSettings::default_draft();
        draft.address = "host.example".to_owned();
        draft.id = "11111111-1111-1111-1111-111111111111".to_owned();
        draft.port = "443".to_owned();
        draft.reverse = Some(ReverseTagDraft::new());
        let err = apply_vless_outbound_settings(&mut outbound, &draft).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    }
}
