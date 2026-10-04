//! `finalmask.tcp[]` layer `type = "xmc"` — the connection disguised as a Minecraft login
//! (Roadmap §2.6 stage 2.4).
//!
//! Checked against `XTLS/Xray-core@main` (`infra/conf/transport_finalmask.go` `XMC` /
//! `XMCProfile`, `transport/internet/finalmask/xmc/{client,server,profile,protocol,derivation}.go`):
//!
//! ```json
//! { "password": "…", "hostname": "mc.example.com",
//!   "profiles": [{ "username": "Steve", "uuid": "…", "texturesValue": "…", "texturesSignature": "…" }] }
//! ```
//!
//! - `password` derives a 1024-bit RSA key on both sides (the fake "online mode" encryption); the
//!   client appends it to the 4-byte verify token and encrypts it with that key (PKCS#1 v1.5), the
//!   server compares it.
//! - The client picks one of `profiles` at random for every connection and sends its username +
//!   UUID; the server accepts only a listed profile and answers with *its* stored textures, which
//!   the client compares field by field — both sides need the identical list.
//! - `hostname` is the server address the client writes into the Minecraft handshake (empty = the
//!   dialed IP); the server reads and ignores it.
//!
//! Besides `Build()` (profiles ≥ 1, password, username `^[A-Za-z0-9_]{3,16}$`, UUID, both
//! textures) the handshake has limits that `xray run -test` never reaches, mirrored here like the
//! other runtime-only failures: the RSA block fits at most [`XMC_MAX_PASSWORD_BYTES`] of password,
//! and a Minecraft string read by the peer is at most [`XMC_MAX_STRING_BYTES`] — textures (read by
//! the client) and `hostname` (read by the server). Past them every connection fails at login.
//!
//! **Schema change:** before v26.7.28 (XTLS/Xray-core#6487) the layer had `usernames: [string]`
//! (empty = `["Dream"]`) instead of `profiles`. A newer core ignores `usernames` and refuses the
//! layer without `profiles`; an older one ignores `profiles`. Settings in the old schema are not
//! refused by Save (they are right for an older core); the version-aware warning and an explicit
//! "start profiles from usernames" action cover the newer one. The typed draft keeps `usernames`
//! in `extras`, byte for byte.

use serde_json::{Map, Value};
use uuid::Uuid;

use super::StreamDirection;
use super::finalmask_layers::{apply_extras, extras_of};
use super::finalmask_mkcp::verbatim_string;

/// Longest `password` (bytes) the client can send: the verify token (4 bytes) + password must fit
/// one PKCS#1 v1.5 block of the derived 1024-bit key (128 − 11 bytes).
pub const XMC_MAX_PASSWORD_BYTES: usize = 128 - 11 - 4;

/// Longest Minecraft protocol string (bytes) the xmc reader accepts (`String.readFrom`).
pub const XMC_MAX_STRING_BYTES: usize = 4096;

/// The pre-v26.7.28 key replaced by `profiles`.
pub const XMC_LEGACY_USERNAMES_KEY: &str = "usernames";

/// What the pre-v26.7.28 core used when `usernames` was empty.
pub const XMC_LEGACY_DEFAULT_USERNAME: &str = "Dream";

/// One `profiles[]` entry — a signed Minecraft profile (`XMCProfile`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XmcProfile {
    /// `username`, verbatim; empty = key absent.
    pub username: String,
    /// `uuid` (hyphenated or 32 hex digits), verbatim; empty = key absent.
    pub uuid: String,
    /// `texturesValue` — the base64 `textures` property of the signed session profile.
    pub textures_value: String,
    /// `texturesSignature` — the Mojang signature of `texturesValue`.
    pub textures_signature: String,
    /// Unknown keys of the entry, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// `finalmask.tcp[].settings` for `type = "xmc"` (v26.7.28 schema).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XmcSettings {
    /// `password`, verbatim; empty = key absent.
    pub password: String,
    /// `hostname` (client side), verbatim; empty = key absent.
    pub hostname: String,
    /// `profiles[]`; empty = key absent.
    pub profiles: Vec<XmcProfile>,
    /// Unknown keys (including the legacy `usernames`), preserved verbatim.
    pub extras: Map<String, Value>,
}

impl XmcSettings {
    /// The legacy `usernames` value, when the draft still carries one.
    pub fn legacy_usernames(&self) -> Option<&Value> {
        self.extras.get(XMC_LEGACY_USERNAMES_KEY).filter(|value| !value.is_null())
    }

    /// Drops the legacy `usernames` key (once `profiles` replaces it).
    pub fn remove_legacy_usernames(&mut self) {
        self.extras.remove(XMC_LEGACY_USERNAMES_KEY);
    }
}

const KNOWN_XMC_KEYS: &[&str] = &["password", "hostname", "profiles"];
/// All keys of a profile — every one a Go `string`.
const KNOWN_PROFILE_KEYS: &[&str] = &["username", "uuid", "texturesValue", "texturesSignature"];

fn parse_profile(value: &Value) -> Option<XmcProfile> {
    let object = value.as_object()?;
    Some(XmcProfile {
        username: verbatim_string(object.get("username"))?,
        uuid: verbatim_string(object.get("uuid"))?,
        textures_value: verbatim_string(object.get("texturesValue"))?,
        textures_signature: verbatim_string(object.get("texturesSignature"))?,
        extras: extras_of(object, KNOWN_PROFILE_KEYS),
    })
}

/// Parses `settings` as `xmc`. `None` when `settings` isn't an object, a string field isn't a
/// string, or `profiles` isn't a list of objects — the layer then stays on the raw-JSON editor.
pub fn parse_xmc_settings(settings: &Value) -> Option<XmcSettings> {
    let object = settings.as_object()?;
    let profiles = match object.get("profiles") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(parse_profile).collect::<Option<_>>()?,
        Some(_) => return None,
    };
    Some(XmcSettings {
        password: verbatim_string(object.get("password"))?,
        hostname: verbatim_string(object.get("hostname"))?,
        profiles,
        extras: extras_of(object, KNOWN_XMC_KEYS),
    })
}

fn profile_to_value(profile: &XmcProfile) -> Value {
    let mut object = Map::new();
    let fields = [
        ("username", &profile.username),
        ("uuid", &profile.uuid),
        ("texturesValue", &profile.textures_value),
        ("texturesSignature", &profile.textures_signature),
    ];
    for (key, text) in fields {
        if !text.is_empty() {
            object.insert(key.to_owned(), Value::String(text.clone()));
        }
    }
    apply_extras(&mut object, &profile.extras);
    Value::Object(object)
}

/// Builds the `settings` `Value` for an `xmc` layer; empty strings and an empty `profiles` are
/// omitted (the core reads absent as empty).
pub fn xmc_settings_to_value(draft: &XmcSettings) -> Value {
    let mut object = Map::new();
    for (key, text) in [("password", &draft.password), ("hostname", &draft.hostname)] {
        if !text.is_empty() {
            object.insert(key.to_owned(), Value::String(text.clone()));
        }
    }
    if !draft.profiles.is_empty() {
        object.insert("profiles".to_owned(), Value::Array(draft.profiles.iter().map(profile_to_value).collect()));
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

/// Whether `settings` is in the pre-v26.7.28 schema: `usernames` set and no `profiles` to use
/// instead. With both present the newer core reads `profiles`, so that one is validated.
pub fn xmc_has_legacy_usernames(settings: &Value) -> bool {
    let set = |key: &str| settings.get(key).is_some_and(|value| !value.is_null());
    let no_profiles = settings
        .get("profiles")
        .is_none_or(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty));
    set(XMC_LEGACY_USERNAMES_KEY) && no_profiles
}

/// Starts `profiles` from the legacy `usernames` (one profile per name, `"Dream"` for an empty
/// list, as the old core did) and removes `usernames`. UUID and textures stay empty to be filled
/// in — the old schema had no signed profiles. Refused without changes when `profiles` is already
/// set or `usernames` isn't a list of strings.
pub fn migrate_legacy_xmc_usernames(draft: &mut XmcSettings) -> Result<(), String> {
    if !draft.profiles.is_empty() {
        return Err("profiles is already set — remove usernames instead".to_owned());
    }
    let names: Vec<String> = match draft.legacy_usernames() {
        None => return Err("there is no usernames list".to_owned()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or("usernames must be a list of strings")?,
        Some(_) => return Err("usernames must be a list of strings".to_owned()),
    };
    let names = if names.is_empty() { vec![XMC_LEGACY_DEFAULT_USERNAME.to_owned()] } else { names };
    draft.profiles = names.into_iter().map(|username| XmcProfile { username, ..Default::default() }).collect();
    draft.extras.remove(XMC_LEGACY_USERNAMES_KEY);
    Ok(())
}

// ─── validation ─────────────────────────────────────────────────────────────

/// `xmcUsernamePattern`: `^[A-Za-z0-9_]{3,16}$`.
pub fn xmc_username_is_valid(username: &str) -> bool {
    (3..=16).contains(&username.len()) && username.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn runtime_note(what: &str) -> String {
    format!("{what} (every connection fails at the Minecraft login; `xray run -test` does not check it)")
}

/// `XMCProfile.Build()`.
fn validate_profile_build(profile: &XmcProfile) -> Result<(), String> {
    if !xmc_username_is_valid(&profile.username) {
        return Err(format!(
            "invalid Minecraft username \"{}\" (3–16 letters, digits, _)",
            profile.username
        ));
    }
    Uuid::parse_str(&profile.uuid).map_err(|_| format!("invalid Minecraft profile UUID \"{}\"", profile.uuid))?;
    if profile.textures_value.is_empty() || profile.textures_signature.is_empty() {
        return Err("texturesValue and texturesSignature are both required".to_owned());
    }
    Ok(())
}

/// Validates a draft like `XMC.Build()` (profiles ≥ 1, password, each profile), then the
/// handshake limits `xray run -test` does not reach: password length on both sides, textures
/// length on both sides (the server sends them, the client reads them), `hostname` length only on
/// the client (outbound) — the server never sends it.
pub fn validate_xmc_settings(draft: &XmcSettings, direction: StreamDirection) -> Result<(), String> {
    if draft.profiles.is_empty() {
        return Err("profiles: at least one Minecraft profile is required".to_owned());
    }
    if draft.password.is_empty() {
        return Err("password is required".to_owned());
    }
    for (index, profile) in draft.profiles.iter().enumerate() {
        validate_profile_build(profile).map_err(|error| format!("profiles[{index}]: {error}"))?;
    }

    if draft.password.len() > XMC_MAX_PASSWORD_BYTES {
        return Err(runtime_note(&format!(
            "password is {} bytes; at most {XMC_MAX_PASSWORD_BYTES} fit the RSA-encrypted login",
            draft.password.len()
        )));
    }
    if direction == StreamDirection::Outbound && draft.hostname.len() > XMC_MAX_STRING_BYTES {
        return Err(runtime_note(&format!(
            "hostname is {} bytes; the server reads at most {XMC_MAX_STRING_BYTES}",
            draft.hostname.len()
        )));
    }
    for (index, profile) in draft.profiles.iter().enumerate() {
        for (key, text) in [("texturesValue", &profile.textures_value), ("texturesSignature", &profile.textures_signature)] {
            if text.len() > XMC_MAX_STRING_BYTES {
                return Err(runtime_note(&format!(
                    "profiles[{index}]: {key} is {} bytes; the client reads at most {XMC_MAX_STRING_BYTES}",
                    text.len()
                )));
            }
        }
    }
    Ok(())
}

/// Save-time check on the JSON itself: Go decoding (string fields, `profiles` a list of objects)
/// first; settings in the pre-v26.7.28 schema ([`xmc_has_legacy_usernames`]) get that release's
/// `Build()` (only `password` required); otherwise [`validate_xmc_settings`].
pub fn validate_xmc(settings: &Value, direction: StreamDirection) -> Result<(), String> {
    let object = settings.as_object().ok_or("settings must be a JSON object")?;
    for key in ["password", "hostname"] {
        if verbatim_string(object.get(key)).is_none() {
            return Err(format!("{key} must be a string"));
        }
    }
    match object.get("profiles") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                let profile = item
                    .as_object()
                    .ok_or_else(|| format!("profiles[{index}] must be a JSON object"))?;
                for key in KNOWN_PROFILE_KEYS {
                    if verbatim_string(profile.get(*key)).is_none() {
                        return Err(format!("profiles[{index}]: {key} must be a string"));
                    }
                }
            }
        }
        Some(_) => return Err("profiles must be an array".to_owned()),
    }
    if xmc_has_legacy_usernames(settings) {
        return match object.get("password").and_then(Value::as_str) {
            Some(password) if !password.is_empty() => Ok(()),
            _ => Err("password is required".to_owned()),
        };
    }
    match parse_xmc_settings(settings) {
        Some(draft) => validate_xmc_settings(&draft, direction),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use StreamDirection::{Inbound, Outbound};

    const UUID: &str = "069a79f4-44e9-4726-a5be-fca90e38aaf5";

    fn profile() -> Value {
        json!({"username": "Steve_01", "uuid": UUID, "texturesValue": "v", "texturesSignature": "s"})
    }

    fn check(settings: Value, direction: StreamDirection) -> Result<(), String> {
        validate_xmc(&settings, direction)
    }

    #[test]
    fn round_trip_is_verbatim_and_keeps_extras() {
        let settings = json!({
            "password": " p w ", "hostname": "mc.example.com", "future": 1,
            "profiles": [{"username": "Steve_01", "uuid": UUID, "texturesValue": "v", "texturesSignature": "s", "x": [1]}]
        });
        let parsed = parse_xmc_settings(&settings).expect("parsed");
        assert_eq!(parsed.password, " p w ");
        assert_eq!(parsed.profiles[0].extras.get("x"), Some(&json!([1])));
        assert_eq!(xmc_settings_to_value(&parsed), settings);
        // Empty strings, `null` and an empty list are the core's zero values: written as absent.
        let empty = parse_xmc_settings(&json!({"password": "", "hostname": null, "profiles": []})).expect("parsed");
        assert_eq!(xmc_settings_to_value(&empty), json!({}));
        // A new, empty profile is an empty object (Save then reports the missing username).
        let draft = XmcSettings { profiles: vec![XmcProfile::default()], ..Default::default() };
        assert_eq!(xmc_settings_to_value(&draft), json!({"profiles": [{}]}));
        // Shapes the typed form can't hold stay on the raw-JSON editor.
        for raw in [
            json!({"password": 1}),
            json!({"profiles": {}}),
            json!({"profiles": [null]}),
            json!({"profiles": [{"uuid": 7}]}),
            json!("xmc"),
        ] {
            assert!(parse_xmc_settings(&raw).is_none(), "{raw}");
        }
    }

    #[test]
    fn validation_mirrors_build() {
        let simple_uuid = json!({"username": "abc", "uuid": "069a79f444e94726a5befca90e38aaf5",
                                 "texturesValue": "v", "texturesSignature": "s"});
        for direction in [Inbound, Outbound] {
            assert_eq!(check(json!({"password": "p", "hostname": "mc.example.com", "profiles": [profile()]}), direction), Ok(()));
            assert_eq!(check(json!({"password": "p", "profiles": [simple_uuid.clone()]}), direction), Ok(()));
        }
        for (settings, needle) in [
            (json!({"password": "p"}), "profiles: at least one"),
            (json!({"profiles": [profile()]}), "password is required"),
            (json!({"password": "p", "profiles": [{"username": "ab"}]}), "profiles[0]: invalid Minecraft username"),
            (json!({"password": "p", "profiles": [{"username": "a b c"}]}), "username"),
            (json!({"password": "p", "profiles": [{"username": "abcdefghijklmnopq"}]}), "username"),
            (json!({"password": "p", "profiles": [{"username": "abc", "uuid": "nope"}]}), "UUID"),
            (json!({"password": "p", "profiles": [{"username": "abc", "uuid": UUID, "texturesValue": "v"}]}), "textures"),
            (json!({"password": 1, "profiles": [profile()]}), "password must be a string"),
            (json!({"password": "p", "profiles": "x"}), "profiles must be an array"),
            (json!({"password": "p", "profiles": [7]}), "profiles[0] must be a JSON object"),
            (json!({"password": "p", "profiles": [{"username": ["x"]}]}), "profiles[0]: username must be a string"),
        ] {
            let error = check(settings.clone(), Inbound).expect_err(&settings.to_string());
            assert!(error.contains(needle), "{settings}: {error}");
        }
        // `Build()` errors come before the runtime limits.
        let error = check(json!({"password": "p".repeat(200)}), Inbound).unwrap_err();
        assert!(error.starts_with("profiles: at least one"), "{error}");
    }

    /// The handshake limits `xray run -test` never reaches.
    #[test]
    fn handshake_limits_are_checked_per_side() {
        let with = |password: String, hostname: String, textures: String| {
            json!({"password": password, "hostname": hostname, "profiles": [
                {"username": "Steve", "uuid": UUID, "texturesValue": textures, "texturesSignature": "s"}
            ]})
        };
        let ok = |n: usize| "x".repeat(n);
        for direction in [Inbound, Outbound] {
            assert_eq!(check(with(ok(XMC_MAX_PASSWORD_BYTES), ok(4096), ok(4096)), direction), Ok(()));
            let error = check(with(ok(XMC_MAX_PASSWORD_BYTES + 1), ok(1), ok(1)), direction).unwrap_err();
            assert!(error.contains("password is 114 bytes; at most 113") && error.contains("xray run -test"), "{error}");
            // Bytes, not characters: 57 × "é" = 114 bytes.
            assert!(check(with("é".repeat(57), ok(1), ok(1)), direction).is_err());
            let error = check(with(ok(1), ok(1), ok(4097)), direction).unwrap_err();
            assert!(error.starts_with("profiles[0]: texturesValue is 4097 bytes"), "{error}");
        }
        // Only the client sends `hostname`; the server ignores it.
        assert_eq!(check(with(ok(1), ok(4097), ok(1)), Inbound), Ok(()));
        assert!(check(with(ok(1), ok(4097), ok(1)), Outbound).unwrap_err().contains("hostname is 4097 bytes"));
    }

    /// Pre-v26.7.28 `usernames` (#6487): not refused, and migratable into profile stubs.
    #[test]
    fn legacy_usernames_schema() {
        let legacy = json!({"password": "p", "usernames": ["Notch", "jeb_"]});
        assert!(xmc_has_legacy_usernames(&legacy));
        assert!(xmc_has_legacy_usernames(&json!({"usernames": [], "profiles": []})));
        assert!(!xmc_has_legacy_usernames(&json!({"usernames": ["a"], "profiles": [profile()]})));
        assert!(!xmc_has_legacy_usernames(&json!({"usernames": null})));
        for direction in [Inbound, Outbound] {
            assert_eq!(check(legacy.clone(), direction), Ok(()));
            assert!(check(json!({"usernames": ["a"]}), direction).unwrap_err().contains("password is required"));
        }
        // With profiles present the new schema is validated.
        assert!(check(json!({"password": "p", "usernames": ["a"], "profiles": [{"username": "a"}]}), Inbound).is_err());

        let mut draft = parse_xmc_settings(&legacy).expect("parsed");
        assert_eq!(draft.legacy_usernames(), Some(&json!(["Notch", "jeb_"])));
        migrate_legacy_xmc_usernames(&mut draft).expect("migrated");
        assert_eq!(
            xmc_settings_to_value(&draft),
            json!({"password": "p", "profiles": [{"username": "Notch"}, {"username": "jeb_"}]})
        );
        // An empty list meant "Dream".
        let mut draft = parse_xmc_settings(&json!({"usernames": []})).expect("parsed");
        migrate_legacy_xmc_usernames(&mut draft).expect("migrated");
        assert_eq!(draft.profiles[0].username, XMC_LEGACY_DEFAULT_USERNAME);
        // Refused without changes.
        for settings in [json!({"usernames": "Notch"}), json!({"usernames": [1]}), json!({"password": "p"}),
                         json!({"usernames": ["a"], "profiles": [{"username": "b"}]})] {
            let mut draft = parse_xmc_settings(&settings).expect("parsed");
            let before = draft.clone();
            assert!(migrate_legacy_xmc_usernames(&mut draft).is_err(), "{settings}");
            assert_eq!(draft, before);
        }
    }
}
