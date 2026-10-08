//! SOCKS outbound Protocol tab (Roadmap §4.2) —
//! <https://xtls.github.io/en/config/outbounds/socks.html>.
//!
//! Kept (user decision 2026-10-06) for one real server-side use: chaining to a local proxy, e.g.
//! Tor at `127.0.0.1:9050`. SOCKS has no encryption of its own.
//!
//! Verified against Xray-core v26.9.30 (`infra/conf/socks.go`, `SocksClientConfig.Build()`) and
//! `xray run -test` 26.9.30:
//! - The documented form is flat: `address` / `port` / `user` / `pass` / `level` / `email`. A
//!   non-null `address` makes `Build()` use the flat keys and ignore `servers`; a user is created
//!   only when `user` is non-empty, and only then are `pass` / `level` / `email` used.
//! - Otherwise `servers[]` must hold exactly one entry, with at most one `users[]` member
//!   (`{user, pass, level, email}`).
//! - Decoding is strict per field: `port` a JSON `uint16`, `level` a `uint32`, `user` / `pass` /
//!   `email` strings. Port 0 or none passes `-test` but dials nowhere, so the editor requires one.
//!
//! The editor writes the flat form. A `servers[]` outbound the core reads with one server and at
//! most one user, all of whose keys exist in the flat form, opens with
//! [`SocksOutboundSettings::legacy_servers`] set and Save rewrites it; any other `servers[]` shape
//! is Raw JSON only ([`legacy_servers_blocker`]). `streamSettings` / `mux` are untouched siblings;
//! unknown `settings` keys are preserved.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// `servers[0]` keys a conversion to the flat form carries over.
const SERVER_KEYS: &[&str] = &["address", "port", "users"];

/// `servers[0].users[0]` keys a conversion to the flat form carries over.
const USER_KEYS: &[&str] = &["user", "pass", "level", "email"];

/// SOCKS outbound Protocol-tab draft (flat `settings` form).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocksOutboundSettings {
    /// `address` — the SOCKS server. Required.
    pub address: String,
    /// `port`, free text validated as 1-65535 on apply. Required.
    pub port: String,
    /// `user`, kept exactly as typed; empty = key absent (no authentication).
    pub user: String,
    /// `pass`, kept exactly as typed; empty = key absent. Used only with `user`.
    pub pass: String,
    /// `level`, free text validated as a `uint32` on apply; empty = key absent. Used only with
    /// `user`.
    pub level: String,
    /// `email`; empty = key absent. Used only with `user`.
    pub email: String,
    /// The draft was read from the legacy `servers[0]` form; apply removes `settings.servers`.
    pub legacy_servers: bool,
}

impl SocksOutboundSettings {
    /// `pass` / `level` / `email` are set although `user` is empty — Xray-core then creates no
    /// user and ignores them.
    pub fn has_ignored_user_fields(&self) -> bool {
        self.user.is_empty()
            && (!self.pass.is_empty() || !self.level.trim().is_empty() || !self.email.trim().is_empty())
    }
}

/// `true` when the core reads `servers[]`: no non-null flat `address`, and `servers` present.
fn reads_servers(settings: &Map<String, Value>) -> bool {
    settings.get("address").is_none_or(Value::is_null) && settings.get("servers").is_some_and(|s| !s.is_null())
}

/// Why a `servers[]` SOCKS outbound cannot be converted to the flat form (and so is Raw JSON
/// only); `None` when it can, or when it is not in that form.
pub fn legacy_servers_blocker(outbound: &Value) -> Option<String> {
    let settings = outbound.get("settings").and_then(Value::as_object)?;
    if !reads_servers(settings) {
        return None;
    }
    legacy_server_entry(settings).err()
}

/// `servers[0]` and its optional single `users[0]`, as returned by [`legacy_server_entry`].
type LegacyServerEntry<'a> = (&'a Map<String, Value>, Option<&'a Map<String, Value>>);

/// The single `servers[0]` entry and its user, when everything has a flat-form equivalent.
fn legacy_server_entry(settings: &Map<String, Value>) -> Result<LegacyServerEntry<'_>, String> {
    let servers = settings
        .get("servers")
        .and_then(Value::as_array)
        .ok_or_else(|| "settings.servers is not a JSON array".to_owned())?;
    let [server] = servers.as_slice() else {
        return Err(format!(
            "Xray-core requires exactly one servers[] entry (found {}) — use one outbound per \
             server and a balancer",
            servers.len()
        ));
    };
    let server = server
        .as_object()
        .ok_or_else(|| "servers[0] is not a JSON object".to_owned())?;
    if let Some(key) = server.keys().find(|key| !SERVER_KEYS.contains(&key.as_str())) {
        return Err(format!("servers[0].{key} has no flat-form equivalent"));
    }
    if server.get("address").is_some_and(|address| !address.is_string()) {
        return Err("servers[0].address is not a string".to_owned());
    }
    let users = match server.get("users") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(users)) => users.as_slice(),
        Some(_) => return Err("servers[0].users is not a JSON array".to_owned()),
    };
    let user = match users {
        [] => None,
        [user] => Some(user.as_object().ok_or_else(|| "servers[0].users[0] is not a JSON object".to_owned())?),
        _ => {
            return Err(format!(
                "Xray-core allows at most one servers[0].users[] member (found {}) — use one \
                 outbound per user and a balancer",
                users.len()
            ));
        }
    };
    if let Some(user) = user {
        if let Some(key) = user.keys().find(|key| !USER_KEYS.contains(&key.as_str())) {
            return Err(format!("servers[0].users[0].{key} has no flat-form equivalent"));
        }
        if let Some(key) = ["user", "pass", "email"]
            .iter()
            .find(|key| user.get(**key).is_some_and(|value| !value.is_string()))
        {
            return Err(format!("servers[0].users[0].{key} is not a string"));
        }
        // The flat form creates a user only for a non-empty `user`.
        if user.get("user").and_then(Value::as_str).is_none_or(str::is_empty) {
            return Err("servers[0].users[0] has no user name — the flat form cannot express it".to_owned());
        }
    }
    Ok((server, user))
}

/// Parses a SOCKS outbound's `settings`: the flat form, or a convertible `servers[]` form. `None`
/// for any other `servers[]` shape — see [`legacy_servers_blocker`].
pub fn parse_socks_outbound_settings(outbound: &Value) -> Option<SocksOutboundSettings> {
    let empty = Map::new();
    let settings = outbound.get("settings").and_then(Value::as_object).unwrap_or(&empty);
    let (server, user, legacy_servers) = if reads_servers(settings) {
        let (server, user) = legacy_server_entry(settings).ok()?;
        (server, user.unwrap_or(&empty), true)
    } else {
        (settings, settings, false)
    };
    let raw = |value: Option<&Value>| value.and_then(Value::as_str).unwrap_or("").to_owned();
    Some(SocksOutboundSettings {
        address: raw(server.get("address")).trim().to_owned(),
        port: numeric_or_string_field(server.get("port")),
        user: raw(user.get("user")),
        pass: raw(user.get("pass")),
        level: numeric_or_string_field(user.get("level")),
        email: raw(user.get("email")).trim().to_owned(),
        legacy_servers,
    })
}

/// Applies a SOCKS draft onto `settings` in place: the flat keys are owned by the draft (with
/// [`SocksOutboundSettings::legacy_servers`], `servers` is removed); every other `settings` key
/// and the outbound's siblings are preserved.
pub fn apply_socks_outbound_settings(
    outbound: &mut Value,
    draft: &SocksOutboundSettings,
) -> ConfigModifyResult<()> {
    let address = draft.address.trim();
    if address.is_empty() {
        return Err(invalid("SOCKS outbound address must not be empty"));
    }
    let port = draft
        .port
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("SOCKS outbound port must be a number from 1 to 65535"))?;
    let level = match draft.level.trim() {
        "" => None,
        text => Some(text.parse::<u32>().map_err(|_| {
            invalid("SOCKS outbound level must be a whole number from 0 to 4294967295 — Xray-core refuses anything else")
        })?),
    };

    let object = outbound
        .as_object_mut()
        .ok_or_else(|| invalid("outbound must be a JSON object"))?;
    if object.get("settings").is_none_or(Value::is_null) {
        object.insert("settings".to_owned(), Value::Object(Map::new()));
    }
    let settings = object
        .get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("settings must be a JSON object"))?;

    settings.insert("address".to_owned(), Value::String(address.to_owned()));
    settings.insert("port".to_owned(), Value::Number(port.into()));
    for (key, value) in [("user", draft.user.as_str()), ("pass", draft.pass.as_str()), ("email", draft.email.trim())] {
        if value.is_empty() {
            settings.remove(key);
        } else {
            settings.insert(key.to_owned(), Value::String(value.to_owned()));
        }
    }
    match level {
        Some(level) => {
            settings.insert("level".to_owned(), Value::Number(level.into()));
        }
        None => {
            settings.remove("level");
        }
    }
    if draft.legacy_servers {
        // `legacy_server_entry` admits only keys carried into the flat form above.
        settings.remove("servers");
    }
    Ok(())
}

fn invalid(message: &str) -> ConfigModifyError {
    ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message.to_owned())
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

    #[test]
    fn flat_form_round_trips_and_keeps_foreign_keys() {
        let original = json!({"protocol": "socks", "tag": "tor", "mux": {"enabled": false},
            "settings": {"address": "127.0.0.1", "port": 9050, "user": " u ", "pass": " p ",
                         "level": 1, "email": "e", "future": 1}});
        let draft = parse_socks_outbound_settings(&original).expect("flat");
        assert_eq!(draft.user, " u ", "never trimmed");
        assert_eq!(draft.pass, " p ", "never trimmed");
        assert!(!draft.has_ignored_user_fields());
        let mut outbound = original.clone();
        apply_socks_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound, original);
    }

    #[test]
    fn empty_optionals_are_removed() {
        let mut outbound = json!({"protocol": "socks", "settings": {"user": "u", "pass": "p", "level": 2, "email": "e"}});
        let draft = SocksOutboundSettings {
            address: "127.0.0.1".to_owned(),
            port: "9050".to_owned(),
            ..SocksOutboundSettings::default()
        };
        apply_socks_outbound_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"], json!({"address": "127.0.0.1", "port": 9050}));
    }

    #[test]
    fn user_fields_without_user_are_flagged() {
        let with = |pass: &str, level: &str, email: &str| SocksOutboundSettings {
            pass: pass.to_owned(),
            level: level.to_owned(),
            email: email.to_owned(),
            ..SocksOutboundSettings::default()
        };
        assert!(with("p", "", "").has_ignored_user_fields());
        assert!(with("", "1", "").has_ignored_user_fields());
        assert!(with("", "", "e").has_ignored_user_fields());
        assert!(!with("", "", "").has_ignored_user_fields());
    }

    /// Values `xray run -test` 26.9.30 refuses, plus a port the outbound cannot dial.
    #[test]
    fn apply_refuses_unusable_values() {
        for (address, port, level) in [("", "1", ""), ("a", "", ""), ("a", "0", ""), ("a", "70000", ""),
                                       ("a", "1", "-1"), ("a", "1", "x")] {
            let draft = SocksOutboundSettings {
                address: address.to_owned(),
                port: port.to_owned(),
                user: "u".to_owned(),
                level: level.to_owned(),
                ..SocksOutboundSettings::default()
            };
            let mut outbound = json!({"protocol": "socks", "settings": {}});
            let error = apply_socks_outbound_settings(&mut outbound, &draft).unwrap_err();
            assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed, "{address} {port} {level}");
            assert_eq!(outbound["settings"], json!({}));
        }
    }

    #[test]
    fn single_server_converts_to_the_flat_form() {
        for (server, flat) in [
            (json!({"address": "127.0.0.1", "port": 9050}), json!({"address": "127.0.0.1", "port": 9050})),
            (
                json!({"address": "127.0.0.1", "port": "1080", "users": [{"user": "u", "pass": "p", "level": 1, "email": "e"}]}),
                json!({"address": "127.0.0.1", "port": 1080, "user": "u", "pass": "p", "level": 1, "email": "e"}),
            ),
        ] {
            let original = json!({"protocol": "socks", "settings": {"servers": [server]}});
            let draft = parse_socks_outbound_settings(&original).expect("convertible");
            assert!(draft.legacy_servers);
            let mut outbound = original.clone();
            apply_socks_outbound_settings(&mut outbound, &draft).expect("apply");
            assert_eq!(outbound["settings"], flat);
        }
    }

    #[test]
    fn flat_address_wins_over_servers_like_the_core() {
        let outbound = json!({"protocol": "socks", "settings": {"address": "a", "port": 1, "servers": [{}, {}]}});
        let draft = parse_socks_outbound_settings(&outbound).expect("flat");
        assert!(!draft.legacy_servers);
        assert!(legacy_servers_blocker(&outbound).is_none());
    }

    #[test]
    fn unconvertible_servers_are_raw_json_only() {
        for (servers, reason) in [
            (json!([]), "exactly one"),
            (json!([{"address": "a"}, {"address": "b"}]), "exactly one"),
            (json!([{"address": "a", "users": [{"user": "x"}, {"user": "y"}]}]), "at most one"),
            (json!([{"address": "a", "users": [{"pass": "p"}]}]), "no user name"),
            (json!([{"address": "a", "users": [{"user": "x", "secret": 1}]}]), "users[0].secret"),
            (json!([{"address": "a", "users": [{"user": 5}]}]), "not a string"),
            (json!([{"address": "a", "tls": true}]), "servers[0].tls"),
            (json!({"address": "a"}), "not a JSON array"),
        ] {
            let outbound = json!({"protocol": "socks", "settings": {"servers": servers}});
            assert!(parse_socks_outbound_settings(&outbound).is_none(), "{servers}");
            let blocker = legacy_servers_blocker(&outbound).expect("blocker");
            assert!(blocker.contains(reason), "{servers}: {blocker}");
        }
    }
}
