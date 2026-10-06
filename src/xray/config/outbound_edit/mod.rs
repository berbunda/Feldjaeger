//! Outbound General fields (tag / sendThrough) + Shell edit identity, and the explicit migration
//! of the removed `proxySettings` into `streamSettings.sockopt.dialerProxy`.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// `proxySettings` as found on disk — a removed feature since Xray-core v26.9.8
/// (XTLS/Xray-core#6058): `OutboundDetourConfig.Build()` refuses any outbound that has the key,
/// whatever the protocol, and names `streamSettings.sockopt.dialerProxy` as the replacement.
/// Read-only: the editor never writes `proxySettings`; it only removes it on an explicit
/// [`OutboundGeneral::migrate_proxy_settings`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegacyProxySettings {
    /// `proxySettings.tag`, trimmed; empty when missing or not a string.
    pub tag: String,
    /// `proxySettings.transportLayer` — before v26.9.8, `true` made the core put `tag` into
    /// `sockopt.dialerProxy` itself, so for it the migration is exact.
    pub transport_layer: bool,
    /// `streamSettings.sockopt.dialerProxy` on disk, trimmed; empty = absent. A set value wins
    /// over the migrated tag (it is the one the core applies).
    pub dialer_proxy: String,
}

/// Result of [`OutboundGeneral::migrate_proxy_settings`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxySettingsMigration {
    /// The `proxySettings.tag` goes into `sockopt.dialerProxy`.
    Moved {
        /// The migrated outbound tag.
        tag: String,
    },
    /// `sockopt.dialerProxy` is already set and stays; `proxySettings` is only removed.
    DialerProxyWins {
        /// The discarded `proxySettings.tag`.
        legacy: String,
        /// The kept `sockopt.dialerProxy`.
        dialer_proxy: String,
    },
    /// `proxySettings` has no tag to move; it is only removed.
    Removed,
    /// Nothing to migrate (no `proxySettings`, or already scheduled).
    NothingToMigrate,
}

/// Full-state General form payload for an outbound.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutboundGeneral {
    /// Outbound tag; empty/whitespace omits the key. Immutable on Shell Save by design —
    /// rename is a standalone action, `rename_outbound_tag` (Roadmap §2.4:99).
    pub tag: Option<String>,
    /// `sendThrough` bind address; empty omits the key.
    pub send_through: Option<String>,
    /// `proxySettings` on disk (see [`LegacyProxySettings`]); `None` when absent or `null`.
    pub legacy_proxy_settings: Option<LegacyProxySettings>,
    /// `true` once the user asked to migrate: Save removes `proxySettings` and, unless
    /// `sockopt.dialerProxy` is already set, writes its tag there. `false` leaves
    /// `proxySettings` exactly as it is on disk.
    pub migrate_proxy_settings: bool,
}

impl OutboundGeneral {
    /// Schedules the `proxySettings` → `sockopt.dialerProxy` migration (draft only; Save writes
    /// it). An existing `dialerProxy` takes precedence.
    pub fn migrate_proxy_settings(&mut self) -> ProxySettingsMigration {
        let Some(legacy) = self.legacy_proxy_settings.as_ref() else {
            return ProxySettingsMigration::NothingToMigrate;
        };
        if self.migrate_proxy_settings {
            return ProxySettingsMigration::NothingToMigrate;
        }
        self.migrate_proxy_settings = true;
        if legacy.tag.is_empty() {
            ProxySettingsMigration::Removed
        } else if legacy.dialer_proxy.is_empty() {
            ProxySettingsMigration::Moved { tag: legacy.tag.clone() }
        } else {
            ProxySettingsMigration::DialerProxyWins {
                legacy: legacy.tag.clone(),
                dialer_proxy: legacy.dialer_proxy.clone(),
            }
        }
    }
}

/// Identity + fingerprint for an outbound Shell Save (mirrors [`super::InboundRef`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRef {
    /// Merged outbound index at edit intent.
    pub outbound_index: usize,
    /// SHA-256 hex of the full canonical outbound JSON at edit intent.
    pub expected_fingerprint: String,
}

/// Reads General fields for UI drafts from an outbound value.
pub fn parse_outbound_general(outbound: &Value) -> OutboundGeneral {
    OutboundGeneral {
        tag: outbound.get("tag").and_then(Value::as_str).map(str::to_owned),
        send_through: outbound
            .get("sendThrough")
            .and_then(Value::as_str)
            .map(str::to_owned),
        legacy_proxy_settings: parse_legacy_proxy_settings(outbound),
        migrate_proxy_settings: false,
    }
}

/// `Some` whenever the core would refuse the outbound: Go decodes a JSON `null` into a nil
/// `*json.RawMessage`, every other value (even `{}` or a string) is non-nil.
fn parse_legacy_proxy_settings(outbound: &Value) -> Option<LegacyProxySettings> {
    let proxy_settings = outbound.get("proxySettings").filter(|value| !value.is_null())?;
    Some(LegacyProxySettings {
        tag: proxy_settings
            .get("tag")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_owned(),
        transport_layer: proxy_settings
            .get("transportLayer")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        dialer_proxy: current_dialer_proxy(outbound).to_owned(),
    })
}

/// `streamSettings.sockopt.dialerProxy`, trimmed; empty when absent or not a string.
fn current_dialer_proxy(outbound: &Value) -> &str {
    outbound
        .get("streamSettings")
        .and_then(|stream| stream.get("sockopt"))
        .and_then(|sockopt| sockopt.get("dialerProxy"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

/// Checks a `sendThrough` value (trimmed; empty = key omitted) the way Xray-core uses it
/// (Roadmap §4.2). Verified against `XTLS/Xray-core@main`: `OutboundDetourConfig.Build()`
/// (`infra/conf/xray.go`) parses the part before the first `/` with `net.ParseAddress` and, when
/// there is no `/`, refuses every domain except exactly `origin` / `srcip` ("unable to send
/// through"); with a `/` it skips that check and stores the text after it as `ViaCidr`, which
/// `ParseRandomIP` (`app/proxyman/outbound/handler.go`) feeds to `net.ParseCIDR` on each connection —
/// a domain or a malformed prefix loads fine and fails at run time. So the accepted forms are an IP
/// (IPv6 optionally in brackets), `IP/prefix` with a prefix that fits the family, `origin` and
/// `srcip`.
pub fn validate_send_through(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() || value == "origin" || value == "srcip" {
        return Ok(());
    }
    let Some((address, prefix)) = value.split_once('/') else {
        return match parse_via_ip(value) {
            Some(_) => Ok(()),
            None => Err(format!(
                "sendThrough \"{value}\" is not an IP address, an IP/prefix range, origin or srcip — \
                 Xray-core refuses it (\"unable to send through\")"
            )),
        };
    };
    let Some(ip) = parse_via_ip(address) else {
        return Err(format!(
            "sendThrough \"{value}\": the part before \"/\" must be an IP address — Xray-core loads \
             it, but every connection through this outbound fails"
        ));
    };
    // `ParseRandomIP` formats the address back as text first: an IPv4-mapped IPv6 address
    // becomes plain IPv4, so its prefix is checked against 32.
    let max = if ip.to_canonical().is_ipv4() { 32 } else { 128 };
    let prefix_ok = !prefix.is_empty()
        && prefix.bytes().all(|byte| byte.is_ascii_digit())
        && prefix.parse::<u32>().is_ok_and(|bits| bits <= max);
    if !prefix_ok {
        return Err(format!(
            "sendThrough \"{value}\": the prefix after \"/\" must be 0–{max} — Xray-core loads it, but \
             every connection through this outbound fails"
        ));
    }
    Ok(())
}

/// `net.ParseAddress` for the IP case: brackets around an IPv6 address are allowed, zones are not.
fn parse_via_ip(text: &str) -> Option<std::net::IpAddr> {
    let text = text.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(text);
    text.parse().ok()
}

/// Applies General fields onto an outbound object in place. `proxySettings` is touched only by
/// a scheduled migration ([`OutboundGeneral::migrate_proxy_settings`]); `sendThrough` must pass
/// [`validate_send_through`].
pub fn apply_outbound_general(
    outbound: &mut Value,
    general: &OutboundGeneral,
) -> ConfigModifyResult<()> {
    if let Some(send_through) = general.send_through.as_deref() {
        validate_send_through(send_through).map_err(|message| invalid(&message))?;
    }
    // Decided on the value being written, not the snapshot the draft was parsed from.
    let migrated_tag = parse_legacy_proxy_settings(outbound)
        .filter(|legacy| general.migrate_proxy_settings && legacy.dialer_proxy.is_empty())
        .map(|legacy| legacy.tag)
        .filter(|tag| !tag.is_empty());

    let object = outbound
        .as_object_mut()
        .ok_or_else(|| invalid("outbound is not a JSON object"))?;

    apply_optional_string(object, "tag", general.tag.as_deref());
    apply_optional_string(object, "sendThrough", general.send_through.as_deref());

    if general.migrate_proxy_settings {
        if let Some(tag) = migrated_tag {
            let stream = object_entry(object, "streamSettings")?;
            let sockopt = object_entry(stream, "sockopt")
                .map_err(|_| invalid("streamSettings.sockopt must be a JSON object"))?;
            sockopt.insert("dialerProxy".to_owned(), Value::String(tag));
        }
        object.remove("proxySettings");
    }

    Ok(())
}

/// `parent[key]` as an object, created when absent or `null`.
fn object_entry<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
) -> ConfigModifyResult<&'a mut Map<String, Value>> {
    if parent.get(key).is_none_or(Value::is_null) {
        parent.insert(key.to_owned(), Value::Object(Map::new()));
    }
    parent
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid(&format!("{key} must be a JSON object")))
}

fn invalid(message: &str) -> ConfigModifyError {
    ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message.to_owned())
}

fn apply_optional_string(object: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        Some(text) => {
            object.insert(key.to_owned(), Value::String(text.to_owned()));
        }
        None => {
            object.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn general_of(outbound: &Value) -> OutboundGeneral {
        parse_outbound_general(outbound)
    }

    #[test]
    fn parse_reads_tag_and_send_through() {
        let outbound = json!({"tag": "direct", "sendThrough": "0.0.0.0", "protocol": "freedom"});
        let general = parse_outbound_general(&outbound);
        assert_eq!(general.tag.as_deref(), Some("direct"));
        assert_eq!(general.send_through.as_deref(), Some("0.0.0.0"));
        assert!(general.legacy_proxy_settings.is_none());
    }

    #[test]
    fn apply_omits_empty_fields_and_preserves_siblings() {
        let mut outbound = json!({"protocol": "freedom", "settings": {}, "mux": {"enabled": true}});
        apply_outbound_general(
            &mut outbound,
            &OutboundGeneral {
                tag: Some("direct".to_owned()),
                send_through: Some(String::new()),
                ..OutboundGeneral::default()
            },
        )
        .expect("apply");
        assert_eq!(outbound["tag"], "direct");
        assert!(outbound.get("sendThrough").is_none());
        assert_eq!(outbound["mux"]["enabled"], true);
    }

    /// Roadmap §4.2: the forms `OutboundDetourConfig.Build()` and `ParseRandomIP` can use.
    #[test]
    fn send_through_forms_follow_the_core() {
        for valid in [
            "", "  ", "0.0.0.0", " 10.0.0.2 ", "2001:db8::1", "[2001:db8::1]", "origin", "srcip",
            "10.0.0.0/8", "2001:db8::/64", "[2001:db8::]/48", "1.2.3.4/32", "::ffff:1.2.3.4/24", "::/0",
        ] {
            assert!(validate_send_through(valid).is_ok(), "{valid:?}");
        }
        // Refused by `Build()`: any domain but exactly origin / srcip.
        for refused in ["Origin", "SRCIP", "example.com", "env:BIND", "fe80::1%eth0"] {
            let error = validate_send_through(refused).unwrap_err();
            assert!(error.contains("unable to send through"), "{refused}: {error}");
        }
        // Loaded by the core, broken at run time.
        for broken in ["origin/24", "example.com/24", "1.2.3.4/abc", "1.2.3.4/", "1.2.3.4/33",
                       "2001:db8::/129", "::ffff:1.2.3.4/120", "10.0.0.0/8/9", "1.2.3.4/+8"] {
            let error = validate_send_through(broken).unwrap_err();
            assert!(error.contains("every connection"), "{broken}: {error}");
        }
    }

    #[test]
    fn apply_refuses_an_unusable_send_through() {
        let mut outbound = json!({"tag": "direct", "protocol": "freedom"});
        let general = |send_through: &str| OutboundGeneral {
            tag: Some("direct".to_owned()),
            send_through: Some(send_through.to_owned()),
            ..OutboundGeneral::default()
        };
        let error = apply_outbound_general(&mut outbound, &general("eth0")).unwrap_err();
        assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(outbound.get("sendThrough").is_none(), "nothing written");
        apply_outbound_general(&mut outbound, &general(" 192.0.2.0/24 ")).expect("CIDR");
        assert_eq!(outbound["sendThrough"], "192.0.2.0/24");
    }

    #[test]
    fn parse_reads_legacy_proxy_settings_in_any_non_null_shape() {
        let outbound = json!({
            "protocol": "vless",
            "proxySettings": {"tag": " chain-out ", "transportLayer": true},
            "streamSettings": {"sockopt": {"dialerProxy": "other"}}
        });
        let legacy = general_of(&outbound).legacy_proxy_settings.expect("proxySettings");
        assert_eq!(legacy.tag, "chain-out");
        assert!(legacy.transport_layer);
        assert_eq!(legacy.dialer_proxy, "other");

        // The core refuses these too: only `null` decodes to a nil pointer.
        for shape in [json!({}), json!({"tag": ""}), json!("chain-out")] {
            let outbound = json!({"protocol": "freedom", "proxySettings": shape});
            let legacy = general_of(&outbound).legacy_proxy_settings.expect("present");
            assert_eq!(legacy.tag, "");
        }
        let outbound = json!({"protocol": "freedom", "proxySettings": null});
        assert!(general_of(&outbound).legacy_proxy_settings.is_none());
    }

    #[test]
    fn save_without_migration_keeps_proxy_settings_verbatim() {
        let original = json!({"protocol": "freedom", "tag": "a", "proxySettings": {"tag": "", "x": 1}});
        let mut outbound = original.clone();
        apply_outbound_general(&mut outbound, &general_of(&original)).expect("apply");
        assert_eq!(outbound, original);
    }

    #[test]
    fn migration_moves_tag_into_dialer_proxy() {
        let original = json!({
            "protocol": "vless", "tag": "a",
            "proxySettings": {"tag": "chain-out"},
            "streamSettings": {"network": "raw", "sockopt": {"mark": 7}}
        });
        let mut general = general_of(&original);
        assert_eq!(
            general.migrate_proxy_settings(),
            ProxySettingsMigration::Moved { tag: "chain-out".to_owned() }
        );
        assert_eq!(general.migrate_proxy_settings(), ProxySettingsMigration::NothingToMigrate);

        let mut outbound = original.clone();
        apply_outbound_general(&mut outbound, &general).expect("apply");
        assert!(outbound.get("proxySettings").is_none());
        assert_eq!(outbound["streamSettings"]["sockopt"]["dialerProxy"], "chain-out");
        assert_eq!(outbound["streamSettings"]["sockopt"]["mark"], 7);
        assert_eq!(outbound["streamSettings"]["network"], "raw");
    }

    #[test]
    fn migration_creates_stream_containers() {
        let original = json!({"protocol": "freedom", "tag": "a", "proxySettings": {"tag": "chain-out"}});
        let mut general = general_of(&original);
        general.migrate_proxy_settings();
        let mut outbound = original.clone();
        apply_outbound_general(&mut outbound, &general).expect("apply");
        assert_eq!(outbound["streamSettings"], json!({"sockopt": {"dialerProxy": "chain-out"}}));
    }

    #[test]
    fn existing_dialer_proxy_wins() {
        let original = json!({
            "protocol": "freedom", "tag": "a",
            "proxySettings": {"tag": "chain-out"},
            "streamSettings": {"sockopt": {"dialerProxy": "kept"}}
        });
        let mut general = general_of(&original);
        assert_eq!(
            general.migrate_proxy_settings(),
            ProxySettingsMigration::DialerProxyWins {
                legacy: "chain-out".to_owned(),
                dialer_proxy: "kept".to_owned(),
            }
        );
        let mut outbound = original.clone();
        apply_outbound_general(&mut outbound, &general).expect("apply");
        assert!(outbound.get("proxySettings").is_none());
        assert_eq!(outbound["streamSettings"]["sockopt"]["dialerProxy"], "kept");
    }

    #[test]
    fn tagless_proxy_settings_is_only_removed() {
        let original = json!({"protocol": "freedom", "tag": "a", "proxySettings": {}});
        let mut general = general_of(&original);
        assert_eq!(general.migrate_proxy_settings(), ProxySettingsMigration::Removed);
        let mut outbound = original.clone();
        apply_outbound_general(&mut outbound, &general).expect("apply");
        assert!(outbound.get("proxySettings").is_none());
        assert!(outbound.get("streamSettings").is_none());
    }

    #[test]
    fn nothing_to_migrate_without_proxy_settings() {
        let mut general = general_of(&json!({"protocol": "freedom"}));
        assert_eq!(general.migrate_proxy_settings(), ProxySettingsMigration::NothingToMigrate);
        assert!(!general.migrate_proxy_settings);
    }

    #[test]
    fn foreign_sockopt_shape_is_refused() {
        let original = json!({
            "protocol": "freedom", "tag": "a",
            "proxySettings": {"tag": "chain-out"},
            "streamSettings": {"sockopt": "bogus"}
        });
        let mut general = general_of(&original);
        general.migrate_proxy_settings();
        let mut outbound = original.clone();
        assert!(apply_outbound_general(&mut outbound, &general).is_err());
    }
}
