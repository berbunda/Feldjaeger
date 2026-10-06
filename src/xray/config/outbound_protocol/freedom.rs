//! Freedom outbound Protocol tab (Roadmap §2.4:96, §2.4:105–107).
//!
//! The editor offers exactly the fields of the official documentation
//! (<https://xtls.github.io/en/config/outbounds/freedom.html>): `redirect`, `userLevel`,
//! `fragment`, `noises[]`, `proxyProtocol`, `finalRules[]`. The documented way to choose the
//! resolve strategy, `streamSettings.sockopt.domainStrategy`, is edited by the shared socket
//! options editor of the Outbound Shell (Roadmap §4.2, [`crate::xray::config::outbound_stream`]),
//! which replaced the narrow field of this tab.
//!
//! `settings.domainStrategy` (and its alias `settings.targetStrategy`) is not documented any more.
//! Verified against `XTLS/Xray-core@main`: `FreedomConfig.Build()` (`infra/conf/freedom.go`) still
//! parses and validates it, but the Freedom handler (`proxy/freedom/freedom.go`, since
//! XTLS/Xray-core#6058) resolves domains only with `sockopt.domainStrategy`. The legacy keys are
//! therefore never written, kept untouched on Save (unknown-key preservation), flagged by
//! [`crate::xray::config::compatibility::outbound_warnings`], and moved into `sockopt` only by an
//! explicit migration ([`FreedomSettingsDraft::migrate_legacy_domain_strategy`]) that fills the
//! socket options draft.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::config::stream::{PortListValue, RangeValue, SockoptDraft};

use super::{FragmentDraft, NoiseDraft, apply_optional_string, ensure_settings_object};

/// Legacy Freedom `settings` keys that select a resolve strategy the core no longer applies, in
/// the core's precedence order (`targetStrategy` wins when non-empty).
pub const FREEDOM_LEGACY_STRATEGY_KEYS: &[&str] = &["targetStrategy", "domainStrategy"];

/// Documented `settings.proxyProtocol` values (`0` = disabled, the key is omitted).
pub const FREEDOM_PROXY_PROTOCOL_VERSIONS: &[u64] = &[0, 1, 2];

/// Documented `finalRules[].action` values.
pub const FREEDOM_FINAL_RULE_ACTIONS: &[&str] = &["allow", "block"];

/// Documented `finalRules[].network` values (empty = key absent, matches every network).
pub const FREEDOM_FINAL_RULE_NETWORKS: &[&str] = &["tcp", "udp", "tcp,udp"];

/// Default `finalRules[].blockDelay` (seconds) applied by the core when the key is absent.
pub const FREEDOM_DEFAULT_BLOCK_DELAY: &str = "30-90";

const KNOWN_FINAL_RULE_KEYS: &[&str] = &["action", "network", "port", "ip", "blockDelay"];

/// JSON shape a list-like value (`NetworkList`, `StringList`) was read in, so that an untouched
/// value is written back in the same shape. New values use the documented shape: a string for
/// `network` (`"tcp,udp"`), an array for `ip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ListForm {
    /// A JSON array of strings.
    #[default]
    Array,
    /// One comma-separated JSON string.
    Text,
}

/// One `settings.finalRules[]` entry. All conditions of a rule are AND-ed; an omitted condition
/// does not restrict. Rules are evaluated in order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FreedomFinalRuleDraft {
    /// `action` — `allow` | `block` (required).
    pub action: String,
    /// `network` — `tcp` | `udp` | `tcp,udp`; empty = key absent.
    pub network: String,
    network_form: ListForm,
    /// `port` — number or port-range string (`PortList`); empty = key absent.
    pub port: PortListValue,
    /// `ip` — CIDR / IP entries (also `geoip:` / `ext:` matchers); empty = key absent.
    pub ip: Vec<String>,
    ip_form: ListForm,
    /// `blockDelay` — `"30"` / `"30-90"` seconds (`Int32Range`); empty = key absent (core
    /// default [`FREEDOM_DEFAULT_BLOCK_DELAY`]).
    pub block_delay: RangeValue,
    /// Unknown rule keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

impl FreedomFinalRuleDraft {
    /// A new rule with the given action and no conditions.
    pub fn new(action: &str) -> Self {
        Self {
            action: action.to_owned(),
            network_form: ListForm::Text,
            ..Self::default()
        }
    }
}

/// Freedom Protocol-tab draft.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FreedomSettingsDraft {
    /// Read-only: the legacy strategy found in `settings` (`targetStrategy` before
    /// `domainStrategy`, as the core reads them); `None` when neither is a non-empty string.
    pub legacy_domain_strategy: Option<String>,
    /// `true` after [`Self::migrate_legacy_domain_strategy`]: Save removes the legacy keys.
    pub remove_legacy_domain_strategy: bool,
    /// `settings.redirect` (`host:port` / `:port`); empty = key absent.
    pub redirect: String,
    /// `settings.userLevel`; `0` = key absent (Xray default).
    pub user_level: u64,
    /// `settings.fragment`; `None` = key absent.
    pub fragment: Option<FragmentDraft>,
    /// `settings.noises[]`; empty = key absent.
    pub noises: Vec<NoiseDraft>,
    /// `settings.proxyProtocol` (`0` disabled = key absent, `1`, `2`).
    pub proxy_protocol: u64,
    /// `settings.finalRules[]`; empty = key absent.
    pub final_rules: Vec<FreedomFinalRuleDraft>,
    /// `true` when `finalRules` exists on disk in a shape the typed editor cannot represent
    /// losslessly; the key is then left untouched and edited through Raw JSON.
    pub final_rules_foreign: bool,
}

/// Result of [`FreedomSettingsDraft::migrate_legacy_domain_strategy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyDomainStrategyMigration {
    /// The legacy value now lives in `sockopt.domainStrategy`.
    Moved {
        /// The migrated strategy.
        value: String,
    },
    /// `sockopt.domainStrategy` was already set and stays (it is the one the core applies); the
    /// legacy value is only removed.
    SockoptWins {
        /// The discarded legacy value.
        legacy: String,
        /// The kept `sockopt` value.
        sockopt: String,
    },
    /// Nothing to migrate.
    NothingToMigrate,
}

impl FreedomSettingsDraft {
    /// Moves the legacy `settings` strategy into `sockopt.domainStrategy` of the socket options
    /// draft (drafts only; Save writes both). An existing `sockopt` value takes precedence.
    pub fn migrate_legacy_domain_strategy(&mut self, sockopt: &mut SockoptDraft) -> LegacyDomainStrategyMigration {
        let Some(legacy) = self.legacy_domain_strategy.clone() else {
            return LegacyDomainStrategyMigration::NothingToMigrate;
        };
        if self.remove_legacy_domain_strategy {
            return LegacyDomainStrategyMigration::NothingToMigrate;
        }
        self.remove_legacy_domain_strategy = true;
        let current = sockopt.domain_strategy.trim();
        if current.is_empty() {
            sockopt.domain_strategy = legacy.clone();
            LegacyDomainStrategyMigration::Moved { value: legacy }
        } else {
            LegacyDomainStrategyMigration::SockoptWins {
                legacy,
                sockopt: current.to_owned(),
            }
        }
    }

}

/// Reads the Freedom draft from an outbound object.
pub(super) fn parse_freedom_settings(outbound: &Value) -> FreedomSettingsDraft {
    let settings = outbound.get("settings").and_then(Value::as_object);
    let field = |key: &str| settings.and_then(|s| s.get(key));

    let fragment = field("fragment")
        .and_then(Value::as_object)
        .map(super::parse_fragment);
    let noises = field("noises")
        .and_then(Value::as_array)
        .map(|array| array.iter().filter_map(Value::as_object).map(super::parse_noise).collect())
        .unwrap_or_default();
    let (final_rules, final_rules_foreign) = match parse_final_rules(field("finalRules")) {
        Some(rules) => (rules, false),
        None => (Vec::new(), true),
    };
    let legacy_domain_strategy = FREEDOM_LEGACY_STRATEGY_KEYS.iter().find_map(|key| {
        field(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    });

    FreedomSettingsDraft {
        legacy_domain_strategy,
        remove_legacy_domain_strategy: false,
        redirect: super::string_field(field("redirect")),
        user_level: field("userLevel").and_then(Value::as_u64).unwrap_or(0),
        fragment,
        noises,
        proxy_protocol: field("proxyProtocol").and_then(Value::as_u64).unwrap_or(0),
        final_rules,
        final_rules_foreign,
    }
}

/// `None` when `finalRules` (or one of its rules) has a shape the typed editor cannot write back
/// unchanged ("lossless or raw", Roadmap §2.6 stage 0.1).
fn parse_final_rules(value: Option<&Value>) -> Option<Vec<FreedomFinalRuleDraft>> {
    match value {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(parse_final_rule).collect(),
        Some(_) => None,
    }
}

fn parse_final_rule(value: &Value) -> Option<FreedomFinalRuleDraft> {
    let object = value.as_object()?;
    let action = match object.get("action") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.trim().to_owned(),
        Some(_) => return None,
    };
    let (network, network_form) = match object.get("network") {
        None | Some(Value::Null) => (Vec::new(), ListForm::Text),
        value => parse_string_list(value)?,
    };
    let (ip, ip_form) = parse_string_list(object.get("ip"))?;
    let extras = object
        .iter()
        .filter(|(key, _)| !KNOWN_FINAL_RULE_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Some(FreedomFinalRuleDraft {
        action,
        network: network.join(","),
        network_form,
        port: PortListValue::parse(object.get("port"))?,
        ip,
        ip_form,
        block_delay: RangeValue::parse(object.get("blockDelay"))?,
        extras,
    })
}

/// Reads a `NetworkList` / `StringList`: an array of strings, or one comma-separated string.
fn parse_string_list(value: Option<&Value>) -> Option<(Vec<String>, ListForm)> {
    match value {
        None | Some(Value::Null) => Some((Vec::new(), ListForm::Array)),
        Some(Value::String(text)) => Some((split_list(text), ListForm::Text)),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(|text| text.trim().to_owned()))
            .collect::<Option<Vec<_>>>()
            .map(|entries| (entries, ListForm::Array)),
        Some(_) => None,
    }
}

fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

fn string_list_to_value(entries: &[String], form: ListForm) -> Option<Value> {
    let entries: Vec<&str> = entries
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.is_empty() {
        return None;
    }
    Some(match form {
        ListForm::Array => Value::Array(entries.into_iter().map(|e| Value::String(e.to_owned())).collect()),
        ListForm::Text => Value::String(entries.join(",")),
    })
}

fn final_rule_to_value(rule: &FreedomFinalRuleDraft) -> Value {
    let mut object = Map::new();
    apply_optional_string(&mut object, "action", &rule.action);
    if let Some(network) = string_list_to_value(&split_list(&rule.network), rule.network_form) {
        object.insert("network".to_owned(), network);
    }
    if let Some(port) = rule.port.to_value() {
        object.insert("port".to_owned(), port);
    }
    if let Some(ip) = string_list_to_value(&rule.ip, rule.ip_form) {
        object.insert("ip".to_owned(), ip);
    }
    if let Some(block_delay) = rule.block_delay.to_value() {
        object.insert("blockDelay".to_owned(), block_delay);
    }
    for (key, value) in &rule.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

/// Writes the Freedom draft into `outbound`: the documented `settings` keys (and the removal of the
/// legacy strategy keys after the migration). Every other key — in `settings` and the outbound
/// itself — is left as it was; `streamSettings` belongs to the stream draft.
pub(super) fn apply_freedom_settings(
    outbound: &mut Value,
    draft: &FreedomSettingsDraft,
) -> ConfigModifyResult<()> {
    validate_freedom_settings(draft)?;

    let settings = ensure_settings_object(outbound)?;
    apply_optional_string(settings, "redirect", &draft.redirect);
    apply_untouched_zero_u64(settings, "userLevel", draft.user_level);
    match &draft.fragment {
        Some(fragment) => {
            settings.insert("fragment".to_owned(), super::fragment_to_value(fragment));
        }
        None => {
            settings.remove("fragment");
        }
    }
    if draft.noises.is_empty() {
        settings.remove("noises");
    } else {
        settings.insert(
            "noises".to_owned(),
            Value::Array(draft.noises.iter().map(super::noise_to_value).collect()),
        );
    }
    apply_untouched_zero_u64(settings, "proxyProtocol", draft.proxy_protocol);
    if !draft.final_rules_foreign {
        if draft.final_rules.is_empty() {
            settings.remove("finalRules");
        } else {
            settings.insert(
                "finalRules".to_owned(),
                Value::Array(draft.final_rules.iter().map(final_rule_to_value).collect()),
            );
        }
    }
    if draft.remove_legacy_domain_strategy {
        for key in FREEDOM_LEGACY_STRATEGY_KEYS {
            settings.remove(*key);
        }
    }
    Ok(())
}

/// Writes a `u64` whose default `0` means "key absent". A present value of another JSON shape is
/// left alone when the draft still holds `0` (the widget could not show it, so it was not edited).
fn apply_untouched_zero_u64(settings: &mut Map<String, Value>, key: &str, value: u64) {
    if value != 0 {
        settings.insert(key.to_owned(), Value::Number(value.into()));
    } else if settings.get(key).is_some_and(|current| current.as_u64().is_some()) {
        settings.remove(key);
    }
}

fn validation_error(message: String) -> ConfigModifyError {
    ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message)
}

fn validate_freedom_settings(draft: &FreedomSettingsDraft) -> ConfigModifyResult<()> {
    for noise in &draft.noises {
        if noise.kind.trim().is_empty() {
            return Err(validation_error("Freedom noise type must not be empty".to_owned()));
        }
        if noise.packet.trim().is_empty() {
            return Err(validation_error("Freedom noise packet must not be empty".to_owned()));
        }
    }
    if !draft.final_rules_foreign {
        for (index, rule) in draft.final_rules.iter().enumerate() {
            validate_final_rule(rule).map_err(|message| {
                validation_error(format!("Freedom finalRules[{index}]: {message}"))
            })?;
        }
    }
    Ok(())
}

/// Mirrors `FreedomFinalRuleConfig.Build()` (`infra/conf/freedom.go`): `action` is matched
/// case-insensitively, `ip` goes through `geodata.ParseIPRules` (CIDR/IP or a `geoip:` / `ext:`
/// matcher), `port` is a `PortList`, `blockDelay` an `Int32Range` cast to unsigned seconds.
fn validate_final_rule(rule: &FreedomFinalRuleDraft) -> Result<(), String> {
    let action = rule.action.trim();
    if action.is_empty() {
        return Err("action is required (allow or block)".to_owned());
    }
    if !FREEDOM_FINAL_RULE_ACTIONS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(action))
    {
        return Err(format!("unknown action \"{action}\" (expected allow or block)"));
    }
    rule.port.validate().map_err(|message| format!("port: {message}"))?;
    for entry in rule.ip.iter().map(|entry| entry.trim()).filter(|entry| !entry.is_empty()) {
        if !is_valid_ip_rule(entry) {
            return Err(format!("ip: \"{entry}\" is not an IP address or CIDR range"));
        }
    }
    if let Some((from, _)) = rule
        .block_delay
        .bounds()
        .map_err(|message| format!("blockDelay: {message}"))?
        && from < 0
    {
        return Err("blockDelay: seconds must not be negative".to_owned());
    }
    Ok(())
}

fn is_valid_ip_rule(entry: &str) -> bool {
    let entry = entry.strip_prefix('!').unwrap_or(entry);
    let lower = entry.to_ascii_lowercase();
    if ["geoip:", "ext:", "ext-ip:"].iter().any(|prefix| lower.starts_with(prefix)) {
        return entry.split_once(':').is_some_and(|(_, rest)| !rest.trim().is_empty());
    }
    let (address, prefix) = match entry.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (entry, None),
    };
    let Ok(ip) = address.trim().parse::<std::net::IpAddr>() else {
        return false;
    };
    match prefix {
        None => true,
        Some(prefix) => {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            prefix.trim().parse::<u8>().is_ok_and(|bits| bits <= max)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(outbound: &Value) -> FreedomSettingsDraft {
        parse_freedom_settings(outbound)
    }

    #[test]
    fn legacy_strategy_is_read_but_never_written_or_dropped_without_migration() {
        let mut outbound = json!({"protocol": "freedom",
                                  "settings": {"domainStrategy": "UseIP", "redirect": ":443"}});
        let draft = parse(&outbound);
        assert_eq!(draft.legacy_domain_strategy.as_deref(), Some("UseIP"));
        apply_freedom_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["domainStrategy"], "UseIP");
        assert!(outbound.get("streamSettings").is_none());

        // `targetStrategy` wins over `domainStrategy`, as in `FreedomConfig.Build()`.
        let both = json!({"settings": {"domainStrategy": "UseIP", "targetStrategy": "ForceIPv4"}});
        assert_eq!(parse(&both).legacy_domain_strategy.as_deref(), Some("ForceIPv4"));
    }

    #[test]
    fn migration_moves_legacy_strategy_into_the_sockopt_draft() {
        let mut outbound = json!({"protocol": "freedom",
                                  "settings": {"domainStrategy": "UseIPv6v4", "futureField": 1}});
        let mut draft = parse(&outbound);
        let mut sockopt = SockoptDraft { mark: Some(7), ..SockoptDraft::default() };
        assert_eq!(
            draft.migrate_legacy_domain_strategy(&mut sockopt),
            LegacyDomainStrategyMigration::Moved { value: "UseIPv6v4".to_owned() }
        );
        assert_eq!(sockopt.domain_strategy, "UseIPv6v4");
        assert_eq!(sockopt.mark, Some(7));
        assert_eq!(
            draft.migrate_legacy_domain_strategy(&mut sockopt),
            LegacyDomainStrategyMigration::NothingToMigrate
        );
        apply_freedom_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"], json!({"futureField": 1}));
        assert!(outbound.get("streamSettings").is_none(), "sockopt is the stream draft's job");
    }

    #[test]
    fn migration_conflict_keeps_sockopt_and_drops_both_legacy_keys() {
        let mut outbound = json!({"protocol": "freedom",
                                  "settings": {"domainStrategy": "UseIP", "targetStrategy": "UseIPv4"}});
        let mut draft = parse(&outbound);
        let mut sockopt = SockoptDraft { domain_strategy: "ForceIP".to_owned(), ..SockoptDraft::default() };
        assert_eq!(
            draft.migrate_legacy_domain_strategy(&mut sockopt),
            LegacyDomainStrategyMigration::SockoptWins {
                legacy: "UseIPv4".to_owned(),
                sockopt: "ForceIP".to_owned(),
            }
        );
        assert_eq!(sockopt.domain_strategy, "ForceIP");
        apply_freedom_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"], json!({}));
    }

    #[test]
    fn proxy_protocol_writes_versions_and_omits_zero() {
        let mut outbound = json!({"protocol": "freedom", "settings": {"proxyProtocol": 2}});
        let mut draft = parse(&outbound);
        assert_eq!(draft.proxy_protocol, 2);
        draft.proxy_protocol = 1;
        apply_freedom_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["proxyProtocol"], 1);
        draft.proxy_protocol = 0;
        apply_freedom_settings(&mut outbound, &draft).expect("apply");
        assert!(outbound["settings"].get("proxyProtocol").is_none());

        // A shape the combo box cannot show is not removed by the untouched `0`.
        let mut foreign = json!({"protocol": "freedom", "settings": {"proxyProtocol": "2"}});
        let draft = parse(&foreign);
        apply_freedom_settings(&mut foreign, &draft).expect("apply");
        assert_eq!(foreign["settings"]["proxyProtocol"], "2");
    }

    #[test]
    fn final_rules_round_trip_keeps_shapes_and_extras() {
        let rules = json!([
            {"action": "block", "network": "tcp,udp", "port": 25, "ip": ["10.0.0.0/8", "geoip:private"],
             "blockDelay": "30-90", "futureRuleKey": true},
            {"action": "allow", "network": ["udp"], "port": "53,5353", "ip": "1.1.1.1,8.8.8.8", "blockDelay": 5},
            {"action": "allow"}
        ]);
        let mut outbound = json!({"protocol": "freedom", "settings": {"finalRules": rules.clone()}});
        let draft = parse(&outbound);
        assert!(!draft.final_rules_foreign);
        assert_eq!(draft.final_rules.len(), 3);
        assert_eq!(draft.final_rules[1].ip, vec!["1.1.1.1", "8.8.8.8"]);
        apply_freedom_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(outbound["settings"]["finalRules"], rules);
    }

    #[test]
    fn new_final_rule_writes_only_filled_fields() {
        let mut outbound = json!({"protocol": "freedom"});
        let mut rule = FreedomFinalRuleDraft::new("block");
        rule.network = "tcp".to_owned();
        rule.ip = vec!["192.168.0.0/16".to_owned(), " ".to_owned()];
        rule.port = PortListValue::new("443");
        let draft = FreedomSettingsDraft {
            final_rules: vec![rule, FreedomFinalRuleDraft::new("allow")],
            ..FreedomSettingsDraft::default()
        };
        apply_freedom_settings(&mut outbound, &draft).expect("apply");
        assert_eq!(
            outbound["settings"]["finalRules"],
            json!([
                {"action": "block", "network": "tcp", "port": 443, "ip": ["192.168.0.0/16"]},
                {"action": "allow"}
            ])
        );
    }

    #[test]
    fn unrepresentable_final_rules_stay_untouched() {
        for rules in [json!("bad"), json!([{"action": 1}]), json!([{"action": "block", "ip": [1]}]),
                      json!([{"action": "block", "blockDelay": 1.5}]), json!(["block"])] {
            let mut outbound = json!({"protocol": "freedom", "settings": {"finalRules": rules.clone()}});
            let draft = parse(&outbound);
            assert!(draft.final_rules_foreign, "{rules}");
            apply_freedom_settings(&mut outbound, &draft).expect("apply");
            assert_eq!(outbound["settings"]["finalRules"], rules);
        }
    }

    #[test]
    fn final_rules_validation_mirrors_the_core() {
        let check = |rule: FreedomFinalRuleDraft| {
            let draft = FreedomSettingsDraft { final_rules: vec![rule], ..FreedomSettingsDraft::default() };
            apply_freedom_settings(&mut json!({"protocol": "freedom"}), &draft)
        };
        assert!(check(FreedomFinalRuleDraft::new("BLOCK")).is_ok());
        let error = check(FreedomFinalRuleDraft::new("")).unwrap_err();
        assert!(error.to_string().contains("finalRules[0]: action is required"));
        assert!(check(FreedomFinalRuleDraft::new("deny")).is_err());

        let with = |edit: fn(&mut FreedomFinalRuleDraft)| {
            let mut rule = FreedomFinalRuleDraft::new("block");
            edit(&mut rule);
            check(rule)
        };
        assert!(with(|r| r.ip = vec!["10.0.0.0/8".into(), "::1".into(), "fd00::/8".into(),
                                    "geoip:cn".into(), "!geoip:private".into()]).is_ok());
        assert!(with(|r| r.ip = vec!["10.0.0.0/33".into()]).is_err());
        assert!(with(|r| r.ip = vec!["example.com".into()]).is_err());
        assert!(with(|r| r.port = PortListValue::new("1000-2000,443")).is_ok());
        assert!(with(|r| r.port = PortListValue::new("70000")).is_err());
        assert!(with(|r| r.block_delay = RangeValue::new("30-90")).is_ok());
        assert!(with(|r| r.block_delay = RangeValue::new("-5")).is_err());
        assert!(with(|r| r.block_delay = RangeValue::new("soon")).is_err());
    }

    #[test]
    fn ip_rule_syntax() {
        for valid in ["1.2.3.4", "10.0.0.0/8", "2001:db8::/32", "geoip:cn", "ext:geoip.dat:cn"] {
            assert!(is_valid_ip_rule(valid), "{valid}");
        }
        for invalid in ["", "geoip:", "1.2.3.4/", "300.1.1.1", "1.2.3.4/abc"] {
            assert!(!is_valid_ip_rule(invalid), "{invalid}");
        }
    }

}
