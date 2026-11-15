//! Freedom outbound Protocol tab (Roadmap §2.4:96, §2.4:105–107).
//!
//! The editor offers the fields of the official documentation
//! (<https://xtls.github.io/en/config/outbounds/freedom.html>) that the current Xray-core still
//! supports: `redirect`, `userLevel`, `proxyProtocol`, `finalRules[]`.
//!
//! `fragment` and `noises[]` are deprecated since Xray-core v26.10.29 (XTLS/Xray-core#7242:
//! `FreedomConfig.Build()` logs a deprecation warning and names `fragment` in
//! `streamSettings.finalmask.tcp` / `noise` in `streamSettings.finalmask.udp` as the replacement),
//! so the form no longer offers them. On disk they are kept untouched (read-only
//! [`FreedomSettingsDraft::legacy_fragment`] / [`FreedomSettingsDraft::legacy_noises`]), flagged by
//! [`crate::xray::config::compatibility::outbound_warnings`] and moved into FinalMask only by the
//! explicit "Fix config" migration ([`FreedomSettingsDraft::migrate_legacy_obfuscation`]). A live
//! check with Xray 26.10.31 (Freedom behind a `tunnel` inbound, 2026-10-31) showed the migrated
//! layers behave the same: the same TCP segmentation and the same noise datagrams before the
//! payload.
//!
//! The documented way to choose the
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
use crate::xray::config::outbound_stream::OutboundStreamDraft;
use crate::xray::config::stream::{FinalMaskChain, FinalMaskLayerDraft, PortListValue, RangeValue, SockoptDraft};

use super::{apply_optional_string, ensure_settings_object};

/// Legacy Freedom `settings` keys that select a resolve strategy the core no longer applies, in
/// the core's precedence order (`targetStrategy` wins when non-empty).
pub const FREEDOM_LEGACY_STRATEGY_KEYS: &[&str] = &["targetStrategy", "domainStrategy"];

/// Documented `settings.proxyProtocol` values (`0` = disabled, the key is omitted).
pub const FREEDOM_PROXY_PROTOCOL_VERSIONS: &[u64] = &[0, 1, 2];

/// Documented `finalRules[].action` values.
pub const FREEDOM_FINAL_RULE_ACTIONS: &[&str] = &["allow", "block"];

/// Documented `finalRules[].network` values (empty = key absent, matches every network).
pub const FREEDOM_FINAL_RULE_NETWORKS: &[&str] = &["tcp", "udp", "tcp,udp"];

/// Default `finalRules[].delay` (seconds), also used by the legacy `blockDelay` alias.
pub const FREEDOM_DEFAULT_BLOCK_DELAY: &str = "30-90";

/// Supported `finalRules[].logLevel` values (empty / omitted means info).
pub const FREEDOM_FINAL_RULE_LOG_LEVELS: &[&str] = &["none", "debug", "info", "warning", "error"];

const KNOWN_FINAL_RULE_KEYS: &[&str] = &["action", "network", "port", "ip", "delay", "logLevel", "blockDelay"];

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
    /// `delay` in seconds; available since v26.11.9. A legacy `blockDelay` takes precedence.
    pub delay: RangeValue,
    /// `logLevel` for blocked connections; empty = info. Raw spelling is preserved until edited.
    pub log_level: String,
    // Keep absent/null and raw number/string forms until the user edits or explicitly removes them.
    original_block_fields: Map<String, Value>,
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

    /// Whether a non-null legacy `blockDelay` is present in this draft.
    pub fn has_legacy_block_delay(&self) -> bool {
        self.range_value("blockDelay", &self.block_delay).is_some_and(|value| !value.is_null())
    }

    /// Whether block-only fields exist (including null keys that can be explicitly removed).
    pub fn has_block_fields(&self) -> bool {
        !self.original_block_fields.is_empty()
            || !self.delay.text.is_empty() || !self.block_delay.text.is_empty()
            || !self.log_level.is_empty()
    }

    /// Explicitly replaces `delay` with the effective legacy value and removes `blockDelay`.
    /// No change is made on failure; the migration stays in the draft until Save.
    pub fn migrate_block_delay(&mut self) -> Result<(), String> {
        if !self.action.eq_ignore_ascii_case("block") {
            return Err("delay is only supported for block rules; remove the block-only fields instead.".to_owned());
        }
        if !self.has_legacy_block_delay() || self.block_delay.bounds()?.is_none() {
            return Err("No usable blockDelay to migrate.".to_owned());
        }
        self.delay = self.block_delay.clone();
        self.block_delay = RangeValue::default();
        self.original_block_fields.remove("blockDelay");
        Ok(())
    }

    /// Explicitly removes `delay`, `blockDelay` and `logLevel`, leaving all other keys intact.
    pub fn remove_block_fields(&mut self) {
        self.delay = RangeValue::default();
        self.block_delay = RangeValue::default();
        self.log_level.clear();
        self.original_block_fields.clear();
    }

    fn range_value(&self, key: &str, value: &RangeValue) -> Option<Value> {
        let original = self.original_block_fields.get(key);
        if RangeValue::parse(original).as_ref() == Some(value) {
            original.cloned()
        } else {
            value.to_value()
        }
    }

    fn log_level_value(&self) -> Option<Value> {
        let original = self.original_block_fields.get("logLevel");
        if original.and_then(Value::as_str).unwrap_or_default() == self.log_level {
            original.cloned()
        } else if self.log_level.is_empty() {
            None
        } else {
            Some(Value::String(self.log_level.clone()))
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
    /// Read-only: the deprecated `settings.fragment` on disk (any non-`null` value), kept as is.
    pub legacy_fragment: Option<Value>,
    /// Read-only: the deprecated `settings.noises` on disk (any non-`null` value), kept as is.
    pub legacy_noises: Option<Value>,
    /// `true` after [`Self::migrate_legacy_obfuscation`]: Save removes `fragment` / `noises`.
    pub remove_legacy_obfuscation: bool,
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

    /// Whether the deprecated `fragment` / `noises` are on disk and not yet migrated.
    pub fn has_legacy_obfuscation(&self) -> bool {
        (self.legacy_fragment.is_some() || self.legacy_noises.is_some()) && !self.remove_legacy_obfuscation
    }

    /// "Fix config": moves the deprecated `fragment` into a `fragment` layer of
    /// `streamSettings.finalmask.tcp` and `noises[]` into one `noise` layer of `finalmask.udp`
    /// (drafts only; Save writes both and removes the old keys). All or nothing: on an error nothing
    /// changes. Refused when a target chain cannot be read by the editor or already has layers (the
    /// order of the masks would be a guess), and for what FinalMask cannot express (`applyTo`
    /// `ipv4` / `ipv6`) — those are left to the user.
    pub fn migrate_legacy_obfuscation(
        &mut self,
        stream: &mut OutboundStreamDraft,
    ) -> Result<LegacyObfuscationMigration, String> {
        if !self.has_legacy_obfuscation() {
            return Err("No deprecated fragment / noises to move.".to_owned());
        }
        let fragment = self.legacy_fragment.as_ref().map(fragment_to_finalmask_layer).transpose()?;
        let noises = self.legacy_noises.as_ref().map(noises_to_finalmask_layer).transpose()?.flatten();
        for (chain, needed, layers) in [
            (FinalMaskChain::Tcp, fragment.is_some(), &stream.finalmask_tcp),
            (FinalMaskChain::Udp, noises.is_some(), &stream.finalmask_udp),
        ] {
            if !needed {
                continue;
            }
            if !stream.finalmask_chain_editable(chain) {
                return Err(format!(
                    "streamSettings.finalmask.{} can't be read by the editor; fix it on the Raw JSON tab first",
                    chain.key()
                ));
            }
            if !layers.is_empty() {
                return Err(format!(
                    "streamSettings.finalmask.{} already has layers — where the moved mask belongs in \
                     that chain is your call; move it on the Raw JSON tab",
                    chain.key()
                ));
            }
        }
        let migration = LegacyObfuscationMigration {
            fragment: fragment.is_some(),
            noises: noises.as_ref().map_or(0, |(_, count)| *count),
        };
        if let Some(layer) = fragment {
            stream.finalmask_tcp.push(layer);
            stream.write_finalmask_tcp = true;
        }
        if let Some((layer, _)) = noises {
            stream.finalmask_udp.push(layer);
            stream.write_finalmask_udp = true;
        }
        self.remove_legacy_obfuscation = true;
        Ok(migration)
    }
}

/// Result of [`FreedomSettingsDraft::migrate_legacy_obfuscation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyObfuscationMigration {
    /// `fragment` became a `fragment` layer in `finalmask.tcp`.
    pub fragment: bool,
    /// `noises[]` items now in the `noise` layer of `finalmask.udp` (`0` = no layer, e.g.
    /// `noises: []`, which is only removed).
    pub noises: usize,
}

/// Freedom `fragment` → FinalMask `fragment` (`FragmentMask`): the same `packets`, `length`,
/// `maxSplit` (and any other key, kept verbatim); `interval` (ms) is named `delay` there.
fn fragment_to_finalmask_layer(fragment: &Value) -> Result<FinalMaskLayerDraft, String> {
    let object = fragment
        .as_object()
        .ok_or_else(|| "settings.fragment is not an object — fix it on the Raw JSON tab".to_owned())?;
    if object.contains_key("delay") {
        return Err("settings.fragment has both interval and delay — fix it on the Raw JSON tab".to_owned());
    }
    let settings = object
        .iter()
        .map(|(key, value)| {
            let key = if key == "interval" { "delay".to_owned() } else { key.clone() };
            (key, value.clone())
        })
        .collect();
    Ok(FinalMaskLayerDraft { layer_type: "fragment".to_owned(), settings: Value::Object(settings) })
}

/// Freedom `noises[]` → one FinalMask `noise` layer, item by item as `ParseNoise` reads them
/// (`infra/conf/freedom.go`): `rand` with `packet` "N-M" → `rand`; `str` / `hex` → the same
/// `type` and the trimmed `packet`; `base64` (standard or URL alphabet, padding optional) →
/// `type: base64` with standard padded base64, the only form `PraseByteSlice` decodes; `delay`
/// as is. `applyTo` `""` / `ip` / `all` is the default and dropped. `None` for an empty list.
fn noises_to_finalmask_layer(noises: &Value) -> Result<Option<(FinalMaskLayerDraft, usize)>, String> {
    let items = noises
        .as_array()
        .ok_or_else(|| "settings.noises is not an array — fix it on the Raw JSON tab".to_owned())?;
    if items.is_empty() {
        return Ok(None);
    }
    let converted = items
        .iter()
        .enumerate()
        .map(|(index, item)| noise_item_to_finalmask(item).map_err(|message| format!("settings.noises[{index}]: {message}")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut settings = Map::new();
    settings.insert("noise".to_owned(), Value::Array(converted));
    Ok(Some((
        FinalMaskLayerDraft { layer_type: "noise".to_owned(), settings: Value::Object(settings) },
        items.len(),
    )))
}

fn noise_item_to_finalmask(item: &Value) -> Result<Value, String> {
    use base64::Engine as _;

    let object = item.as_object().ok_or_else(|| "not an object".to_owned())?;
    let text = |key: &str| match object.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(format!("{key} is not a string")),
    };
    let apply_to = text("applyTo")?;
    if !matches!(apply_to.to_ascii_lowercase().as_str(), "" | "ip" | "all") {
        return Err(format!(
            "applyTo \"{apply_to}\" has no FinalMask equivalent (the noise layer applies to every \
             address) — move this item by hand or drop applyTo first"
        ));
    }
    let packet = text("packet")?.trim().to_owned();
    let mut converted = Map::new();
    match text("type")?.as_str() {
        "rand" => {
            converted.insert("rand".to_owned(), Value::String(packet));
        }
        kind @ ("str" | "hex") => {
            converted.insert("type".to_owned(), Value::String(kind.to_owned()));
            converted.insert("packet".to_owned(), Value::String(packet));
        }
        "base64" => {
            // Freedom accepts both alphabets with or without padding; FinalMask only standard.
            let url_safe = packet.replace('+', "-").replace('/', "_").replace('=', "");
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(url_safe)
                .map_err(|_| format!("packet \"{packet}\" is not valid base64"))?;
            converted.insert("type".to_owned(), Value::String("base64".to_owned()));
            converted.insert(
                "packet".to_owned(),
                Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
            );
        }
        other => return Err(format!("type \"{other}\" is not rand / str / hex / base64")),
    }
    for (key, value) in object {
        match key.as_str() {
            "type" | "packet" | "applyTo" => {}
            "rand" | "randRange" => {
                return Err(format!("{key} would change meaning in FinalMask — fix it on the Raw JSON tab"));
            }
            _ => {
                converted.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(Value::Object(converted))
}

/// Reads the Freedom draft from an outbound object.
pub(super) fn parse_freedom_settings(outbound: &Value) -> FreedomSettingsDraft {
    let settings = outbound.get("settings").and_then(Value::as_object);
    let field = |key: &str| settings.and_then(|s| s.get(key));

    let legacy = |key: &str| field(key).filter(|value| !value.is_null()).cloned();
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
        legacy_fragment: legacy("fragment"),
        legacy_noises: legacy("noises"),
        remove_legacy_obfuscation: false,
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
    // Go accepts case aliases too. Leave such objects on the lossless Raw JSON path
    // rather than adding a second spelling whose precedence would depend on JSON order.
    if object.keys().any(|key| ["delay", "blockDelay", "logLevel"].iter()
        .any(|known| key.eq_ignore_ascii_case(known) && key.as_str() != *known)) {
        return None;
    }
    let log_level = match object.get("logLevel") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(_) => return None,
    };
    let original_block_fields = ["delay", "blockDelay", "logLevel"].into_iter()
        .filter_map(|key| object.get(key).map(|value| (key.to_owned(), value.clone())))
        .collect();
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
        delay: RangeValue::parse(object.get("delay"))?,
        log_level,
        original_block_fields,
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
    for (key, value) in [
        ("delay", rule.range_value("delay", &rule.delay)),
        ("blockDelay", rule.range_value("blockDelay", &rule.block_delay)),
        ("logLevel", rule.log_level_value()),
    ] {
        if let Some(value) = value {
            object.insert(key.to_owned(), value);
        }
    }
    for (key, value) in &rule.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

/// Writes the Freedom draft into `outbound`: the documented `settings` keys (and the removal of the
/// legacy strategy keys, or of `fragment` / `noises`, after the migrations). Every other key — in `settings` and the outbound
/// itself — is left as it was; `streamSettings` belongs to the stream draft.
pub(super) fn apply_freedom_settings(
    outbound: &mut Value,
    draft: &FreedomSettingsDraft,
) -> ConfigModifyResult<()> {
    validate_freedom_settings(draft)?;

    let settings = ensure_settings_object(outbound)?;
    apply_optional_string(settings, "redirect", &draft.redirect);
    apply_untouched_zero_u64(settings, "userLevel", draft.user_level);
    // `fragment` / `noises` are not edited any more: kept as they are until "Fix config".
    if draft.remove_legacy_obfuscation {
        settings.remove("fragment");
        settings.remove("noises");
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
/// matcher), `port` is a `PortList`, `delay` / `blockDelay` are `Int32Range` seconds.
/// The editor keeps its existing non-negative timeout restriction; reading remains lossless.
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
    for (key, range) in [("delay", &rule.delay), ("blockDelay", &rule.block_delay)] {
        if let Some((from, _)) = range.bounds().map_err(|message| format!("{key}: {message}"))?
            && from < 0 {
            return Err(format!("{key}: seconds must not be negative"));
        }
    }
    if !action.eq_ignore_ascii_case("block") {
        let has_delay = [("delay", &rule.delay), ("blockDelay", &rule.block_delay)].into_iter()
            .any(|(key, range)| rule.range_value(key, range).is_some_and(|value| !value.is_null()));
        if has_delay || !rule.log_level.is_empty() {
            return Err("delay, blockDelay and logLevel are only supported for block rules; use Remove block-only fields or edit Raw JSON.".to_owned());
        }
    } else if !rule.log_level.is_empty() && !FREEDOM_FINAL_RULE_LOG_LEVELS.iter()
        .any(|known| known.eq_ignore_ascii_case(&rule.log_level)) {
        return Err("logLevel: expected none, debug, info, warning or error".to_owned());
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

    /// Runs "Fix config" on `outbound` and applies both drafts, as the Outbound Shell's Save does.
    fn fix_config(outbound: &Value) -> Result<(Value, LegacyObfuscationMigration), String> {
        use crate::xray::config::outbound_stream::{apply_outbound_stream, parse_outbound_stream};
        let mut draft = parse(outbound);
        let mut stream = parse_outbound_stream(outbound);
        let migration = draft.migrate_legacy_obfuscation(&mut stream)?;
        let mut result = outbound.clone();
        apply_freedom_settings(&mut result, &draft).map_err(|e| e.to_string())?;
        apply_outbound_stream(&mut result, &stream).map_err(|e| e.to_string())?;
        Ok((result, migration))
    }

    #[test]
    fn fix_config_moves_fragment_and_noises_into_finalmask() {
        let outbound = json!({"protocol": "freedom", "settings": {
            "fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20", "maxSplit": "2-4"},
            "noises": [
                {"type": "rand", "packet": " 10-20 ", "delay": "10-16"},
                {"type": "str", "packet": "abc", "applyTo": "IP"},
                {"type": "hex", "packet": "0a0b", "delay": 5},
                {"type": "base64", "packet": "-_8"}
            ],
            "redirect": ":443"
        }, "streamSettings": {"sockopt": {"mark": 7}}});
        let (fixed, migration) = fix_config(&outbound).expect("fix");
        assert_eq!(migration, LegacyObfuscationMigration { fragment: true, noises: 4 });
        assert_eq!(fixed["settings"], json!({"redirect": ":443"}));
        assert_eq!(fixed["streamSettings"]["sockopt"], json!({"mark": 7}));
        assert_eq!(
            fixed["streamSettings"]["finalmask"]["tcp"],
            json!([{"type": "fragment", "settings": {"packets": "tlshello", "length": "100-200", "delay": "10-20", "maxSplit": "2-4"}}])
        );
        // `-_8` is URL-safe unpadded base64 for fb ff; FinalMask needs the standard padded "+/8=".
        assert_eq!(
            fixed["streamSettings"]["finalmask"]["udp"],
            json!([{"type": "noise", "settings": {"noise": [
                {"rand": "10-20", "delay": "10-16"},
                {"type": "str", "packet": "abc"},
                {"type": "hex", "packet": "0a0b", "delay": 5},
                {"type": "base64", "packet": "+/8="}
            ]}}])
        );
        // Done once: the button goes away.
        let mut draft = parse(&outbound);
        let mut stream = crate::xray::config::outbound_stream::parse_outbound_stream(&outbound);
        draft.migrate_legacy_obfuscation(&mut stream).expect("first");
        assert!(!draft.has_legacy_obfuscation());
        assert!(draft.migrate_legacy_obfuscation(&mut stream).is_err());
    }

    #[test]
    fn fix_config_refuses_what_finalmask_cannot_say_and_changes_nothing() {
        let refused = |settings: Value, stream: Value| {
            let outbound = json!({"protocol": "freedom", "settings": settings, "streamSettings": stream});
            fix_config(&outbound).expect_err("refused")
        };
        let ipv6 = json!({"noises": [{"type": "rand", "packet": "5", "applyTo": "ipv6"}]});
        assert!(refused(ipv6, json!({})).contains("applyTo"));
        let busy_tcp = json!({"finalmask": {"tcp": [{"type": "sudoku", "settings": {"password": "p"}}]}});
        let fragment = json!({"fragment": {"packets": "1-1", "length": "3", "interval": "0"}});
        assert!(refused(fragment.clone(), busy_tcp).contains("already has layers"));
        assert!(refused(json!({"fragment": {"interval": "1", "delay": "2"}}), json!({})).contains("interval and delay"));
        assert!(refused(json!({"noises": [{"type": "base64", "packet": "!!"}]}), json!({})).contains("base64"));
        assert!(refused(json!({"noises": [{"type": "Rand", "packet": "5"}]}), json!({})).contains("Rand"));
        assert!(refused(json!({"fragment": "1-3"}), json!({})).contains("not an object"));
        // A failed fix leaves the drafts as they were.
        let outbound = json!({"protocol": "freedom", "settings": {
            "fragment": {"packets": "1-1", "length": "3", "interval": "0"},
            "noises": [{"type": "rand", "packet": "5", "applyTo": "ipv4"}]}});
        let mut draft = parse(&outbound);
        let mut stream = crate::xray::config::outbound_stream::parse_outbound_stream(&outbound);
        assert!(draft.migrate_legacy_obfuscation(&mut stream).is_err());
        assert!(draft.has_legacy_obfuscation());
        assert!(stream.finalmask_tcp.is_empty() && !stream.write_finalmask_tcp);
        // An empty list is only removed; a udp chain with layers does not matter for fragment.
        let outbound = json!({"protocol": "freedom", "settings": {"noises": [], "fragment": {"packets": "1-1", "length": "3", "interval": "0"}},
                              "streamSettings": {"finalmask": {"udp": [{"type": "salamander", "settings": {"password": "p"}}]}}});
        let (fixed, migration) = fix_config(&outbound).expect("fix");
        assert_eq!(migration, LegacyObfuscationMigration { fragment: true, noises: 0 });
        assert_eq!(fixed["settings"], json!({}));
        assert_eq!(fixed["streamSettings"]["finalmask"]["udp"][0]["type"], "salamander");
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
            {"action": "block", "network": ["udp"], "port": "53,5353", "ip": "1.1.1.1,8.8.8.8", "blockDelay": 5},
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
    fn final_rule_timing_fields_round_trip_without_normalization() {
        for rule in [
            json!({"action": "block", "delay": "003", "blockDelay": 7, "logLevel": "WARNING", "future": [1]}),
            json!({"action": "block", "delay": null, "blockDelay": null, "logLevel": null}),
            json!({"action": "allow", "delay": null, "logLevel": ""}),
        ] {
            let mut outbound = json!({"protocol": "freedom", "settings": {"finalRules": [rule.clone()]}});
            let mut draft = parse(&outbound);
            assert!(!draft.final_rules_foreign);
            draft.redirect = ":443".to_owned();
            apply_freedom_settings(&mut outbound, &draft).unwrap();
            assert_eq!(outbound["settings"]["finalRules"][0], rule);
        }
    }

    #[test]
    fn explicit_timeout_migration_preserves_legacy_precedence_and_other_fields() {
        let original = json!({"protocol": "freedom", "settings": {"finalRules": [
            {"action": "block", "delay": 0, "blockDelay": "30-90", "logLevel": "WARNING", "future": {"keep": true}}
        ]}});
        let mut draft = parse(&original);
        let mut unchanged = original.clone();
        apply_freedom_settings(&mut unchanged, &draft).unwrap();
        assert_eq!(unchanged, original);
        draft.final_rules[0].migrate_block_delay().unwrap();
        let migrated = draft.clone();
        assert!(draft.final_rules[0].migrate_block_delay().is_err());
        assert_eq!(draft, migrated);
        let mut result = original;
        apply_freedom_settings(&mut result, &draft).unwrap();
        let rule = &result["settings"]["finalRules"][0];
        assert_eq!(rule["delay"], "30-90");
        assert!(rule.get("blockDelay").is_none());
        assert_eq!(rule["logLevel"], "WARNING");
        assert_eq!(rule["future"]["keep"], true);
    }

    #[test]
    fn changing_action_never_implicitly_removes_block_fields() {
        let mut outbound = json!({"protocol": "freedom", "settings": {"finalRules": [
            {"action": "block", "delay": 5, "blockDelay": 9, "logLevel": "none", "future": true}
        ]}});
        let original = outbound.clone();
        let mut draft = parse(&outbound);
        draft.final_rules[0].action = "allow".to_owned();
        assert!(apply_freedom_settings(&mut outbound, &draft).is_err());
        assert_eq!(outbound, original);
        let before = draft.clone();
        assert!(draft.final_rules[0].migrate_block_delay().is_err());
        assert_eq!(draft, before);
        draft.final_rules[0].remove_block_fields();
        apply_freedom_settings(&mut outbound, &draft).unwrap();
        assert_eq!(outbound["settings"]["finalRules"][0], json!({"action": "allow", "future": true}));
    }

    #[test]
    fn unsupported_timing_shapes_and_case_aliases_stay_on_raw_json_path() {
        for rule in [json!({"action": "block", "delay": {"future": 1}}),
            json!({"action": "block", "logLevel": 7}),
            json!({"action": "block", "Delay": 7}),
            json!({"action": "block", "loglevel": "info"})] {
            let mut outbound = json!({"protocol": "freedom", "settings": {"finalRules": [rule.clone()]}});
            let draft = parse(&outbound);
            assert!(draft.final_rules_foreign);
            apply_freedom_settings(&mut outbound, &draft).unwrap();
            assert_eq!(outbound["settings"]["finalRules"][0], rule);
        }
    }

    #[test]
    fn final_rule_log_levels_and_allow_field_checks_match_latest_core() {
        for level in ["", "none", "debug", "info", "warning", "error", "WARNING"] {
            let rule = parse_final_rule(&json!({"action": "block", "logLevel": level})).unwrap();
            assert!(validate_final_rule(&rule).is_ok());
        }
        for level in ["warn", "verbose", " INFO "] {
            let rule = parse_final_rule(&json!({"action": "block", "logLevel": level})).unwrap();
            assert!(validate_final_rule(&rule).is_err());
        }
        for field in ["delay", "blockDelay", "logLevel"] {
            let value = if field == "logLevel" { json!("info") } else { json!(0) };
            let rule = parse_final_rule(&json!({"action": "allow", field: value})).unwrap();
            assert!(validate_final_rule(&rule).is_err());
        }
    }

    #[test]
    fn final_rule_parity_with_local_xray() {
        use crate::xray::XrayCoreVersion;
        let Some(binary) = crate::xray::local_xray::local_xray_bin() else {
            eprintln!("no local Xray — skipping Freedom finalRules parity");
            return;
        };
        let version = std::process::Command::new(&binary).arg("version").output().unwrap();
        let version = XrayCoreVersion::parse(&String::from_utf8_lossy(&version.stdout)).unwrap();
        let modern = version >= XrayCoreVersion::new(26, 11, 9);
        let directory = std::env::temp_dir().join(format!("feldjaeger-finalrules-parity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("config.json");
        let mut failures = Vec::new();
        let cases = [
            (json!({"action": "block", "delay": "1-3", "logLevel": "debug"}), true),
            (json!({"action": "block", "blockDelay": 1}), true),
            (json!({"action": "block", "delay": 0, "blockDelay": "1"}), true),
            (json!({"action": "block", "logLevel": "WARNING"}), true),
            (json!({"action": "block", "logLevel": "none"}), true),
            (json!({"action": "allow", "delay": null, "logLevel": ""}), true),
            (json!({"action": "allow", "delay": 0}), false),
            (json!({"action": "allow", "blockDelay": 0}), false),
            (json!({"action": "allow", "logLevel": "info"}), false),
            (json!({"action": "block", "logLevel": "verbose"}), false),
        ];
        for (index, (rule, expected)) in cases.iter().enumerate() {
            let parsed = parse_final_rule(rule).unwrap();
            assert_eq!(validate_final_rule(&parsed).is_ok(), *expected, "model case {index}");
            let config = json!({"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [rule]}}]});
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            let output = std::process::Command::new(&binary).args(["run", "-test", "-c"])
                .arg(&path).output().unwrap();
            if output.status.success() != (!modern || *expected) {
                failures.push(index);
            }
        }
        std::fs::remove_dir_all(directory).unwrap();
        assert!(failures.is_empty(), "Freedom finalRules core parity cases: {failures:?}");
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
