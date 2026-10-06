//! Loopback outbound Protocol tab (Roadmap §4.2 "Outbounds Shell: Loopback").
//!
//! Verified against `XTLS/Xray-core@main`: `LoopbackConfig` (`infra/conf/loopback.go`) has exactly
//! two keys — `inboundTag` (string) and `sniffing` (the inbound `SniffingConfig`: `enabled`,
//! `destOverride`, `domainsExcluded`, `ipsExcluded`, `metadataOnly`, `routeOnly`). The handler
//! (`proxy/loopback/loopback.go`) hands every connection back to the dispatcher as if it had arrived
//! on an inbound tagged `inboundTag`, so routing rules with that `inboundTag` decide where it goes
//! next; sniffing runs again only when `sniffing.enabled` is true. Routing matches `inboundTag`
//! exactly (`app/router/condition.go`: case-sensitive, no trimming, an empty tag matches no rule),
//! so the tag is kept exactly as typed.
//!
//! `sniffing` reuses the inbound draft ([`SniffingSettings`]) and is written only when the user
//! changed it, so a Save leaves an untouched `sniffing` byte for byte. A `sniffing` or `inboundTag`
//! of a shape the editor cannot show is never overwritten unless the user replaces it.

use serde_json::Value;

use crate::xray::config::inbound_edit::{SniffingSettings, apply_inbound_sniffing, parse_sniffing_settings};
use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

use super::ensure_settings_object;

/// Loopback Protocol-tab draft.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoopbackSettingsDraft {
    /// `settings.inboundTag`, exactly as typed; empty = key absent.
    pub inbound_tag: String,
    /// `inboundTag` on disk is not a string (Xray-core refuses it); kept until the user types a tag.
    pub inbound_tag_foreign: bool,
    /// `settings.sniffing` as edited.
    pub sniffing: SniffingSettings,
    /// `settings.sniffing` as read from disk; written only when [`Self::sniffing`] differs.
    pub disk_sniffing: SniffingSettings,
    /// `settings.sniffing` on disk is neither an object nor `null`: never written.
    pub sniffing_foreign: bool,
}

/// Where routing sends the connections a Loopback outbound re-injects (a hint under the field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopbackRouting {
    /// `inboundTag` is empty: no rule with an `inboundTag` condition can match.
    NoTag,
    /// No routing rule names the tag: the other rules decide (possibly this outbound again).
    NoRule,
    /// Rules naming the tag, as `routing.rules` indexes in order.
    Rules(Vec<usize>),
    /// The rule at this index names the tag and sends the traffic back to this very outbound.
    LoopsBack {
        /// `routing.rules` index.
        rule: usize,
    },
}

/// Reads the Loopback draft from an outbound object.
pub(super) fn parse_loopback_settings(outbound: &Value) -> LoopbackSettingsDraft {
    let settings = outbound.get("settings").and_then(Value::as_object);
    let (inbound_tag, inbound_tag_foreign) = match settings.and_then(|s| s.get("inboundTag")) {
        None | Some(Value::Null) => (String::new(), false),
        Some(Value::String(tag)) => (tag.clone(), false),
        Some(_) => (String::new(), true),
    };
    let (sniffing, sniffing_foreign) = match settings.and_then(|s| s.get("sniffing")) {
        None | Some(Value::Null) => (SniffingSettings::default(), false),
        Some(Value::Object(_)) => {
            // `parse_sniffing_settings` reads the `sniffing` key of the object it is given.
            let holder = Value::Object(settings.cloned().unwrap_or_default());
            (parse_sniffing_settings(&holder), false)
        }
        Some(_) => (SniffingSettings::default(), true),
    };
    LoopbackSettingsDraft {
        inbound_tag,
        inbound_tag_foreign,
        disk_sniffing: sniffing.clone(),
        sniffing,
        sniffing_foreign,
    }
}

/// Writes the Loopback draft into `settings`; every other key is left as it was.
pub(super) fn apply_loopback_settings(outbound: &mut Value, draft: &LoopbackSettingsDraft) -> ConfigModifyResult<()> {
    let sniffing_changed = draft.sniffing != draft.disk_sniffing;
    if sniffing_changed && draft.sniffing_foreign {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "Loopback settings.sniffing is not a JSON object; fix or remove it on the Raw JSON tab \
             before editing sniffing"
                .to_owned(),
        ));
    }

    if sniffing_changed
        && let Some(token) = draft.sniffing.unknown_dest_override.iter().find(|token| !dest_override_known_to_core(token))
    {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!(
                "Loopback settings.sniffing.destOverride \"{token}\" is unknown to Xray-core (http, tls, quic, \
                 fakedns); remove it on the Raw JSON tab"
            ),
        ));
    }

    let settings = ensure_settings_object(outbound)?;
    if !draft.inbound_tag.is_empty() {
        settings.insert("inboundTag".to_owned(), Value::String(draft.inbound_tag.clone()));
    } else if !draft.inbound_tag_foreign {
        settings.remove("inboundTag");
    }
    if sniffing_changed {
        // `apply_inbound_sniffing` works on whatever object holds the `sniffing` key.
        let mut holder = Value::Object(std::mem::take(settings));
        let written = apply_inbound_sniffing(&mut holder, &draft.sniffing);
        if let Value::Object(object) = holder {
            *settings = object;
        }
        written?;
    }
    Ok(())
}

/// `SniffingConfig.Build()` lowercases each `destOverride` entry and accepts these spellings
/// (`https` / `ssl` mean `tls`, `fakedns+others` means `fakedns`); anything else fails the build.
fn dest_override_known_to_core(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "http" | "tls" | "https" | "ssl" | "quic" | "fakedns" | "fakedns+others"
    )
}

/// What `routing` does with the connections of the Loopback outbound `own_tag` that re-enter as
/// `inbound_tag` — matched like `InboundTagMatcher`: exact, both `StringList` forms (array, or a
/// string split at `,`).
pub fn loopback_routing(routing: Option<&Value>, own_tag: &str, inbound_tag: &str) -> LoopbackRouting {
    if inbound_tag.is_empty() {
        return LoopbackRouting::NoTag;
    }
    let rules = routing
        .and_then(|routing| routing.get("rules"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut matching = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let names_tag = match rule.get("inboundTag") {
            Some(Value::Array(tags)) => tags.iter().any(|tag| tag.as_str() == Some(inbound_tag)),
            Some(Value::String(tags)) => tags.split(',').any(|tag| tag == inbound_tag),
            _ => false,
        };
        if !names_tag {
            continue;
        }
        let own_tag = own_tag.trim();
        if !own_tag.is_empty() && rule.get("outboundTag").and_then(Value::as_str) == Some(own_tag) {
            return LoopbackRouting::LoopsBack { rule: index };
        }
        matching.push(index);
    }
    if matching.is_empty() {
        LoopbackRouting::NoRule
    } else {
        LoopbackRouting::Rules(matching)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(outbound: &Value) -> LoopbackSettingsDraft {
        parse_loopback_settings(outbound)
    }

    #[test]
    fn untouched_draft_keeps_settings_byte_for_byte() {
        let original = json!({"protocol": "loopback", "tag": "lb", "settings": {
            "inboundTag": " exact tag ", "sniffing": {"enabled": true}, "future": 1}});
        let mut outbound = original.clone();
        let draft = parse(&outbound);
        assert_eq!(draft.inbound_tag, " exact tag ", "kept untrimmed — routing matches exactly");
        assert_eq!(draft.sniffing.enabled, Some(true));
        apply_loopback_settings(&mut outbound, &draft).unwrap();
        assert_eq!(outbound, original);
    }

    #[test]
    fn edits_write_tag_and_sniffing_and_keep_other_keys() {
        let mut outbound = json!({"protocol": "loopback", "settings": {
            "sniffing": {"enabled": false, "domainsExcluded": ["courier.push.apple.com"]}, "future": 1}});
        let mut draft = parse(&outbound);
        draft.inbound_tag = "tls-repeat".to_owned();
        draft.sniffing.enabled = Some(true);
        draft.sniffing.dest_override = vec!["tls".to_owned()];
        apply_loopback_settings(&mut outbound, &draft).unwrap();
        let settings = &outbound["settings"];
        assert_eq!(settings["inboundTag"], "tls-repeat");
        assert_eq!(settings["future"], 1);
        assert_eq!(settings["sniffing"]["enabled"], true);
        assert_eq!(settings["sniffing"]["destOverride"], json!(["tls"]));
        assert_eq!(settings["sniffing"]["domainsExcluded"], json!(["courier.push.apple.com"]));

        // A new outbound gets a minimal sniffing object; clearing the tag removes the key.
        let mut fresh = json!({"protocol": "loopback", "settings": {}});
        let mut draft = parse(&fresh);
        draft.sniffing.enabled = Some(true);
        apply_loopback_settings(&mut fresh, &draft).unwrap();
        assert_eq!(fresh["settings"], json!({"sniffing": {"enabled": true}}));
        let mut draft = parse(&json!({"settings": {"inboundTag": "x"}}));
        draft.inbound_tag.clear();
        let mut cleared = json!({"settings": {"inboundTag": "x"}});
        apply_loopback_settings(&mut cleared, &draft).unwrap();
        assert_eq!(cleared["settings"], json!({}));
    }

    #[test]
    fn foreign_shapes_are_kept_until_replaced() {
        let original = json!({"protocol": "loopback", "settings": {"inboundTag": 5, "sniffing": "on"}});
        let mut outbound = original.clone();
        let mut draft = parse(&outbound);
        assert!(draft.inbound_tag_foreign && draft.sniffing_foreign);
        apply_loopback_settings(&mut outbound, &draft).unwrap();
        assert_eq!(outbound, original);

        draft.inbound_tag = "typed".to_owned();
        apply_loopback_settings(&mut outbound, &draft).unwrap();
        assert_eq!(outbound["settings"]["inboundTag"], "typed");
        draft.sniffing.enabled = Some(true);
        assert!(apply_loopback_settings(&mut outbound, &draft).is_err(), "foreign sniffing");
    }

    #[test]
    fn dest_override_tokens_follow_sniffing_config_build() {
        let mut outbound = json!({"protocol": "loopback", "settings": {}});
        let mut draft = parse(&outbound);
        draft.sniffing.dest_override = vec!["smtp".to_owned()];
        assert!(apply_loopback_settings(&mut outbound, &draft).is_err());

        // Spellings the core maps (any case) are kept; a token it refuses blocks a sniffing edit
        // but not a Save that leaves sniffing alone.
        let aliases = json!({"settings": {"sniffing": {"enabled": false, "destOverride": ["HTTPS", "fakedns+others"]}}});
        let mut draft = parse(&aliases);
        draft.sniffing.enabled = Some(true);
        apply_loopback_settings(&mut aliases.clone(), &draft).expect("aliases");
        let refused = json!({"settings": {"inboundTag": "a", "sniffing": {"destOverride": ["smtp"]}}});
        let mut draft = parse(&refused);
        apply_loopback_settings(&mut refused.clone(), &draft).expect("sniffing untouched");
        draft.sniffing.route_only = Some(true);
        let error = apply_loopback_settings(&mut refused.clone(), &draft).unwrap_err();
        assert!(error.message().contains("smtp"), "{error}");
    }

    /// Parity with a local `xray run -test` (`XRAY_BIN` / `xray-bin`), when one is present.
    #[test]
    fn parity_with_xray_run_test() {
        use crate::xray::local_xray::local_xray_bin;
        // (settings, core accepts)
        let cases = [
            (json!({"inboundTag": "repeat"}), true),
            (json!({}), true),
            (json!({"inboundTag": "repeat", "sniffing": {"enabled": true, "destOverride": ["tls", "HTTPS", "fakedns+others"],
                    "domainsExcluded": ["courier.push.apple.com"], "routeOnly": true}}), true),
            (json!({"inboundTag": "repeat", "sniffing": {"enabled": true, "destOverride": ["smtp"]}}), false),
            (json!({"inboundTag": 5}), false),
        ];
        let Some(xray) = local_xray_bin() else {
            eprintln!("no local Xray (XRAY_BIN / xray-bin) — skipping the Loopback `xray run -test` parity check");
            return;
        };
        let dir = std::env::temp_dir().join(format!("feldjaeger-loopback-parity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("parity temp dir");
        let mut failures = Vec::new();
        for (index, (settings, accepts)) in cases.into_iter().enumerate() {
            let outbound = json!({"tag": "lb", "protocol": "loopback", "settings": settings});
            // Feldjäger's verdict on the same settings, edited in full (sniffing counts as changed).
            let mut draft = parse(&outbound);
            draft.disk_sniffing = SniffingSettings { enabled: None, ..SniffingSettings::default() };
            let ours = !draft.inbound_tag_foreign && apply_loopback_settings(&mut outbound.clone(), &draft).is_ok();
            let path = dir.join(format!("case-{index}.json"));
            let config = json!({"outbounds": [outbound]});
            std::fs::write(&path, serde_json::to_string_pretty(&config).expect("serialize")).expect("write config");
            let output = std::process::Command::new(&xray).args(["run", "-test", "-c"]).arg(&path).output();
            let output = output.unwrap_or_else(|error| panic!("cannot run {}: {error}", xray.display()));
            if output.status.success() != accepts || ours != accepts {
                failures.push(format!(
                    "case {index}: core {}, Feldjäger {ours}, expected {accepts}\n{}",
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).trim()
                ));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(failures.is_empty(), "parity mismatches:\n{}", failures.join("\n\n"));
    }

    #[test]
    fn routing_hint_matches_like_the_core() {
        let routing = json!({"rules": [
            {"inboundTag": ["Repeat"], "outboundTag": "direct"},
            {"inboundTag": "a,repeat", "outboundTag": "proxy"},
            {"inboundTag": ["repeat"], "outboundTag": "block"},
            {"inboundTag": ["loop"], "outboundTag": "lb"}
        ]});
        assert_eq!(loopback_routing(Some(&routing), "lb", ""), LoopbackRouting::NoTag);
        assert_eq!(loopback_routing(Some(&routing), "lb", "repeat"), LoopbackRouting::Rules(vec![1, 2]));
        assert_eq!(loopback_routing(Some(&routing), "lb", "REPEAT"), LoopbackRouting::NoRule, "case-sensitive");
        assert_eq!(loopback_routing(Some(&routing), "lb", " repeat"), LoopbackRouting::NoRule, "no trimming");
        assert_eq!(loopback_routing(Some(&routing), "lb", "loop"), LoopbackRouting::LoopsBack { rule: 3 });
        assert_eq!(loopback_routing(None, "lb", "repeat"), LoopbackRouting::NoRule);
    }
}
