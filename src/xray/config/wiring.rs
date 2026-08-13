//! Cross-section wiring consistency checks: `stats` ↔ `policy` ↔ `api` ↔ `metrics`
//! (Roadmap §2.5:106), and `routing` ↔ `balancers` ↔ `outbounds` ↔ `observatory`
//! (Roadmap §2.5:108).
//!
//! These are informational, non-fatal warnings — none of `stats`/`api`/`metrics` has a
//! structured editor yet, so this module only *detects* documented wiring requirements
//! (<https://xtls.github.io/en/config/stats.html>, `config/api.html`, `config/metrics.html`,
//! `config/policy.html>`, `config/routing.html`) that the loaded config does not satisfy.
//! `routing.balancers[]` itself has no structured editor either (see
//! `Feldjaeger-Архитектура.md` §20.1.1 — deliberately out of scope for the read-only Routing
//! page); this module only reads the raw JSON to flag inconsistencies. Nothing here blocks
//! Save.

use serde_json::Value;

use super::sections::XrayConfigSections;

/// Detects wiring problems between `stats`, `policy`, `api`, and `metrics`.
///
/// Returns human-readable warnings (no secrets — these sections carry no credentials).
pub fn stats_wiring_warnings(sections: &XrayConfigSections) -> Vec<String> {
    let mut warnings = Vec::new();

    let stats_enabled = sections.stats().is_some();
    let policy_wants_stats = policy_wants_stats(sections);

    if policy_wants_stats && !stats_enabled {
        warnings.push(
            "policy enables statistics tracking (a system or user-level stats flag is true), \
             but the top-level `stats` object is missing — no data will be collected until \
             `stats: {}` is added."
                .to_owned(),
        );
    }
    if stats_enabled && !policy_wants_stats {
        warnings.push(
            "`stats` is enabled, but no `policy` system or user-level flag turns on any \
             statistic — the stats module is running with nothing to record."
                .to_owned(),
        );
    }

    if let Some(api) = sections.api() {
        if api_services_include(api.value(), "StatsService") && !stats_enabled {
            warnings.push(
                "`api.services` includes StatsService, but the top-level `stats` object is \
                 missing — the API will report empty statistics."
                    .to_owned(),
            );
        }
        if let Some(warning) = unreachable_endpoint_warning("api", api.value(), sections, None) {
            warnings.push(warning);
        }
    }

    if let Some(metrics) = sections.metrics()
        && let Some(warning) =
            unreachable_endpoint_warning("metrics", metrics.value(), sections, Some("Metrics"))
    {
        warnings.push(warning);
    }

    warnings
}

/// Whether any `policy` system or user-level flag would actually collect statistics.
fn policy_wants_stats(sections: &XrayConfigSections) -> bool {
    let Some(policy) = sections.policy_summary() else {
        return false;
    };
    let system_wants = policy.system_policy.as_ref().is_some_and(|system| {
        system.stats_inbound_uplink == Some(true)
            || system.stats_inbound_downlink == Some(true)
            || system.stats_outbound_uplink == Some(true)
            || system.stats_outbound_downlink == Some(true)
    });
    let levels_want = policy.user_levels.iter().any(|level| {
        level.stats_user_uplink == Some(true)
            || level.stats_user_downlink == Some(true)
            || level.stats_user_online == Some(true)
    });
    system_wants || levels_want
}

/// Whether `api.services[]` (case-insensitive) contains `service`.
fn api_services_include(api: &Value, service: &str) -> bool {
    api.get("services")
        .and_then(Value::as_array)
        .is_some_and(|services| {
            services
                .iter()
                .any(|entry| entry.as_str().is_some_and(|s| s.eq_ignore_ascii_case(service)))
        })
}

/// Detects an `api`/`metrics`-style endpoint (`{ tag, listen, .. }`) that cannot be reached:
/// no `listen` address, and no routing rule forwards traffic to its outbound `tag`.
///
/// `default_tag` mirrors the wire default (`metrics.tag` defaults to `"Metrics"` when empty;
/// `api.tag` has no documented default, so `None` is passed for `api`).
fn unreachable_endpoint_warning(
    kind: &str,
    value: &Value,
    sections: &XrayConfigSections,
    default_tag: Option<&str>,
) -> Option<String> {
    let listen = value
        .get("listen")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if listen.is_some() {
        return None;
    }

    let tag = value
        .get("tag")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(default_tag);

    match tag {
        None => Some(format!(
            "`{kind}` has no `listen` address and no `tag` — it cannot be reached at all; set \
             `listen`, or set `tag` and route an inbound to it."
        )),
        Some(tag) if !routing_forwards_to_outbound_tag(sections, tag) => Some(format!(
            "`{kind}` has no `listen` address and no routing rule forwards traffic to \
             outboundTag `{tag}` — the {kind} endpoint is unreachable without manual inbound + \
             routing wiring."
        )),
        Some(_) => None,
    }
}

fn routing_forwards_to_outbound_tag(sections: &XrayConfigSections, tag: &str) -> bool {
    let Some(routing) = sections.routing() else {
        return false;
    };
    let Some(rules) = routing.value().get("rules").and_then(Value::as_array) else {
        return false;
    };
    rules.iter().any(|rule| {
        rule.get("outboundTag")
            .and_then(Value::as_str)
            .is_some_and(|t| t.trim().eq_ignore_ascii_case(tag))
    })
}

/// Detects wiring problems between `routing.rules[].balancerTag`, `routing.balancers[]`,
/// `outbounds[].tag`, and `observatory`/`burstObservatory` (Roadmap §2.5:108).
///
/// Returns human-readable warnings (tags/selectors carry no secrets). `routing.balancers[]`
/// has no typed model — everything here reads the raw JSON, same style as
/// [`stats_wiring_warnings`].
pub fn routing_wiring_warnings(sections: &XrayConfigSections) -> Vec<String> {
    let mut warnings = Vec::new();

    let Some(routing) = sections.routing() else {
        return warnings;
    };
    let routing_value = routing.value();
    let Some(rules) = routing_value.get("rules").and_then(Value::as_array) else {
        return warnings;
    };
    let balancers = routing_value.get("balancers").and_then(Value::as_array);

    let balancer_tags: Vec<&str> = balancers
        .map(|list| {
            list.iter()
                .filter_map(|b| tag_field(b, "tag"))
                .collect()
        })
        .unwrap_or_default();
    let outbound_tags: Vec<&str> = sections
        .outbounds()
        .iter()
        .filter_map(|o| tag_field(o.value(), "tag"))
        .collect();

    rule_target_warnings(rules, &balancer_tags, &mut warnings);

    if let Some(balancers) = balancers {
        balancer_warnings(sections, balancers, &outbound_tags, &mut warnings);
    }

    warnings
}

/// Trimmed, non-empty string field, matching the tag-comparison convention used throughout
/// this module and [`super::tag_refs`].
fn tag_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Checks each `routing.rules[]` entry's `outboundTag` / `balancerTag` pair.
fn rule_target_warnings(rules: &[Value], balancer_tags: &[&str], warnings: &mut Vec<String>) {
    for (index, rule) in rules.iter().enumerate() {
        let outbound_tag = tag_field(rule, "outboundTag");
        let balancer_tag = tag_field(rule, "balancerTag");

        match (outbound_tag, balancer_tag) {
            (Some(outbound_tag), Some(balancer_tag)) => warnings.push(format!(
                "routing.rules[{index}] (rule #{}) sets both outboundTag `{outbound_tag}` and \
                 balancerTag `{balancer_tag}` — per the Xray docs outboundTag wins and \
                 balancerTag is silently ignored.",
                index + 1
            )),
            (None, Some(balancer_tag))
                if !balancer_tags
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(balancer_tag)) =>
            {
                warnings.push(format!(
                    "routing.rules[{index}] (rule #{}) balancerTag `{balancer_tag}` does not \
                     match any routing.balancers[].tag.",
                    index + 1
                ));
            }
            _ => {}
        }
    }
}

/// Checks each `routing.balancers[]` entry: duplicate tags, dead selectors, unknown
/// fallbackTag, and `leastPing`/`leastLoad` observatory coverage.
fn balancer_warnings(
    sections: &XrayConfigSections,
    balancers: &[Value],
    outbound_tags: &[&str],
    warnings: &mut Vec<String>,
) {
    let mut seen_tags: Vec<&str> = Vec::new();

    for (index, balancer) in balancers.iter().enumerate() {
        let tag = tag_field(balancer, "tag");
        let label = tag.unwrap_or("(untagged)");

        if let Some(tag) = tag {
            if seen_tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                warnings.push(format!(
                    "routing.balancers[{index}] tag `{tag}` duplicates another balancer's tag \
                     — balancerTag resolution is ambiguous."
                ));
            } else {
                seen_tags.push(tag);
            }
        }

        let selector_prefixes = selector_field(balancer);
        let matched_outbounds: Vec<&str> = match &selector_prefixes {
            Some(prefixes) => outbound_tags
                .iter()
                .copied()
                .filter(|outbound| matches_any_prefix(outbound, prefixes))
                .collect(),
            None => Vec::new(),
        };

        if let Some(prefixes) = &selector_prefixes
            && !prefixes.is_empty()
            && matched_outbounds.is_empty()
        {
            warnings.push(format!(
                "routing.balancers[{index}] (`{label}`) selector matches no configured \
                 outbound tag — this balancer has zero eligible outbounds."
            ));
        }

        if let Some(fallback_tag) = tag_field(balancer, "fallbackTag")
            && !outbound_tags
                .iter()
                .any(|t| t.eq_ignore_ascii_case(fallback_tag))
        {
            warnings.push(format!(
                "routing.balancers[{index}] (`{label}`) fallbackTag `{fallback_tag}` does not \
                 match any outbound tag."
            ));
        }

        if let Some(strategy_type) = balancer
            .get("strategy")
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            && matches!(strategy_type.to_ascii_lowercase().as_str(), "leastping" | "leastload")
        {
            match observatory_subject_selectors(sections) {
                None => warnings.push(format!(
                    "routing.balancers[{index}] (`{label}`) strategy `{strategy_type}` requires \
                     an observatory or burstObservatory section, but neither is configured — \
                     every outbound is excluded and the balancer is non-functional."
                )),
                Some(observatory_selectors) if !matched_outbounds.is_empty() => {
                    let covered = matched_outbounds
                        .iter()
                        .any(|outbound| matches_any_prefix(outbound, &observatory_selectors));
                    if !covered {
                        warnings.push(format!(
                            "routing.balancers[{index}] (`{label}`) strategy `{strategy_type}` \
                             outbounds are not covered by any observatory/burstObservatory \
                             subjectSelector — they will be excluded."
                        ));
                    }
                }
                Some(_) => {}
            }
        }
    }
}

/// `selector[]` as trimmed, non-empty prefix strings — `None` when the field is absent,
/// `Some(vec)` (possibly empty) when present, matching [`super::tag_refs`]'s interpretation.
fn selector_field(balancer: &Value) -> Option<Vec<&str>> {
    balancer.get("selector").and_then(Value::as_array).map(|list| {
        list.iter()
            .filter_map(|entry| entry.as_str().map(str::trim).filter(|s| !s.is_empty()))
            .collect()
    })
}

/// Whether `tag` starts with any of `prefixes` (case-insensitive), the same balancer
/// `selector` prefix-match semantics used by [`super::tag_refs`].
fn matches_any_prefix<S: AsRef<str>>(tag: &str, prefixes: &[S]) -> bool {
    let tag_lower = tag.to_ascii_lowercase();
    prefixes
        .iter()
        .any(|prefix| tag_lower.starts_with(&prefix.as_ref().to_ascii_lowercase()))
}

/// Combined `subjectSelector` prefixes from `observatory` and `burstObservatory` — `None`
/// only when neither section is configured at all.
fn observatory_subject_selectors(sections: &XrayConfigSections) -> Option<Vec<String>> {
    let observatory = sections.observatory_summary();
    let burst_observatory = sections.burst_observatory_summary();
    if observatory.is_none() && burst_observatory.is_none() {
        return None;
    }
    let mut selectors = Vec::new();
    if let Some(observatory) = observatory {
        selectors.extend(observatory.subject_selectors);
    }
    if let Some(burst_observatory) = burst_observatory {
        selectors.extend(burst_observatory.subject_selectors);
    }
    Some(selectors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::config::parser::XrayConfigParser;

    fn sections_from(json: &str) -> XrayConfigSections {
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file("/etc/xray/config.json", json);
        assert!(outcome.is_success(), "{:?}", outcome.errors());
        outcome.into_sections()
    }

    #[test]
    fn no_sections_no_warnings() {
        let sections = sections_from(r#"{}"#);
        assert!(stats_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn policy_wants_stats_but_stats_missing() {
        let sections = sections_from(
            r#"{"policy":{"levels":{"0":{"statsUserUplink":true}}}}"#,
        );
        let warnings = stats_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("stats"));
        assert!(warnings[0].contains("missing"));
    }

    #[test]
    fn system_policy_stats_flag_alone_triggers_warning() {
        let sections = sections_from(
            r#"{"policy":{"system":{"statsOutboundDownlink":true}}}"#,
        );
        assert_eq!(stats_wiring_warnings(&sections).len(), 1);
    }

    #[test]
    fn stats_enabled_but_policy_never_collects() {
        let sections = sections_from(r#"{"stats":{},"policy":{"levels":{"0":{"handshake":4}}}}"#);
        let warnings = stats_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("nothing to record"));
    }

    #[test]
    fn stats_enabled_no_policy_section_at_all() {
        let sections = sections_from(r#"{"stats":{}}"#);
        assert_eq!(stats_wiring_warnings(&sections).len(), 1);
    }

    #[test]
    fn stats_and_policy_aligned_no_warning() {
        let sections =
            sections_from(r#"{"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true}}}}"#);
        assert!(stats_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn api_stats_service_without_stats_object() {
        let sections = sections_from(
            r#"{"api":{"tag":"api","listen":"127.0.0.1:8080","services":["StatsService"]}}"#,
        );
        let warnings = stats_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("StatsService"));
    }

    #[test]
    fn api_with_listen_is_always_reachable() {
        let sections = sections_from(r#"{"api":{"tag":"api","listen":"127.0.0.1:8080"}}"#);
        assert!(stats_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn api_without_listen_or_tag_is_unreachable() {
        let sections = sections_from(r#"{"api":{"services":["HandlerService"]}}"#);
        let warnings = stats_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("`api`"));
        assert!(warnings[0].contains("no `tag`"));
    }

    #[test]
    fn api_without_listen_but_routed_is_reachable() {
        let sections = sections_from(
            r#"{
                "api":{"tag":"api-out","services":["HandlerService"]},
                "routing":{"rules":[{"inboundTag":["api-in"],"outboundTag":"api-out"}]}
            }"#,
        );
        assert!(stats_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn api_without_listen_and_not_routed_is_unreachable() {
        let sections = sections_from(
            r#"{
                "api":{"tag":"api-out","services":["HandlerService"]},
                "routing":{"rules":[{"inboundTag":["x"],"outboundTag":"direct"}]}
            }"#,
        );
        let warnings = stats_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("`api-out`"));
    }

    #[test]
    fn metrics_without_listen_or_tag_uses_default_tag_and_is_unreachable() {
        let sections = sections_from(r#"{"metrics":{}}"#);
        let warnings = stats_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("`Metrics`"));
    }

    #[test]
    fn metrics_with_listen_is_reachable() {
        let sections = sections_from(r#"{"metrics":{"listen":"127.0.0.1:11111"}}"#);
        assert!(stats_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn metrics_routed_via_default_tag_is_reachable() {
        let sections = sections_from(
            r#"{
                "metrics":{},
                "routing":{"rules":[{"inboundTag":["m-in"],"outboundTag":"Metrics"}]}
            }"#,
        );
        assert!(stats_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn unknown_fields_do_not_affect_detection() {
        let sections = sections_from(
            r#"{
                "stats":{},
                "policy":{"levels":{"0":{"statsUserUplink":true,"futureField":1}}},
                "api":{"tag":"api","listen":"127.0.0.1:8080","futureField":true}
            }"#,
        );
        assert!(stats_wiring_warnings(&sections).is_empty());
    }

    // routing_wiring_warnings (Roadmap §2.5:108)

    #[test]
    fn routing_no_section_no_warnings() {
        let sections = sections_from(r#"{}"#);
        assert!(routing_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn routing_no_balancers_no_warnings() {
        let sections = sections_from(
            r#"{"routing":{"rules":[{"outboundTag":"direct"}]}}"#,
        );
        assert!(routing_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn rule_with_both_outbound_and_balancer_tag_warns() {
        let sections = sections_from(
            r#"{
                "routing":{
                    "rules":[{"outboundTag":"direct","balancerTag":"lb"}],
                    "balancers":[{"tag":"lb","selector":["direct"]}]
                },
                "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        );
        let warnings = routing_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("outboundTag `direct`"));
        assert!(warnings[0].contains("balancerTag `lb`"));
    }

    #[test]
    fn rule_balancer_tag_unknown_warns() {
        let sections = sections_from(
            r#"{"routing":{"rules":[{"balancerTag":"missing"}],"balancers":[{"tag":"lb"}]}}"#,
        );
        let warnings = routing_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("balancerTag `missing`"));
        assert!(warnings[0].contains("does not match"));
    }

    #[test]
    fn rule_balancer_tag_known_no_warning() {
        let sections = sections_from(
            r#"{"routing":{"rules":[{"balancerTag":"lb"}],"balancers":[{"tag":"lb"}]}}"#,
        );
        assert!(routing_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn duplicate_balancer_tags_warn() {
        let sections = sections_from(
            r#"{
                "routing":{
                    "rules":[],
                    "balancers":[{"tag":"lb"},{"tag":"lb"}]
                }
            }"#,
        );
        let warnings = routing_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("duplicates"));
    }

    #[test]
    fn balancer_selector_matches_no_outbound_warns() {
        let sections = sections_from(
            r#"{
                "routing":{"rules":[],"balancers":[{"tag":"lb","selector":["warp"]}]},
                "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        );
        let warnings = routing_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("zero eligible outbounds"));
    }

    #[test]
    fn balancer_selector_prefix_match_no_warning() {
        let sections = sections_from(
            r#"{
                "routing":{"rules":[],"balancers":[{"tag":"lb","selector":["warp"]}]},
                "outbounds":[{"tag":"warp-primary","protocol":"wireguard"}]
            }"#,
        );
        assert!(routing_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn balancer_fallback_tag_unknown_warns() {
        let sections = sections_from(
            r#"{
                "routing":{
                    "rules":[],
                    "balancers":[{"tag":"lb","selector":["direct"],"fallbackTag":"missing"}]
                },
                "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        );
        let warnings = routing_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("fallbackTag `missing`"));
    }

    #[test]
    fn least_ping_without_observatory_warns() {
        let sections = sections_from(
            r#"{
                "routing":{
                    "rules":[],
                    "balancers":[{
                        "tag":"lb",
                        "selector":["direct"],
                        "strategy":{"type":"leastPing"}
                    }]
                },
                "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        );
        let warnings = routing_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("leastPing"));
        assert!(warnings[0].contains("non-functional"));
    }

    #[test]
    fn least_load_without_observatory_coverage_warns() {
        let sections = sections_from(
            r#"{
                "routing":{
                    "rules":[],
                    "balancers":[{
                        "tag":"lb",
                        "selector":["direct"],
                        "strategy":{"type":"leastLoad"}
                    }]
                },
                "outbounds":[{"tag":"direct","protocol":"freedom"}],
                "observatory":{"subjectSelector":["warp"]}
            }"#,
        );
        let warnings = routing_wiring_warnings(&sections);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("leastLoad"));
        assert!(warnings[0].contains("not covered"));
    }

    #[test]
    fn least_load_with_observatory_coverage_no_warning() {
        let sections = sections_from(
            r#"{
                "routing":{
                    "rules":[],
                    "balancers":[{
                        "tag":"lb",
                        "selector":["direct"],
                        "strategy":{"type":"leastLoad"}
                    }]
                },
                "outbounds":[{"tag":"direct","protocol":"freedom"}],
                "observatory":{"subjectSelector":["direct"]}
            }"#,
        );
        assert!(routing_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn least_load_covered_by_burst_observatory() {
        let sections = sections_from(
            r#"{
                "routing":{
                    "rules":[],
                    "balancers":[{
                        "tag":"lb",
                        "selector":["direct"],
                        "strategy":{"type":"leastLoad"}
                    }]
                },
                "outbounds":[{"tag":"direct","protocol":"freedom"}],
                "burstObservatory":{"subjectSelector":["direct"],"pingConfig":{"interval":"10s"}}
            }"#,
        );
        assert!(routing_wiring_warnings(&sections).is_empty());
    }

    #[test]
    fn random_strategy_does_not_require_observatory() {
        let sections = sections_from(
            r#"{
                "routing":{
                    "rules":[],
                    "balancers":[{
                        "tag":"lb",
                        "selector":["direct"],
                        "strategy":{"type":"random"}
                    }]
                },
                "outbounds":[{"tag":"direct","protocol":"freedom"}]
            }"#,
        );
        assert!(routing_wiring_warnings(&sections).is_empty());
    }
}
