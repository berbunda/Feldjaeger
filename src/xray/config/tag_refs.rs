//! Routing / balancer tag reference scans for Delete hard-blocks.

use serde_json::Value;

use super::sections::XrayConfigSections;

/// Human-readable routing/balancer references to an inbound tag.
pub fn inbound_tag_references(sections: &XrayConfigSections, inbound_tag: &str) -> Vec<String> {
    let tag = inbound_tag.trim();
    if tag.is_empty() {
        return Vec::new();
    }
    let mut refs = Vec::new();
    if let Some(routing) = sections.routing() {
        collect_inbound_tag_refs(routing.value(), tag, &mut refs);
    }
    refs
}

/// Human-readable routing/balancer references to an outbound tag.
pub fn outbound_tag_references(sections: &XrayConfigSections, outbound_tag: &str) -> Vec<String> {
    let tag = outbound_tag.trim();
    if tag.is_empty() {
        return Vec::new();
    }
    let mut refs = Vec::new();
    if let Some(routing) = sections.routing() {
        collect_outbound_tag_refs(routing.value(), tag, &mut refs);
    }
    refs
}

fn collect_inbound_tag_refs(routing: &Value, inbound_tag: &str, refs: &mut Vec<String>) {
    let Some(rules) = routing.get("rules").and_then(Value::as_array) else {
        return;
    };
    for (index, rule) in rules.iter().enumerate() {
        let Some(tags) = rule.get("inboundTag").and_then(Value::as_array) else {
            continue;
        };
        let hit = tags.iter().any(|v| {
            v.as_str()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case(inbound_tag))
        });
        if hit {
            refs.push(format!(
                "routing.rules[{index}] inboundTag (rule #{})",
                index + 1
            ));
        }
    }
}

fn collect_outbound_tag_refs(routing: &Value, outbound_tag: &str, refs: &mut Vec<String>) {
    if let Some(rules) = routing.get("rules").and_then(Value::as_array) {
        for (index, rule) in rules.iter().enumerate() {
            if rule
                .get("outboundTag")
                .and_then(Value::as_str)
                .is_some_and(|t| t.trim().eq_ignore_ascii_case(outbound_tag))
            {
                refs.push(format!(
                    "routing.rules[{index}] outboundTag (rule #{})",
                    index + 1
                ));
            }
        }
    }

    if let Some(balancers) = routing.get("balancers").and_then(Value::as_array) {
        for (index, balancer) in balancers.iter().enumerate() {
            let balancer_tag = balancer
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or("(untagged)");
            let Some(selectors) = balancer.get("selector").and_then(Value::as_array) else {
                continue;
            };
            for selector in selectors {
                let Some(prefix) = selector.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
                    continue;
                };
                // Xray balancer selector is a prefix match against outbound tags.
                if outbound_tag
                    .to_ascii_lowercase()
                    .starts_with(&prefix.to_ascii_lowercase())
                {
                    refs.push(format!(
                        "routing.balancers[{index}] selector `{prefix}` (balancer `{balancer_tag}`)"
                    ));
                }
            }
        }
    }
}

/// Formats a hard-block error detail for Status Bar / dialogs.
pub fn format_tag_reference_block(kind: &str, tag: &str, refs: &[String]) -> String {
    let listed = refs.join("; ");
    format!(
        "Cannot delete {kind} `{tag}`: still referenced in routing — {listed}. Remove those references first."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::config::parser::XrayConfigParser;
    use serde_json::json;

    fn sections_from(value: Value) -> XrayConfigSections {
        let json = serde_json::to_string(&value).unwrap();
        let parser = XrayConfigParser::new();
        let outcome = parser.parse_single_file("/etc/xray/config.json", &json);
        assert!(outcome.is_success(), "{:?}", outcome.errors());
        outcome.into_sections()
    }

    #[test]
    fn inbound_refs_from_rules() {
        let sections = sections_from(json!({
            "inbounds": [{"tag": "a", "protocol": "vmess"}],
            "routing": {
                "rules": [
                    {"inboundTag": ["a"], "outboundTag": "direct"},
                    {"inboundTag": ["other"], "outboundTag": "proxy"}
                ]
            }
        }));
        let refs = inbound_tag_references(&sections, "a");
        assert_eq!(refs.len(), 1);
        assert!(refs[0].contains("rules[0]"));
        assert!(inbound_tag_references(&sections, "missing").is_empty());
    }

    #[test]
    fn outbound_refs_from_rules_and_balancer_prefix() {
        let sections = sections_from(json!({
            "outbounds": [{"tag": "warp-out", "protocol": "freedom"}],
            "routing": {
                "rules": [{"outboundTag": "warp-out", "type": "field"}],
                "balancers": [{
                    "tag": "b1",
                    "selector": ["warp"]
                }]
            }
        }));
        let refs = outbound_tag_references(&sections, "warp-out");
        assert!(refs.iter().any(|r| r.contains("outboundTag")));
        assert!(refs.iter().any(|r| r.contains("selector `warp`")));
    }
}
