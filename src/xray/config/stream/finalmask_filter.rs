//! `finalmask.tcp[].settings` / `finalmask.udp[].settings` for `type = "filter"` (Roadmap §4.5,
//! audit v26.10.21 D) — source-IP filtering on the listening side, XTLS/Xray-core#7206
//! (v26.10.21): `infra/conf/transport_finalmask.go` (`Filter`) and
//! `transport/internet/finalmask/filter`.
//!
//! ```jsonc
//! { "blockedSourceIPs": ["10.0.0.0/8", "geoip:cn"], "allowedSourceIPs": ["!geoip:private"] }
//! ```
//!
//! Both lists are IP rules as in a routing rule's `ip`, parsed by `geodata.ParseIPRules`: an IP or
//! CIDR (prefix ≤ 32 / 128), `geoip:CODE`, `ext:FILE:CODE` / `ext-ip:FILE:CODE`, each optionally
//! negated by leading `!`. A blocked source is dropped; with `allowedSourceIPs` set, a source must
//! also match it. Empty lists = the layer does nothing. On TCP the filter wraps the listener
//! (`Listen`), before every per-connection mask, so its position in `tcp[]` does not matter; on
//! UDP it wraps the server packet conn in chain order. The client-side wrappers pass everything
//! through: in an outbound the layer has no effect (`xray run -test` accepts it, checked with
//! `xray.exe` 26.10.21).
//!
//! `Build()` checks each rule; whether a geo file and code exist is checked against the server's
//! files (`checkFile`), which only `xray run -test` there can do.

use serde_json::{Map, Value};

use super::finalmask_layers::{apply_extras, extras_of, string_array_field};

/// `finalmask.*[].settings` for `type = "filter"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterSettings {
    /// `blockedSourceIPs` — IP rules whose sources are dropped; empty = key absent.
    pub blocked_source_ips: Vec<String>,
    /// `allowedSourceIPs` — IP rules a source must match when set; empty = key absent.
    pub allowed_source_ips: Vec<String>,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

const KNOWN_FILTER_KEYS: &[&str] = &["blockedSourceIPs", "allowedSourceIPs"];

/// Parses `settings` as `filter`. Absent / `null` settings are an empty filter; `None` when
/// `settings` isn't an object or a list isn't an array of strings (the core refuses that too).
pub fn parse_filter_settings(settings: &Value) -> Option<FilterSettings> {
    let object = match settings {
        Value::Null => return Some(FilterSettings::default()),
        Value::Object(object) => object,
        _ => return None,
    };
    Some(FilterSettings {
        blocked_source_ips: string_array_field(object.get("blockedSourceIPs"))?,
        allowed_source_ips: string_array_field(object.get("allowedSourceIPs"))?,
        extras: extras_of(object, KNOWN_FILTER_KEYS),
    })
}

fn rules_to_value(rules: &[String]) -> Option<Value> {
    let rules: Vec<Value> = rules
        .iter()
        .map(|rule| rule.trim())
        .filter(|rule| !rule.is_empty())
        .map(|rule| Value::String(rule.to_owned()))
        .collect();
    (!rules.is_empty()).then_some(Value::Array(rules))
}

/// Builds the `settings` `Value` for a `filter` layer.
pub fn filter_settings_to_value(draft: &FilterSettings) -> Value {
    let mut object = Map::new();
    for (key, rules) in [("blockedSourceIPs", &draft.blocked_source_ips), ("allowedSourceIPs", &draft.allowed_source_ips)] {
        if let Some(value) = rules_to_value(rules) {
            object.insert(key.to_owned(), value);
        }
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

/// Validates a `filter` layer like `Filter.Build()`: every non-blank rule of both lists
/// ([`validate_filter_ip_rule`]).
pub fn validate_filter_settings(draft: &FilterSettings) -> Result<(), String> {
    for (key, rules) in [("blockedSourceIPs", &draft.blocked_source_ips), ("allowedSourceIPs", &draft.allowed_source_ips)] {
        for (index, rule) in rules.iter().map(|rule| rule.trim()).filter(|rule| !rule.is_empty()).enumerate() {
            validate_filter_ip_rule(rule).map_err(|error| format!("{key}[{index}]: {error}"))?;
        }
    }
    Ok(())
}

/// One IP rule as `geodata.ParseIPRules` reads it: leading `!` toggle negation; `geoip:CODE` and
/// `ext:FILE:CODE` / `ext-ip:FILE:CODE` need a file and a code (which may be negated again);
/// anything else is an IP address (IPv6 optionally in brackets) with an optional `/prefix` of at
/// most 32 / 128 — a domain name is refused ("unsupported address family").
pub fn validate_filter_ip_rule(rule: &str) -> Result<(), String> {
    let bare = rule.trim_start_matches('!');
    if let Some(code) = bare.strip_prefix("geoip:") {
        return match code.trim_start_matches('!') {
            "" => Err(format!("\"{rule}\": empty geoip code")),
            _ => Ok(()),
        };
    }
    if let Some(rest) = ["ext:", "ext-ip:"].iter().find_map(|prefix| bare.strip_prefix(prefix)) {
        let Some((file, code)) = rest.split_once(':') else {
            return Err(format!("\"{rule}\": expected ext:FILE:CODE"));
        };
        if file.is_empty() {
            return Err(format!("\"{rule}\": empty file"));
        }
        if code.trim_start_matches('!').is_empty() {
            return Err(format!("\"{rule}\": empty code"));
        }
        return Ok(());
    }
    let (ip, prefix) = match bare.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (bare, None),
    };
    let ip = ip.strip_prefix('[').and_then(|ip| ip.strip_suffix(']')).unwrap_or(ip);
    let max = match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => 32,
        Ok(std::net::IpAddr::V6(_)) => 128,
        Err(_) => {
            return Err(format!(
                "\"{rule}\": expected an IP address or CIDR, geoip:CODE or ext:FILE:CODE (a domain name is not accepted)"
            ));
        }
    };
    if let Some(prefix) = prefix {
        match prefix.parse::<u32>() {
            Ok(bits) if bits <= max => {}
            Ok(bits) => return Err(format!("\"{rule}\": CIDR prefix length {bits} exceeds max {max}")),
            Err(_) => return Err(format!("\"{rule}\": invalid CIDR prefix length \"{prefix}\"")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rules_follow_parse_ip_rules() {
        for good in [
            "10.0.0.0/8",
            "1.2.3.4",
            "::1/128",
            "[2606:4700::1111]",
            "!10.0.0.0/8",
            "geoip:private",
            "!geoip:!cn",
            "ext:geoip.dat:ru",
            "ext-ip:custom.dat:list",
        ] {
            assert_eq!(validate_filter_ip_rule(good), Ok(()), "{good}");
        }
        for (bad, needle) in [
            ("10.0.0.0/33", "exceeds max 32"),
            ("::/129", "exceeds max 128"),
            ("10.0.0.0/x", "invalid CIDR prefix"),
            ("example.com", "domain name is not accepted"),
            ("geoip:", "empty geoip code"),
            ("ext:geoip.dat", "expected ext:FILE:CODE"),
            ("ext::cn", "empty file"),
            ("ext-ip:geoip.dat:!", "empty code"),
        ] {
            let error = validate_filter_ip_rule(bad).expect_err(bad);
            assert!(error.contains(needle), "{bad}: {error}");
        }
    }

    #[test]
    fn settings_round_trip_and_validate() {
        let settings = json!({"blockedSourceIPs": ["10.0.0.0/8", "geoip:cn"], "allowedSourceIPs": ["127.0.0.1"], "future": 1});
        let draft = parse_filter_settings(&settings).expect("typed");
        assert_eq!(filter_settings_to_value(&draft), settings);
        assert_eq!(validate_filter_settings(&draft), Ok(()));
        assert_eq!(parse_filter_settings(&Value::Null), Some(FilterSettings::default()));
        assert_eq!(filter_settings_to_value(&FilterSettings::default()), json!({}));
        assert!(parse_filter_settings(&json!({"blockedSourceIPs": "10.0.0.0/8"})).is_none());
        let bad = FilterSettings { allowed_source_ips: vec![String::new(), "10.0.0.0/33".to_owned()], ..FilterSettings::default() };
        assert_eq!(
            validate_filter_settings(&bad).unwrap_err(),
            "allowedSourceIPs[0]: \"10.0.0.0/33\": CIDR prefix length 33 exceeds max 32"
        );
    }
}
