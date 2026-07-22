//! Unit tests for the lossless Xray configuration model.

use super::*;
use crate::xray::config::errors::ConfigErrorKind;
use serde_json::json;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("xray")
        .join(name)
}

fn read_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture(name))
        .unwrap_or_else(|error| panic!("failed to read fixture {name}: {error}"))
}

#[test]
fn parse_single_config() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_single_file(
        "/usr/local/etc/xray/config.json",
        &read_fixture("minimal.json"),
    );

    assert!(outcome.is_success());
    let sections = outcome.sections();
    assert!(sections.log().is_some());
    assert_eq!(sections.inbounds().len(), 1);
    assert_eq!(sections.outbounds().len(), 1);
    assert_eq!(
        sections.log().unwrap().source_file(),
        "/usr/local/etc/xray/config.json"
    );
}

#[test]
fn parse_config_directory() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_directory([
        ("/etc/xray/01_log.json", r#"{"log":{"loglevel":"warning"}}"#),
        (
            "/etc/xray/03-inbounds.json",
            r#"{"inbounds":[{"tag":"in-a","protocol":"vless","port":443}]}"#,
        ),
        (
            "/etc/xray/routing.json",
            r#"{"routing":{"domainStrategy":"AsIs","rules":[]}}"#,
        ),
    ]);

    assert!(outcome.is_success());
    let sections = outcome.sections();
    assert_eq!(
        sections.log().unwrap().source_file(),
        "/etc/xray/01_log.json"
    );
    assert_eq!(
        sections.routing().unwrap().source_file(),
        "/etc/xray/routing.json"
    );
    assert_eq!(sections.inbounds().len(), 1);
    assert_eq!(
        sections.inbounds()[0].source_file(),
        "/etc/xray/03-inbounds.json"
    );
}

#[test]
fn preserves_unknown_top_level_section() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(&read_fixture("with_unknown_sections.json"));

    assert!(outcome.is_success());
    let sections = outcome.sections();
    assert!(sections.extra_section("customExperimentalModule").is_some());
    assert!(sections.extra_section("legacyFeatureFlag").is_some());
    assert_eq!(sections.extra_sections().len(), 2);

    // Kind is available for classification without failing the parse.
    let classified = ConfigError::new(
        ConfigErrorKind::UnknownSection,
        "unknown top-level section `customExperimentalModule` preserved",
    )
    .with_section("customExperimentalModule");
    assert_eq!(classified.kind(), ConfigErrorKind::UnknownSection);
}

#[test]
fn unknown_inbound_protocol_is_accepted() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "inbounds":[{"tag":"x","protocol":"future_protocol","port":1}],
            "outbounds":[{"protocol":"freedom","tag":"direct"}]
        }"#,
    );

    assert!(outcome.is_success());
    let summaries = outcome.sections().inbound_summaries();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].protocol.as_deref(), Some("future_protocol"));
    assert_eq!(
        outcome.sections().inbounds()[0]
            .value()
            .get("protocol")
            .and_then(|v| v.as_str()),
        Some("future_protocol")
    );
}

#[test]
fn unknown_outbound_protocol_is_accepted() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "inbounds":[],
            "outbounds":[{"tag":"x","protocol":"future_protocol"}]
        }"#,
    );

    assert!(outcome.is_success());
    let summaries = outcome.sections().outbound_summaries();
    assert_eq!(summaries[0].protocol.as_deref(), Some("future_protocol"));
}

#[test]
fn empty_config_object() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str("{}");

    assert!(outcome.is_success());
    assert!(outcome.sections().is_empty());
    assert!(outcome.sections().inbound_summaries().is_empty());
    assert!(outcome.sections().outbound_summaries().is_empty());
}

#[test]
fn missing_optional_sections() {
    let parser = XrayConfigParser::new();
    let outcome = parser
        .parse_str(r#"{"inbounds":[{"protocol":"dokodemo-door","port":1000}],"outbounds":[]}"#);

    assert!(outcome.is_success());
    let sections = outcome.sections();
    assert!(sections.log().is_none());
    assert!(sections.api().is_none());
    assert!(sections.dns().is_none());
    assert!(sections.routing().is_none());
    assert!(sections.policy().is_none());
    assert!(sections.stats().is_none());
    assert!(sections.reverse().is_none());
    assert!(sections.observatory().is_none());
    assert!(sections.burst_observatory().is_none());
    assert!(sections.metrics().is_none());
    assert_eq!(sections.inbounds().len(), 1);
}

#[test]
fn two_inbounds_summaries() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "inbounds":[
                {
                    "tag":"a",
                    "protocol":"vless",
                    "listen":"0.0.0.0",
                    "port":443,
                    "settings":{"clients":[{"id":"1"},{"id":"2"}]}
                },
                {
                    "tag":"b",
                    "protocol":"vmess",
                    "port":8443
                }
            ]
        }"#,
    );

    let summaries = outcome.sections().inbound_summaries();
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].index, 0);
    assert_eq!(summaries[0].tag.as_deref(), Some("a"));
    assert_eq!(summaries[0].protocol.as_deref(), Some("vless"));
    assert_eq!(summaries[0].listen.as_deref(), Some("0.0.0.0"));
    assert_eq!(summaries[0].port, Some(443));
    assert_eq!(summaries[0].clients_count, Some(2));
    assert_eq!(summaries[1].index, 1);
    assert_eq!(summaries[1].tag.as_deref(), Some("b"));
    assert_eq!(summaries[1].clients_count, None);
}

#[test]
fn three_outbounds_summaries() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "outbounds":[
                {"tag":"direct","protocol":"freedom"},
                {"tag":"block","protocol":"blackhole"},
                {"tag":"proxy","protocol":"vless"}
            ]
        }"#,
    );

    let summaries = outcome.sections().outbound_summaries();
    assert_eq!(summaries.len(), 3);
    assert_eq!(summaries[0].tag.as_deref(), Some("direct"));
    assert_eq!(summaries[0].description, "Direct connection");
    assert_eq!(summaries[1].tag.as_deref(), Some("block"));
    assert_eq!(summaries[1].description, "Response: none");
    assert_eq!(summaries[2].tag.as_deref(), Some("proxy"));
    assert_eq!(summaries[2].protocol.as_deref(), Some("vless"));
    assert_eq!(summaries[2].description, "Summary unavailable");
}

#[test]
fn outbound_summary_protocol_descriptions_and_send_through() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "outbounds":[
                {
                    "tag":"direct",
                    "protocol":"freedom",
                    "sendThrough":"10.0.0.1"
                },
                {
                    "tag":"block",
                    "protocol":"blackhole",
                    "settings":{"response":{"type":"http"}}
                },
                {
                    "tag":"warp",
                    "protocol":"wireguard",
                    "settings":{"peers":[{"publicKey":"x"},{"publicKey":"y"}]}
                },
                {
                    "tag":"socks-out",
                    "protocol":"socks",
                    "settings":{"servers":[{"address":"127.0.0.1","port":1080}]}
                },
                {
                    "tag":"x",
                    "protocol":"future_protocol"
                }
            ]
        }"#,
    );

    let summaries = outcome.sections().outbound_summaries();
    assert_eq!(summaries[0].send_through.as_deref(), Some("10.0.0.1"));
    assert_eq!(summaries[0].description, "Direct connection");
    assert_eq!(summaries[1].description, "Response: http");
    assert_eq!(summaries[2].description, "Peers: 2");
    assert_eq!(summaries[3].description, "Proxy server configured");
    assert_eq!(summaries[4].description, "Summary unavailable");
    assert!(summaries[4].send_through.is_none());
}

#[test]
fn outbound_missing_tag_is_accepted() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(r#"{"outbounds":[{"protocol":"freedom"}]}"#);
    let summaries = outcome.sections().outbound_summaries();
    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].tag.is_none());
    assert_eq!(summaries[0].description, "Direct connection");
}

#[test]
fn preserves_inbound_and_outbound_order() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_directory([
        (
            "/etc/xray/10_outbounds.json",
            r#"{"outbounds":[{"tag":"first","protocol":"freedom"},{"tag":"second","protocol":"blackhole"}]}"#,
        ),
        (
            "/etc/xray/05_inbounds.json",
            r#"{"inbounds":[{"tag":"one","protocol":"vless"},{"tag":"two","protocol":"vmess"}]}"#,
        ),
        (
            "/etc/xray/20_more_outbounds.json",
            r#"{"outbounds":[{"tag":"third","protocol":"vless"}]}"#,
        ),
    ]);

    let sections = outcome.sections();
    // Directory files are sorted by path: 05, 10, 20.
    let inbound_tags: Vec<_> = sections
        .inbounds()
        .iter()
        .map(|item| item.value().get("tag").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(inbound_tags, vec![Some("one"), Some("two")]);

    let outbound_tags: Vec<_> = sections
        .outbounds()
        .iter()
        .map(|item| item.value().get("tag").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(
        outbound_tags,
        vec![Some("first"), Some("second"), Some("third")]
    );
}

#[test]
fn source_file_is_tracked_per_section() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_directory([
        ("/cfg/routing.json", r#"{"routing":{"rules":[]}}"#),
        (
            "/cfg/03-inbounds.json",
            r#"{"inbounds":[{"tag":"in","protocol":"vless"}]}"#,
        ),
        ("/cfg/dns.json", r#"{"dns":{"servers":["1.1.1.1"]}}"#),
    ]);

    let sections = outcome.sections();
    assert_eq!(
        sections.routing().unwrap().source_file(),
        "/cfg/routing.json"
    );
    assert_eq!(sections.dns().unwrap().source_file(), "/cfg/dns.json");
    assert_eq!(
        sections.inbounds()[0].source_file(),
        "/cfg/03-inbounds.json"
    );
}

#[test]
fn corrupted_dns_keeps_other_sections() {
    let parser = XrayConfigParser::new();
    // Directory: routing valid, dns file invalid JSON.
    let outcome = parser.parse_directory([
        (
            "/cfg/routing.json",
            r#"{"routing":{"domainStrategy":"AsIs"}}"#,
        ),
        ("/cfg/dns.json", r#"{not-valid-json"#),
        (
            "/cfg/inbounds.json",
            r#"{"inbounds":[{"protocol":"vless","port":1}]}"#,
        ),
    ]);

    assert!(outcome.is_partial());
    assert!(!outcome.has_fatal_errors());
    assert!(
        outcome
            .errors()
            .iter()
            .any(|error| error.kind() == ConfigErrorKind::InvalidJson
                && error.source_file() == Some("/cfg/dns.json"))
    );
    assert!(outcome.sections().routing().is_some());
    assert!(outcome.sections().dns().is_none());
    assert_eq!(outcome.sections().inbounds().len(), 1);
}

#[test]
fn corrupted_routing_primitive_is_flagged_but_preserved() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "routing": "broken",
            "dns": {"servers": ["8.8.8.8"]},
            "inbounds": []
        }"#,
    );

    assert!(outcome.is_partial());
    assert!(outcome.errors().iter().any(|error| error.kind()
        == ConfigErrorKind::UnsupportedStructure
        && error.section() == Some("routing")));
    assert_eq!(
        outcome.sections().routing().unwrap().value(),
        &json!("broken")
    );
    assert!(outcome.sections().dns().is_some());
}

#[test]
fn invalid_json_returns_error_without_panic() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_single_file("config.json", &read_fixture("invalid.json"));

    assert!(!outcome.is_success());
    assert!(!outcome.is_partial());
    assert!(outcome.has_fatal_errors());
    assert!(outcome.sections().is_empty());
    assert_eq!(outcome.errors()[0].kind(), ConfigErrorKind::InvalidJson);
}

#[test]
fn duplicate_inbound_tag() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "inbounds":[
                {"tag":"same","protocol":"vless"},
                {"tag":"same","protocol":"vmess"}
            ]
        }"#,
    );

    assert!(outcome.is_partial());
    assert_eq!(outcome.sections().inbounds().len(), 2);
    assert!(
        outcome
            .errors()
            .iter()
            .any(|error| error.kind() == ConfigErrorKind::DuplicateTags
                && error.message().contains("inbound"))
    );
}

#[test]
fn duplicate_outbound_tag() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "outbounds":[
                {"tag":"dup","protocol":"freedom"},
                {"tag":"dup","protocol":"blackhole"}
            ]
        }"#,
    );

    assert!(outcome.is_partial());
    assert_eq!(outcome.sections().outbounds().len(), 2);
    assert!(
        outcome
            .errors()
            .iter()
            .any(|error| error.kind() == ConfigErrorKind::DuplicateTags
                && error.message().contains("outbound"))
    );
}

#[test]
fn rejects_non_object_root() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str("[]");

    assert!(outcome.has_fatal_errors() || !outcome.is_success());
    assert!(outcome.sections().is_empty());
    assert!(
        outcome
            .errors()
            .iter()
            .any(|error| error.kind() == ConfigErrorKind::UnsupportedStructure)
    );
}

#[test]
fn full_sample_preserves_nested_unknown_fields() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_path(&fixture("full_sample.json"));

    assert!(outcome.is_success());
    let sections = outcome.sections();
    let first = &sections.inbounds()[0];
    assert_eq!(
        first.value().pointer("/settings/unknownClientField"),
        Some(&json!("preserved"))
    );
    assert!(
        sections
            .extra_section("unsupportedTopLevelSection")
            .is_some()
    );
    assert!(sections.burst_observatory().is_some());
}

#[test]
fn transport_lands_in_extra_sections_while_fakedns_is_known() {
    let parser = XrayConfigParser::new();
    let outcome = parser
        .parse_str(r#"{"transport":{"tcpSettings":{}},"fakedns":[{"ipPool":"198.18.0.0/16"}]}"#);

    assert!(outcome.is_success());
    assert!(outcome.sections().extra_section("transport").is_some());
    assert!(outcome.sections().fakedns().is_some());
    assert!(outcome.sections().extra_section("fakedns").is_none());
}

#[test]
fn fakedns_summary_missing_section() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str("{}");
    assert!(outcome.sections().fakedns_summary().is_none());
}

#[test]
fn fakedns_summary_default_ipv4_object() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_single_file(
        "config.json",
        r#"{"fakedns":{"ipPool":"198.18.0.0/15","poolSize":65535}}"#,
    );
    let summary = outcome
        .sections()
        .fakedns_summary()
        .expect("FakeDNS summary");
    assert_eq!(summary.pools.len(), 1);
    assert_eq!(summary.pools[0].ip_pool.as_deref(), Some("198.18.0.0/15"));
    assert_eq!(summary.pools[0].pool_size, Some(65535));
    assert_eq!(summary.pools[0].address_family, FakeDnsAddressFamily::Ipv4);
    assert_eq!(summary.source_file, "config.json");
    assert!(summary.warnings.is_empty());
}

#[test]
fn fakedns_summary_custom_ipv4_and_ipv6_array() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "fakedns": [
                {"ipPool":"198.18.0.0/16","poolSize":1024},
                {"ipPool":"fc00::/18","poolSize":65535}
            ]
        }"#,
    );
    let summary = outcome
        .sections()
        .fakedns_summary()
        .expect("FakeDNS summary");
    assert_eq!(summary.pools.len(), 2);
    assert_eq!(summary.pools[0].ip_pool.as_deref(), Some("198.18.0.0/16"));
    assert_eq!(summary.pools[0].pool_size, Some(1024));
    assert_eq!(summary.pools[0].address_family, FakeDnsAddressFamily::Ipv4);
    assert_eq!(summary.pools[1].ip_pool.as_deref(), Some("fc00::/18"));
    assert_eq!(summary.pools[1].address_family, FakeDnsAddressFamily::Ipv6);
}

#[test]
fn fakedns_summary_missing_fields_and_invalid_cidr() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(r#"{"fakedns":{"ipPool":"not-a-cidr","futureFlag":true}}"#);
    let summary = outcome
        .sections()
        .fakedns_summary()
        .expect("FakeDNS summary");
    assert!(summary.pools[0].ip_pool.is_some());
    assert!(summary.pools[0].pool_size.is_none());
    assert_eq!(
        summary.pools[0].address_family,
        FakeDnsAddressFamily::Unknown
    );
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("`poolSize` is missing"))
    );
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("unknown field `futureFlag`"))
    );
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("unsupported address") || warning.contains("CIDR"))
    );
    // Unknown nested field remains in the lossless model.
    assert!(
        outcome
            .sections()
            .fakedns()
            .expect("section")
            .value()
            .get("futureFlag")
            .is_some()
    );
}

#[test]
fn fakedns_summary_uses_owner_in_config_directory() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_directory([(
        "/cfg/05-fakedns.json",
        r#"{"fakedns":{"ipPool":"198.18.0.0/15","poolSize":65535}}"#,
    )]);
    let summary = outcome
        .sections()
        .fakedns_summary()
        .expect("directory FakeDNS");
    assert_eq!(summary.source_file, "/cfg/05-fakedns.json");
}

#[test]
fn observatory_summary_missing_section() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str("{}");
    assert!(outcome.sections().observatory_summary().is_none());
}

#[test]
fn observatory_summary_empty_section() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(r#"{"observatory":{}}"#);
    let summary = outcome
        .sections()
        .observatory_summary()
        .expect("empty Observatory");
    assert!(summary.probe_url.is_none());
    assert!(summary.probe_interval.is_none());
    assert!(summary.subject_selectors.is_empty());
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("`probeUrl` is missing"))
    );
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("`probeInterval` is missing"))
    );
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("`subjectSelector` is missing"))
    );
}

#[test]
fn observatory_summary_one_and_multiple_selectors() {
    let parser = XrayConfigParser::new();
    let one = parser.parse_str(
        r#"{
            "observatory": {
                "probeUrl": "https://www.google.com/generate_204",
                "probeInterval": "10s",
                "subjectSelector": ["proxy"]
            }
        }"#,
    );
    let one_summary = one.sections().observatory_summary().expect("one selector");
    assert_eq!(one_summary.subject_selectors, ["proxy"]);
    assert!(one_summary.warnings.is_empty());

    let many = parser.parse_str(
        r#"{
            "observatory": {
                "probeUrl": "https://www.google.com/generate_204",
                "probeInterval": "10s",
                "subjectSelector": ["proxy", "warp", "vpn"]
            }
        }"#,
    );
    let many_summary = many
        .sections()
        .observatory_summary()
        .expect("many selectors");
    assert_eq!(many_summary.subject_selectors, ["proxy", "warp", "vpn"]);
}

#[test]
fn observatory_summary_empty_selectors_and_malformed_entries() {
    let parser = XrayConfigParser::new();
    let empty = parser.parse_str(
        r#"{
            "observatory": {
                "probeUrl": "https://example.com",
                "probeInterval": "5s",
                "subjectSelector": []
            }
        }"#,
    );
    let empty_summary = empty
        .sections()
        .observatory_summary()
        .expect("empty selectors");
    assert!(empty_summary.subject_selectors.is_empty());
    assert!(
        empty_summary
            .warnings
            .iter()
            .any(|warning| warning.contains("`subjectSelector` is empty"))
    );

    let malformed = parser.parse_str(
        r#"{
            "observatory": {
                "probeUrl": "https://example.com",
                "probeInterval": "5s",
                "subjectSelector": ["proxy", 12, "warp"]
            }
        }"#,
    );
    let malformed_summary = malformed
        .sections()
        .observatory_summary()
        .expect("malformed selectors");
    assert_eq!(malformed_summary.subject_selectors, ["proxy", "warp"]);
    assert!(
        malformed_summary
            .warnings
            .iter()
            .any(|warning| warning.contains("entry #2") && warning.contains("skipped"))
    );
}

#[test]
fn observatory_summary_preserves_unknown_fields() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "observatory": {
                "probeUrl": "https://example.com",
                "probeInterval": "10s",
                "subjectSelector": ["proxy"],
                "enableConcurrency": true
            }
        }"#,
    );
    let summary = outcome
        .sections()
        .observatory_summary()
        .expect("Observatory");
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("unknown field `enableConcurrency`"))
    );
    assert_eq!(
        outcome
            .sections()
            .observatory()
            .expect("section")
            .value()
            .get("enableConcurrency"),
        Some(&json!(true))
    );
}

#[test]
fn observatory_summary_uses_owner_in_config_directory() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_directory([(
        "/cfg/07-observatory.json",
        r#"{
            "observatory": {
                "probeUrl": "https://example.com",
                "probeInterval": "10s",
                "subjectSelector": ["proxy"]
            }
        }"#,
    )]);
    let summary = outcome
        .sections()
        .observatory_summary()
        .expect("directory Observatory");
    assert_eq!(summary.source_file, "/cfg/07-observatory.json");
}

#[test]
fn burst_observatory_summary_missing_and_empty_section() {
    let parser = XrayConfigParser::new();
    assert!(
        parser
            .parse_str("{}")
            .sections()
            .burst_observatory_summary()
            .is_none()
    );

    let outcome = parser.parse_str(r#"{"burstObservatory":{}}"#);
    let summary = outcome
        .sections()
        .burst_observatory_summary()
        .expect("empty BurstObservatory");
    assert!(summary.subject_selectors.is_empty());
    assert!(summary.ping_config.is_none());
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("`subjectSelector` is missing"))
    );
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("`pingConfig` is missing"))
    );
}

#[test]
fn burst_observatory_summary_extracts_supported_fields() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "burstObservatory": {
                "subjectSelector": ["proxy", "warp", "hk", "jp"],
                "pingConfig": {
                    "destination": "https://www.google.com/generate_204",
                    "connectivity": "https://connectivitycheck.gstatic.com/generate_204",
                    "interval": "30s",
                    "timeout": "5s",
                    "sampling": 10,
                    "httpMethod": "HEAD"
                }
            }
        }"#,
    );
    let summary = outcome
        .sections()
        .burst_observatory_summary()
        .expect("BurstObservatory");
    assert_eq!(summary.subject_selectors, ["proxy", "warp", "hk", "jp"]);
    let ping = summary.ping_config.expect("ping config");
    assert_eq!(
        ping.destination.as_deref(),
        Some("https://www.google.com/generate_204")
    );
    assert_eq!(ping.interval.as_deref(), Some("30s"));
    assert_eq!(ping.timeout.as_deref(), Some("5s"));
    assert_eq!(ping.sampling, Some(10));
    assert_eq!(ping.http_method.as_deref(), Some("HEAD"));
    assert!(ping.summary.contains("30s"));
    assert!(summary.warnings.is_empty());
}

#[test]
fn burst_observatory_summary_supports_one_selector_and_defaulted_ping_config() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "burstObservatory": {
                "subjectSelector": ["proxy"],
                "pingConfig": {}
            }
        }"#,
    );
    let summary = outcome
        .sections()
        .burst_observatory_summary()
        .expect("BurstObservatory");
    assert_eq!(summary.subject_selectors, ["proxy"]);
    let ping = summary.ping_config.expect("defaulted ping config");
    assert!(ping.destination.is_none());
    assert!(ping.connectivity.is_none());
    assert!(ping.interval.is_none());
    assert!(ping.timeout.is_none());
    assert!(ping.sampling.is_none());
    assert!(ping.http_method.is_none());
    assert!(summary.warnings.is_empty());
}

#[test]
fn burst_observatory_summary_tolerates_malformed_and_missing_optional_fields() {
    let parser = XrayConfigParser::new();
    let malformed = parser.parse_str(
        r#"{
            "burstObservatory": {
                "subjectSelector": ["proxy", 4, "warp"],
                "pingConfig": {
                    "destination": 42,
                    "sampling": -1
                }
            }
        }"#,
    );
    let summary = malformed
        .sections()
        .burst_observatory_summary()
        .expect("malformed BurstObservatory");
    assert_eq!(summary.subject_selectors, ["proxy", "warp"]);
    let ping = summary.ping_config.expect("partially usable ping config");
    assert!(ping.destination.is_none());
    assert!(ping.interval.is_none());
    assert!(ping.timeout.is_none());
    assert!(ping.sampling.is_none());
    assert!(summary.warnings.len() >= 3);

    let invalid_ping =
        parser.parse_str(r#"{"burstObservatory":{"subjectSelector":["proxy"],"pingConfig":[]}}"#);
    let invalid_summary = invalid_ping
        .sections()
        .burst_observatory_summary()
        .expect("section remains available");
    assert!(invalid_summary.ping_config.is_none());
    assert!(
        invalid_summary
            .warnings
            .iter()
            .any(|warning| warning.contains("unsupported type"))
    );
}

#[test]
fn burst_observatory_unknown_fields_are_warned_and_preserved() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "burstObservatory": {
                "subjectSelector": ["proxy"],
                "futureSectionField": true,
                "pingConfig": {
                    "destination": "https://example.com/generate_204",
                    "futurePingField": {"enabled": true}
                }
            }
        }"#,
    );
    let summary = outcome
        .sections()
        .burst_observatory_summary()
        .expect("BurstObservatory");
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("futureSectionField"))
    );
    assert!(
        summary
            .warnings
            .iter()
            .any(|warning| warning.contains("futurePingField"))
    );
    let raw = outcome
        .sections()
        .burst_observatory()
        .expect("raw section")
        .value();
    assert_eq!(raw.get("futureSectionField"), Some(&json!(true)));
    assert_eq!(
        raw.get("pingConfig")
            .and_then(|ping| ping.get("futurePingField")),
        Some(&json!({"enabled": true}))
    );
}

#[test]
fn burst_observatory_summary_uses_config_directory_owner() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_directory([(
        "/cfg/08-burst-observatory.json",
        r#"{
            "burstObservatory": {
                "subjectSelector": ["proxy"],
                "pingConfig": {"destination": "https://example.com/generate_204"}
            }
        }"#,
    )]);
    let summary = outcome
        .sections()
        .burst_observatory_summary()
        .expect("directory BurstObservatory");
    assert_eq!(summary.source_file, "/cfg/08-burst-observatory.json");
}

#[test]
fn known_section_names_match_model() {
    assert!(XrayConfigSections::is_known_section("inbounds"));
    assert!(XrayConfigSections::is_known_section("burstObservatory"));
    assert!(!XrayConfigSections::is_known_section("futureSection"));
    assert!(KNOWN_SECTION_NAMES.contains(&"metrics"));
}

#[test]
fn dns_summary_distinguishes_missing_and_empty_section() {
    let parser = XrayConfigParser::new();
    let missing = parser.parse_single_file("config.json", "{}");
    assert!(missing.sections().dns_summary().is_none());

    let empty = parser.parse_single_file("config.json", r#"{"dns":{}}"#);
    let summary = empty.sections().dns_summary().expect("empty DNS summary");
    assert!(summary.query_strategy.is_none());
    assert!(summary.disable_cache.is_none());
    assert!(summary.disable_fallback.is_none());
    assert!(summary.disable_fallback_if_match.is_none());
    assert!(summary.tag.is_none());
    assert!(summary.servers.is_empty());
    assert!(summary.hosts.is_empty());
    assert_eq!(summary.source_file, "config.json");
}

#[test]
fn policy_summary_from_full_sample_and_confdir_owner() {
    let parser = XrayConfigParser::new();
    let sample = parser.parse_path(&fixture("full_sample.json"));
    assert!(sample.is_success());
    let summary = sample.sections().policy_summary().expect("policy summary");
    assert_eq!(summary.user_policy_count, Some(1));
    assert_eq!(summary.user_levels[0].level, "0");
    assert_eq!(summary.user_levels[0].handshake, Some(4));
    assert_eq!(summary.user_levels[0].conn_idle, Some(300));
    assert!(summary.system_policy.is_none());

    let directory = parser.parse_directory([(
        "/cfg/03-policy.json",
        r#"{"policy":{"levels":{"1":{"handshake":8}},"system":{"statsInboundUplink":true}}}"#,
    )]);
    let owned = directory
        .sections()
        .policy_summary()
        .expect("directory policy");
    assert_eq!(owned.source_file, "/cfg/03-policy.json");
    assert_eq!(owned.user_levels[0].level, "1");
    assert_eq!(
        owned
            .system_policy
            .as_ref()
            .and_then(|system| system.stats_inbound_uplink),
        Some(true)
    );
}

#[test]
fn dns_summary_supports_server_address_variants() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "dns": {
                "servers": [
                    "8.8.8.8",
                    "https://1.1.1.1/dns-query",
                    "localhost",
                    "fakedns",
                    "future+dns://resolver.example"
                ]
            }
        }"#,
    );
    let summary = outcome.sections().dns_summary().expect("DNS summary");
    let addresses: Vec<_> = summary
        .servers
        .iter()
        .map(|server| server.address.as_deref())
        .collect();
    assert_eq!(
        addresses,
        vec![
            Some("8.8.8.8"),
            Some("https://1.1.1.1/dns-query"),
            Some("localhost"),
            Some("fakedns"),
            Some("future+dns://resolver.example"),
        ]
    );
    assert!(summary.servers[0].domains.is_empty());
    assert!(summary.servers[0].skip_fallback.is_none());
}

#[test]
fn dns_summary_extracts_general_and_object_server_fields() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "dns": {
                "queryStrategy": "UseIPv4",
                "disableCache": true,
                "disableFallback": false,
                "disableFallbackIfMatch": true,
                "tag": "dns-internal",
                "servers": [{
                    "address": "1.2.3.4",
                    "domains": ["domain:xray.com", "geosite:openai"],
                    "expectedIPs": ["geoip:cn"],
                    "skipFallback": true,
                    "clientIP": "192.0.2.10",
                    "futureServerField": {"preserved": true}
                }],
                "futureDnsField": [1, 2, 3]
            }
        }"#,
    );
    assert!(outcome.is_success());
    let summary = outcome.sections().dns_summary().expect("DNS summary");
    assert_eq!(summary.query_strategy.as_deref(), Some("UseIPv4"));
    assert_eq!(summary.disable_cache, Some(true));
    assert_eq!(summary.disable_fallback, Some(false));
    assert_eq!(summary.disable_fallback_if_match, Some(true));
    assert_eq!(summary.tag.as_deref(), Some("dns-internal"));
    assert_eq!(summary.servers.len(), 1);
    assert_eq!(summary.servers[0].domains.len(), 2);
    assert_eq!(summary.servers[0].expected_ips, ["geoip:cn"]);
    assert_eq!(summary.servers[0].skip_fallback, Some(true));
    assert_eq!(summary.servers[0].client_ip.as_deref(), Some("192.0.2.10"));
    assert_eq!(
        outcome
            .sections()
            .dns()
            .expect("raw DNS")
            .value()
            .pointer("/servers/0/futureServerField/preserved"),
        Some(&json!(true))
    );
    assert!(
        outcome
            .sections()
            .dns()
            .expect("raw DNS")
            .value()
            .get("futureDnsField")
            .is_some()
    );
}

#[test]
fn dns_summary_supports_ipv4_ipv6_and_domain_alias_hosts() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_str(
        r#"{
            "dns": {
                "hosts": {
                    "ipv4.example": "192.0.2.1",
                    "ipv6.example": "2001:db8::1",
                    "alias.example": "target.example",
                    "many.example": ["198.51.100.1", "2001:db8::2"]
                }
            }
        }"#,
    );
    let summary = outcome.sections().dns_summary().expect("DNS summary");
    assert_eq!(summary.hosts.len(), 5);
    assert!(
        summary
            .hosts
            .iter()
            .any(|host| { host.domain == "ipv4.example" && host.target == "192.0.2.1" })
    );
    assert!(
        summary
            .hosts
            .iter()
            .any(|host| { host.domain == "ipv6.example" && host.target == "2001:db8::1" })
    );
    assert!(
        summary
            .hosts
            .iter()
            .any(|host| { host.domain == "alias.example" && host.target == "target.example" })
    );
    assert_eq!(
        summary
            .hosts
            .iter()
            .filter(|host| host.domain == "many.example")
            .count(),
        2
    );
}

#[test]
fn dns_summary_uses_dns_owner_in_config_directory() {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_directory([
        ("/cfg/01-log.json", r#"{"log":{"loglevel":"warning"}}"#),
        (
            "/cfg/02-dns.json",
            r#"{"dns":{"servers":["https://1.1.1.1/dns-query"]}}"#,
        ),
    ]);
    let summary = outcome.sections().dns_summary().expect("DNS summary");
    assert_eq!(summary.source_file, "/cfg/02-dns.json");
}
