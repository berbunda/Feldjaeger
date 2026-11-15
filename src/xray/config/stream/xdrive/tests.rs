use super::super::StreamDirection::{self, Inbound, Outbound};
use super::*;
use serde_json::json;

#[test]
fn editable_streams_preserve_storage_tls_and_aliases_on_unrelated_changes() {
    use crate::xray::config::{
        inbound_stream::{apply_inbound_stream, parse_inbound_stream},
        outbound_stream::{apply_outbound_stream, parse_outbound_stream},
    };
    for direction in [Inbound, Outbound] {
        let mut value = entity(direction);
        value["streamSettings"]["network"] = json!("XDRIVE");
        value["streamSettings"]["security"] = json!("tls");
        value["streamSettings"]["tlsSettings"] = json!({"alpn":"h3","fingerprint":"hellochrome_155","futureTLS":{"keep":true},"useSystemCA":null});
        let original = value.clone();
        if direction == Inbound {
            let mut draft = parse_inbound_stream(&value);
            apply_inbound_stream(&mut value, &draft).unwrap();
            assert_eq!(value, original);
            draft.xdrive.eager_window_ms = Some(10000);
            draft.write_xdrive = true;
            apply_inbound_stream(&mut value, &draft).unwrap();
        } else {
            let mut draft = parse_outbound_stream(&value);
            apply_outbound_stream(&mut value, &draft).unwrap();
            assert_eq!(value, original);
            draft.xdrive.eager_window_ms = Some(10000);
            draft.write_xdrive = true;
            apply_outbound_stream(&mut value, &draft).unwrap();
        }
        assert_eq!(
            value["streamSettings"]["tlsSettings"],
            original["streamSettings"]["tlsSettings"]
        );
        assert_eq!(value["streamSettings"]["network"], "XDRIVE");
        assert_eq!(
            value["streamSettings"]["xdriveSettings"]["eagerWindowMs"],
            10000
        );
    }
}

#[test]
fn storage_tls_edit_changes_only_the_requested_fields_and_keeps_inactive_modes() {
    use crate::xray::config::inbound_stream::{apply_inbound_stream, parse_inbound_stream};
    let mut value = entity(Inbound);
    value["streamSettings"]["security"] = json!("tls");
    value["streamSettings"]["tlsSettings"] =
        json!({"alpn":"h3","useSystemCA":null,"futureTLS":{"keep":true}});
    value["streamSettings"]["realitySettings"] = json!({"preserve":"inactive"});
    let before = value.clone();
    let mut draft = parse_inbound_stream(&value);
    draft.xdrive_security.tls.server_name = "storage.example.com".to_owned();
    draft.write_xdrive_security = true;
    apply_inbound_stream(&mut value, &draft).unwrap();
    let mut expected = before.clone();
    expected["streamSettings"]["tlsSettings"]["serverName"] = json!("storage.example.com");
    assert_eq!(value, expected);
    let tls = value["streamSettings"]["tlsSettings"].clone();
    draft.xdrive_security.mode = crate::xray::InboundSecurityMode::None;
    apply_inbound_stream(&mut value, &draft).unwrap();
    assert_eq!(value["streamSettings"]["tlsSettings"], tls);
    assert_eq!(
        value["streamSettings"]["realitySettings"],
        before["streamSettings"]["realitySettings"]
    );
}

#[test]
fn leaving_xdrive_preserves_storage_settings_and_other_transport_data() {
    use crate::xray::config::outbound_stream::{apply_outbound_stream, parse_outbound_stream};
    let mut value = entity(Outbound);
    value["streamSettings"]["xhttpSettings"] = json!({"future":"keep"});
    let old = value["streamSettings"]["xdriveSettings"].clone();
    let mut draft = parse_outbound_stream(&value);
    draft.select_transport(crate::xray::OutboundTransport::Raw);
    apply_outbound_stream(&mut value, &draft).unwrap();
    assert_eq!(value["streamSettings"]["xdriveSettings"], old);
    assert_eq!(value["streamSettings"]["xhttpSettings"]["future"], "keep");
}

#[test]
fn storage_editor_output_parity_with_official_core() {
    let Some(binary) = crate::xray::local_xray::local_xray_bin() else {
        return;
    };
    let directory =
        std::env::temp_dir().join(format!("feldjaeger-xdrive-editor-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.json");
    let mut failures = Vec::new();
    let mut count = 0;
    for direction in [Inbound, Outbound] {
        for storage in [
            json!({"service":"local","remoteFolder":"local-folder","future":{"keep":true}}),
            json!({"service":"google-drive","remoteFolder":"folder-id","secrets":["a","b","c"],"eagerWindowMs":10000}),
            json!({"service":"template","template":{}}),
            s3(),
        ] {
            let mut value = entity(direction);
            let settings = parse_xdrive_settings(Some(&storage));
            if direction == Inbound {
                let mut draft = crate::xray::parse_inbound_stream(&value);
                draft.xdrive = settings;
                draft.write_xdrive = true;
                draft.xdrive_security.mode = crate::xray::InboundSecurityMode::Tls;
                draft.xdrive_security.tls.alpn = vec!["h3".to_owned()];
                draft.write_xdrive_security = true;
                crate::xray::apply_inbound_stream(&mut value, &draft).unwrap();
            } else {
                let mut draft = crate::xray::parse_outbound_stream(&value);
                draft.xdrive = settings;
                draft.write_xdrive = true;
                draft.security.mode = crate::xray::InboundSecurityMode::Tls;
                draft.security.tls.alpn = vec!["h3".to_owned()];
                draft.write = true;
                crate::xray::apply_outbound_stream(&mut value, &draft).unwrap();
            }
            assert!(validate_xdrive_entity(&value, direction).is_ok());
            let root = if direction == Inbound {
                json!({"inbounds":[value]})
            } else {
                json!({"outbounds":[value]})
            };
            std::fs::write(&path, serde_json::to_vec(&root).unwrap()).unwrap();
            let result = std::process::Command::new(&binary)
                .args(["run", "-test", "-c"])
                .arg(&path)
                .output()
                .unwrap();
            count += 1;
            if !result.status.success() {
                failures.push((direction, count));
            }
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        failures.is_empty(),
        "XDRIVE editor output parity failed (credentials omitted): {failures:?}"
    );
    eprintln!("XDRIVE editor parity: {count} configurations");
}

fn entity(direction: StreamDirection) -> Value {
    let pair = crate::xray::parse_vlessenc_stdout(include_str!(
        "../../../remote_cli/fixtures/vlessenc.stdout.txt"
    ))
    .unwrap()
    .x25519;
    let mut value = json!({"protocol":"vless", "tag":"drive", "streamSettings":{
        "network":"xdrive", "xdriveSettings":{"service":"local","remoteFolder":"xdrive-test"}
    }});
    match direction {
        Inbound => {
            value["port"] = json!(12345);
            value["settings"] = json!({"decryption":pair.decryption,
            "clients":[{"id":"0f59c2c4-ef28-4847-9ead-b222e50da5fb"}]});
        }
        Outbound => {
            value["settings"] = json!({"address":"127.0.0.1","port":12345,
                "id":"0f59c2c4-ef28-4847-9ead-b222e50da5fb","encryption":pair.encryption});
            value["mux"] = json!({"enabled":true});
        }
    }
    value
}

#[test]
fn lossless_unknown_null_empty_and_malformed_shapes() {
    assert_eq!(xdrive_settings_to_value(&parse_xdrive_settings(None)), None);
    for value in [
        json!(null),
        json!(false),
        json!(["raw-secret"]),
        json!({}),
        json!({
            "service":"future", "remoteFolder":"  preserve  ", "secrets":["one","","three"],
            "segmentBytes":0, "flushIntervalMs":null, "pollIntervalMs":"raw-secret", "maxPollIntervalMs":4294967296_u64,
            "sessionTtlSeconds":-1, "concurrency":1.5, "eagerWindowMs":4294967295_u64, "holeTimeoutMs":false,
            "xmux":{"maxConcurrency":" 5-10 ", "hKeepAlivePeriod":null,"future":{"raw":"secret"}},
            "s3":{"endpoint":null,"region":"","pathStyle":false,"future":[1,2]},
            "template":{"arbitrary":{"auth":"raw-secret"}}, "future":{"keep":true}
        }),
        json!({"Service":"local","service":"Google Drive"}),
        json!({"service":"s3","s3":{"Endpoint":"https://example.com"}}),
    ] {
        let draft = parse_xdrive_settings(Some(&value));
        assert_eq!(xdrive_settings_to_value(&draft), Some(value));
    }
}

#[test]
fn typed_edit_keeps_unknown_and_explicit_null_values() {
    let original = json!({"service":"local", "secrets":null, "future":{"keep":true},
        "xmux":{"maxConnections":"1-1","hMaxReusableSecs":" 1800-3000 ","future":{"n":1}},
        "s3":{"bucket":"unused","future":null}});
    let mut draft = parse_xdrive_settings(Some(&original));
    draft.eager_window_ms = Some(10000);
    draft
        .xmux
        .as_mut()
        .unwrap()
        .extras
        .insert("future".to_owned(), json!({"n":2}));
    let mut expected = original;
    expected["eagerWindowMs"] = json!(10000);
    expected["xmux"]["future"] = json!({"n":2});
    assert_eq!(xdrive_settings_to_value(&draft), Some(expected));
    assert!(validate_xdrive_settings(&draft).is_ok());
}

#[test]
fn debug_and_errors_never_echo_secret_bearing_values() {
    let canary = "OAuth-credential-canary";
    for value in [
        json!({"service":canary,"secrets":[canary],"s3":{"endpoint":canary},
        "xmux":{"maxConcurrency":canary},"template":{"token":canary},"unknown":canary}),
        json!({"Service":canary}),
        json!([canary]),
    ] {
        let draft = parse_xdrive_settings(Some(&value));
        assert!(!format!("{draft:?}").contains(canary));
        assert!(!format!("{:?}", draft.s3).contains(canary));
        assert!(!format!("{:?}", draft.xmux).contains(canary));
        assert!(
            !validate_xdrive_settings(&draft)
                .unwrap_err()
                .contains(canary)
        );
    }
}

#[test]
fn uint32_fields_accept_zero_max_and_preserve_every_other_form() {
    for key in XDRIVE_UINT32_FIELDS {
        for value in [json!(0), json!(u32::MAX), json!(null)] {
            let settings = json!({"service":"local", *key:value});
            assert!(validate_xdrive_settings(&parse_xdrive_settings(Some(&settings))).is_ok());
        }
        for value in [
            json!(-1),
            json!(4294967296_u64),
            json!(1.0),
            json!("100"),
            json!([]),
        ] {
            let settings = json!({"service":"local", *key:value});
            let draft = parse_xdrive_settings(Some(&settings));
            assert_eq!(xdrive_settings_to_value(&draft), Some(settings));
            assert!(validate_xdrive_settings(&draft).is_err());
        }
    }
}

#[test]
fn xmux_conflicts_and_known_shapes_are_checked() {
    for (pool, valid) in [
        (json!({}), true),
        (json!(null), true),
        (json!({"maxConcurrency":0,"maxConnections":"4"}), true),
        (
            json!({"maxConcurrency":"1-2","maxConnections":"0-1"}),
            false,
        ),
        (json!({"hKeepAlivePeriod":9223372036854775807_i64}), true),
        (json!({"maxConnections":1.5}), false),
        (json!({"hKeepAlivePeriod":true}), false),
    ] {
        let value = json!({"service":"local","xmux":pool});
        assert_eq!(
            validate_xdrive_settings(&parse_xdrive_settings(Some(&value))).is_ok(),
            valid
        );
    }
}

fn s3() -> Value {
    json!({"service":"s3","remoteFolder":"folder/prefix/", "secrets":["access","secret"],
    "s3":{"endpoint":"https://s3.example.com/base","bucket":"bucket","region":"us-east-1","pathStyle":true}})
}

#[test]
fn services_and_s3_follow_core_rules_without_network_requests() {
    for settings in [
        json!({"service":"local"}),
        json!({"service":"google-drive","secrets":["a","b","c"]}),
        json!({"service":"Google Drive","secrets":["",null,""]}),
        json!({"service":"template","template":null}),
        s3(),
    ] {
        assert!(validate_xdrive_settings(&parse_xdrive_settings(Some(&settings))).is_ok());
    }
    for (path, invalid) in [
        ("/s3/endpoint", json!("https://user:pass@example.com")),
        ("/s3/endpoint", json!("https://example.com?")),
        ("/s3/endpoint", json!("https://example.com#frag")),
        ("/s3/endpoint", json!("ftp://example.com")),
        ("/s3/bucket", json!("a/b")),
        ("/s3/region", json!("bad/region")),
        ("/remoteFolder", json!("a/../b")),
        ("/remoteFolder", json!("/root")),
        ("/remoteFolder", json!("a//")),
        ("/secrets", json!(["a"])),
        ("/secrets", json!(["a", "secret\n"])),
        ("/secrets", json!(["a/b", "secret"])),
        ("/s3/pathStyle", json!("false")),
    ] {
        let mut value = s3();
        *value.pointer_mut(path).unwrap_or_else(|| panic!("{path}")) = invalid;
        assert!(
            validate_xdrive_settings(&parse_xdrive_settings(Some(&value))).is_err(),
            "{path}"
        );
    }
    let mut virtual_hosted = s3();
    virtual_hosted["s3"]["pathStyle"] = json!(false);
    assert!(validate_xdrive_settings(&parse_xdrive_settings(Some(&virtual_hosted))).is_ok());
    virtual_hosted["s3"]["endpoint"] = json!("http://127.0.0.1:9000");
    assert!(validate_xdrive_settings(&parse_xdrive_settings(Some(&virtual_hosted))).is_err());
}

#[test]
fn direction_constraints_include_legacy_outbound_and_reverse_exception() {
    for direction in [Inbound, Outbound] {
        let base = entity(direction);
        assert!(validate_xdrive_entity(&base, direction).is_ok());
        let mut none = base.clone();
        none["settings"][if direction == Inbound {
            "decryption"
        } else {
            "encryption"
        }] = json!("none");
        assert!(validate_xdrive_entity(&none, direction).is_err());
        let mut other = base.clone();
        other["protocol"] = json!("socks");
        assert!(validate_xdrive_entity(&other, direction).is_err());
        let mut flow = base.clone();
        flow["settings"]["flow"] = json!("xtls-rprx-vision");
        assert!(validate_xdrive_entity(&flow, direction).is_err());
    }
    let mut inbound = entity(Inbound);
    inbound["port"] = json!("12345-12346");
    assert!(validate_xdrive_entity(&inbound, Inbound).is_err());
    inbound["port"] = json!("12345-12345");
    assert!(validate_xdrive_entity(&inbound, Inbound).is_ok());
    for mux in [
        json!({"enabled":false}),
        json!({"enabled":true,"concurrency":-1}),
        json!({"enabled":true,"xudpConcurrency":-1}),
        json!({"enabled":true,"xudpProxyUDP443":"skip"}),
    ] {
        let mut outbound = entity(Outbound);
        outbound["mux"] = mux;
        assert!(validate_xdrive_entity(&outbound, Outbound).is_err());
        outbound["settings"]["reverse"] = json!({"tag":"reverse"});
        assert!(validate_xdrive_entity(&outbound, Outbound).is_ok());
    }
    let mut outbound = entity(Outbound);
    outbound["settings"]["testpre"] = json!(1);
    assert!(validate_xdrive_entity(&outbound, Outbound).is_err());
    outbound["settings"]
        .as_object_mut()
        .unwrap()
        .remove("testpre");
    let flat = outbound["settings"].clone();
    outbound["settings"] = json!({"vnext":[{"address":"127.0.0.1","port":12345,"users":[{
        "id":flat["id"],"encryption":flat["encryption"]}]}]});
    assert!(validate_xdrive_entity(&outbound, Outbound).is_ok());
}

#[test]
fn h3_alpn_masks_and_brutal_match_core() {
    let mut value = entity(Inbound);
    value["streamSettings"]["security"] = json!("tls");
    value["streamSettings"]["tlsSettings"] = json!({"alpn":["h3"]});
    value["streamSettings"]["xdriveSettings"] =
        json!({"service":"google-drive","secrets":["a","b","c"]});
    value["streamSettings"]["finalmask"] =
        json!({"udp":[{"type":"salamander","settings":{"password":"test"}}]});
    assert!(xdrive_uses_h3(&value["streamSettings"]));
    assert!(validate_xdrive_entity(&value, Inbound).is_err());
    value["streamSettings"]["finalmask"] =
        json!({"udp":[{"type":"noise","settings":{"noise":[]}}]});
    assert!(validate_xdrive_entity(&value, Inbound).is_ok());
    value["streamSettings"]["finalmask"]["quicParams"] = json!({"congestion":"brutal"});
    assert!(validate_xdrive_entity(&value, Inbound).is_err());
    value["streamSettings"]["tlsSettings"]["alpn"] = json!(["h3", "h2"]);
    assert!(!xdrive_uses_h3(&value["streamSettings"]));
    assert!(validate_xdrive_entity(&value, Inbound).is_ok());
}

#[test]
fn gates_warnings_and_storage_client_tls_use_the_shared_model() {
    use crate::xray::config::compatibility::{check_inbound_compatibility, first_failing_gate};
    use crate::xray::{
        CompatibilityGateId, CompatibilityWarningId, XrayCoreVersion, inbound_warnings,
    };
    let mut value = entity(Inbound);
    value["streamSettings"]["security"] = json!("tls");
    value["streamSettings"]["tlsSettings"] = json!({"alpn":["h3"]});
    assert!(
        check_inbound_compatibility(&value).is_ok(),
        "storage client needs no server certificate"
    );
    let warnings = inbound_warnings(&value, Some(XrayCoreVersion::new(26, 10, 31)));
    assert!(
        warnings
            .iter()
            .any(|w| w.id == CompatibilityWarningId::XdriveBeta)
    );
    assert!(warnings.iter().any(|w| matches!(
        w.id,
        CompatibilityWarningId::RequiresNewerCore {
            feature: crate::xray::CoreFeature::XdriveBeta,
            ..
        }
    )));
    assert!(
        !warnings
            .iter()
            .any(|w| w.id == CompatibilityWarningId::QuicParamsUnusedTransport)
    );
    value["settings"]["decryption"] = json!("none");
    assert_eq!(first_failing_gate(&value), Some(CompatibilityGateId::G15));
    assert!(
        check_inbound_compatibility(&value)
            .unwrap_err()
            .to_string()
            .contains("settings.decryption")
    );
    value["streamSettings"]["network"] = json!("tcp");
    assert_eq!(first_failing_gate(&value), Some(CompatibilityGateId::G12));
}

#[test]
fn xdrive_parity_with_official_core() {
    let Some(binary) = crate::xray::local_xray::local_xray_bin() else {
        return;
    };
    let output = std::process::Command::new(&binary)
        .arg("version")
        .output()
        .unwrap();
    let version =
        crate::xray::XrayCoreVersion::parse(&String::from_utf8_lossy(&output.stdout)).unwrap();
    if version < crate::xray::XrayCoreVersion::new(26, 10, 31) {
        return;
    }
    let dir =
        std::env::temp_dir().join(format!("feldjaeger-xdrive-parity-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let mut cases = Vec::new();
    for direction in [Inbound, Outbound] {
        let base = entity(direction);
        cases.push(("local", direction, base.clone(), true));
        for (name, settings) in [
            (
                "google",
                json!({"service":"google-drive","secrets":["a","b","c"]}),
            ),
            (
                "legacy",
                json!({"service":"Google Drive","secrets":["a","b","c"]}),
            ),
            ("template", json!({"service":"template","template":{}})),
            ("s3", s3()),
            (
                "google-secrets",
                json!({"service":"google-drive","secrets":["a"]}),
            ),
            (
                "uint32-negative",
                json!({"service":"local","segmentBytes":-1}),
            ),
            (
                "pool-conflict",
                json!({"service":"local","xmux":{"maxConnections":1,"maxConcurrency":1}}),
            ),
        ] {
            let mut value = base.clone();
            value["streamSettings"]["xdriveSettings"] = settings;
            let expected = validate_xdrive_entity(&value, direction).is_ok();
            cases.push((name, direction, value, expected));
        }
        let mut tls = base.clone();
        tls["streamSettings"]["security"] = json!("tls");
        tls["streamSettings"]["tlsSettings"] = json!({"alpn":["h3"]});
        cases.push(("h3", direction, tls.clone(), true));
        tls["streamSettings"]["finalmask"] = json!({"quicParams":{"congestion":"brutal"}});
        cases.push(("h3-brutal", direction, tls, false));
        let mut flow = base.clone();
        flow["settings"]["flow"] = json!("xtls-rprx-vision");
        cases.push(("flow", direction, flow, false));
        let mut none = base;
        none["settings"][if direction == Inbound {
            "decryption"
        } else {
            "encryption"
        }] = json!("none");
        cases.push(("no-encryption", direction, none, false));
        for endpoint in [
            "HTTPS://s3.example.com/base",
            "http://127.0.0.1:9000",
            "https://s3.example.com/base path",
            "https://s3.example.com/#",
            "https://@s3.example.com",
            "https://s3.example.com?",
            "https://s3.example.com/%invalid",
            "https://s3.example.com\t",
        ] {
            let mut value = entity(direction);
            let mut storage = s3();
            storage["s3"]["endpoint"] = json!(endpoint);
            value["streamSettings"]["xdriveSettings"] = storage;
            let expected = validate_xdrive_entity(&value, direction).is_ok();
            cases.push(("s3-url", direction, value, expected));
        }
        let mut value = entity(direction);
        value["settings"][if direction == Inbound {
            "decryption"
        } else {
            "encryption"
        }] = json!("invalid-encryption");
        cases.push(("invalid-encryption", direction, value, false));
    }
    for mux in [
        json!({"enabled":false}),
        json!({"enabled":true,"concurrency":-1}),
        json!({"enabled":true,"xudpConcurrency":-1}),
        json!({"enabled":true,"xudpProxyUDP443":"skip"}),
    ] {
        let mut value = entity(Outbound);
        value["mux"] = mux;
        cases.push(("mux-invalid", Outbound, value.clone(), false));
        value["settings"]["reverse"] = json!({"tag":"reverse"});
        cases.push(("reverse", Outbound, value, true));
    }
    for port in [
        json!(0),
        json!("12345-12345"),
        json!("12345-12346"),
        json!("12345,12346"),
    ] {
        let mut value = entity(Inbound);
        value["port"] = port;
        let expected = validate_xdrive_entity(&value, Inbound).is_ok();
        cases.push(("inbound-port", Inbound, value, expected));
    }
    eprintln!("XDRIVE parity: {} cases on {version}", cases.len());
    let mut failures = Vec::new();
    for (name, direction, value, expected) in cases {
        // Syntax acceptance on the older pre-beta core does not prove runtime interoperability.
        assert_eq!(
            xdrive_settings_to_value(&parse_xdrive_settings(
                value.pointer("/streamSettings/xdriveSettings")
            )),
            value.pointer("/streamSettings/xdriveSettings").cloned()
        );
        let root = if direction == Inbound {
            json!({"inbounds":[value]})
        } else {
            json!({"outbounds":[value]})
        };
        std::fs::write(&path, serde_json::to_vec(&root).unwrap()).unwrap();
        let result = std::process::Command::new(&binary)
            .args(["run", "-test", "-c"])
            .arg(&path)
            .output()
            .unwrap();
        if result.status.success() != expected {
            failures.push((name, direction));
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        failures.is_empty(),
        "XDRIVE parity mismatches (no config/credentials printed): {failures:?}"
    );
}

#[test]
fn shared_mutation_pipeline_preserves_storage_data_and_rejects_invalid_mux_atomically() {
    use crate::xray::config::modify::{
        AddUserRequest, UpdateOutboundShellRequest, add_user, update_outbound_shell,
    };
    use crate::xray::config::outbound_edit::{OutboundRef, parse_outbound_general};
    use crate::xray::config::{EditableXrayConfig, XrayConfigParser};
    let mut inbound = entity(Inbound);
    inbound["streamSettings"]["security"] = json!("tls");
    inbound["streamSettings"]["tlsSettings"] = json!({"alpn":["h3"]});
    inbound["streamSettings"]["xdriveSettings"]["future"] = json!({"preserve":"marker"});
    let outbound = entity(Outbound);
    let root = json!({"inbounds":[inbound.clone()],"outbounds":[outbound]});
    let json = serde_json::to_string(&root).unwrap();
    let outcome = XrayConfigParser::new().parse_single_file("/etc/xray/config.json", &json);
    assert!(outcome.is_success());
    let mut config = EditableXrayConfig::from_single_file(
        "/etc/xray/config.json",
        root,
        outcome.into_sections(),
    );
    add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "new".to_owned(),
            id: None,
            flow: None,
            level: 0,
            reverse: None,
        },
    )
    .expect("storage client needs no listener certificate");
    assert_eq!(
        config.sections().inbounds()[0].value()["streamSettings"],
        inbound["streamSettings"]
    );
    let before = config.clone();
    let outbound = config.sections().outbounds()[0].value();
    let mut general = parse_outbound_general(outbound);
    general.mux.as_mut().unwrap().enabled = false;
    let request = UpdateOutboundShellRequest {
        outbound_ref: OutboundRef {
            outbound_index: 0,
            expected_fingerprint: config.outbound_object_fingerprint(0).unwrap(),
        },
        general,
        settings: crate::xray::config::outbound_protocol::parse_outbound_settings(outbound)
            .unwrap(),
        stream: crate::xray::config::outbound_stream::parse_outbound_stream(outbound),
        core_version: None,
    };
    assert!(update_outbound_shell(&mut config, request).is_err());
    assert_eq!(
        config, before,
        "failed XDRIVE save must leave all roots unchanged"
    );
}

#[test]
fn method_overrides_network_and_raw_case_aliases_never_disappear() {
    use crate::xray::config::compatibility::check_inbound_compatibility;
    let mut value = entity(Inbound);
    value["streamSettings"]["network"] = json!("tcp");
    value["streamSettings"]["method"] = json!("xdrive");
    value["streamSettings"]["security"] = json!("tls");
    value["streamSettings"]["tlsSettings"] = json!({"alpn":["h3"]});
    assert!(xdrive_is_active(&value));
    assert!(xdrive_uses_h3(&value["streamSettings"]));
    assert!(check_inbound_compatibility(&value).is_ok());
    let mut reverse = entity(Outbound);
    reverse["settings"]["reverse"] = json!({"tag":"reverse"});
    reverse["mux"] = json!({"enabled":"invalid"});
    assert!(validate_xdrive_entity(&reverse, Outbound).is_err());
    assert_eq!(
        super::super::quic_transport_of(&value["streamSettings"]),
        Some(super::super::QuicTransport::XdriveH3)
    );
    for original in [
        json!({"Service":"local"}),
        json!({"service":"local","xmux":{"MaxConnections":1}}),
    ] {
        let mut draft = parse_xdrive_settings(Some(&original));
        assert!(!draft.is_structured_editable());
        assert!(validate_xdrive_settings(&draft).is_ok());
        draft.service = Some("google-drive".to_owned());
        assert!(validate_xdrive_settings(&draft).is_err());
        assert_eq!(xdrive_settings_to_value(&draft), Some(original));
    }
}
