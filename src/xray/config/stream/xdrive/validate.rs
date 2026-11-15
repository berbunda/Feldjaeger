//! Validation reports paths and fixed explanations, never values from credential-bearing JSON.
use super::{XDRIVE_UINT32_FIELDS, XdriveSettingsDraft, xdrive_settings_to_value};
use crate::xray::config::stream::{PortListValue, RangeValue, StreamDirection};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

fn fail(path: &str, reason: &str) -> String {
    format!("{path}: {reason}")
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Whether the selected network is XDRIVE (settings alone do not select a transport).
pub fn xdrive_is_active(entity: &Value) -> bool {
    entity
        .get("streamSettings")
        .is_some_and(|s| network(s).eq_ignore_ascii_case("xdrive"))
}

fn network(stream: &Value) -> &str {
    stream
        .get("method")
        .filter(|v| !v.is_null())
        .or_else(|| stream.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// XDRIVE uses h3 only for TLS with ALPN exactly `["h3"]` (StringList also accepts `"h3"`).
pub fn xdrive_uses_h3(stream: &Value) -> bool {
    network(stream).eq_ignore_ascii_case("xdrive")
        && text(stream, "security").eq_ignore_ascii_case("tls")
        && stream
            .get("tlsSettings")
            .and_then(|tls| tls.get("alpn"))
            .is_some_and(|v| {
                v.as_str() == Some("h3")
                    || v.as_array().is_some_and(|a| a.len() == 1 && a[0] == "h3")
            })
}

/// Validates editable settings against XDriveConfig.Build, without filling runtime defaults.
pub fn validate_xdrive_settings(draft: &XdriveSettingsDraft) -> Result<(), String> {
    if let Some(text) = draft
        .template_editor_text
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        serde_json::from_str::<Value>(text).map_err(|_| {
            fail(
                "streamSettings.xdriveSettings.template",
                "invalid JSON; input is not included in this error",
            )
        })?;
    }
    if !draft.is_structured_editable()
        && super::parse_xdrive_settings(draft.original.as_ref()) != *draft
    {
        return Err(fail(
            "streamSettings.xdriveSettings",
            "this shape requires the raw JSON editor; structured edits cannot be applied",
        ));
    }
    validate_settings_value(&xdrive_settings_to_value(draft).unwrap_or(Value::Null))
}

fn validate_settings_value(value: &Value) -> Result<(), String> {
    let normalized = normalize_settings(value);
    let value = &normalized;
    let path = "streamSettings.xdriveSettings";
    if value.is_null() {
        return Ok(());
    }
    let object = value
        .as_object()
        .ok_or_else(|| fail(path, "must be an object or null"))?;
    for key in ["service", "remoteFolder"] {
        if object
            .get(key)
            .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            return Err(fail(&format!("{path}.{key}"), "must be a string or null"));
        }
    }
    for key in XDRIVE_UINT32_FIELDS {
        if object
            .get(*key)
            .is_some_and(|v| !v.is_null() && v.as_u64().is_none_or(|n| n > u32::MAX as u64))
        {
            return Err(fail(
                &format!("{path}.{key}"),
                "must be a uint32 integer or null",
            ));
        }
    }
    if object
        .get("secrets")
        .filter(|v| !v.is_null())
        .is_some_and(|secrets| {
            secrets
                .as_array()
                .is_none_or(|items| items.iter().any(|v| !v.is_null() && !v.is_string()))
        })
    {
        return Err(fail(
            &format!("{path}.secrets"),
            "must be an array of strings or null",
        ));
    }
    let secrets = value
        .get("secrets")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let service = text(value, "service");
    match service {
        "local" => {}
        "google-drive" | "Google Drive" if secrets.len() == 3 => {}
        "google-drive" | "Google Drive" => {
            return Err(fail(
                path,
                "Google Drive needs 3 secrets in order: ClientID, ClientSecret, RefreshToken",
            ));
        }
        "template" if object.contains_key("template") => {}
        "template" => return Err(fail(path, "template service needs a template node")),
        "s3" => {}
        _ => {
            return Err(fail(
                &format!("{path}.service"),
                "expected local, google-drive, template or s3",
            ));
        }
    }
    if let Some(xmux) = object.get("xmux").filter(|v| !v.is_null()) {
        let pool = xmux
            .as_object()
            .ok_or_else(|| fail(&format!("{path}.xmux"), "must be an object or null"))?;
        let mut positive = [false; 2];
        for (index, key) in [
            "maxConcurrency",
            "maxConnections",
            "cMaxReuseTimes",
            "hMaxRequestTimes",
            "hMaxReusableSecs",
        ]
        .iter()
        .enumerate()
        {
            if let Some(v) = pool.get(*key).filter(|v| !v.is_null()) {
                let bounds = RangeValue::parse(Some(v))
                    .and_then(|r| r.bounds().ok().flatten())
                    .ok_or_else(|| {
                        fail(
                            &format!("{path}.xmux.{key}"),
                            "must be an int32 number or range string",
                        )
                    })?;
                if index < 2 {
                    positive[index] = bounds.1 > 0;
                }
            }
        }
        if positive == [true, true] {
            return Err(fail(
                &format!("{path}.xmux"),
                "maxConnections and maxConcurrency cannot both be positive",
            ));
        }
        if pool
            .get("hKeepAlivePeriod")
            .is_some_and(|v| !v.is_null() && v.as_i64().is_none())
        {
            return Err(fail(
                &format!("{path}.xmux.hKeepAlivePeriod"),
                "must be an int64 integer or null",
            ));
        }
    }
    if let Some(s3) = object.get("s3").filter(|v| !v.is_null()) {
        if !s3.is_object() {
            return Err(fail(&format!("{path}.s3"), "must be an object or null"));
        }
        for key in ["endpoint", "region", "bucket"] {
            if s3.get(key).is_some_and(|v| !v.is_null() && !v.is_string()) {
                return Err(fail(
                    &format!("{path}.s3.{key}"),
                    "must be a string or null",
                ));
            }
        }
        if s3
            .get("pathStyle")
            .is_some_and(|v| !v.is_null() && !v.is_boolean())
        {
            return Err(fail(
                &format!("{path}.s3.pathStyle"),
                "must be a boolean or null",
            ));
        }
    }
    if service == "s3" {
        validate_s3(value)?;
    }
    Ok(())
}

// Go's JSON decoder matches known keys case-insensitively. The model keeps such objects raw;
// validation uses a temporary canonical copy, in the same key order as serialization to Xray.
fn normalize_settings(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let names = [
        "service",
        "remoteFolder",
        "secrets",
        "xmux",
        "s3",
        "template",
    ];
    let mut normalized = serde_json::Map::new();
    for (key, value) in object {
        let canonical = names
            .iter()
            .chain(XDRIVE_UINT32_FIELDS)
            .find(|name| key.eq_ignore_ascii_case(name))
            .copied()
            .unwrap_or(key);
        let nested_names: &[&str] = match canonical {
            "s3" => &["endpoint", "region", "bucket", "pathStyle"],
            "xmux" => &[
                "maxConcurrency",
                "maxConnections",
                "cMaxReuseTimes",
                "hMaxRequestTimes",
                "hMaxReusableSecs",
                "hKeepAlivePeriod",
            ],
            _ => &[],
        };
        let value = if let Some(nested) = value.as_object().filter(|_| !nested_names.is_empty()) {
            let mut result = serde_json::Map::new();
            for (key, value) in nested {
                let key = nested_names
                    .iter()
                    .find(|name| key.eq_ignore_ascii_case(name))
                    .copied()
                    .unwrap_or(key);
                result.insert(key.to_owned(), value.clone());
            }
            Value::Object(result)
        } else {
            value.clone()
        };
        normalized.insert(canonical.to_owned(), value);
    }
    Value::Object(normalized)
}

fn valid_header(value: &str) -> bool {
    value.bytes().all(|b| b == b'\t' || b >= 32 && b != 127)
}
fn valid_name(value: &str) -> bool {
    !value.chars().any(|c| c < ' ' || c == '\u{7f}' || c == '\\')
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}
fn validate_s3(value: &Value) -> Result<(), String> {
    let path = "streamSettings.xdriveSettings.s3";
    let s3 = value
        .get("s3")
        .filter(|v| v.is_object())
        .ok_or_else(|| fail(path, "s3 service needs an s3 object"))?;
    let endpoint = text(s3, "endpoint");
    let url = url::Url::parse(endpoint).ok();
    let authority = endpoint
        .split_once("://")
        .map(|(_, s)| s.split(['/', '?', '#']).next().unwrap_or(""));
    let scheme = endpoint
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    let invalid_escape = endpoint.as_bytes().iter().enumerate().any(|(index, byte)| {
        *byte == b'%'
            && endpoint
                .as_bytes()
                .get(index + 1..index + 3)
                .is_none_or(|hex| !hex.iter().all(u8::is_ascii_hexdigit))
    });
    if !matches!(scheme.as_deref(), Some("https" | "http"))
        || endpoint.bytes().any(|b| b < 32 || b == 127)
        || invalid_escape
        || url.as_ref().is_none_or(|u| {
            u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || u.query().is_some()
                || u.fragment().is_some_and(|f| !f.is_empty())
        })
        || authority.is_some_and(|a| a.contains('@'))
    {
        return Err(fail(
            path,
            "endpoint must be an http(s) URL without credentials, query or fragment",
        ));
    }
    let region = text(s3, "region");
    if !valid_header(region) || region.contains(['/', ',', ' ', '\t']) {
        return Err(fail(path, "invalid signing region"));
    }
    let bucket = text(s3, "bucket");
    if !valid_name(bucket) || bucket.contains('/') {
        return Err(fail(path, "bucket needs a name without path separators"));
    }
    if s3.get("pathStyle").and_then(Value::as_bool) == Some(false) {
        let host = authority
            .map(|a| {
                if let Some(a) = a.strip_prefix('[') {
                    a.split(']').next().unwrap_or("")
                } else {
                    a.split(':').next().unwrap_or("")
                }
            })
            .unwrap_or("");
        if host.parse::<std::net::IpAddr>().is_ok()
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            || bucket.contains("..")
            || bucket.starts_with('.')
            || bucket.ends_with('.')
        {
            return Err(fail(
                path,
                "virtual-hosted addressing needs a DNS endpoint and DNS-compatible bucket",
            ));
        }
    }
    if !valid_name(
        text(value, "remoteFolder")
            .strip_suffix('/')
            .unwrap_or(text(value, "remoteFolder")),
    ) {
        return Err(fail(
            "streamSettings.xdriveSettings.remoteFolder",
            "S3 needs a nonempty relative prefix without empty, '.' or '..' components",
        ));
    }
    let secrets = value
        .get("secrets")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if !(2..=3).contains(&secrets.len())
        || secrets
            .iter()
            .take(2)
            .any(|v| v.as_str().is_none_or(str::is_empty))
        || secrets
            .iter()
            .any(|v| !valid_header(v.as_str().unwrap_or("")))
        || secrets
            .first()
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains(['/', ' ', ',', '\t']))
    {
        return Err(fail(
            "streamSettings.xdriveSettings.secrets",
            "S3 needs valid AccessKeyID, SecretAccessKey and optional SessionToken",
        ));
    }
    Ok(())
}

/// Validates XDRIVE settings even on an inactive network (the core builds present settings),
/// then the selected transport's direction-dependent VLESS/Mux/port and h3 constraints.
/// Format checks never generate keys or claim that two independently supplied keys form a pair;
/// key generation and final cryptographic/runtime validation remain with the official core.
pub fn validate_xdrive_entity(entity: &Value, direction: StreamDirection) -> Result<(), String> {
    let Some(stream) = entity.get("streamSettings") else {
        return Ok(());
    };
    if let Some(settings) = stream.get("xdriveSettings") {
        validate_settings_value(settings)?;
    }
    if !xdrive_is_active(entity) {
        return Ok(());
    }
    if !text(entity, "protocol").eq_ignore_ascii_case("vless") {
        return Err(fail("protocol", "XDRIVE requires VLESS"));
    }
    let settings = entity.get("settings").unwrap_or(&Value::Null);
    match direction {
        StreamDirection::Inbound => {
            validate_encryption(text(settings, "decryption"), direction)?;
            if settings
                .get("clients")
                .and_then(Value::as_array)
                .is_some_and(|users| {
                    users
                        .iter()
                        .any(|u| !text(u, "flow").is_empty() || !text(settings, "flow").is_empty())
                })
            {
                return Err(fail(
                    "settings.clients[].flow",
                    "XDRIVE does not support VLESS flow",
                ));
            }
            if let Some(port) = entity.get("port").filter(|v| !v.is_null()) {
                let parsed = PortListValue::parse(Some(port))
                    .ok_or_else(|| fail("port", "XDRIVE requires one inbound port"))?;
                parsed
                    .validate()
                    .map_err(|_| fail("port", "XDRIVE requires one inbound port"))?;
                let port = parsed.text.trim();
                // Environment ports are resolved only by the remote core. Never read local env.
                if !(port.starts_with("env:") && !port.contains(',')) && !single_port(port) {
                    return Err(fail("port", "XDRIVE requires exactly one inbound port"));
                }
            }
        }
        StreamDirection::Outbound => {
            let account = if settings.get("address").is_some_and(|v| !v.is_null()) {
                settings
            } else {
                settings.pointer("/vnext/0/users/0").unwrap_or(&Value::Null)
            };
            validate_encryption(text(account, "encryption"), direction)?;
            if !text(account, "flow").is_empty() {
                return Err(fail("settings.flow", "XDRIVE does not support VLESS flow"));
            }
            if account
                .get("testpre")
                .is_some_and(|v| !v.is_null() && v.as_u64() != Some(0))
            {
                return Err(fail(
                    "settings.testpre",
                    "XDRIVE does not support VLESS testpre",
                ));
            }
            let reverse = settings.get("address").is_some_and(|v| !v.is_null())
                && account.get("reverse").is_some_and(|v| !v.is_null());
            // Reverse supplies its own Mux, but does not bypass JSON decoding of a supplied mux.
            let mux = crate::xray::config::outbound_edit::parse_outbound_mux(entity);
            crate::xray::config::outbound_edit::validate_outbound_mux(&mux)
                .map_err(|_| fail("mux", "XDRIVE requires valid Mux settings"))?;
            if !reverse
                && (!mux.enabled
                    || mux.effective_concurrency().is_none_or(|v| v < 0)
                    || mux.xudp_concurrency.parse::<i16>().is_ok_and(|v| v < 0)
                    || mux.xudp_proxy_udp443 == "skip")
            {
                return Err(fail(
                    "mux",
                    "XDRIVE needs enabled Mux, nonnegative concurrency/xudpConcurrency and UDP443 other than skip",
                ));
            }
        }
    }
    if xdrive_uses_h3(stream) {
        if let Some(quic) = stream.pointer("/finalmask/quicParams") {
            let congestion = text(quic, "congestion").to_ascii_lowercase();
            if matches!(congestion.as_str(), "brutal" | "force-brutal") {
                return Err(fail(
                    "streamSettings.finalmask.quicParams.congestion",
                    "XDRIVE h3 supports bbr or reno, not brutal",
                ));
            }
        }
        let service = stream
            .get("xdriveSettings")
            .map(|s| text(s, "service"))
            .unwrap_or("");
        if matches!(service, "google-drive" | "Google Drive")
            && stream
                .pointer("/finalmask/udp")
                .and_then(Value::as_array)
                .is_some_and(|layers| {
                    layers
                        .iter()
                        .any(|l| !text(l, "type").eq_ignore_ascii_case("noise"))
                })
        {
            return Err(fail(
                "streamSettings.finalmask.udp",
                "Google Drive over h3 supports only noise UDP masks",
            ));
        }
    }
    Ok(())
}

fn single_port(value: &str) -> bool {
    if let Ok(port) = value.parse::<u16>() {
        return port > 0;
    }
    value.split_once('-').is_some_and(|(a, b)| {
        a.parse::<u16>().is_ok_and(|port| port > 0) && a.parse::<u16>() == b.parse::<u16>()
    })
}

fn validate_encryption(value: &str, direction: StreamDirection) -> Result<(), String> {
    let key = if direction == StreamDirection::Inbound {
        "settings.decryption"
    } else {
        "settings.encryption"
    };
    let error = || {
        fail(
            key,
            "XDRIVE requires VLESS Encryption from xray vlessenc (not empty or none)",
        )
    };
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() < 4
        || parts[0] != "mlkem768x25519plus"
        || !matches!(parts[1], "native" | "xorpub" | "random")
    {
        return Err(error());
    }
    if direction == StreamDirection::Outbound {
        if !matches!(parts[2], "0rtt" | "1rtt") {
            return Err(error());
        }
    } else if !parts[2]
        .trim_end_matches('s')
        .splitn(2, '-')
        .all(|s| s.parse::<i64>().is_ok())
    {
        return Err(error());
    }
    let mut keys = 0;
    for part in &parts[3..] {
        if part.len() < 20 {
            continue;
        }
        let length = URL_SAFE_NO_PAD.decode(part).map_err(|_| error())?.len();
        if length != 32
            && length
                != if direction == StreamDirection::Inbound {
                    64
                } else {
                    1184
                }
        {
            return Err(error());
        }
        keys += 1;
    }
    if keys == 0 {
        return Err(error());
    }
    Ok(())
}
