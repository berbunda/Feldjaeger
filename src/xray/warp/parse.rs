//! Parse generated `wgcf-cli` Xray WireGuard outbound JSON into internal model.

use serde_json::Value;

use super::error::{WarpError, WarpErrorKind, WarpResult};
use super::types::{
    SecretString, WarpCredentials, WarpProposedChange, CLOUDFLARE_WARP_PEER_PUBLIC_KEY,
};

/// Parses generated Xray outbound JSON bytes into [`WarpCredentials`].
///
/// Accepts either a full outbound object (`protocol` + `settings`) or a bare
/// `settings` object. Never logs secret material.
pub fn parse_generated_xray_outbound(bytes: &[u8]) -> WarpResult<WarpCredentials> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        WarpError::new(
            WarpErrorKind::GeneratedConfigurationInvalid,
            "generated outbound is not valid JSON",
        )
    })?;
    parse_generated_xray_value(value)
}

/// Parses a generated outbound [`Value`].
pub fn parse_generated_xray_value(mut value: Value) -> WarpResult<WarpCredentials> {
    if value.get("settings").is_none() {
        // Bare settings object from some generators — wrap.
        if value.get("secretKey").is_some() {
            value = Value::Object(
                [
                    ("protocol".to_owned(), Value::String("wireguard".into())),
                    ("settings".to_owned(), value),
                ]
                .into_iter()
                .collect(),
            );
        }
    }

    let protocol = value
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("wireguard");
    if !protocol.eq_ignore_ascii_case("wireguard") {
        return Err(WarpError::new(
            WarpErrorKind::GeneratedConfigurationInvalid,
            "generated outbound protocol must be wireguard",
        ));
    }

    let settings = value.get("settings").ok_or_else(|| {
        WarpError::new(
            WarpErrorKind::GeneratedConfigurationMissing,
            "generated outbound missing settings",
        )
    })?;

    let private_key = settings
        .get("secretKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            WarpError::new(
                WarpErrorKind::GeneratedConfigurationMissing,
                "generated outbound missing secretKey",
            )
        })?;

    let addresses = settings
        .get("address")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.trim().to_owned()))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if addresses.is_empty() {
        return Err(WarpError::new(
            WarpErrorKind::GeneratedConfigurationMissing,
            "generated outbound missing address",
        ));
    }
    validate_addresses(&addresses)?;

    let peers = settings
        .get("peers")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WarpError::new(
                WarpErrorKind::GeneratedConfigurationMissing,
                "generated outbound missing peers",
            )
        })?;
    if peers.is_empty() {
        return Err(WarpError::new(
            WarpErrorKind::GeneratedConfigurationMissing,
            "generated outbound peers array is empty",
        ));
    }
    let peer = &peers[0];
    let peer_public_key = peer
        .get("publicKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            WarpError::new(
                WarpErrorKind::GeneratedConfigurationMissing,
                "generated outbound missing peer publicKey",
            )
        })?
        .to_owned();

    let endpoint = peer
        .get("endpoint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            WarpError::new(
                WarpErrorKind::GeneratedConfigurationMissing,
                "generated outbound missing peer endpoint",
            )
        })?
        .to_owned();
    validate_endpoint(&endpoint)?;

    let reserved = match settings.get("reserved") {
        None => None,
        Some(Value::Array(items)) => {
            let mut bytes = Vec::with_capacity(items.len());
            for item in items {
                let Some(n) = item.as_u64() else {
                    return Err(WarpError::new(
                        WarpErrorKind::GeneratedConfigurationInvalid,
                        "reserved entries must be integers",
                    ));
                };
                if n > 255 {
                    return Err(WarpError::new(
                        WarpErrorKind::GeneratedConfigurationInvalid,
                        "reserved byte out of range",
                    ));
                }
                bytes.push(n as u8);
            }
            Some(bytes)
        }
        Some(_) => {
            return Err(WarpError::new(
                WarpErrorKind::GeneratedConfigurationInvalid,
                "reserved must be an array of bytes",
            ));
        }
    };

    let mtu = settings
        .get("mtu")
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    let domain_strategy = settings
        .get("domainStrategy")
        .and_then(Value::as_str)
        .map(str::to_owned);

    Ok(WarpCredentials {
        private_key: SecretString::new(private_key),
        peer_public_key,
        addresses,
        endpoint,
        reserved,
        mtu,
        domain_strategy,
        outbound_value: value,
    })
}

/// Builds a confirmation summary without exposing secrets.
pub fn proposed_change_from_credentials(
    credentials: &WarpCredentials,
    outbound_tag: &str,
) -> WarpProposedChange {
    WarpProposedChange {
        outbound_tag: outbound_tag.to_owned(),
        endpoint: credentials.endpoint.clone(),
        addresses: credentials.addresses.clone(),
        has_reserved: credentials.reserved.is_some(),
        mtu: credentials.mtu,
        summary_line: format!(
            "tag={outbound_tag}; endpoint={}; addresses={}; reserved={}",
            credentials.endpoint,
            credentials.addresses.join(","),
            if credentials.reserved.is_some() {
                "yes"
            } else {
                "no"
            }
        ),
    }
}

/// Applies the chosen outbound tag onto a credentials outbound value (clone).
pub fn outbound_value_with_tag(credentials: &WarpCredentials, tag: &str) -> Value {
    let mut value = credentials.outbound_value.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert("tag".to_owned(), Value::String(tag.to_owned()));
        if !object.contains_key("protocol") {
            object.insert(
                "protocol".to_owned(),
                Value::String("wireguard".to_owned()),
            );
        }
    }
    value
}

fn validate_endpoint(endpoint: &str) -> WarpResult<()> {
    if endpoint.contains(' ') || !endpoint.contains(':') {
        return Err(WarpError::new(
            WarpErrorKind::GeneratedConfigurationInvalid,
            "endpoint must be host:port",
        ));
    }
    Ok(())
}

fn validate_addresses(addresses: &[String]) -> WarpResult<()> {
    for address in addresses {
        if !address.contains('/') {
            return Err(WarpError::new(
                WarpErrorKind::GeneratedConfigurationInvalid,
                "address entries must include a CIDR prefix",
            ));
        }
    }
    Ok(())
}

/// Returns `true` when peer key matches the well-known Cloudflare WARP key.
pub fn peer_is_cloudflare_warp(peer_public_key: &str) -> bool {
    peer_public_key == CLOUDFLARE_WARP_PEER_PUBLIC_KEY
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_outbound(reserved: Option<Vec<u8>>, with_v6: bool) -> Value {
        let mut address = vec![json!("172.16.0.2/32")];
        if with_v6 {
            address.push(json!("2606:4700:110::1/128"));
        }
        let mut settings = json!({
            "secretKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "address": address,
            "peers": [{
                "publicKey": CLOUDFLARE_WARP_PEER_PUBLIC_KEY,
                "allowedIPs": ["0.0.0.0/0", "::/0"],
                "endpoint": "engage.cloudflareclient.com:2408"
            }],
            "mtu": 1280
        });
        if let Some(bytes) = reserved {
            settings.as_object_mut().unwrap().insert(
                "reserved".into(),
                Value::Array(bytes.into_iter().map(|b| json!(b)).collect()),
            );
        }
        json!({
            "protocol": "wireguard",
            "settings": settings,
            "tag": "wireguard"
        })
    }

    #[test]
    fn parse_ipv4_and_ipv6_with_reserved() {
        let value = sample_outbound(Some(vec![1, 2, 3]), true);
        let creds = parse_generated_xray_value(value).unwrap();
        assert_eq!(creds.addresses.len(), 2);
        assert_eq!(creds.reserved.as_deref(), Some(&[1, 2, 3][..]));
        assert_eq!(creds.mtu, Some(1280));
    }

    #[test]
    fn parse_ipv4_only_without_reserved() {
        let value = sample_outbound(None, false);
        let creds = parse_generated_xray_value(value).unwrap();
        assert_eq!(creds.addresses.len(), 1);
        assert!(creds.reserved.is_none());
    }

    #[test]
    fn missing_secret_key_fails() {
        let mut value = sample_outbound(None, false);
        value
            .pointer_mut("/settings")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("secretKey");
        let err = parse_generated_xray_value(value).unwrap_err();
        assert_eq!(err.kind(), WarpErrorKind::GeneratedConfigurationMissing);
    }

    #[test]
    fn debug_redacts_private_key() {
        let creds = parse_generated_xray_value(sample_outbound(None, false)).unwrap();
        let rendered = format!("{creds:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("AAAAAAAA"));
    }
}
