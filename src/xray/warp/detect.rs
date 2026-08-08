//! Detection and classification of WARP-related WireGuard outbounds.

use serde_json::Value;

use super::types::{
    endpoint_looks_like_cloudflare, tag_looks_like_warp_hint, WarpOutboundClassification,
    WarpOwnershipRecord, CLOUDFLARE_WARP_PEER_PUBLIC_KEY,
};
use crate::xray::config::{RoutingSummary, XrayConfigSections};

/// Read-only view of one outbound considered during WARP detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedWarpOutbound {
    /// Merged outbound index.
    pub index: usize,
    /// Outbound tag when present.
    pub tag: Option<String>,
    /// Classification relative to Feldjäger ownership.
    pub classification: WarpOutboundClassification,
    /// Endpoint when present (no secrets).
    pub endpoint: Option<String>,
    /// Assigned addresses when present.
    pub addresses: Vec<String>,
    /// Peer public key when present.
    pub peer_public_key: Option<String>,
    /// Whether required WireGuard fields validate.
    pub structurally_valid: bool,
    /// Short safe summary (no private key).
    pub summary: String,
}

/// Extracts WireGuard fields needed for WARP detection from an outbound JSON value.
pub fn wireguard_probe(value: &Value) -> WireguardProbe {
    let settings = value.get("settings");
    let secret_key = settings
        .and_then(|s| s.get("secretKey"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let addresses = settings
        .and_then(|s| s.get("address"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let peers = settings
        .and_then(|s| s.get("peers"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let first_peer = peers.first();
    let peer_public_key = first_peer
        .and_then(|peer| peer.get("publicKey"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let endpoint = first_peer
        .and_then(|peer| peer.get("endpoint"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let reserved_ok = match settings.and_then(|s| s.get("reserved")) {
        None => true,
        Some(Value::Array(items)) => items.iter().all(|item| item.as_u64().is_some()),
        Some(_) => false,
    };
    let structurally_valid = secret_key.is_some()
        && peer_public_key
            .as_deref()
            .is_some_and(|key| !key.trim().is_empty())
        && endpoint.as_deref().is_some_and(|ep| !ep.trim().is_empty())
        && !addresses.is_empty()
        && reserved_ok;

    WireguardProbe {
        has_secret_key: secret_key.is_some(),
        addresses,
        peer_public_key,
        endpoint,
        structurally_valid,
    }
}

/// Non-secret WireGuard field probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardProbe {
    /// Whether `secretKey` is present and non-empty (value never retained).
    pub has_secret_key: bool,
    /// Interface addresses.
    pub addresses: Vec<String>,
    /// Peer public key.
    pub peer_public_key: Option<String>,
    /// Peer endpoint.
    pub endpoint: Option<String>,
    /// Required field presence / shape.
    pub structurally_valid: bool,
}

/// Classifies a WireGuard outbound given optional ownership metadata.
pub fn classify_wireguard_outbound(
    tag: Option<&str>,
    probe: &WireguardProbe,
    ownership: Option<&WarpOwnershipRecord>,
) -> WarpOutboundClassification {
    if !probe.structurally_valid {
        return WarpOutboundClassification::Invalid;
    }

    if let Some(owned) = ownership {
        if owned.managed {
            if let Some(tag) = tag {
                if tag == owned.outbound_tag {
                    return WarpOutboundClassification::Managed;
                }
            }
        }
    }

    let cloudflare_hint = probe
        .endpoint
        .as_deref()
        .is_some_and(endpoint_looks_like_cloudflare)
        || probe
            .peer_public_key
            .as_deref()
            .is_some_and(|key| key == CLOUDFLARE_WARP_PEER_PUBLIC_KEY)
        || tag.is_some_and(tag_looks_like_warp_hint);

    if cloudflare_hint {
        WarpOutboundClassification::PossibleWarp
    } else if ownership.is_some() {
        // Ownership exists for another tag — treat this WG outbound as external.
        WarpOutboundClassification::External
    } else {
        WarpOutboundClassification::Unknown
    }
}

/// Detects WARP-related outbounds from loaded sections + ownership.
pub fn detect_warp_outbounds(
    sections: &XrayConfigSections,
    ownership: Option<&WarpOwnershipRecord>,
) -> Vec<DetectedWarpOutbound> {
    let summaries = crate::xray::config::outbound_summaries(sections);
    let mut detected = Vec::new();

    for (index, sourced) in sections.outbounds().iter().enumerate() {
        let value = sourced.value();
        let protocol = value
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !protocol.eq_ignore_ascii_case("wireguard") {
            continue;
        }
        let tag = value
            .get("tag")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let probe = wireguard_probe(value);
        let classification = classify_wireguard_outbound(tag.as_deref(), &probe, ownership);
        let summary = summaries
            .get(index)
            .map(|row| row.description.clone())
            .unwrap_or_else(|| "WireGuard".to_owned());
        let classification = if classification == WarpOutboundClassification::Unknown {
            WarpOutboundClassification::External
        } else {
            classification
        };
        detected.push(DetectedWarpOutbound {
            index,
            tag,
            classification,
            endpoint: probe.endpoint.clone(),
            addresses: probe.addresses.clone(),
            peer_public_key: probe.peer_public_key.clone(),
            structurally_valid: probe.structurally_valid,
            summary,
        });
    }

    detected
}

/// Counts routing rules that reference `outbound_tag`.
pub fn count_routing_references(
    routing: Option<&RoutingSummary>,
    outbound_tag: &str,
) -> (usize, Vec<String>) {
    let Some(routing) = routing else {
        return (0, Vec::new());
    };
    let mut refs = Vec::new();
    for rule in &routing.rules {
        if rule
            .outbound_tag
            .as_deref()
            .is_some_and(|tag| tag == outbound_tag)
        {
            let criteria = if rule.criteria.is_empty() {
                "rule".to_owned()
            } else {
                rule.criteria.join(", ")
            };
            refs.push(format!("Rule #{} ({criteria})", rule.index + 1));
        }
    }
    (refs.len(), refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_managed_by_ownership_tag() {
        let probe = WireguardProbe {
            has_secret_key: true,
            addresses: vec!["172.16.0.2/32".into()],
            peer_public_key: Some(CLOUDFLARE_WARP_PEER_PUBLIC_KEY.into()),
            endpoint: Some("engage.cloudflareclient.com:2408".into()),
            structurally_valid: true,
        };
        let ownership = WarpOwnershipRecord {
            outbound_tag: "warp".into(),
            managed: true,
            helper_version: None,
        };
        assert_eq!(
            classify_wireguard_outbound(Some("warp"), &probe, Some(&ownership)),
            WarpOutboundClassification::Managed
        );
    }

    #[test]
    fn tag_alone_is_hint_not_managed() {
        let probe = WireguardProbe {
            has_secret_key: true,
            addresses: vec!["172.16.0.2/32".into()],
            peer_public_key: Some(CLOUDFLARE_WARP_PEER_PUBLIC_KEY.into()),
            endpoint: Some("engage.cloudflareclient.com:2408".into()),
            structurally_valid: true,
        };
        assert_eq!(
            classify_wireguard_outbound(Some("warp"), &probe, None),
            WarpOutboundClassification::PossibleWarp
        );
    }

    #[test]
    fn missing_secret_key_invalid() {
        let value = json!({
            "protocol": "wireguard",
            "tag": "warp",
            "settings": {
                "address": ["172.16.0.2/32"],
                "peers": [{
                    "publicKey": CLOUDFLARE_WARP_PEER_PUBLIC_KEY,
                    "endpoint": "engage.cloudflareclient.com:2408"
                }]
            }
        });
        let probe = wireguard_probe(&value);
        assert!(!probe.structurally_valid);
        assert_eq!(
            classify_wireguard_outbound(Some("warp"), &probe, None),
            WarpOutboundClassification::Invalid
        );
    }
}
