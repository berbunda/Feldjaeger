//! Outbound General fields (tag / sendThrough / proxySettings) + Shell edit identity.

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// `proxySettings` — chains this outbound's traffic through another outbound's dialer, ahead of
/// this outbound's own `protocol`/`streamSettings` (Roadmap §2.1:58 follow-up; closes part of
/// backlog §4.2's "chain proxying: tag / transportLayer"). Protocol-agnostic — a sibling of
/// `settings`/`streamSettings`, not part of either. See
/// <https://xtls.github.io/en/config/outbound.html#outboundobject>.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxySettingsDraft {
    /// `tag` — the outbound to chain through. Required; an empty value is treated as "absent"
    /// (the whole `proxySettings` object is omitted on write).
    pub tag: String,
    /// `transportLayer` — when `true`, only the transport connection is reused from the target
    /// outbound (this outbound still runs its own protocol handshake). Default `false`.
    pub transport_layer: bool,
}

/// Full-state General form payload for an outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundGeneral {
    /// Outbound tag; empty/whitespace omits the key. Immutable on Shell Save by design —
    /// rename is a standalone action, `rename_outbound_tag` (Roadmap §2.4:99).
    pub tag: Option<String>,
    /// `sendThrough` bind address; empty omits the key.
    pub send_through: Option<String>,
    /// `proxySettings`; `None` (or an empty `tag`) omits the key.
    pub proxy_settings: Option<ProxySettingsDraft>,
}

/// Identity + fingerprint for an outbound Shell Save (mirrors [`super::InboundRef`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRef {
    /// Merged outbound index at edit intent.
    pub outbound_index: usize,
    /// SHA-256 hex of the full canonical outbound JSON at edit intent.
    pub expected_fingerprint: String,
}

/// Reads General fields for UI drafts from an outbound value.
pub fn parse_outbound_general(outbound: &Value) -> OutboundGeneral {
    let proxy_settings = outbound
        .get("proxySettings")
        .and_then(Value::as_object)
        .and_then(|object| {
            let tag = object
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_owned();
            if tag.is_empty() {
                return None;
            }
            Some(ProxySettingsDraft {
                tag,
                transport_layer: object
                    .get("transportLayer")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        });
    OutboundGeneral {
        tag: outbound.get("tag").and_then(Value::as_str).map(str::to_owned),
        send_through: outbound
            .get("sendThrough")
            .and_then(Value::as_str)
            .map(str::to_owned),
        proxy_settings,
    }
}

/// Applies General fields onto an outbound object in place.
pub fn apply_outbound_general(
    outbound: &mut Value,
    general: &OutboundGeneral,
) -> ConfigModifyResult<()> {
    let object = outbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "outbound is not a JSON object".to_owned(),
        )
    })?;

    apply_optional_string(object, "tag", general.tag.as_deref());
    apply_optional_string(object, "sendThrough", general.send_through.as_deref());

    let chain_tag = general
        .proxy_settings
        .as_ref()
        .map(|p| p.tag.trim())
        .filter(|tag| !tag.is_empty());
    match chain_tag {
        Some(tag) => {
            let mut proxy_settings = Map::new();
            proxy_settings.insert("tag".to_owned(), Value::String(tag.to_owned()));
            if general.proxy_settings.as_ref().is_some_and(|p| p.transport_layer) {
                proxy_settings.insert("transportLayer".to_owned(), Value::Bool(true));
            }
            object.insert("proxySettings".to_owned(), Value::Object(proxy_settings));
        }
        None => {
            object.remove("proxySettings");
        }
    }

    Ok(())
}

fn apply_optional_string(object: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        Some(text) => {
            object.insert(key.to_owned(), Value::String(text.to_owned()));
        }
        None => {
            object.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_reads_tag_and_send_through() {
        let outbound = json!({"tag": "direct", "sendThrough": "0.0.0.0", "protocol": "freedom"});
        let general = parse_outbound_general(&outbound);
        assert_eq!(general.tag.as_deref(), Some("direct"));
        assert_eq!(general.send_through.as_deref(), Some("0.0.0.0"));
    }

    #[test]
    fn apply_omits_empty_fields_and_preserves_siblings() {
        let mut outbound = json!({"protocol": "freedom", "settings": {}, "mux": {"enabled": true}});
        apply_outbound_general(
            &mut outbound,
            &OutboundGeneral {
                tag: Some("direct".to_owned()),
                send_through: Some(String::new()),
                proxy_settings: None,
            },
        )
        .expect("apply");
        assert_eq!(outbound["tag"], "direct");
        assert!(outbound.get("sendThrough").is_none());
        assert_eq!(outbound["mux"]["enabled"], true);
    }

    #[test]
    fn parse_reads_proxy_settings() {
        let outbound = json!({
            "protocol": "vless",
            "proxySettings": {"tag": "chain-out", "transportLayer": true}
        });
        let general = parse_outbound_general(&outbound);
        let proxy_settings = general.proxy_settings.expect("proxySettings");
        assert_eq!(proxy_settings.tag, "chain-out");
        assert!(proxy_settings.transport_layer);
    }

    #[test]
    fn empty_tag_proxy_settings_parses_as_absent() {
        let outbound = json!({"protocol": "freedom", "proxySettings": {"tag": ""}});
        assert!(parse_outbound_general(&outbound).proxy_settings.is_none());
    }

    #[test]
    fn apply_writes_and_removes_proxy_settings() {
        let mut outbound = json!({"protocol": "freedom", "settings": {}});
        apply_outbound_general(
            &mut outbound,
            &OutboundGeneral {
                tag: None,
                send_through: None,
                proxy_settings: Some(ProxySettingsDraft {
                    tag: "chain-out".to_owned(),
                    transport_layer: true,
                }),
            },
        )
        .expect("apply");
        assert_eq!(outbound["proxySettings"]["tag"], "chain-out");
        assert_eq!(outbound["proxySettings"]["transportLayer"], true);

        apply_outbound_general(
            &mut outbound,
            &OutboundGeneral {
                tag: None,
                send_through: None,
                proxy_settings: None,
            },
        )
        .expect("apply");
        assert!(outbound.get("proxySettings").is_none());
    }

    #[test]
    fn apply_omits_proxy_settings_with_empty_tag() {
        let mut outbound = json!({"protocol": "freedom", "settings": {}});
        apply_outbound_general(
            &mut outbound,
            &OutboundGeneral {
                tag: None,
                send_through: None,
                proxy_settings: Some(ProxySettingsDraft {
                    tag: String::new(),
                    transport_layer: false,
                }),
            },
        )
        .expect("apply");
        assert!(outbound.get("proxySettings").is_none());
    }
}
