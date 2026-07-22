//! Read-only VLESS client summaries extracted from configuration sections.
//!
//! The GUI must not dig into `settings.clients` / `settings.users` itself.
//! Extraction stays in the Xray model layer so raw JSON remains untouched.

use serde_json::Value;

use super::sections::XrayConfigSections;
use super::summary::InboundSummary;

/// Protocol name currently supported for the Users page client list.
pub const SUPPORTED_USER_PROTOCOL: &str = "vless";

/// Read-only summary of one VLESS inbound client / user.
///
/// Fields mirror the official UserObject / classic client object (`id`, `email`,
/// `flow`). There is no `enabled` flag in stock Xray VLESS config, so it is not
/// invented here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessClientSummary {
    /// Zero-based index of the parent inbound in the merged inbound list.
    pub inbound_index: usize,
    /// Parent inbound `tag`, when present.
    pub inbound_tag: Option<String>,
    /// File that contributed the parent inbound.
    pub source_file: String,
    /// Zero-based index inside that inbound's clients/users array.
    pub client_index: usize,
    /// Client `id` (UUID or custom string).
    pub id: Option<String>,
    /// Client `email` used for stats / logs.
    pub email: Option<String>,
    /// Optional XTLS `flow` (for example `xtls-rprx-vision`).
    pub flow: Option<String>,
}

/// Alias used by the Users page and ApplicationService APIs.
pub type UserSummary = VlessClientSummary;

/// One inbound that can appear in the Users page selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedUserInbound {
    /// Index into the merged inbound list.
    pub inbound_index: usize,
    /// Inbound tag, when present.
    pub tag: Option<String>,
    /// Protocol string (currently always `vless` for this list).
    pub protocol: String,
    /// Listen port, when present.
    pub port: Option<u64>,
    /// Number of extracted VLESS clients for this inbound.
    pub clients_count: usize,
    /// Source file of the inbound.
    pub source_file: String,
}

impl SupportedUserInbound {
    /// Combo-box label: `tag · VLESS · :443`.
    pub fn label(&self) -> String {
        let tag = self
            .tag
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("—");
        let protocol = display_protocol_label(&self.protocol);
        let port = self
            .port
            .map(|port| format!(":{port}"))
            .unwrap_or_else(|| ":—".to_owned());
        format!("{tag} · {protocol} · {port}")
    }
}

/// Extracts VLESS clients from all inbounds (order preserved).
///
/// Looks at `settings.clients` first (classic / widely deployed), then
/// `settings.users` (current English docs UserObject array). Unknown nested
/// fields are ignored; the sourced inbound JSON is never modified.
pub fn extract_vless_clients(sections: &XrayConfigSections) -> Vec<VlessClientSummary> {
    let mut clients = Vec::new();

    for (inbound_index, inbound) in sections.inbounds().iter().enumerate() {
        if !is_vless_inbound(inbound.value()) {
            continue;
        }

        let inbound_tag = string_field(inbound.value(), "tag");
        let source_file = inbound.source_file().to_owned();

        for (client_index, client) in client_objects(inbound.value()).into_iter().enumerate() {
            clients.push(VlessClientSummary {
                inbound_index,
                inbound_tag: inbound_tag.clone(),
                source_file: source_file.clone(),
                client_index,
                id: string_field(client, "id"),
                email: string_field(client, "email"),
                flow: string_field(client, "flow"),
            });
        }
    }

    clients
}

/// Builds the selector list of inbounds that support the Users page (VLESS).
pub fn supported_user_inbounds(
    inbounds: &[InboundSummary],
    clients: &[VlessClientSummary],
) -> Vec<SupportedUserInbound> {
    inbounds
        .iter()
        .filter(|inbound| {
            inbound
                .protocol
                .as_deref()
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case(SUPPORTED_USER_PROTOCOL))
        })
        .map(|inbound| {
            let clients_count = clients
                .iter()
                .filter(|client| client.inbound_index == inbound.index)
                .count();
            SupportedUserInbound {
                inbound_index: inbound.index,
                tag: inbound.tag.clone(),
                protocol: inbound
                    .protocol
                    .clone()
                    .unwrap_or_else(|| SUPPORTED_USER_PROTOCOL.to_owned()),
                port: inbound.port,
                clients_count,
                source_file: inbound.source_file.clone(),
            }
        })
        .collect()
}

/// Filters client summaries to one inbound index.
pub fn clients_for_inbound(
    clients: &[VlessClientSummary],
    inbound_index: usize,
) -> Vec<VlessClientSummary> {
    clients
        .iter()
        .filter(|client| client.inbound_index == inbound_index)
        .cloned()
        .collect()
}

fn is_vless_inbound(value: &Value) -> bool {
    value
        .get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|protocol| protocol.eq_ignore_ascii_case(SUPPORTED_USER_PROTOCOL))
}

fn client_objects(inbound: &Value) -> Vec<&Value> {
    let settings = match inbound.get("settings") {
        Some(settings) => settings,
        None => return Vec::new(),
    };

    // Classic field name used by most deployed configs and our fixtures.
    if let Some(array) = settings.get("clients").and_then(Value::as_array) {
        return array.iter().collect();
    }

    // Official English docs currently document `users` for VLESS UserObject.
    if let Some(array) = settings.get("users").and_then(Value::as_array) {
        return array.iter().collect();
    }

    Vec::new()
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn display_protocol_label(protocol: &str) -> String {
    if protocol.eq_ignore_ascii_case("vless") {
        "VLESS".to_owned()
    } else {
        protocol.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::config::XrayConfigParser;

    #[test]
    fn extracts_clients_array() {
        let outcome = XrayConfigParser::new().parse_str(
            r#"{
                "inbounds":[{
                    "tag":"vless-in",
                    "protocol":"vless",
                    "port":443,
                    "settings":{
                        "clients":[
                            {"id":"u1","email":"a@example.com","flow":"xtls-rprx-vision"},
                            {"id":"u2","email":"b@example.com"}
                        ],
                        "decryption":"none"
                    }
                }]
            }"#,
        );
        let clients = extract_vless_clients(outcome.sections());
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].email.as_deref(), Some("a@example.com"));
        assert_eq!(clients[0].id.as_deref(), Some("u1"));
        assert_eq!(clients[0].flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(clients[0].inbound_tag.as_deref(), Some("vless-in"));
        assert!(clients[1].flow.is_none());
    }

    #[test]
    fn extracts_users_array_from_docs_shape() {
        let outcome = XrayConfigParser::new().parse_str(
            r#"{
                "inbounds":[{
                    "tag":"docs",
                    "protocol":"vless",
                    "settings":{
                        "users":[{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","email":"love@xray.com"}],
                        "decryption":"none"
                    }
                }]
            }"#,
        );
        let clients = extract_vless_clients(outcome.sections());
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].email.as_deref(), Some("love@xray.com"));
    }

    #[test]
    fn ignores_non_vless_inbounds() {
        let outcome = XrayConfigParser::new().parse_str(
            r#"{
                "inbounds":[{
                    "tag":"vmess-in",
                    "protocol":"vmess",
                    "settings":{"clients":[{"id":"x","email":"x@x"}]}
                }]
            }"#,
        );
        assert!(extract_vless_clients(outcome.sections()).is_empty());
    }

    #[test]
    fn supported_inbound_label_format() {
        let choice = SupportedUserInbound {
            inbound_index: 0,
            tag: Some("vless-reality-443".to_owned()),
            protocol: "vless".to_owned(),
            port: Some(443),
            clients_count: 1,
            source_file: "/etc/xray/config.json".to_owned(),
        };
        assert_eq!(choice.label(), "vless-reality-443 · VLESS · :443");
    }
}
