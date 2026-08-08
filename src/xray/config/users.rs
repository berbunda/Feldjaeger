//! Read-only inbound client summaries extracted from configuration sections.
//!
//! The GUI must not dig into `settings.clients` / `settings.users` itself.
//! Extraction stays in the Xray model layer so raw JSON remains untouched.

use serde_json::Value;

use super::inbound_clients::InboundClientProtocol;
use super::sections::XrayConfigSections;
use super::summary::InboundSummary;

/// Protocol names supported for the Users list in IB-L1.
pub const SUPPORTED_USER_PROTOCOL: &str = "vless";

/// Read-only summary of one VLESS inbound client / user.
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

/// Read-only summary of one Trojan inbound client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanClientSummary {
    /// Parent inbound index.
    pub inbound_index: usize,
    /// Parent inbound tag.
    pub inbound_tag: Option<String>,
    /// Source file.
    pub source_file: String,
    /// Client index.
    pub client_index: usize,
    /// Email when present.
    pub email: Option<String>,
    /// Whether a non-empty password is present (never the secret itself).
    pub has_password: bool,
}

/// Read-only summary of one Hysteria inbound user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaClientSummary {
    /// Parent inbound index.
    pub inbound_index: usize,
    /// Parent inbound tag.
    pub inbound_tag: Option<String>,
    /// Source file.
    pub source_file: String,
    /// Client index.
    pub client_index: usize,
    /// Email when present.
    pub email: Option<String>,
    /// Whether a non-empty auth is present (never the secret itself).
    pub has_auth: bool,
    /// Policy level (default 0 when absent on wire).
    pub level: u32,
}

/// Enum read model for Users tab (IB-L1 / Wave A).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundClientSummary {
    /// VLESS client row.
    Vless(VlessClientSummary),
    /// Trojan client row.
    Trojan(TrojanClientSummary),
    /// Hysteria user row.
    Hysteria(HysteriaClientSummary),
}

impl InboundClientSummary {
    /// Parent inbound index.
    pub fn inbound_index(&self) -> usize {
        match self {
            Self::Vless(c) => c.inbound_index,
            Self::Trojan(c) => c.inbound_index,
            Self::Hysteria(c) => c.inbound_index,
        }
    }

    /// Client index inside the array.
    pub fn client_index(&self) -> usize {
        match self {
            Self::Vless(c) => c.client_index,
            Self::Trojan(c) => c.client_index,
            Self::Hysteria(c) => c.client_index,
        }
    }

    /// Display email when present.
    pub fn email(&self) -> Option<&str> {
        match self {
            Self::Vless(c) => c.email.as_deref(),
            Self::Trojan(c) => c.email.as_deref(),
            Self::Hysteria(c) => c.email.as_deref(),
        }
    }
}

/// Alias used by legacy Users page APIs (VLESS-only list).
pub type UserSummary = VlessClientSummary;

/// One inbound that can appear in the Users page selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedUserInbound {
    /// Index into the merged inbound list.
    pub inbound_index: usize,
    /// Inbound tag, when present.
    pub tag: Option<String>,
    /// Protocol string.
    pub protocol: String,
    /// Listen port, when present.
    pub port: Option<u64>,
    /// Number of extracted clients for this inbound.
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

/// Extracts VLESS + Trojan clients (order preserved).
pub fn extract_inbound_clients(sections: &XrayConfigSections) -> Vec<InboundClientSummary> {
    let mut clients = Vec::new();

    for (inbound_index, inbound) in sections.inbounds().iter().enumerate() {
        let Some(protocol) = inbound
            .value()
            .get("protocol")
            .and_then(Value::as_str)
            .and_then(InboundClientProtocol::from_wire)
        else {
            continue;
        };
        if !protocol.mutate_enabled() {
            continue;
        }

        let inbound_tag = string_field(inbound.value(), "tag");
        let source_file = inbound.source_file().to_owned();

        for (client_index, client) in client_objects(inbound.value()).into_iter().enumerate() {
            match protocol {
                InboundClientProtocol::Vless => {
                    clients.push(InboundClientSummary::Vless(VlessClientSummary {
                        inbound_index,
                        inbound_tag: inbound_tag.clone(),
                        source_file: source_file.clone(),
                        client_index,
                        id: string_field(client, "id"),
                        email: string_field(client, "email"),
                        flow: string_field(client, "flow"),
                    }));
                }
                InboundClientProtocol::Trojan => {
                    let has_password = client
                        .get("password")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .is_some_and(|s| !s.is_empty());
                    clients.push(InboundClientSummary::Trojan(TrojanClientSummary {
                        inbound_index,
                        inbound_tag: inbound_tag.clone(),
                        source_file: source_file.clone(),
                        client_index,
                        email: string_field(client, "email"),
                        has_password,
                    }));
                }
                InboundClientProtocol::Tunnel => {}
                InboundClientProtocol::Hysteria => {
                    let has_auth = client
                        .get("auth")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .is_some_and(|s| !s.is_empty());
                    let level = client
                        .get("level")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as u32;
                    clients.push(InboundClientSummary::Hysteria(HysteriaClientSummary {
                        inbound_index,
                        inbound_tag: inbound_tag.clone(),
                        source_file: source_file.clone(),
                        client_index,
                        email: string_field(client, "email"),
                        has_auth,
                        level,
                    }));
                }
            }
        }
    }

    clients
}

/// Extracts VLESS clients from all inbounds (order preserved).
pub fn extract_vless_clients(sections: &XrayConfigSections) -> Vec<VlessClientSummary> {
    extract_inbound_clients(sections)
        .into_iter()
        .filter_map(|client| match client {
            InboundClientSummary::Vless(summary) => Some(summary),
            InboundClientSummary::Trojan(_) | InboundClientSummary::Hysteria(_) => None,
        })
        .collect()
}

/// Builds the selector list of inbounds that support Users mutate (VLESS + Trojan).
pub fn supported_user_inbounds(
    inbounds: &[InboundSummary],
    clients: &[InboundClientSummary],
) -> Vec<SupportedUserInbound> {
    inbounds
        .iter()
        .filter(|inbound| {
            inbound
                .protocol
                .as_deref()
                .and_then(InboundClientProtocol::from_wire)
                .is_some_and(|p| p.mutate_enabled())
        })
        .map(|inbound| {
            let clients_count = clients
                .iter()
                .filter(|client| client.inbound_index() == inbound.index)
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
    clients: &[InboundClientSummary],
    inbound_index: usize,
) -> Vec<InboundClientSummary> {
    clients
        .iter()
        .filter(|client| client.inbound_index() == inbound_index)
        .cloned()
        .collect()
}

/// Filters VLESS client summaries to one inbound index (legacy helper).
pub fn vless_clients_for_inbound(
    clients: &[VlessClientSummary],
    inbound_index: usize,
) -> Vec<VlessClientSummary> {
    clients
        .iter()
        .filter(|client| client.inbound_index == inbound_index)
        .cloned()
        .collect()
}

/// Builds the selector list from VLESS-only summaries (legacy Users page).
pub fn supported_vless_user_inbounds(
    inbounds: &[InboundSummary],
    clients: &[VlessClientSummary],
) -> Vec<SupportedUserInbound> {
    let mapped: Vec<InboundClientSummary> = clients
        .iter()
        .cloned()
        .map(InboundClientSummary::Vless)
        .collect();
    supported_user_inbounds(inbounds, &mapped)
}

fn client_objects(inbound: &Value) -> Vec<&Value> {
    let settings = match inbound.get("settings") {
        Some(settings) => settings,
        None => return Vec::new(),
    };

    if let Some(array) = settings.get("clients").and_then(Value::as_array) {
        return array.iter().collect();
    }

    if let Some(array) = settings.get("users").and_then(Value::as_array) {
        return array.iter().collect();
    }

    Vec::new()
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn display_protocol_label(protocol: &str) -> String {
    match protocol.to_ascii_lowercase().as_str() {
        "vless" => "VLESS".to_owned(),
        "trojan" => "Trojan".to_owned(),
        "hysteria" => "Hysteria".to_owned(),
        _ => protocol.to_owned(),
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
                    "settings":{"clients":[{"id":"a","email":"a@b.c"}]}
                }]
            }"#,
        );
        assert!(outcome.is_success());
        let clients = extract_vless_clients(outcome.sections());
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id.as_deref(), Some("a"));
    }

    #[test]
    fn extracts_trojan_clients() {
        let outcome = XrayConfigParser::new().parse_str(
            r#"{
                "inbounds":[{
                    "tag":"tr",
                    "protocol":"trojan",
                    "settings":{"clients":[{"password":"secret","email":"t@e"}]}
                }]
            }"#,
        );
        assert!(outcome.is_success());
        let clients = extract_inbound_clients(outcome.sections());
        assert_eq!(clients.len(), 1);
        match &clients[0] {
            InboundClientSummary::Trojan(t) => {
                assert!(t.has_password);
                assert_eq!(t.email.as_deref(), Some("t@e"));
            }
            _ => panic!("expected trojan"),
        }
    }

    #[test]
    fn extracts_hysteria_clients_from_users_array() {
        let outcome = XrayConfigParser::new().parse_str(
            r#"{
                "inbounds":[{
                    "tag":"hy",
                    "protocol":"hysteria",
                    "settings":{"version":2,"users":[{"auth":"secret","email":"h@e","level":1}]}
                }]
            }"#,
        );
        assert!(outcome.is_success());
        let clients = extract_inbound_clients(outcome.sections());
        assert_eq!(clients.len(), 1);
        match &clients[0] {
            InboundClientSummary::Hysteria(h) => {
                assert!(h.has_auth);
                assert_eq!(h.email.as_deref(), Some("h@e"));
                assert_eq!(h.level, 1);
            }
            _ => panic!("expected hysteria"),
        }
    }
}
