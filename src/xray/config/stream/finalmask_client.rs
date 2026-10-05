//! The client side of an inbound's FinalMask chain (Roadmap §2.6 stage 6.1) — what a share link
//! carries as `fm` and what "Copy client finalmask JSON" copies.
//!
//! The VLESS / VMess share-link standard (XTLS/Xray-core discussion #716, §4.3.20, since
//! 2026-01-31) has `fm`: "corresponds to the `finalmask` item of the config; like XHTTP `extra`
//! the whole JSON is shared, `encodeURIComponent`-escaped". Clients put it into the outbound's
//! `streamSettings.finalmask` as it is (v2rayN `BaseFmt` reads it for `vless://` and `trojan://`
//! alike, and it replaces the finalmask the client would build itself).
//!
//! So the link must hold the *client's* chain, not the server's. Both sides list layers in the
//! same order (the first element innermost), and most masks are symmetric — the client needs the
//! same layer with the same settings. Derived from Xray-core (`transport/internet/finalmask/*`,
//! `infra/conf/transport_finalmask.go`):
//! - `fragment` and `noise` act only on what their own side writes (`fragment/conn.go`,
//!   `noise/conn.go` read through); the client needs no pair, and the server's choice of cuts or
//!   junk is no client setting — dropped. A dropped layer does not shift the others: on reads it
//!   was a pass-through anyway;
//! - `udphop` is client-only and never on an inbound (refused on save) — dropped if found;
//! - `xicmp.ips` means "accepted peer IPs" on the server and "IPs to send to" on the client
//!   (`xicmp/server.go` vs `client.go`; empty = the dialed address) — removed;
//! - `realm.ipMode` / `realm.portMapping` describe the local network of their side (address
//!   family, UPnP / NAT-PMP mapping on the gateway) — removed; `url`, `stunServers`, `tlsConfig`
//!   are the realm server both sides meet at;
//! - `xdns` needs `resolvers` on the client — the server ignores them, so it usually has none and
//!   the client must add its own (a note says so);
//! - everything else (`header-custom`, `sudoku`, `xmc`, `mkcp-legacy`, `salamander`, …) is copied
//!   as it is, client-only keys the server ignores (`xmc.hostname`, `xicmp.dgram`) included;
//!   a type Feldjäger does not know is copied with a note.
//!
//! `quicParams` is not shared: its fields tune each side's own QUIC stack (rates, windows,
//! timeouts), the client keeps its defaults.

use serde_json::{Map, Value};

use super::finalmask::{FinalMaskChain, FinalMaskLayerDraft};

/// The client's `streamSettings.finalmask`, derived from an inbound's chains.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientFinalMask {
    /// `{"tcp": [...]}` and / or `{"udp": [...]}` — only chains with layers.
    pub value: Value,
    /// Types of the layers the client mirrors, in chain order (`tcp` first).
    pub layer_types: Vec<String>,
    /// What the client still has to add or check, one sentence each.
    pub notes: Vec<String>,
}

impl ClientFinalMask {
    /// One-line JSON for the share link's `fm` (the caller percent-encodes it).
    pub fn compact_json(&self) -> String {
        self.value.to_string()
    }

    /// Indented JSON for pasting into a client config.
    pub fn pretty_json(&self) -> String {
        serde_json::to_string_pretty(&self.value).unwrap_or_else(|_| self.value.to_string())
    }
}

/// Mask types known to Feldjäger whose client layer is the server layer as it is.
const COPIED_TYPES: &[&str] = &["header-custom", "sudoku", "xmc", "mkcp-legacy", "salamander"];

/// The client chain for the chains the inbound's listeners use (`chains`; pass only those — an
/// unused chain is not the client's business). `None` when no layer needs a client pair.
pub fn client_finalmask(chains: &[(FinalMaskChain, &[FinalMaskLayerDraft])]) -> Option<ClientFinalMask> {
    let mut object = Map::new();
    let mut layer_types = Vec::new();
    let mut notes = Vec::new();
    for &(chain, layers) in chains {
        let mut client_layers = Vec::new();
        for layer in layers {
            let kind = layer.layer_type.trim();
            let Some((settings, note)) = client_layer(chain, kind, &layer.settings) else {
                continue;
            };
            let mut entry = Map::new();
            entry.insert("type".to_owned(), Value::String(kind.to_owned()));
            entry.insert("settings".to_owned(), Value::Object(settings));
            client_layers.push(Value::Object(entry));
            layer_types.push(kind.to_owned());
            notes.extend(note);
        }
        if !client_layers.is_empty() {
            object.insert(chain.key().to_owned(), Value::Array(client_layers));
        }
    }
    if object.is_empty() {
        return None;
    }
    Some(ClientFinalMask {
        value: Value::Object(object),
        layer_types,
        notes,
    })
}

/// One server layer as the client needs it: `None` when the client needs no pair, otherwise the
/// client's `settings` and an optional note.
fn client_layer(chain: FinalMaskChain, kind: &str, settings: &Value) -> Option<(Map<String, Value>, Option<String>)> {
    let mut settings = settings.as_object().cloned().unwrap_or_default();
    let lower = kind.to_ascii_lowercase();
    let note = match (chain, lower.as_str()) {
        (_, "fragment" | "noise" | "udphop") => return None,
        (FinalMaskChain::Udp, "xicmp") => {
            settings.remove("ips");
            None
        }
        (FinalMaskChain::Udp, "realm") => {
            settings.remove("ipMode");
            settings.remove("portMapping");
            None
        }
        (FinalMaskChain::Udp, "xdns") => {
            let has_resolvers = settings
                .get("resolvers")
                .and_then(Value::as_array)
                .is_some_and(|resolvers| !resolvers.is_empty());
            (!has_resolvers).then(|| {
                format!(
                    "{chain_key}: `{kind}` — add `resolvers` on the client (the DNS resolver it tunnels \
                     through); the server has none to share",
                    chain_key = chain.key()
                )
            })
        }
        (_, known) if COPIED_TYPES.contains(&known) => None,
        _ => Some(format!(
            "{chain_key}: `{kind}` is not known to Feldjäger — copied as it is; check whether the \
             client needs it",
            chain_key = chain.key()
        )),
    };
    Some((settings, note))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn layer(kind: &str, settings: Value) -> FinalMaskLayerDraft {
        FinalMaskLayerDraft {
            layer_type: kind.to_owned(),
            settings,
        }
    }

    #[test]
    fn one_sided_layers_are_dropped_and_symmetric_ones_copied() {
        let tcp = vec![
            layer("fragment", json!({"packets": "tlshello"})),
            layer("Sudoku", json!({"password": "p", "paddingMax": 4})),
            layer("header-custom", json!({"clients": [[{"rand": 4}]], "servers": [[{"rand": 4}]]})),
        ];
        let udp = vec![
            layer("noise", json!({"noise": [{"rand": "10-20"}]})),
            layer("mkcp-legacy", json!({"value": "seed"})),
            layer("salamander", json!({"password": "cat", "packetSize": "512-1200"})),
        ];
        let client = client_finalmask(&[(FinalMaskChain::Tcp, &tcp), (FinalMaskChain::Udp, &udp)]).expect("client");
        assert_eq!(
            client.value,
            json!({
                "tcp": [
                    {"type": "Sudoku", "settings": {"password": "p", "paddingMax": 4}},
                    {"type": "header-custom", "settings": {"clients": [[{"rand": 4}]], "servers": [[{"rand": 4}]]}}
                ],
                "udp": [
                    {"type": "mkcp-legacy", "settings": {"value": "seed"}},
                    {"type": "salamander", "settings": {"password": "cat", "packetSize": "512-1200"}}
                ]
            })
        );
        assert_eq!(client.layer_types, ["Sudoku", "header-custom", "mkcp-legacy", "salamander"]);
        assert!(client.notes.is_empty());
        assert_eq!(client.compact_json(), client.value.to_string());
    }

    #[test]
    fn nothing_to_mirror_is_none() {
        let tcp = vec![layer("fragment", json!({}))];
        let udp = vec![layer("noise", json!({})), layer("udphop", json!({"remotePorts": "1-2"}))];
        assert_eq!(client_finalmask(&[(FinalMaskChain::Tcp, &tcp), (FinalMaskChain::Udp, &udp)]), None);
        assert_eq!(client_finalmask(&[]), None);
    }

    #[test]
    fn side_specific_keys_are_removed() {
        let udp = vec![
            layer("xicmp", json!({"ips": ["203.0.113.7"], "dgram": true})),
            layer(
                "realm",
                json!({
                    "url": "realm://t@realm.example.com/id",
                    "stunServers": ["stun.example.com:3478"],
                    "ipMode": "4",
                    "portMapping": {"enabled": true}
                }),
            ),
        ];
        let client = client_finalmask(&[(FinalMaskChain::Udp, &udp)]).expect("client");
        assert_eq!(
            client.value["udp"],
            json!([
                {"type": "xicmp", "settings": {"dgram": true}},
                {"type": "realm", "settings": {"url": "realm://t@realm.example.com/id", "stunServers": ["stun.example.com:3478"]}}
            ])
        );
        assert!(client.notes.is_empty());
    }

    #[test]
    fn xdns_without_resolvers_and_unknown_types_get_notes() {
        let udp = vec![
            layer("xdns", json!({"domains": [{"names": ["t.example.com"]}]})),
            layer("future-mask", json!({"k": 1})),
        ];
        let client = client_finalmask(&[(FinalMaskChain::Udp, &udp)]).expect("client");
        assert_eq!(client.value["udp"][0]["settings"], json!({"domains": [{"names": ["t.example.com"]}]}));
        assert_eq!(client.value["udp"][1], json!({"type": "future-mask", "settings": {"k": 1}}));
        assert_eq!(client.notes.len(), 2);
        assert!(client.notes[0].contains("resolvers"));
        assert!(client.notes[1].contains("future-mask"));

        let with_resolvers = vec![layer("xdns", json!({"domains": [], "resolvers": [{"addrs": ["1.1.1.1"]}]}))];
        let client = client_finalmask(&[(FinalMaskChain::Udp, &with_resolvers)]).expect("client");
        assert!(client.notes.is_empty());
    }
}
