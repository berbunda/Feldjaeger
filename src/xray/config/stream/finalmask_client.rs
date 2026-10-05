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
//!
//! Import (stage 6.2, [`server_finalmask_from_client`]) reads the same table backwards: a pasted
//! link's `fm` becomes the new inbound's chains, without what only the client uses.

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

/// The server chains imported from a share link's `fm` (Roadmap §2.6 stage 6.2): the inverse of
/// [`client_finalmask`]. `None` for a chain with nothing to write.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerFinalMaskImport {
    /// `finalmask.tcp` layers for the new inbound.
    pub tcp: Option<Vec<FinalMaskLayerDraft>>,
    /// `finalmask.udp` layers for the new inbound.
    pub udp: Option<Vec<FinalMaskLayerDraft>>,
    /// What was not imported or was changed, one sentence each.
    pub warnings: Vec<String>,
}

/// Server chains from a share link's `fm` text (the client's `streamSettings.finalmask`).
///
/// The same layer table as [`client_finalmask`], read the other way: symmetric masks become the
/// server layer as they are; what only shapes the client's own traffic (`fragment`, `noise`) or
/// only works when dialing (`udphop`) has no server pair and is left out; client keys are removed
/// where the server ignores them (`xdns.resolvers`, `xmc.hostname`, `xicmp.dgram`) or reads them
/// differently (`xicmp.ips` — accepted peers on a server, targets on a client; `realm.ipMode` /
/// `portMapping` — the client's own network). `quicParams` tunes the client's QUIC stack and is
/// not imported. Every omission or change is reported, nothing is dropped silently.
pub fn server_finalmask_from_client(fm: &str) -> ServerFinalMaskImport {
    let mut import = ServerFinalMaskImport::default();
    let object = match serde_json::from_str::<Value>(fm) {
        Ok(Value::Object(object)) => object,
        Ok(_) => {
            import.warnings.push("`fm` is not a JSON object — FinalMask not imported.".to_owned());
            return import;
        }
        Err(_) => {
            import.warnings.push("`fm` is not valid JSON — FinalMask not imported.".to_owned());
            return import;
        }
    };
    for (key, value) in &object {
        let chain = match key.as_str() {
            "tcp" => FinalMaskChain::Tcp,
            "udp" => FinalMaskChain::Udp,
            "quicParams" => {
                import.warnings.push(
                    "fm.quicParams tunes the client's own QUIC stack — not imported; set the \
                     server's on the Stream tab if needed."
                        .to_owned(),
                );
                continue;
            }
            other => {
                import.warnings.push(format!("fm.{other} is not a FinalMask key — not imported."));
                continue;
            }
        };
        if value.is_null() {
            continue;
        }
        let Some(layers) = value.as_array().and_then(|array| super::finalmask::parse_finalmask_layers(array)) else {
            import.warnings.push(format!(
                "fm.{key} can't be read as a layer list — not imported; add the layers on the Stream tab."
            ));
            continue;
        };
        let mut server_layers = Vec::new();
        for layer in layers {
            let kind = layer.layer_type.trim().to_owned();
            let (settings, warning) = server_layer(chain, &kind, &layer.settings);
            import.warnings.extend(warning);
            if let Some(settings) = settings {
                server_layers.push(FinalMaskLayerDraft {
                    layer_type: kind,
                    settings: Value::Object(settings),
                });
            }
        }
        if !server_layers.is_empty() {
            match chain {
                FinalMaskChain::Tcp => import.tcp = Some(server_layers),
                FinalMaskChain::Udp => import.udp = Some(server_layers),
            }
        }
    }
    import
}

/// One client layer as the server needs it: the server's `settings` (`None` = no server pair)
/// and an optional warning.
fn server_layer(chain: FinalMaskChain, kind: &str, settings: &Value) -> (Option<Map<String, Value>>, Option<String>) {
    let mut settings = settings.as_object().cloned().unwrap_or_default();
    let location = format!("fm.{}", chain.key());
    let mut strip = |keys: &[&str], why: &str| {
        let removed: Vec<String> = keys
            .iter()
            .filter(|key| settings.remove(**key).is_some())
            .map(|key| format!("`{key}`"))
            .collect();
        (!removed.is_empty()).then(|| format!("{location}: `{kind}` — client keys {} not imported ({why}).", removed.join(", ")))
    };
    let warning = match (chain, kind.to_ascii_lowercase().as_str()) {
        (_, "fragment" | "noise") => {
            return (
                None,
                Some(format!(
                    "{location}: `{kind}` only shapes what the client sends — the server needs no \
                     matching layer; not imported."
                )),
            );
        }
        (_, "udphop") => {
            return (
                None,
                Some(format!("{location}: `{kind}` is client-only — a server cannot listen with it; not imported.")),
            );
        }
        (FinalMaskChain::Udp, "xicmp") => strip(
            &["ips", "dgram"],
            "on a server `ips` limits the accepted peers, `dgram` is ignored",
        ),
        (FinalMaskChain::Udp, "xdns") => strip(&["resolvers"], "the server ignores them"),
        (FinalMaskChain::Udp, "realm") => strip(&["ipMode", "portMapping"], "they describe the client's network"),
        (FinalMaskChain::Tcp, "xmc") => strip(&["hostname"], "the server ignores it"),
        (_, known) if COPIED_TYPES.contains(&known) => None,
        _ => Some(format!(
            "{location}: `{kind}` is not known to Feldjäger — imported as it is; check that the \
             server needs it."
        )),
    };
    (Some(settings), warning)
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

    #[test]
    fn import_keeps_symmetric_layers_and_reports_the_rest() {
        let fm = json!({
            "tcp": [
                {"type": "fragment", "settings": {"packets": "tlshello"}},
                {"type": "xmc", "settings": {"password": "p", "hostname": "mc.example.com", "profiles": []}},
                {"type": "sudoku", "settings": {"password": "s"}}
            ],
            "udp": [
                {"type": "udphop", "settings": {"remotePorts": "1000-2000"}},
                {"type": "xicmp", "settings": {"ips": ["203.0.113.7"], "dgram": true}},
                {"type": "xdns", "settings": {"domains": [{"names": ["t.example.com"]}], "resolvers": [{"addrs": ["1.1.1.1"]}]}},
                {"type": "realm", "settings": {"url": "realm://t@r.example.com/id", "stunServers": ["s:3478"], "ipMode": "4"}},
                {"type": "noise", "settings": {}},
                {"type": "future-mask", "settings": {}}
            ],
            "quicParams": {"congestion": "bbr"},
            "extra": 1
        });
        let import = server_finalmask_from_client(&fm.to_string());
        assert_eq!(
            import.tcp,
            Some(vec![
                layer("xmc", json!({"password": "p", "profiles": []})),
                layer("sudoku", json!({"password": "s"})),
            ])
        );
        assert_eq!(
            import.udp,
            Some(vec![
                layer("xicmp", json!({})),
                layer("xdns", json!({"domains": [{"names": ["t.example.com"]}]})),
                layer("realm", json!({"url": "realm://t@r.example.com/id", "stunServers": ["s:3478"]})),
                layer("future-mask", json!({})),
            ])
        );
        let warned = |needle: &str| import.warnings.iter().any(|w| w.contains(needle));
        for needle in ["`fragment`", "`hostname`", "`udphop`", "`ips`, `dgram`", "`resolvers`", "`ipMode`", "`noise`", "future-mask", "quicParams", "fm.extra"] {
            assert!(warned(needle), "no warning about {needle}: {:?}", import.warnings);
        }
        assert_eq!(import.warnings.len(), 10, "{:?}", import.warnings);
    }

    #[test]
    fn import_of_unreadable_fm_imports_nothing() {
        for (fm, needle) in [("not json", "valid JSON"), ("[1]", "JSON object"), (r#"{"tcp": {"type": "x"}}"#, "fm.tcp")] {
            let import = server_finalmask_from_client(fm);
            assert_eq!((import.tcp, import.udp), (None, None), "{fm}");
            assert!(import.warnings.iter().any(|w| w.contains(needle)), "{fm}: {:?}", import.warnings);
        }
        let only_client_side = server_finalmask_from_client(r#"{"tcp": [{"type": "fragment"}], "udp": null}"#);
        assert_eq!((only_client_side.tcp, only_client_side.udp), (None, None));
    }

    /// A server chain shared as `fm` and imported again comes back unchanged when it holds only
    /// symmetric layers.
    #[test]
    fn share_then_import_round_trips_symmetric_chains() {
        let tcp = vec![layer("header-custom", json!({"clients": [[{"rand": 4}]]})), layer("sudoku", json!({"password": "p"}))];
        let udp = vec![layer("mkcp-legacy", json!({"value": "seed"})), layer("salamander", json!({"password": "cat"}))];
        let fm = client_finalmask(&[(FinalMaskChain::Tcp, &tcp), (FinalMaskChain::Udp, &udp)]).expect("client");
        let import = server_finalmask_from_client(&fm.compact_json());
        assert_eq!((import.tcp, import.udp), (Some(tcp), Some(udp)));
        assert!(import.warnings.is_empty(), "{:?}", import.warnings);
    }
}
