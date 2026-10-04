//! `streamSettings.finalmask` `tcp[]` / `udp[]` masking-layer chains (Roadmap §2.3:86).
//!
//! FinalMask is Xray-core's reworked TCP/UDP packet-masking subsystem: a sibling of
//! `realitySettings`/`tlsSettings` under `streamSettings`, applying the final layer of
//! disguise after transport and security processing. Each array holds ordered layers of
//! `{ "type": string, "settings": object }`; the first element is the innermost layer.
//! See <https://xtls.github.io/ru/config/transports/finalmask.html>.

use serde_json::{Map, Value};

use super::StreamDirection;
use super::finalmask_layers::{
    parse_fragment_mask_settings, parse_noise_mask_settings, parse_realm_settings,
    parse_salamander_settings, parse_sudoku_settings, parse_udphop_settings, parse_xdns_settings,
    parse_xicmp_settings, validate_fragment_mask_settings, validate_noise_mask_settings,
    validate_realm_settings, validate_salamander_settings, validate_sudoku_settings,
    validate_udphop_settings, validate_xdns_settings,
    validate_xicmp_settings, xdns_has_legacy_fields,
};
use super::finalmask_mkcp::validate_mkcp_legacy;
use super::finalmask_xmc::validate_xmc;
use super::finalmask_raw::{
    validate_header_custom_tcp, validate_header_custom_udp, validate_header_custom_udp_sizes,
};
use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Documented `finalmask.tcp[].type` values.
pub const TCP_FINALMASK_TYPES: &[&str] = &["header-custom", "fragment", "sudoku", "xmc"];

/// Documented `finalmask.udp[].type` values.
pub const UDP_FINALMASK_TYPES: &[&str] = &[
    "header-custom",
    "mkcp-legacy",
    "noise",
    "salamander",
    "sudoku",
    "xdns",
    "xicmp",
    "realm",
    "udphop",
];

/// `finalmask.udp[].type` values that only work on the dialing side: their server wrapper fails
/// (`udphop`: `WrapPacketConnServer` returns `"udphop: client only"`), so an inbound's UDP
/// listener cannot start with them — and `xray run -test` does not notice, it never listens.
pub const CLIENT_ONLY_UDP_FINALMASK_TYPES: &[&str] = &["udphop"];

/// Which `finalmask` layer chain a list of layers belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FinalMaskChain {
    /// `finalmask.tcp[]`.
    Tcp,
    /// `finalmask.udp[]`.
    Udp,
}

impl FinalMaskChain {
    /// The JSON key under `finalmask` (`"tcp"` / `"udp"`).
    pub fn key(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// The documented layer types of this chain.
    pub fn types(self) -> &'static [&'static str] {
        match self {
            Self::Tcp => TCP_FINALMASK_TYPES,
            Self::Udp => UDP_FINALMASK_TYPES,
        }
    }

    /// The other chain.
    pub fn other(self) -> Self {
        match self {
            Self::Tcp => Self::Udp,
            Self::Udp => Self::Tcp,
        }
    }
}

/// Whether a layer of `layer_type` works in `chain` on the `direction` side. Matching is
/// case-insensitive like the core's loader (`LoadWithID` lower-cases the id); unknown types
/// apply (the core decides, and `xray run -test` reports it).
pub fn finalmask_layer_type_applies(
    layer_type: &str,
    chain: FinalMaskChain,
    direction: StreamDirection,
) -> bool {
    let client_only = chain == FinalMaskChain::Udp
        && CLIENT_ONLY_UDP_FINALMASK_TYPES
            .iter()
            .any(|kind| layer_type.trim().eq_ignore_ascii_case(kind));
    !(client_only && direction == StreamDirection::Inbound)
}

/// One `finalmask.tcp[]` / `finalmask.udp[]` masking layer.
///
/// `settings` is preserved as a raw JSON object (same trust boundary as
/// [`crate::xray::config::inbound_security::TlsSettingsDraft::ech_sockopt`]) — FinalMask layer
/// types have many type-specific sub-fields, so Feldjäger models the layer chain (type +
/// ordering) as typed data while leaving each layer's settings as opaque JSON per
/// `docs/rules.md`'s "rare/advanced fields may be displayed through generic JSON" allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalMaskLayerDraft {
    /// `type` (preset from [`TCP_FINALMASK_TYPES`] / [`UDP_FINALMASK_TYPES`], or free text for
    /// unlisted/future types).
    pub layer_type: String,
    /// `settings` object (defaults to an empty object).
    pub settings: Value,
}

impl Default for FinalMaskLayerDraft {
    fn default() -> Self {
        Self {
            layer_type: String::new(),
            settings: Value::Object(Map::new()),
        }
    }
}

/// Parses a `finalmask.tcp` / `finalmask.udp` array into typed layers.
///
/// Returns `None` when any element doesn't match `{ "type": string, "settings"?: object }` —
/// callers should then leave the array untouched/preserved-raw instead of "owning" it, matching
/// the existing `finalmask` non-object preservation fallback for `quicParams`.
pub fn parse_finalmask_layers(array: &[Value]) -> Option<Vec<FinalMaskLayerDraft>> {
    array
        .iter()
        .map(|entry| {
            let object = entry.as_object()?;
            let layer_type = object.get("type")?.as_str()?.to_owned();
            let settings = match object.get("settings") {
                Some(value) if value.is_object() => value.clone(),
                Some(_) => return None,
                None => Value::Object(Map::new()),
            };
            Some(FinalMaskLayerDraft {
                layer_type,
                settings,
            })
        })
        .collect()
}

/// Builds the `finalmask.tcp` / `finalmask.udp` array `Value` from typed layers.
pub fn finalmask_layers_to_value(layers: &[FinalMaskLayerDraft]) -> Value {
    Value::Array(
        layers
            .iter()
            .map(|layer| {
                let mut object = Map::new();
                object.insert(
                    "type".to_owned(),
                    Value::String(layer.layer_type.trim().to_owned()),
                );
                object.insert("settings".to_owned(), layer.settings.clone());
                Value::Object(object)
            })
            .collect(),
    )
}

/// Validates one layer chain before writing: every layer has a non-empty `type`, works on the
/// `direction` side ([`finalmask_layer_type_applies`]), and passes [`validate_finalmask_layer`].
pub fn validate_finalmask_layers(
    layers: &[FinalMaskLayerDraft],
    chain: FinalMaskChain,
    direction: StreamDirection,
) -> ConfigModifyResult<()> {
    let invalid = |message: String| ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message);
    for (index, layer) in layers.iter().enumerate() {
        let location = format!("finalmask.{}[{index}]", chain.key());
        let layer_type = layer.layer_type.trim();
        if layer_type.is_empty() {
            return Err(invalid(format!("FinalMask layers require a non-empty type ({location})")));
        }
        if !finalmask_layer_type_applies(layer_type, chain, direction) {
            return Err(invalid(format!(
                "{location}: `{layer_type}` is a client-only mask — Xray-core cannot listen with it \
                 (\"{layer_type}: client only\"), so this {} would not start. Remove the layer — \
                 it belongs in the client's outbound",
                direction.as_str()
            )));
        }
        validate_finalmask_layer(chain, direction, layer_type, &layer.settings).map_err(|error| {
            invalid(format!("{location} ({}): {error}", layer_type.to_ascii_lowercase()))
        })?;
    }
    Ok(())
}

/// One layer's checks, mirroring the core's `Build()` per type (Roadmap §2.6 stages 1.1, 1.2,
/// 1.4; the GUI shows the result next to the layer):
///
/// - a type of the other chain (`fragment` in `udp`, `salamander` in `tcp`) is an error — the
///   core's loader for this chain does not know it; a type known to neither chain is left to the
///   core (it may be newer than Feldjäger);
/// - typed layers (`fragment`, `salamander`, `sudoku`, `noise`, `xicmp`, `udphop`, `realm`) are checked on
///   their parsed draft; `settings` the typed form can't represent are left to the core;
/// - `header-custom` is checked on the JSON itself ([`super::finalmask_raw`]), though it has
///   typed forms since stages 2.2 (TCP) and 2.3 (UDP); for
///   UDP also the header sizes the core measures when the listener / dialer is created (stage
///   2.3), which depend on `mode` and `direction`; so is `mkcp-legacy` (stage 2.1,
///   [`super::finalmask_mkcp`]), whose typed form can't hold a non-string `header` / `value`
///   that Go decoding rejects; so is `xmc` (stage 2.4, [`super::finalmask_xmc`]) — `hostname`
///   length matters only on the client side, hence `direction`, and the pre-v26.7.28
///   `usernames` schema is not refused;
/// - `xdns` (stage 1.3) needs `resolvers` only on the client side, hence `direction`; settings in
///   the pre-v26.9.30 schema are not refused — they are right for an older core, and the
///   version-aware warning covers a newer one;
/// - `sudoku` (both chains) has no `Build()` checks; its `ascii` mode and custom tables are read
///   only when the core builds the byte tables (stage 2.5), so those are runtime checks.
///
/// An empty `type` is `Ok` here ([`validate_finalmask_layers`] reports it).
pub fn validate_finalmask_layer(
    chain: FinalMaskChain,
    direction: StreamDirection,
    layer_type: &str,
    settings: &Value,
) -> Result<(), String> {
    let kind = layer_type.trim().to_ascii_lowercase();
    if !chain.types().contains(&kind.as_str()) && chain.other().types().contains(&kind.as_str()) {
        return Err(format!(
            "`{kind}` is a finalmask.{} mask — Xray-core does not accept it in finalmask.{}",
            chain.other().key(),
            chain.key()
        ));
    }
    fn typed<D>(settings: &Value, parse: fn(&Value) -> Option<D>, validate: fn(&D) -> Result<(), String>) -> Result<(), String> {
        parse(settings).map_or(Ok(()), |draft| validate(&draft))
    }
    match (chain, kind.as_str()) {
        (FinalMaskChain::Tcp, "fragment") => typed(settings, parse_fragment_mask_settings, validate_fragment_mask_settings),
        (FinalMaskChain::Tcp, "header-custom") => validate_header_custom_tcp(settings),
        (FinalMaskChain::Tcp, "xmc") => validate_xmc(settings, direction),
        (_, "sudoku") => typed(settings, parse_sudoku_settings, validate_sudoku_settings),
        (FinalMaskChain::Udp, "header-custom") => validate_header_custom_udp(settings)
            .and_then(|()| validate_header_custom_udp_sizes(settings, direction)),
        (FinalMaskChain::Udp, "mkcp-legacy") => validate_mkcp_legacy(settings),
        (FinalMaskChain::Udp, "noise") => typed(settings, parse_noise_mask_settings, validate_noise_mask_settings),
        (FinalMaskChain::Udp, "salamander") => typed(settings, parse_salamander_settings, validate_salamander_settings),
        (FinalMaskChain::Udp, "xicmp") => typed(settings, parse_xicmp_settings, validate_xicmp_settings),
        (FinalMaskChain::Udp, "udphop") => typed(settings, parse_udphop_settings, validate_udphop_settings),
        (FinalMaskChain::Udp, "realm") => typed(settings, parse_realm_settings, validate_realm_settings),
        (FinalMaskChain::Udp, "xdns") if !xdns_has_legacy_fields(settings) => match parse_xdns_settings(settings) {
            Some(draft) => validate_xdns_settings(&draft, direction),
            None => Ok(()),
        },
        _ => Ok(()),
    }
}

/// The hy2 share-URI `obfs` an inbound's `finalmask.udp` chain maps to (Roadmap §2.6 stage 4.1):
/// `Ok(Some(password))` for `obfs=salamander&obfs-password=…`, `Ok(None)` for no `obfs`, and
/// `Err` when the chain needs a client layer a hy2 link cannot carry.
///
/// Reads the typed layers of the Stream-tab editor, not raw JSON. The idea: a hy2 link describes
/// the *whole* client side of the chain, and its only mask is plain salamander — so the link is
/// built only when what the client must mirror is exactly that:
/// - `noise` is skipped: it only acts on writes (`noise/conn.go` `ReadFrom` is a pass-through),
///   so the client needs no matching layer;
/// - `salamander` with a Gecko `packetSize` is refused: Gecko frames and pads QUIC handshake
///   packets (`salamander/gecko.go`), which a plain-salamander hy2 client cannot read;
/// - any other remaining layer, or more than one, is refused — the client would need it too.
pub fn hy2_share_obfs(udp: &[FinalMaskLayerDraft]) -> Result<Option<String>, String> {
    let mirrored: Vec<&FinalMaskLayerDraft> = udp
        .iter()
        .filter(|layer| !layer.layer_type.trim().eq_ignore_ascii_case("noise"))
        .collect();
    let layer = match mirrored.as_slice() {
        [] => return Ok(None),
        [layer] if layer.layer_type.trim().eq_ignore_ascii_case("salamander") => layer,
        [layer] => {
            return Err(format!(
                "finalmask.udp layer `{}` has no hy2 share URI parameter — the client needs the \
                 identical layer, so configure it by hand",
                layer.layer_type.trim()
            ));
        }
        _ => {
            return Err(
                "finalmask.udp chains more than one layer the client must mirror — a hy2 share URI \
                 carries only a single salamander obfs, so configure the client by hand"
                    .to_owned(),
            );
        }
    };
    let settings = parse_salamander_settings(&layer.settings).ok_or_else(|| {
        "finalmask.udp salamander settings can't be read — fix them on the Stream tab".to_owned()
    })?;
    if matches!(settings.packet_size.bounds(), Ok(Some((_, to))) if to > 0) {
        return Err(
            "finalmask.udp salamander has packetSize (Gecko) — hy2 share URIs carry only plain \
             salamander obfs, which cannot talk to a Gecko server"
                .to_owned(),
        );
    }
    let password = settings.password.trim();
    if password.is_empty() {
        return Err("finalmask.udp salamander has no password".to_owned());
    }
    Ok(Some(password.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_typed_layers_with_default_settings() {
        let array = vec![
            json!({"type": "fragment", "settings": {"packets": "tlshello"}}),
            json!({"type": "sudoku"}),
        ];
        let layers = parse_finalmask_layers(&array).expect("layers");
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].layer_type, "fragment");
        assert_eq!(layers[0].settings, json!({"packets": "tlshello"}));
        assert_eq!(layers[1].layer_type, "sudoku");
        assert_eq!(layers[1].settings, json!({}));
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(parse_finalmask_layers(&[json!("not-an-object")]).is_none());
        assert!(parse_finalmask_layers(&[json!({"settings": {}})]).is_none());
        assert!(parse_finalmask_layers(&[json!({"type": "fragment", "settings": "bad"})]).is_none());
    }

    #[test]
    fn roundtrips_layers_to_value() {
        let layers = vec![FinalMaskLayerDraft {
            layer_type: "salamander".to_owned(),
            settings: json!({"password": "secret"}),
        }];
        let value = finalmask_layers_to_value(&layers);
        assert_eq!(
            value,
            json!([{"type": "salamander", "settings": {"password": "secret"}}])
        );
        let parsed = parse_finalmask_layers(value.as_array().unwrap()).expect("layers");
        assert_eq!(parsed, layers);
    }

    fn layer(layer_type: &str, settings: Value) -> FinalMaskLayerDraft {
        FinalMaskLayerDraft {
            layer_type: layer_type.to_owned(),
            settings,
        }
    }

    #[test]
    fn validate_rejects_empty_type() {
        let layers = vec![layer("noise", json!({})), FinalMaskLayerDraft::default()];
        let err = validate_finalmask_layers(&layers, FinalMaskChain::Udp, StreamDirection::Inbound)
            .unwrap_err();
        assert!(err.message().contains("type"));
        assert!(err.message().contains("finalmask.udp[1]"));
    }

    #[test]
    fn validate_accepts_non_empty_type() {
        let layers = vec![layer("noise", json!({}))];
        assert!(validate_finalmask_layers(&layers, FinalMaskChain::Udp, StreamDirection::Inbound).is_ok());
    }

    /// Roadmap §2.6 stage 1.1: `udphop`'s server wrapper is `"udphop: client only"`.
    #[test]
    fn udphop_is_client_only() {
        use StreamDirection::{Inbound, Outbound};
        assert!(!finalmask_layer_type_applies(" UDPHop ", FinalMaskChain::Udp, Inbound));
        assert!(finalmask_layer_type_applies("udphop", FinalMaskChain::Udp, Outbound));
        assert!(finalmask_layer_type_applies("salamander", FinalMaskChain::Udp, Inbound));
        // Unknown / future types are left to the core.
        assert!(finalmask_layer_type_applies("future-mask", FinalMaskChain::Udp, Inbound));

        let layers = vec![layer("udphop", json!({"mode": "intervalRemote"}))];
        let err = validate_finalmask_layers(&layers, FinalMaskChain::Udp, Inbound).unwrap_err();
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(err.message().contains("finalmask.udp[0]"));
        assert!(err.message().contains("client only"));
        assert!(validate_finalmask_layers(&layers, FinalMaskChain::Udp, Outbound).is_ok());
    }

    #[test]
    fn validate_checks_typed_udphop_settings_on_the_client_side() {
        let outbound = |settings: Value| {
            validate_finalmask_layers(&[layer("udphop", settings)], FinalMaskChain::Udp, StreamDirection::Outbound)
        };
        let err = outbound(json!({"mode": "intervalRemote", "interval": 2})).unwrap_err();
        assert!(err.message().contains("finalmask.udp[0] (udphop): interval must be at least 5"));
        assert!(outbound(json!({})).unwrap_err().message().contains("mode is required"));
        // Settings the typed form can't represent are left to the core.
        assert!(outbound(json!({"mode": 1})).is_ok());
    }

    /// Roadmap §2.6 stage 1.4: every documented type is dispatched to its `Build()` mirror, and a
    /// type of the other chain is refused.
    #[test]
    fn validate_dispatches_every_type_and_refuses_the_other_chain() {
        use FinalMaskChain::{Tcp, Udp};
        let refused = [
            (Tcp, "fragment", json!({"packets": "0-3", "length": "1-2"}), "packets"),
            (Tcp, "header-custom", json!({"clients": [[{"capture": "x"}]]}), "clients[0][0]"),
            (Tcp, "xmc", json!({}), "profiles"),
            (Udp, "header-custom", json!({"mode": "PREFIX"}), "mode"),
            (Udp, "header-custom", json!({"server": [{"reuse": "x"}]}), "unknown variable"),
            (Udp, "mkcp-legacy", json!({"header": "none"}), "header"),
            (Udp, "noise", json!({"noise": [{"packet": [1], "rand": 2}]}), "noise[0]"),
            (Udp, "salamander", json!({"packetSize": "0-1200"}), "packetSize"),
            (Udp, "salamander", json!({"password": "abc"}), "at least 4"),
            (Tcp, "sudoku", json!({"customTable": "xxppvvv"}), "customTable"),
            (Udp, "sudoku", json!({"ascii": "binary"}), "ascii"),
            (Udp, "xicmp", json!({"ips": ["10.0.0.0/8"]}), "ips"),
            (Udp, "xdns", json!({"domains": [{"name": "t.example.com"}]}), "types"),
            (Udp, "fragment", json!({}), "finalmask.tcp mask"),
            (Tcp, "salamander", json!({}), "finalmask.udp mask"),
            (Tcp, "Noise", json!({}), "not accept it in finalmask.tcp"),
        ];
        for (chain, kind, settings, needle) in refused {
            let error = validate_finalmask_layer(chain, StreamDirection::Inbound, kind, &settings).expect_err(kind);
            assert!(error.contains(needle), "{kind}: {error}");
        }
        for (chain, kind, settings) in [
            (Tcp, "fragment", json!({"packets": "tlshello", "length": "100-200"})),
            (Tcp, "sudoku", json!({"password": "p"})),
            (Udp, "sudoku", json!({})),
            // The ASCII layout reads no custom table.
            (Tcp, "sudoku", json!({"ascii": "prefer_ascii", "customTable": "bad"})),
            (Udp, "salamander", json!({"password": "pass"})),
            (Udp, "future-mask", json!({"anything": 1})),
            // The pre-v26.9.30 xdns schema is right for an older core (a warning covers newer).
            (Udp, "xdns", json!({"domains": ["t.example.com:txt"]})),
            (Udp, "xdns", json!({"domains": [{"name": "t.example.com", "types": [16]}]})),
            (Udp, "", json!({})),
            // Unrepresentable typed settings are left to the core.
            (Tcp, "fragment", json!({"packets": 1})),
        ] {
            assert_eq!(validate_finalmask_layer(chain, StreamDirection::Inbound, kind, &settings), Ok(()), "{kind} {settings}");
        }
        let layers = [layer("noise", json!({})), layer("salamander", json!({"packetSize": 4096}))];
        let err = validate_finalmask_layers(&layers, Udp, StreamDirection::Inbound).unwrap_err();
        assert!(err.message().contains("finalmask.udp[1] (salamander): packetSize"), "{}", err.message());
    }

    /// Roadmap §2.6 stage 1.3: the xdns client needs resolvers, the server does not.
    #[test]
    fn xdns_resolvers_are_required_on_the_client_side_only() {
        let settings = json!({"domains": [{"name": "t.example.com", "types": [16]}]});
        assert_eq!(validate_finalmask_layer(FinalMaskChain::Udp, StreamDirection::Inbound, "xdns", &settings), Ok(()));
        let error = validate_finalmask_layer(FinalMaskChain::Udp, StreamDirection::Outbound, "xdns", &settings).unwrap_err();
        assert!(error.contains("resolvers"), "{error}");
    }

    /// Roadmap §2.6 stage 1.2: `realm` works on both sides and is checked like `Realm.Build()`.
    #[test]
    fn validate_checks_typed_realm_settings_on_both_sides() {
        let valid = json!({"url": "realm://t@realm.example.com/room", "stunServers": ["stun.example.com:3478"]});
        for direction in [StreamDirection::Inbound, StreamDirection::Outbound] {
            assert!(finalmask_layer_type_applies("realm", FinalMaskChain::Udp, direction));
            let layers = [layer("noise", json!({})), layer("Realm", valid.clone())];
            assert!(validate_finalmask_layers(&layers, FinalMaskChain::Udp, direction).is_ok());
        }
        let layers = [layer("realm", json!({"url": "realm://t@h/room"}))];
        let err = validate_finalmask_layers(&layers, FinalMaskChain::Udp, StreamDirection::Inbound).unwrap_err();
        assert!(err.message().contains("finalmask.udp[0] (realm): stunServers"), "{}", err.message());
        // Raw-only settings are left to the core.
        let raw = [layer("realm", json!({"portMapping": {"enabled": "yes"}}))];
        assert!(validate_finalmask_layers(&raw, FinalMaskChain::Udp, StreamDirection::Inbound).is_ok());
    }

    #[test]
    fn hy2_share_obfs_maps_plain_salamander() {
        let udp = [layer("Salamander", json!({"password": "cat"}))];
        assert_eq!(hy2_share_obfs(&udp), Ok(Some("cat".to_owned())));
    }

    #[test]
    fn hy2_share_obfs_is_none_without_mirrored_layers() {
        assert_eq!(hy2_share_obfs(&[]), Ok(None));
        // `noise` acts only on writes — the client needs no matching layer.
        assert_eq!(hy2_share_obfs(&[layer("noise", json!({}))]), Ok(None));
        let udp = [layer("noise", json!({})), layer("salamander", json!({"password": "cat"}))];
        assert_eq!(hy2_share_obfs(&udp), Ok(Some("cat".to_owned())));
    }

    #[test]
    fn hy2_share_obfs_refuses_what_a_link_cannot_carry() {
        let gecko = [layer("salamander", json!({"password": "cat", "packetSize": "512-1200"}))];
        assert!(hy2_share_obfs(&gecko).unwrap_err().contains("Gecko"));
        // A zero upper bound keeps plain salamander, as in `Salamander.Build()`.
        let plain = [layer("salamander", json!({"password": "cat", "packetSize": 0}))];
        assert_eq!(hy2_share_obfs(&plain), Ok(Some("cat".to_owned())));
        let sudoku = [layer("sudoku", json!({"password": "p"}))];
        assert!(hy2_share_obfs(&sudoku).unwrap_err().contains("`sudoku`"));
        let two = [
            layer("salamander", json!({"password": "cat"})),
            layer("sudoku", json!({"password": "p"})),
        ];
        assert!(hy2_share_obfs(&two).unwrap_err().contains("more than one"));
        assert!(hy2_share_obfs(&[layer("salamander", json!({}))]).unwrap_err().contains("no password"));
    }
}
