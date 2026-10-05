//! `finalmask.udp[]` layer `type = "mkcp-legacy"` — the former mKCP `kcpSettings.header` /
//! `seed` obfuscation as a FinalMask layer (Roadmap §2.6 stage 2.1).
//!
//! Checked against `XTLS/Xray-core@main` (`infra/conf/transport_finalmask.go` `MkcpLegacy`,
//! `transport/internet/finalmask/mkcp/{header,aes128gcm,original}`): `settings` is
//! `{header, value}`, both Go strings, and `Build()` picks one of three masks:
//!
//! - `header` empty, `value` empty — the original mKCP obfuscation;
//! - `header` empty, `value` set — AES-128-GCM with `value` as the password;
//! - `header` one of [`MKCP_LEGACY_HEADERS`] (case-insensitive) — a fake packet header; only
//!   `dns` reads `value` (the queried domain, empty = `www.baidu.com`), the others ignore it.
//!
//! The `dns` domain is encoded only when the listener/dialer is created (`NewHeaderDNS`), so a
//! name the core can't encode passes `Build()` and `xray run -test` and fails at start — the
//! check is mirrored here like the other runtime-only failures (`udphop`, `realm`).
//!
//! The typed draft keeps both strings verbatim (no trimming: a password and a domain are used
//! byte for byte by the core); a non-string `header` / `value` keeps the layer on the raw-JSON
//! editor (lossless-or-raw rule, stage 0.1).

use serde_json::{Map, Value};

use super::finalmask::FinalMaskLayerDraft;
use super::finalmask_layers::{apply_extras, extras_of};

/// `mkcp-legacy` `header` values (case-insensitive; empty = no header — `value` is then the
/// AES-128-GCM password, or nothing for the original obfuscation).
pub const MKCP_LEGACY_HEADERS: &[&str] = &["dns", "dtls", "srtp", "utp", "wechat", "wireguard"];

/// The domain `Build()` uses for `header = "dns"` when `value` is empty.
pub const MKCP_LEGACY_DEFAULT_DNS_DOMAIN: &str = "www.baidu.com";

/// `finalmask.udp[].settings` for `type = "mkcp-legacy"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MkcpLegacySettings {
    /// `header`, verbatim; empty = key absent.
    pub header: String,
    /// `value`, verbatim; empty = key absent.
    pub value: String,
    /// Unknown keys, preserved verbatim.
    pub extras: Map<String, Value>,
}

/// What `MkcpLegacy.Build()` makes of a draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MkcpLegacyMode {
    /// No header, no value: the original mKCP obfuscation.
    Original,
    /// No header, `value` = AES-128-GCM password.
    Aes128Gcm,
    /// Fake DNS query for `domain` (`value`, or [`MKCP_LEGACY_DEFAULT_DNS_DOMAIN`]).
    Dns {
        /// The domain written into every packet.
        domain: String,
    },
    /// A fixed fake header (canonical lower-case name) that does not read `value`.
    Header(&'static str),
}

impl MkcpLegacySettings {
    /// The mask `Build()` selects; `None` for a `header` the core rejects.
    pub fn mode(&self) -> Option<MkcpLegacyMode> {
        if self.header.is_empty() {
            return Some(if self.value.is_empty() {
                MkcpLegacyMode::Original
            } else {
                MkcpLegacyMode::Aes128Gcm
            });
        }
        let header = self.header.to_lowercase();
        let name = MKCP_LEGACY_HEADERS.iter().copied().find(|known| *known == header)?;
        Some(match name {
            "dns" => MkcpLegacyMode::Dns {
                domain: if self.value.is_empty() {
                    MKCP_LEGACY_DEFAULT_DNS_DOMAIN.to_owned()
                } else {
                    self.value.clone()
                },
            },
            other => MkcpLegacyMode::Header(other),
        })
    }
}

const KNOWN_MKCP_LEGACY_KEYS: &[&str] = &["header", "value"];

/// A Go `string` field read verbatim: absent / `null` = `""`; `None` when not a string.
pub(super) fn verbatim_string(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => Some(String::new()),
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => None,
    }
}

/// Parses `settings` as `mkcp-legacy`. `None` when `settings` isn't an object or `header` /
/// `value` isn't a string.
pub fn parse_mkcp_legacy_settings(settings: &Value) -> Option<MkcpLegacySettings> {
    let object = settings.as_object()?;
    Some(MkcpLegacySettings {
        header: verbatim_string(object.get("header"))?,
        value: verbatim_string(object.get("value"))?,
        extras: extras_of(object, KNOWN_MKCP_LEGACY_KEYS),
    })
}

/// Builds the `settings` `Value` for an `mkcp-legacy` layer; empty strings are omitted (the
/// core reads absent as empty).
pub fn mkcp_legacy_settings_to_value(draft: &MkcpLegacySettings) -> Value {
    let mut object = Map::new();
    for (key, text) in [("header", &draft.header), ("value", &draft.value)] {
        if !text.is_empty() {
            object.insert(key.to_owned(), Value::String(text.clone()));
        }
    }
    apply_extras(&mut object, &draft.extras);
    Value::Object(object)
}

/// Validates a draft like `MkcpLegacy.Build()` (known `header`) plus the `dns` domain encoding
/// that only runs at listen/dial time.
pub fn validate_mkcp_legacy_settings(draft: &MkcpLegacySettings) -> Result<(), String> {
    match draft.mode() {
        None => Err(format!(
            "invalid header \"{}\" (expected dns, dtls, srtp, utp, wechat, wireguard or empty)",
            draft.header
        )),
        Some(MkcpLegacyMode::Dns { domain }) => {
            encoded_dns_name_len(&domain).map(|_| ()).map_err(|error| format!("value: {error}"))
        }
        Some(_) => Ok(()),
    }
}

/// Save-time check on the JSON itself: Go decoding (`header` / `value` must be strings) first,
/// then [`validate_mkcp_legacy_settings`].
pub fn validate_mkcp_legacy(settings: &Value) -> Result<(), String> {
    let object = settings.as_object().ok_or("settings must be a JSON object")?;
    for key in KNOWN_MKCP_LEGACY_KEYS {
        if verbatim_string(object.get(*key)).is_none() {
            return Err(format!("{key} must be a string"));
        }
    }
    match parse_mkcp_legacy_settings(settings) {
        Some(draft) => validate_mkcp_legacy_settings(&draft),
        None => Ok(()),
    }
}

/// The pre-v26.1.31 `kcpSettings.header.type` values (`kcpHeaderLoader`, lower-cased by
/// `LoadWithID`) → the `mkcp-legacy` `header`; `None` = `none`, a header of size 0.
const LEGACY_KCP_HEADER_TYPES: &[(&str, Option<&str>)] = &[
    ("none", None),
    ("srtp", Some("srtp")),
    ("utp", Some("utp")),
    ("wechat-video", Some("wechat")),
    ("dtls", Some("dtls")),
    ("wireguard", Some("wireguard")),
    ("dns", Some("dns")),
];

/// The `finalmask.udp[]` layers that put the same bytes on the wire as the pre-v26.1.31
/// `kcpSettings.header` / `seed` (Roadmap §2.6 stage 5.2; `header` / `seed` are the raw values,
/// `None` = key absent).
///
/// Checked against the core before XTLS/Xray-core#5560 (`kcp/config.go`, `kcp/io.go`,
/// `infra/conf/transport_internet.go`): the old mKCP **always** sealed packets — AES-128-GCM keyed
/// by `seed` when set, the original obfuscation otherwise — and wrote the fake header in front of
/// the sealed bytes (`[header][sealed]`). One `mkcp-legacy` layer is either a header or a cipher,
/// so the result is two layers: the cipher first (innermost), then the header, which ends up
/// outside (`FinalMask.ListenPacket` wraps the socket with the last layer first).
///
/// Errors (nothing to migrate faithfully): a `seed` that is not a string; an empty-string `seed`
/// (the old core keyed AES-128-GCM with it, while an empty `value` means the original
/// obfuscation); a `header` that is not an object with a string `type` the old loader knew; a
/// non-string `dns` `domain`; a domain the core cannot encode. Other keys inside `header` were
/// ignored by the old core and are not carried over.
pub fn mkcp_legacy_layers_from_kcp(
    header: Option<&Value>,
    seed: Option<&Value>,
) -> Result<Vec<FinalMaskLayerDraft>, String> {
    let cipher = match seed {
        None | Some(Value::Null) => Map::new(),
        Some(Value::String(seed)) if seed.is_empty() => {
            return Err("kcpSettings.seed is an empty string: the old core encrypted with \
                        AES-128-GCM keyed by it, which a mkcp-legacy layer cannot express (an empty \
                        value means the original obfuscation)"
                .to_owned());
        }
        Some(Value::String(seed)) => Map::from_iter([("value".to_owned(), Value::String(seed.clone()))]),
        Some(_) => return Err("kcpSettings.seed must be a string".to_owned()),
    };
    let mut layers = vec![cipher];

    match header {
        None | Some(Value::Null) => {}
        Some(Value::Object(object)) => {
            let kind = object
                .get("type")
                .and_then(Value::as_str)
                .ok_or("kcpSettings.header has no string `type`")?;
            let lower = kind.to_lowercase();
            let header = LEGACY_KCP_HEADER_TYPES
                .iter()
                .find(|(legacy, _)| *legacy == lower)
                .map(|(_, header)| *header)
                .ok_or_else(|| format!("kcpSettings.header.type \"{kind}\" is not an mKCP header"))?;
            if let Some(header) = header {
                let mut settings = Map::from_iter([("header".to_owned(), Value::String(header.to_owned()))]);
                if header == "dns" {
                    let domain = verbatim_string(object.get("domain"))
                        .ok_or("kcpSettings.header.domain must be a string")?;
                    // Both cores fall back to the same default for an empty domain.
                    if !domain.is_empty() {
                        settings.insert("value".to_owned(), Value::String(domain));
                    }
                }
                layers.push(settings);
            }
        }
        Some(_) => return Err("kcpSettings.header must be a JSON object".to_owned()),
    }

    layers
        .into_iter()
        .map(|settings| {
            let settings = Value::Object(settings);
            validate_mkcp_legacy(&settings).map_err(|error| format!("mkcp-legacy: {error}"))?;
            Ok(FinalMaskLayerDraft {
                layer_type: "mkcp-legacy".to_owned(),
                settings,
            })
        })
        .collect()
}

/// Size of the 256-byte buffer `NewHeaderDNS` packs the query name into.
const DNS_NAME_BUFFER: usize = 256;

/// Length of `domain` packed as a DNS query name, mirroring the core's `packDomainName(domain +
/// ".", make([]byte, 256))` (a trimmed copy of `miekg/dns`).
///
/// Every `.` ends a label and is traded for a length byte; `\x` escapes `x` (so `\.` is a dot
/// inside a label). Errors where the core errors — a label of 64 bytes or more, or a name that
/// overflows the buffer — and also where the core would panic: a name of exactly 256 bytes makes
/// `buf[:257]` slice past the buffer. Empty labels (`a..b`) are not errors in the core either.
pub fn encoded_dns_name_len(domain: &str) -> Result<usize, String> {
    let mut name = domain.as_bytes().to_vec();
    name.push(b'.');
    let (mut off, mut begin, mut i) = (0usize, 0usize, 0usize);
    while i < name.len() {
        match name[i] {
            b'\\' => {
                if off + 1 > DNS_NAME_BUFFER {
                    return Err("domain is too long to encode".to_owned());
                }
                // The core shifts the rest left over the backslash; the loop step then skips
                // the escaped byte.
                name.remove(i);
            }
            b'.' => {
                let label_len = i - begin;
                if label_len >= 64 {
                    return Err(format!(
                        "domain label \"{}\" is {label_len} bytes; at most 63 fit a DNS name",
                        String::from_utf8_lossy(&name[begin..i])
                    ));
                }
                if off + 1 + label_len > DNS_NAME_BUFFER {
                    return Err("domain is too long to encode (at most 255 bytes as a DNS name)".to_owned());
                }
                off += 1 + label_len;
                begin = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if off + 1 > DNS_NAME_BUFFER {
        return Err("domain is too long to encode (at most 255 bytes as a DNS name)".to_owned());
    }
    Ok(off + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn draft(header: &str, value: &str) -> MkcpLegacySettings {
        MkcpLegacySettings { header: header.to_owned(), value: value.to_owned(), ..Default::default() }
    }

    #[test]
    fn mode_mirrors_build() {
        assert_eq!(draft("", "").mode(), Some(MkcpLegacyMode::Original));
        assert_eq!(draft("", "pw").mode(), Some(MkcpLegacyMode::Aes128Gcm));
        assert_eq!(
            draft("DNS", "").mode(),
            Some(MkcpLegacyMode::Dns { domain: MKCP_LEGACY_DEFAULT_DNS_DOMAIN.to_owned() })
        );
        assert_eq!(draft("dns", "a.example").mode(), Some(MkcpLegacyMode::Dns { domain: "a.example".to_owned() }));
        assert_eq!(draft("WeChat", "ignored").mode(), Some(MkcpLegacyMode::Header("wechat")));
        // Not trimmed, like the core: " dns" and the old kcpSettings names are rejected.
        for header in [" dns", "none", "wechat-video"] {
            assert_eq!(draft(header, "").mode(), None, "{header}");
        }
    }

    #[test]
    fn round_trip_is_verbatim_and_keeps_extras() {
        let settings = json!({"header": "DNS", "value": " spaced.example ", "future": [1]});
        let parsed = parse_mkcp_legacy_settings(&settings).expect("parsed");
        assert_eq!(parsed.value, " spaced.example ");
        assert_eq!(mkcp_legacy_settings_to_value(&parsed), settings);
        // Empty strings / null are the core's zero value and are written as absent.
        let empty = parse_mkcp_legacy_settings(&json!({"header": "", "value": null})).expect("parsed");
        assert_eq!(mkcp_legacy_settings_to_value(&empty), json!({}));
        // Non-string known keys stay on the raw-JSON editor.
        assert!(parse_mkcp_legacy_settings(&json!({"header": 1})).is_none());
        assert!(parse_mkcp_legacy_settings(&json!({"value": true})).is_none());
        assert!(parse_mkcp_legacy_settings(&json!("dns")).is_none());
    }

    #[test]
    fn header_is_case_insensitive_and_types_are_go_strings() {
        for header in ["", "dns", "DTLS", "srtp", "utp", "wechat", "WireGuard"] {
            assert_eq!(validate_mkcp_legacy(&json!({"header": header, "value": "x"})), Ok(()), "{header}");
        }
        assert!(validate_mkcp_legacy(&json!({"header": "none"})).unwrap_err().contains("invalid header"));
        assert!(validate_mkcp_legacy(&json!({"value": 1})).unwrap_err().contains("value"));
        assert!(validate_mkcp_legacy(&json!([])).unwrap_err().contains("JSON object"));
    }

    fn migrated(header: Option<Value>, seed: Option<Value>) -> Result<Vec<Value>, String> {
        mkcp_legacy_layers_from_kcp(header.as_ref(), seed.as_ref()).map(|layers| {
            layers
                .into_iter()
                .map(|layer| {
                    assert_eq!(layer.layer_type, "mkcp-legacy");
                    layer.settings
                })
                .collect()
        })
    }

    /// Roadmap §2.6 stage 5.2: cipher first (innermost), header last (outermost), like the old
    /// `[header][sealed]`; the old core always sealed, so no seed is the original obfuscation.
    #[test]
    fn legacy_kcp_header_and_seed_become_cipher_then_header() {
        assert_eq!(
            migrated(Some(json!({"type": "WeChat-Video"})), Some(json!("s3cret"))),
            Ok(vec![json!({"value": "s3cret"}), json!({"header": "wechat"})])
        );
        assert_eq!(migrated(Some(json!({"type": "none"})), None), Ok(vec![json!({})]));
        assert_eq!(migrated(None, Some(json!("s3cret"))), Ok(vec![json!({"value": "s3cret"})]));
        assert_eq!(migrated(None, Some(Value::Null)), Ok(vec![json!({})]));
        for kind in ["srtp", "utp", "dtls", "wireguard"] {
            assert_eq!(
                migrated(Some(json!({"type": kind, "ignored": 1})), None),
                Ok(vec![json!({}), json!({"header": kind})]),
                "{kind}"
            );
        }
        // `dns.domain` becomes `value`; empty falls back to the same default in both cores.
        assert_eq!(
            migrated(Some(json!({"type": "dns", "domain": "q.example"})), None),
            Ok(vec![json!({}), json!({"header": "dns", "value": "q.example"})])
        );
        assert_eq!(
            migrated(Some(json!({"type": "dns"})), None),
            Ok(vec![json!({}), json!({"header": "dns"})])
        );
    }

    #[test]
    fn legacy_kcp_values_without_a_faithful_equivalent_are_refused() {
        let refused = |header: Option<Value>, seed: Option<Value>, needle: &str| {
            let error = migrated(header.clone(), seed.clone()).unwrap_err();
            assert!(error.contains(needle), "{header:?} {seed:?}: {error}");
        };
        refused(None, Some(json!("")), "empty string");
        refused(None, Some(json!(42)), "seed must be a string");
        refused(Some(json!({"type": "http"})), None, "not an mKCP header");
        refused(Some(json!({"domain": "a"})), None, "no string `type`");
        refused(Some(json!("dns")), None, "JSON object");
        refused(Some(json!({"type": "dns", "domain": 1})), None, "domain must be a string");
        refused(Some(json!({"type": "dns", "domain": "a".repeat(64)})), None, "mkcp-legacy: value");
    }

    /// `NewHeaderDNS` / `packDomainName` limits, including the slice panic at exactly 256 bytes.
    #[test]
    fn dns_domain_mirrors_pack_domain_name() {
        assert_eq!(encoded_dns_name_len("www.baidu.com"), Ok(15));
        // `\.` is a dot inside the label: one 5-byte label, not two.
        assert_eq!(encoded_dns_name_len(r"a\.bcd"), Ok(7));
        // Empty labels terminate the name early but are not errors.
        assert!(encoded_dns_name_len("a..b").is_ok());

        let label63 = "a".repeat(63);
        assert!(encoded_dns_name_len(&label63).is_ok());
        let error = encoded_dns_name_len(&format!("{label63}a.example")).unwrap_err();
        assert!(error.contains("64 bytes"), "{error}");

        // Four 63-byte labels = 256 bytes + terminator: the core panics on `buf[:257]`.
        let at_buffer = [label63.as_str(); 4].join(".");
        assert!(encoded_dns_name_len(&at_buffer).unwrap_err().contains("too long"));
        let just_fits = format!("{}.{}", [label63.as_str(); 3].join("."), "a".repeat(62));
        assert_eq!(encoded_dns_name_len(&just_fits), Ok(256));
        assert!(encoded_dns_name_len(&format!("{at_buffer}.a")).unwrap_err().contains("too long"));

        assert!(validate_mkcp_legacy(&json!({"header": "dns", "value": format!("{label63}a")}))
            .unwrap_err()
            .starts_with("value: "));
        // Only `dns` reads `value`.
        assert_eq!(validate_mkcp_legacy(&json!({"header": "utp", "value": format!("{label63}a")})), Ok(()));
    }
}
