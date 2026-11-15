//! Outbound `mux` (Roadmap §4.2) — [`MuxObject`](https://xtls.github.io/en/config/outbound.html#muxobject).
//!
//! Verified against Xray-core v26.9.30 (`infra/conf/xray.go` `MuxConfig`,
//! `app/proxyman/outbound/handler.go`) and `xray run -test` / live runs of `xray.exe` 26.9.30:
//! - JSON decoding is strict per field: `enabled` must be a bool, `concurrency` /
//!   `xudpConcurrency` an integer that fits `int16` (a string, `8.5` or `40000` fail the load);
//!   a non-object `mux` fails too, `null` means absent, unknown keys are ignored.
//! - `xudpProxyUDP443` must be exactly `""` / `reject` / `allow` / `skip` (case-sensitive) and is
//!   checked even with `enabled: false`.
//! - Before v26.11.9, `concurrency`: `0` = 8, connection reuse limit = 128. Since v26.11.9,
//!   non-negative values through 128 become 128 and reuse limit = 1024. Negative disables TCP
//!   Mux on either version. `xudpConcurrency`: `0` = UDP rides the TCP Mux, negative = the
//!   protocol's own UDP (UoT for VLESS), positive = a separate XUDP tunnel (documented maximum
//!   1024).

use serde_json::{Map, Number, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
use crate::xray::config::compatibility::XrayCoreVersion;

/// The values `MuxConfig.Build()` accepts for `xudpProxyUDP443` (empty = `reject`).
pub const MUX_XUDP_PROXY_UDP443_VALUES: &[&str] = &["reject", "allow", "skip"];

/// Current-core connection reuse limit (`MaxConnection`), not a JSON field validation limit.
pub const MUX_CONCURRENCY_EFFECTIVE_MAX: i64 = 1024;

/// Version-dependent Mux behavior for presentation; calculation never changes the draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxBehavior {
    /// TCP default when concurrency is absent or zero.
    pub default_concurrency: i64,
    /// Small positive TCP values are raised to this by the core.
    pub minimum_positive_concurrency: i64,
    /// Maximum total session allocations per underlying connection.
    pub connection_reuse_limit: i64,
    /// TCP concurrency after default/minimum and reuse limit; negative means disabled.
    pub effective_concurrency: Option<i64>,
    /// Positive XUDP concurrency capped by reuse; zero shares TCP, negative uses protocol UDP.
    pub effective_xudp_concurrency: Option<i64>,
    /// False means the current-core defaults are assumed, as with compatibility warnings.
    pub version_known: bool,
}

/// Documented maximum of `xudpConcurrency`.
pub const MUX_XUDP_CONCURRENCY_DOCUMENTED_MAX: i64 = 1024;

/// Outbound `mux` draft. Numbers are free text (empty = key absent) and are checked on apply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutboundMux {
    /// `enabled`.
    pub enabled: bool,
    /// `concurrency`; empty = key absent (default depends on the installed core).
    pub concurrency: String,
    /// `xudpConcurrency`; empty = key absent (UDP rides the TCP Mux).
    pub xudp_concurrency: String,
    /// `xudpProxyUDP443`; empty = key absent (`reject`). A value outside
    /// [`MUX_XUDP_PROXY_UDP443_VALUES`] read from disk is kept as typed until changed.
    pub xudp_proxy_udp443: String,
    /// Unknown `mux` keys, preserved verbatim.
    pub extras: Map<String, Value>,
    /// Why the `mux` on disk cannot be represented (a non-object, a field of the wrong JSON
    /// type) — the editor then leaves it untouched; `None` when editable.
    pub foreign: Option<String>,
}

impl OutboundMux {
    /// Nothing to write: the draft equals an absent `mux`.
    pub fn is_empty(&self) -> bool {
        !self.enabled
            && self.concurrency.trim().is_empty()
            && self.xudp_concurrency.trim().is_empty()
            && self.xudp_proxy_udp443.is_empty()
            && self.extras.is_empty()
    }

    /// Effective concurrency for the current core (unknown version assumes v26.11.9+).
    pub fn effective_concurrency(&self) -> Option<i64> {
        self.behavior_for_core(None).effective_concurrency
    }

    /// Computes defaults and effective limits using Discovery's version, without rewriting JSON.
    pub fn behavior_for_core(&self, core: Option<XrayCoreVersion>) -> MuxBehavior {
        let modern = core.is_none_or(|core| core >= XrayCoreVersion::new(26, 11, 9));
        let default_concurrency = if modern { 128 } else { 8 };
        let minimum_positive_concurrency = if modern { 128 } else { 1 };
        let connection_reuse_limit = if modern { MUX_CONCURRENCY_EFFECTIVE_MAX } else { 128 };
        let effective_concurrency = parse_i16_text(&self.concurrency).ok().map(|value| {
            let value = i64::from(value.unwrap_or(0));
            if value < 0 { value }
            else if value == 0 { default_concurrency }
            else { value.clamp(minimum_positive_concurrency, connection_reuse_limit) }
        });
        let effective_xudp_concurrency = parse_i16_text(&self.xudp_concurrency).ok()
            .map(|value| i64::from(value.unwrap_or(0)).min(connection_reuse_limit));
        MuxBehavior {
            default_concurrency, minimum_positive_concurrency, connection_reuse_limit,
            effective_concurrency: if self.foreign.is_none() { effective_concurrency } else { None },
            effective_xudp_concurrency: if self.foreign.is_none() { effective_xudp_concurrency } else { None },
            version_known: core.is_some(),
        }
    }
}

/// Reads `mux` from an outbound object; an absent or `null` `mux` gives the default draft.
pub fn parse_outbound_mux(outbound: &Value) -> OutboundMux {
    let Some(mux) = outbound.get("mux").filter(|value| !value.is_null()) else {
        return OutboundMux::default();
    };
    let Some(object) = mux.as_object() else {
        return OutboundMux {
            foreign: Some("mux is not a JSON object".to_owned()),
            ..OutboundMux::default()
        };
    };
    let mut draft = OutboundMux::default();
    let mut problems = Vec::new();
    for (key, value) in object {
        match key.as_str() {
            "enabled" => match value {
                Value::Bool(enabled) => draft.enabled = *enabled,
                _ => problems.push("enabled is not true/false"),
            },
            "concurrency" => match integer_text(value) {
                Some(text) => draft.concurrency = text,
                None => problems.push("concurrency is not an integer from -32768 to 32767"),
            },
            "xudpConcurrency" => match integer_text(value) {
                Some(text) => draft.xudp_concurrency = text,
                None => problems.push("xudpConcurrency is not an integer from -32768 to 32767"),
            },
            "xudpProxyUDP443" => match value {
                Value::String(text) => draft.xudp_proxy_udp443 = text.clone(),
                _ => problems.push("xudpProxyUDP443 is not a string"),
            },
            _ => {
                draft.extras.insert(key.clone(), value.clone());
            }
        }
    }
    if !problems.is_empty() {
        draft.foreign = Some(format!("{} — Xray-core does not load it", problems.join("; ")));
    }
    draft
}

/// `int16` JSON number → text; anything else (a string, a fraction, out of range) → `None`.
fn integer_text(value: &Value) -> Option<String> {
    let number = value.as_i64()?;
    i16::try_from(number).ok().map(|number| number.to_string())
}

/// Trimmed text → `int16`: empty = `Ok(None)`.
fn parse_i16_text(text: &str) -> Result<Option<i16>, ()> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse::<i16>().map(Some).map_err(|_| ())
}

/// Checks a draft the way `MuxConfig` decodes and builds it.
pub fn validate_outbound_mux(mux: &OutboundMux) -> Result<(), String> {
    if let Some(reason) = &mux.foreign {
        return Err(format!("mux on disk cannot be edited here ({reason}); use Raw JSON"));
    }
    for (key, text) in [("concurrency", &mux.concurrency), ("xudpConcurrency", &mux.xudp_concurrency)] {
        if parse_i16_text(text).is_err() {
            return Err(format!(
                "mux.{key} \"{}\" must be a whole number from -32768 to 32767 — Xray-core does not \
                 load anything else",
                text.trim()
            ));
        }
    }
    let udp443 = mux.xudp_proxy_udp443.as_str();
    if !udp443.is_empty() && !MUX_XUDP_PROXY_UDP443_VALUES.contains(&udp443) {
        return Err(format!(
            "mux.xudpProxyUDP443 \"{udp443}\" must be reject, allow or skip (lowercase) — Xray-core \
             refuses anything else, even with Mux disabled"
        ));
    }
    Ok(())
}

/// Writes `mux` into an outbound object. Untouched when the draft equals what is on disk (Save
/// without edits is byte-for-byte); removed when the draft is empty; otherwise rebuilt from the
/// draft with unknown keys kept and `enabled` always written.
pub(super) fn apply_outbound_mux(
    object: &mut Map<String, Value>,
    mux: &OutboundMux,
) -> ConfigModifyResult<()> {
    let on_disk = parse_outbound_mux(&Value::Object(object.clone()));
    if on_disk == *mux {
        return Ok(());
    }
    validate_outbound_mux(mux).map_err(|message| {
        ConfigModifyError::new(ConfigModifyErrorKind::ValidationFailed, message)
    })?;
    if mux.is_empty() {
        object.remove("mux");
        return Ok(());
    }
    // `extras` never holds a known key (parse sorts them out), so the draft's fields win.
    let mut written = mux.extras.clone();
    written.insert("enabled".to_owned(), Value::Bool(mux.enabled));
    for (key, text) in [("concurrency", &mux.concurrency), ("xudpConcurrency", &mux.xudp_concurrency)] {
        if let Ok(Some(value)) = parse_i16_text(text) {
            written.insert(key.to_owned(), Value::Number(Number::from(value)));
        }
    }
    if !mux.xudp_proxy_udp443.is_empty() {
        written.insert("xudpProxyUDP443".to_owned(), Value::String(mux.xudp_proxy_udp443.clone()));
    }
    object.insert("mux".to_owned(), Value::Object(written));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn apply(outbound: &Value, mux: &OutboundMux) -> ConfigModifyResult<Value> {
        let mut object = outbound.as_object().cloned().expect("object");
        apply_outbound_mux(&mut object, mux)?;
        Ok(Value::Object(object))
    }

    #[test]
    fn parse_reads_every_field_and_keeps_unknown_keys() {
        let outbound = json!({"mux": {
            "enabled": true, "concurrency": -1, "xudpConcurrency": 16,
            "xudpProxyUDP443": "skip", "future": [1]
        }});
        let mux = parse_outbound_mux(&outbound);
        assert!(mux.enabled);
        assert_eq!(mux.concurrency, "-1");
        assert_eq!(mux.xudp_concurrency, "16");
        assert_eq!(mux.xudp_proxy_udp443, "skip");
        assert_eq!(mux.extras, json!({"future": [1]}).as_object().cloned().unwrap());
        assert!(mux.foreign.is_none());
        assert_eq!(parse_outbound_mux(&json!({"mux": null})), OutboundMux::default());
        assert_eq!(parse_outbound_mux(&json!({})), OutboundMux::default());
    }

    /// Shapes `xray run -test` 26.9.30 refuses at decoding.
    #[test]
    fn parse_marks_shapes_the_core_cannot_decode() {
        for mux in [
            json!("on"),
            json!({"enabled": "true"}),
            json!({"concurrency": "8"}),
            json!({"concurrency": 8.5}),
            json!({"concurrency": 40000}),
            json!({"xudpConcurrency": -40000}),
            json!({"xudpProxyUDP443": 1}),
        ] {
            let draft = parse_outbound_mux(&json!({ "mux": mux }));
            assert!(draft.foreign.is_some(), "{mux}");
            assert!(validate_outbound_mux(&draft).is_err(), "{mux}");
        }
    }

    #[test]
    fn save_without_edits_is_byte_for_byte() {
        for outbound in [
            json!({"protocol": "vless"}),
            json!({"protocol": "vless", "mux": null}),
            json!({"protocol": "vless", "mux": {}}),
            json!({"protocol": "vless", "mux": {"concurrency": 8, "enabled": false, "x": 1}}),
            // Kept although the core refuses it: only an edit replaces it.
            json!({"protocol": "vless", "mux": {"enabled": true, "xudpProxyUDP443": "Reject"}}),
            json!({"protocol": "vless", "mux": "on"}),
        ] {
            let mux = parse_outbound_mux(&outbound);
            assert_eq!(apply(&outbound, &mux).expect("apply"), outbound);
        }
    }

    #[test]
    fn apply_writes_numbers_and_always_enabled() {
        let outbound = json!({"protocol": "vless", "mux": {"future": true}});
        let mut mux = parse_outbound_mux(&outbound);
        mux.enabled = true;
        mux.concurrency = " -1 ".to_owned();
        mux.xudp_concurrency = "16".to_owned();
        mux.xudp_proxy_udp443 = "allow".to_owned();
        let written = apply(&outbound, &mux).expect("apply");
        assert_eq!(
            written["mux"],
            json!({"future": true, "enabled": true, "concurrency": -1, "xudpConcurrency": 16, "xudpProxyUDP443": "allow"})
        );

        mux.enabled = false;
        mux.xudp_concurrency.clear();
        let written = apply(&written, &mux).expect("disable");
        assert_eq!(written["mux"], json!({"future": true, "enabled": false, "concurrency": -1, "xudpProxyUDP443": "allow"}));
    }

    #[test]
    fn empty_draft_removes_mux() {
        let outbound = json!({"protocol": "vless", "tag": "a", "mux": {"enabled": true}});
        let written = apply(&outbound, &OutboundMux::default()).expect("apply");
        assert_eq!(written, json!({"protocol": "vless", "tag": "a"}));
    }

    #[test]
    fn apply_refuses_what_the_core_refuses() {
        let outbound = json!({"protocol": "vless"});
        for (concurrency, udp443) in [("8.5", ""), ("40000", ""), ("eight", ""), ("8", "Reject"), ("8", "deny")] {
            let mux = OutboundMux {
                enabled: true,
                concurrency: concurrency.to_owned(),
                xudp_proxy_udp443: udp443.to_owned(),
                ..OutboundMux::default()
            };
            let error = apply(&outbound, &mux).unwrap_err();
            assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed, "{concurrency} {udp443}");
        }
        // The value is checked with Mux disabled too, like `MuxConfig.Build()`.
        let disabled = OutboundMux { xudp_proxy_udp443: "x".to_owned(), ..OutboundMux::default() };
        assert!(apply(&outbound, &disabled).is_err());
    }

    #[test]
    fn effective_concurrency_follows_the_core() {
        let with = |text: &str| OutboundMux { concurrency: text.to_owned(), ..OutboundMux::default() };
        assert_eq!(with("").effective_concurrency(), Some(128));
        assert_eq!(with("0").effective_concurrency(), Some(128));
        assert_eq!(with("-1").effective_concurrency(), Some(-1));
        assert_eq!(with("300").effective_concurrency(), Some(300));
        assert_eq!(with("x").effective_concurrency(), None);
    }

    #[test]
    fn versioned_mux_limits_preserve_explicit_settings() {
        let old = Some(XrayCoreVersion::new(26, 10, 31));
        let new = Some(XrayCoreVersion::new(26, 11, 9));
        for (text, before, after) in [
            ("", 8, 128), ("0", 8, 128), ("1", 1, 128), ("127", 127, 128),
            ("128", 128, 128), ("129", 128, 129), ("1024", 128, 1024),
            ("32767", 128, 1024), ("-1", -1, -1), ("-32768", -32768, -32768),
        ] {
            let original = serde_json::json!({"mux": {"enabled": true, "concurrency": text.parse::<i16>().unwrap_or(0),
                "xudpConcurrency": 300, "future": true}});
            let draft = parse_outbound_mux(&original);
            let mut with_text = draft.clone();
            with_text.concurrency = text.to_owned();
            assert_eq!(with_text.behavior_for_core(old).effective_concurrency, Some(before));
            assert_eq!(with_text.behavior_for_core(new).effective_concurrency, Some(after));
            assert_eq!(with_text.behavior_for_core(None).effective_concurrency, Some(after));
            assert_eq!(with_text.behavior_for_core(old).effective_xudp_concurrency, Some(128));
            assert_eq!(with_text.behavior_for_core(new).effective_xudp_concurrency, Some(300));
            assert_eq!(apply(&original, &draft).unwrap(), original);
        }
    }
}
