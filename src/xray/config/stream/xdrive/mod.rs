//! Lossless XDRIVE beta settings (Xray v26.11.9). Both listener and dialer access storage
//! as clients; direction changes VLESS/Mux constraints, not the settings wire format.
//! Unknown shapes and explicit nulls remain raw until explicitly edited. No storage I/O here.

#[cfg(test)]
mod tests;
mod validate;

use super::RangeValue;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
pub use validate::{
    validate_xdrive_entity, validate_xdrive_settings, xdrive_is_active, xdrive_uses_h3,
};

/// Supported beta service spellings; the legacy alias is read without automatic migration.
pub const XDRIVE_SERVICES: &[&str] = &["local", "google-drive", "template", "s3"];
/// Numeric settings are uint32; zero/absence leaves defaults to the core.
pub const XDRIVE_UINT32_FIELDS: &[&str] = &[
    "segmentBytes",
    "flushIntervalMs",
    "pollIntervalMs",
    "maxPollIntervalMs",
    "sessionTtlSeconds",
    "concurrency",
    "eagerWindowMs",
    "holeTimeoutMs",
];

/// Editable XDRIVE settings; secret-bearing fields deliberately have no derived Debug.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct XdriveSettingsDraft {
    /// Pending generic template editor text; never serialized or Debug-printed.
    /// Invalid JSON blocks validation while keeping the last parsed template intact.
    pub template_editor_text: Option<String>,
    /// `service`, including unknown or legacy spellings read from disk.
    pub service: Option<String>,
    /// `remoteFolder`: folder ID, local path or storage prefix, as given.
    pub remote_folder: Option<String>,
    /// Ordered service credentials. Never include in diagnostics or Debug.
    pub secrets: Option<Vec<String>>,
    /// `segmentBytes`.
    pub segment_bytes: Option<u32>,
    /// `flushIntervalMs`.
    pub flush_interval_ms: Option<u32>,
    /// `pollIntervalMs`.
    pub poll_interval_ms: Option<u32>,
    /// `maxPollIntervalMs`.
    pub max_poll_interval_ms: Option<u32>,
    /// `sessionTtlSeconds`.
    pub session_ttl_seconds: Option<u32>,
    /// `concurrency` (storage requests, distinct from outbound Mux concurrency).
    pub concurrency: Option<u32>,
    /// `eagerWindowMs`.
    pub eager_window_ms: Option<u32>,
    /// `holeTimeoutMs`.
    pub hole_timeout_ms: Option<u32>,
    /// Client-side connection pool, also used by an inbound's storage client.
    pub xmux: Option<XdriveXmuxDraft>,
    /// Arbitrary template JSON. Deep validation belongs to the core's runtime.
    pub template: Option<Value>,
    /// S3 service settings.
    pub s3: Option<XdriveS3Draft>,
    /// Unknown keys and unsupported shapes, including explicit nulls. May contain secrets.
    pub extras: Map<String, Value>,
    original: Option<Value>,
    raw: Option<Value>,
}

impl std::fmt::Debug for XdriveSettingsDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdriveSettingsDraft")
            .field("present", &self.original.is_some())
            .field("raw", &self.raw.is_some())
            .field("extra_fields", &self.extras.len())
            .finish_non_exhaustive()
    }
}

impl XdriveSettingsDraft {
    /// False for non-object nodes and known case aliases; use the preserved raw JSON path.
    pub fn is_structured_editable(&self) -> bool {
        self.raw.is_none()
    }
}

/// XDRIVE's six-field XMUX pool. Options retain absence separately from explicit zero.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct XdriveXmuxDraft {
    /// `maxConcurrency`, incompatible with positive maxConnections.
    pub max_concurrency: Option<RangeValue>,
    /// `maxConnections`.
    pub max_connections: Option<RangeValue>,
    /// `cMaxReuseTimes`.
    pub c_max_reuse_times: Option<RangeValue>,
    /// `hMaxRequestTimes`.
    pub h_max_request_times: Option<RangeValue>,
    /// `hMaxReusableSecs`.
    pub h_max_reusable_secs: Option<RangeValue>,
    /// `hKeepAlivePeriod`, signed int64 seconds.
    pub h_keep_alive_period: Option<i64>,
    /// Unknown fields / unsupported shapes; never printed by Debug.
    pub extras: Map<String, Value>,
}

/// S3 wire settings; credentials remain in the parent `secrets` array.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct XdriveS3Draft {
    /// `endpoint` (HTTP(S) without URL credentials, query or fragment).
    pub endpoint: Option<String>,
    /// `region` (empty leaves the core's default).
    pub region: Option<String>,
    /// `bucket`.
    pub bucket: Option<String>,
    /// `pathStyle`; absent/null means true in Xray.
    pub path_style: Option<bool>,
    /// Unknown fields / unsupported shapes; never printed by Debug.
    pub extras: Map<String, Value>,
}

macro_rules! opaque_debug {
    ($ty:ty, $name:literal) => {
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct($name).finish_non_exhaustive()
            }
        }
    };
}
opaque_debug!(XdriveXmuxDraft, "XdriveXmuxDraft");
opaque_debug!(XdriveS3Draft, "XdriveS3Draft");

fn take<T: DeserializeOwned>(object: &mut Map<String, Value>, key: &str) -> Option<T> {
    let parsed = serde_json::from_value(object.get(key)?.clone()).ok()?;
    object.remove(key);
    Some(parsed)
}

fn put<T: serde::Serialize>(object: &mut Map<String, Value>, key: &str, value: &Option<T>) {
    if let Some(value) = value {
        // All callers use JSON-compatible scalar/container types.
        if let Ok(value) = serde_json::to_value(value) {
            object.insert(key.to_owned(), value);
        }
    }
}

/// Reads an optional settings node without rejecting unknown fields or malformed shapes.
pub fn parse_xdrive_settings(value: Option<&Value>) -> XdriveSettingsDraft {
    let Some(value) = value else {
        return XdriveSettingsDraft::default();
    };
    let Some(object) = value.as_object() else {
        return XdriveSettingsDraft {
            original: Some(value.clone()),
            raw: Some(value.clone()),
            ..Default::default()
        };
    };
    // Go decodes known keys case-insensitively. Keep a case alias / duplicates on the raw path
    // rather than adding a canonical key whose precedence could differ in the core.
    let known = [
        "service",
        "remoteFolder",
        "secrets",
        "xmux",
        "s3",
        "template",
    ];
    if object.keys().any(|key| {
        known
            .iter()
            .chain(XDRIVE_UINT32_FIELDS)
            .any(|name| key.eq_ignore_ascii_case(name) && key != name)
    }) || [
        ("s3", &["endpoint", "region", "bucket", "pathStyle"][..]),
        (
            "xmux",
            &[
                "maxConcurrency",
                "maxConnections",
                "cMaxReuseTimes",
                "hMaxRequestTimes",
                "hMaxReusableSecs",
                "hKeepAlivePeriod",
            ][..],
        ),
    ]
    .iter()
    .any(|(key, known)| {
        object
            .get(*key)
            .and_then(Value::as_object)
            .is_some_and(|nested| {
                nested.keys().any(|key| {
                    known
                        .iter()
                        .any(|name| key.eq_ignore_ascii_case(name) && key != name)
                })
            })
    }) {
        return XdriveSettingsDraft {
            original: Some(value.clone()),
            raw: Some(value.clone()),
            ..Default::default()
        };
    }
    let mut extras = object.clone();
    let xmux = extras
        .get("xmux")
        .and_then(Value::as_object)
        .map(parse_xmux);
    if xmux.is_some() {
        extras.remove("xmux");
    }
    let s3 = extras.get("s3").and_then(Value::as_object).map(parse_s3);
    if s3.is_some() {
        extras.remove("s3");
    }
    XdriveSettingsDraft {
        template_editor_text: None,
        service: take(&mut extras, "service"),
        remote_folder: take(&mut extras, "remoteFolder"),
        secrets: take(&mut extras, "secrets"),
        segment_bytes: take(&mut extras, "segmentBytes"),
        flush_interval_ms: take(&mut extras, "flushIntervalMs"),
        poll_interval_ms: take(&mut extras, "pollIntervalMs"),
        max_poll_interval_ms: take(&mut extras, "maxPollIntervalMs"),
        session_ttl_seconds: take(&mut extras, "sessionTtlSeconds"),
        concurrency: take(&mut extras, "concurrency"),
        eager_window_ms: take(&mut extras, "eagerWindowMs"),
        hole_timeout_ms: take(&mut extras, "holeTimeoutMs"),
        template: extras.remove("template"),
        xmux,
        s3,
        extras,
        original: Some(value.clone()),
        raw: None,
    }
}

fn parse_xmux(object: &Map<String, Value>) -> XdriveXmuxDraft {
    let mut extras = object.clone();
    let mut range = |key| {
        let value = extras.get(key)?;
        if value.is_null() {
            return None;
        }
        let parsed = RangeValue::parse(Some(value))?;
        extras.remove(key);
        Some(parsed)
    };
    XdriveXmuxDraft {
        max_concurrency: range("maxConcurrency"),
        max_connections: range("maxConnections"),
        c_max_reuse_times: range("cMaxReuseTimes"),
        h_max_request_times: range("hMaxRequestTimes"),
        h_max_reusable_secs: range("hMaxReusableSecs"),
        h_keep_alive_period: take(&mut extras, "hKeepAlivePeriod"),
        extras,
    }
}

fn parse_s3(object: &Map<String, Value>) -> XdriveS3Draft {
    let mut extras = object.clone();
    XdriveS3Draft {
        endpoint: take(&mut extras, "endpoint"),
        region: take(&mut extras, "region"),
        bucket: take(&mut extras, "bucket"),
        path_style: take(&mut extras, "pathStyle"),
        extras,
    }
}

/// Serializes without validation: reading is broader than writing, including unknown service names.
/// An absent untouched node stays absent; explicit null, zero and empty values stay explicit.
pub fn xdrive_settings_to_value(draft: &XdriveSettingsDraft) -> Option<Value> {
    if let Some(raw) = &draft.raw {
        return Some(raw.clone());
    }
    let mut object = draft.extras.clone();
    put(&mut object, "service", &draft.service);
    put(&mut object, "remoteFolder", &draft.remote_folder);
    put(&mut object, "secrets", &draft.secrets);
    put(&mut object, "segmentBytes", &draft.segment_bytes);
    put(&mut object, "flushIntervalMs", &draft.flush_interval_ms);
    put(&mut object, "pollIntervalMs", &draft.poll_interval_ms);
    put(
        &mut object,
        "maxPollIntervalMs",
        &draft.max_poll_interval_ms,
    );
    put(&mut object, "sessionTtlSeconds", &draft.session_ttl_seconds);
    put(&mut object, "concurrency", &draft.concurrency);
    put(&mut object, "eagerWindowMs", &draft.eager_window_ms);
    put(&mut object, "holeTimeoutMs", &draft.hole_timeout_ms);
    put(&mut object, "template", &draft.template);
    if let Some(xmux) = &draft.xmux {
        let mut pool = xmux.extras.clone();
        for (key, range) in [
            ("maxConcurrency", &xmux.max_concurrency),
            ("maxConnections", &xmux.max_connections),
            ("cMaxReuseTimes", &xmux.c_max_reuse_times),
            ("hMaxRequestTimes", &xmux.h_max_request_times),
            ("hMaxReusableSecs", &xmux.h_max_reusable_secs),
        ] {
            if let Some(range) = range {
                let original = draft
                    .original
                    .as_ref()
                    .and_then(|v| v.get("xmux"))
                    .and_then(|v| v.get(key));
                let value = if original
                    .is_some_and(|v| RangeValue::parse(Some(v)).as_ref() == Some(range))
                {
                    original.cloned()
                } else {
                    range.to_value()
                };
                if let Some(value) = value {
                    pool.insert(key.to_owned(), value);
                }
            }
        }
        put(&mut pool, "hKeepAlivePeriod", &xmux.h_keep_alive_period);
        object.insert("xmux".to_owned(), Value::Object(pool));
    }
    if let Some(s3) = &draft.s3 {
        let mut settings = s3.extras.clone();
        put(&mut settings, "endpoint", &s3.endpoint);
        put(&mut settings, "region", &s3.region);
        put(&mut settings, "bucket", &s3.bucket);
        put(&mut settings, "pathStyle", &s3.path_style);
        object.insert("s3".to_owned(), Value::Object(settings));
    }
    if object.is_empty() && draft.original.is_none() {
        None
    } else {
        Some(Value::Object(object))
    }
}
