//! Presentation and explicit draft edits for XDRIVE. JSON stays in the application/domain layer.
use super::ApplicationService;
use crate::xray::{
    InboundProtocolDraft, InboundSecurityMode, OutboundTransport, RangeValue, StreamMethod,
    XDRIVE_UINT32_FIELDS, XdriveS3Draft, XdriveSettingsDraft, XdriveXmuxDraft,
    validate_xdrive_settings, xdrive_settings_to_value,
};
use serde_json::Value;

/// Which existing shell editor owns the storage settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdriveEditorSide {
    Inbound,
    Outbound,
}

/// A presentation-only text field; Debug is deliberately unavailable for credential values.
#[derive(Clone)]
pub struct XdriveFieldView {
    /// Allowlisted edit command identifier.
    pub id: String,
    /// JSON field label.
    pub label: String,
    /// Editable text (may be a credential).
    pub text: String,
    /// Hide the text by default.
    pub secret: bool,
    /// Render inside the advanced section.
    pub advanced: bool,
}

/// Presentation-only view for Stream's shared storage form. Never Debug-print its fields.
#[derive(Clone)]
pub struct XdriveEditorView {
    /// Stable only within this editor session; used for masked-field widget state.
    pub identity: uuid::Uuid,
    /// Typed editing is unavailable for raw/case-alias nodes.
    pub editable: bool,
    /// Allowlisted fields, already formatted without GUI-side JSON parsing.
    pub fields: Vec<XdriveFieldView>,
    /// Safe validation explanation (never echoes input values).
    pub problem: Option<String>,
    /// Generic template editor text. May contain credentials.
    pub template: Option<String>,
    /// Number of preserved fields with no structured control.
    pub preserved_count: usize,
}

fn scalar(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        None | Some(Value::Null) => String::new(),
        _ => "Unsupported JSON shape; use Raw JSON".to_owned(),
    }
}

impl ApplicationService {
    fn xdrive_draft(&self, side: XdriveEditorSide) -> Option<&XdriveSettingsDraft> {
        match side {
            XdriveEditorSide::Inbound => self
                .inbound_editor_session()
                .filter(|s| s.stream.method == Some(StreamMethod::Xdrive))
                .map(|s| &s.stream.xdrive),
            XdriveEditorSide::Outbound => self
                .outbound_editor_session()
                .filter(|s| s.stream.transport == Some(OutboundTransport::Xdrive))
                .map(|s| &s.stream.xdrive),
        }
    }

    fn commit_xdrive(
        &mut self,
        side: XdriveEditorSide,
        draft: XdriveSettingsDraft,
    ) -> Result<(), String> {
        match side {
            XdriveEditorSide::Inbound => {
                let session = self
                    .inbound_editor_session_mut()
                    .ok_or("No inbound editor")?;
                session.stream.xdrive = draft;
                session.stream.write_xdrive = true;
                session.dirty = true;
                session.diff_preview = None;
            }
            XdriveEditorSide::Outbound => {
                let session = self
                    .outbound_editor_session_mut()
                    .ok_or("No outbound editor")?;
                session.stream.xdrive = draft;
                session.stream.write_xdrive = true;
                session.diff_preview = None;
            }
        }
        Ok(())
    }

    /// Read-only projection; merely opening the form never changes a draft or its write flags.
    pub fn xdrive_editor_view(&self, side: XdriveEditorSide) -> Option<XdriveEditorView> {
        let draft = self.xdrive_draft(side)?;
        let value = xdrive_settings_to_value(draft).unwrap_or(Value::Null);
        let mut fields = Vec::new();
        let mut field = |id: &str, label: &str, text: String, secret: bool, advanced: bool| {
            fields.push(XdriveFieldView {
                id: id.to_owned(),
                label: label.to_owned(),
                text,
                secret,
                advanced,
            });
        };
        field(
            "service",
            "service",
            scalar(value.get("service")),
            false,
            false,
        );
        field(
            "remoteFolder",
            "remoteFolder / folder ID",
            scalar(value.get("remoteFolder")),
            false,
            false,
        );
        let service = value.get("service").and_then(Value::as_str).unwrap_or("");
        let credentials = value.get("secrets").and_then(Value::as_array);
        let required = if matches!(service, "google-drive" | "Google Drive" | "s3") {
            3
        } else {
            0
        };
        for index in 0..credentials.map_or(0, Vec::len).max(required) {
            let label = match (service, index) {
                ("google-drive" | "Google Drive", 0) => "ClientID (secrets[0])",
                ("google-drive" | "Google Drive", 1) => "ClientSecret (secrets[1])",
                ("google-drive" | "Google Drive", 2) => "RefreshToken (secrets[2])",
                ("s3", 0) => "AccessKeyID (secrets[0])",
                ("s3", 1) => "SecretAccessKey (secrets[1])",
                ("s3", 2) => "SessionToken (optional, secrets[2])",
                _ => "Preserved credential",
            };
            field(
                &format!("secret{index}"),
                label,
                scalar(credentials.and_then(|v| v.get(index))),
                true,
                false,
            );
        }
        if service == "s3" {
            for key in ["endpoint", "region", "bucket", "pathStyle"] {
                field(
                    &format!("s3.{key}"),
                    key,
                    scalar(value.get("s3").and_then(|s| s.get(key))),
                    false,
                    false,
                );
            }
        }
        for key in XDRIVE_UINT32_FIELDS {
            field(key, key, scalar(value.get(key)), false, true);
        }
        for key in [
            "maxConcurrency",
            "maxConnections",
            "cMaxReuseTimes",
            "hMaxRequestTimes",
            "hMaxReusableSecs",
            "hKeepAlivePeriod",
        ] {
            field(
                &format!("xmux.{key}"),
                key,
                scalar(value.get("xmux").and_then(|s| s.get(key))),
                false,
                true,
            );
        }
        let template = if service == "template"
            || draft.template.is_some()
            || draft.template_editor_text.is_some()
        {
            Some(draft.template_editor_text.clone().unwrap_or_else(|| {
                draft
                    .template
                    .as_ref()
                    .and_then(|value| serde_json::to_string_pretty(value).ok())
                    .unwrap_or_default()
            }))
        } else {
            None
        };
        Some(XdriveEditorView {
            identity: match side {
                XdriveEditorSide::Inbound => self.inbound_editor_session()?.xdrive_editor_id,
                XdriveEditorSide::Outbound => self.outbound_editor_session()?.xdrive_editor_id,
            },
            editable: draft.is_structured_editable(),
            fields,
            problem: validate_xdrive_settings(draft).err(),
            template,
            preserved_count: draft.extras.len()
                + draft.s3.as_ref().map_or(0, |s| s.extras.len())
                + draft.xmux.as_ref().map_or(0, |s| s.extras.len()),
        })
    }

    /// Edits one allowlisted field, retaining all siblings and the last valid template JSON.
    pub fn set_xdrive_field(
        &mut self,
        side: XdriveEditorSide,
        field: &str,
        text: String,
    ) -> Result<(), String> {
        let mut draft = self
            .xdrive_draft(side)
            .ok_or("No active XDRIVE editor")?
            .clone();
        if !draft.is_structured_editable() {
            return Err("Use Raw JSON for this preserved settings shape".to_owned());
        }
        match field {
            "service" => {
                draft.service = Some(text);
                draft.extras.remove("service");
            }
            "remoteFolder" => {
                draft.remote_folder = Some(text);
                draft.extras.remove("remoteFolder");
            }
            "template" => {
                if text.is_empty() {
                    draft.template = None;
                } else if let Ok(value) = serde_json::from_str(&text) {
                    draft.template = Some(value);
                }
                draft.template_editor_text = Some(text);
            }
            key if key.starts_with("secret") => {
                let index: usize = key[6..].parse().map_err(|_| "Unknown credential field")?;
                let value = xdrive_settings_to_value(&draft).unwrap_or(Value::Null);
                let mut values = match value.get("secrets") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(values)) => values.clone(),
                    _ => return Err("Credential array requires Raw JSON editing".to_owned()),
                };
                if index > values.len().max(2) {
                    return Err("Unknown credential index".to_owned());
                }
                values.resize(values.len().max(index + 1), Value::String(String::new()));
                values[index] = Value::String(text);
                draft.secrets = serde_json::from_value(Value::Array(values.clone())).ok();
                draft.extras.remove("secrets");
                if draft.secrets.is_none() {
                    draft
                        .extras
                        .insert("secrets".to_owned(), Value::Array(values));
                }
            }
            key if XDRIVE_UINT32_FIELDS.contains(&key) => {
                let value = if text.is_empty() {
                    None
                } else {
                    text.parse::<u32>().ok()
                };
                match key {
                    "segmentBytes" => draft.segment_bytes = value,
                    "flushIntervalMs" => draft.flush_interval_ms = value,
                    "pollIntervalMs" => draft.poll_interval_ms = value,
                    "maxPollIntervalMs" => draft.max_poll_interval_ms = value,
                    "sessionTtlSeconds" => draft.session_ttl_seconds = value,
                    "concurrency" => draft.concurrency = value,
                    "eagerWindowMs" => draft.eager_window_ms = value,
                    "holeTimeoutMs" => draft.hole_timeout_ms = value,
                    _ => {}
                }
                draft.extras.remove(key);
                if value.is_none() && !text.is_empty() {
                    draft.extras.insert(key.to_owned(), Value::String(text));
                }
            }
            key if key.starts_with("s3.") => {
                if draft.extras.contains_key("s3") {
                    return Err("Preserved s3 shape requires Raw JSON editing".to_owned());
                }
                let s3 = draft.s3.get_or_insert_with(XdriveS3Draft::default);
                let key = &key[3..];
                match key {
                    "endpoint" => s3.endpoint = Some(text),
                    "region" => s3.region = Some(text),
                    "bucket" => s3.bucket = Some(text),
                    "pathStyle" => {
                        s3.path_style = match text.as_str() {
                            "" => None,
                            "true" => Some(true),
                            "false" => Some(false),
                            _ => return Err("pathStyle must be true, false, or empty".to_owned()),
                        }
                    }
                    _ => return Err("Unknown S3 field".to_owned()),
                };
                s3.extras.remove(key);
            }
            key if key.starts_with("xmux.") => {
                if draft.extras.contains_key("xmux") {
                    return Err("Preserved xmux shape requires Raw JSON editing".to_owned());
                }
                let xmux = draft.xmux.get_or_insert_with(XdriveXmuxDraft::default);
                let key = &key[5..];
                let range = if text.is_empty() {
                    None
                } else {
                    Some(RangeValue::new(&text))
                };
                match key {
                    "maxConcurrency" => xmux.max_concurrency = range,
                    "maxConnections" => xmux.max_connections = range,
                    "cMaxReuseTimes" => xmux.c_max_reuse_times = range,
                    "hMaxRequestTimes" => xmux.h_max_request_times = range,
                    "hMaxReusableSecs" => xmux.h_max_reusable_secs = range,
                    "hKeepAlivePeriod" => xmux.h_keep_alive_period = text.parse().ok(),
                    _ => return Err("Unknown XMUX field".to_owned()),
                };
                xmux.extras.remove(key);
                if key == "hKeepAlivePeriod"
                    && !text.is_empty()
                    && xmux.h_keep_alive_period.is_none()
                {
                    xmux.extras.insert(key.to_owned(), Value::String(text));
                }
            }
            _ => return Err("Unknown XDRIVE field".to_owned()),
        }
        self.commit_xdrive(side, draft)
    }

    /// Gets storage-client TLS fields for an active inbound, without exposing a JSON model.
    pub fn inbound_xdrive_tls_fields(&self) -> Option<Vec<XdriveFieldView>> {
        let session = self
            .inbound_editor_session()
            .filter(|s| s.stream.method == Some(StreamMethod::Xdrive))?;
        let security = &session.stream.xdrive_security;
        let mut fields = Vec::new();
        for (key, text) in [
            (
                "security",
                security
                    .unknown_wire
                    .clone()
                    .unwrap_or_else(|| security.mode.as_wire().to_owned()),
            ),
            ("serverName", security.tls.server_name.clone()),
            ("alpn", security.tls.alpn.join(",")),
            ("fingerprint", security.tls.fingerprint.clone()),
            ("echConfigList", security.tls.ech_config_list.clone()),
            (
                "pinnedPeerCertSha256",
                security.tls.pinned_peer_cert_sha256.clone(),
            ),
            (
                "verifyPeerCertByName",
                security.tls.verify_peer_cert_by_name.clone(),
            ),
        ] {
            fields.push(XdriveFieldView {
                id: key.to_owned(),
                label: key.to_owned(),
                text,
                secret: false,
                advanced: false,
            });
        }
        Some(fields)
    }

    /// Changes client TLS on an inbound storage connection. Server certificate controls stay separate.
    pub fn set_inbound_xdrive_tls_field(
        &mut self,
        field: &str,
        text: String,
    ) -> Result<(), String> {
        let session = self
            .inbound_editor_session_mut()
            .filter(|s| s.stream.method == Some(StreamMethod::Xdrive))
            .ok_or("No inbound XDRIVE editor")?;
        let security = &mut session.stream.xdrive_security;
        match field {
            "security" => {
                security.mode = match text.as_str() {
                    "none" => InboundSecurityMode::None,
                    "tls" => InboundSecurityMode::Tls,
                    _ => return Err("Select none or tls for storage client security".to_owned()),
                };
            }
            "serverName" => security.tls.server_name = text,
            "alpn" => {
                security.tls.alpn = if text.is_empty() {
                    Vec::new()
                } else {
                    text.split(',').map(str::to_owned).collect()
                }
            }
            "fingerprint" => security.tls.fingerprint = text,
            "echConfigList" => security.tls.ech_config_list = text,
            "pinnedPeerCertSha256" => security.tls.pinned_peer_cert_sha256 = text,
            "verifyPeerCertByName" => security.tls.verify_peer_cert_by_name = text,
            _ => return Err("Unknown storage TLS field".to_owned()),
        }
        if field == "security" {
            security.unknown_wire = None;
        }
        session.stream.write_xdrive_security = true;
        session.dirty = true;
        session.diff_preview = None;
        Ok(())
    }

    /// Explicit Google Drive beta preset for new/empty storage settings; no existing data is deleted.
    /// Encryption keys and OAuth setup remain explicit user actions using the official core.
    pub fn apply_xdrive_google_preset(&mut self, side: XdriveEditorSide) -> Result<String, String> {
        let old = self.xdrive_draft(side).ok_or("Select XDRIVE first")?;
        if xdrive_settings_to_value(old).is_some_and(|v| v != serde_json::json!({})) {
            return Err("Preset applies only to empty XDRIVE settings; edit existing fields individually to preserve them".to_owned());
        }
        match side {
            XdriveEditorSide::Inbound => {
                let session = self
                    .inbound_editor_session_mut()
                    .ok_or("No inbound editor")?;
                if !matches!(session.protocol, InboundProtocolDraft::Vless { .. }) {
                    return Err("XDRIVE requires VLESS".to_owned());
                }
                if !session.stream.xdrive_security.is_editable()
                    || session.stream.xdrive_security.mode != InboundSecurityMode::None
                {
                    return Err("Preset requires unconfigured storage security; edit existing settings individually".to_owned());
                }
                session.stream.xdrive_security.mode = InboundSecurityMode::Tls;
                session.stream.xdrive_security.tls.alpn = vec!["h2".to_owned()];
                session.stream.write_xdrive_security = true;
                if session.general.port.is_none() {
                    session.general.port = Some(443);
                }
            }
            XdriveEditorSide::Outbound => {
                let session = self
                    .outbound_editor_session_mut()
                    .ok_or("No outbound editor")?;
                if !matches!(
                    session.settings,
                    crate::xray::OutboundSettingsDraft::Vless(_)
                ) {
                    return Err("XDRIVE requires VLESS".to_owned());
                }
                if !session.stream.security.is_editable()
                    || session.stream.security.mode != InboundSecurityMode::None
                {
                    return Err("Preset requires unconfigured storage security; edit existing settings individually".to_owned());
                }
                let mux = session.general.mux.get_or_insert_with(Default::default);
                if mux.foreign.is_some()
                    || mux.concurrency.trim().starts_with('-')
                    || mux.xudp_concurrency.trim().starts_with('-')
                    || mux.xudp_proxy_udp443 == "skip"
                {
                    return Err(
                        "Correct existing Mux settings explicitly before applying the preset"
                            .to_owned(),
                    );
                }
                mux.enabled = true;
                session.stream.security.mode = InboundSecurityMode::Tls;
                session.stream.security.tls.alpn = vec!["h2".to_owned()];
                session.stream.write = true;
                if let crate::xray::OutboundSettingsDraft::Vless(settings) = &mut session.settings {
                    if settings.address.is_empty() {
                        settings.address = "127.0.0.1".to_owned();
                    }
                    if settings.port.is_empty() {
                        settings.port = "443".to_owned();
                    }
                }
            }
        }
        let mut draft = XdriveSettingsDraft::default();
        draft.service = Some("google-drive".to_owned());
        draft.eager_window_ms = Some(10000);
        draft.secrets = Some(vec![String::new(); 3]);
        self.commit_xdrive(side, draft)?;
        let mux_note=match side{XdriveEditorSide::Inbound=>"Enable Mux in the paired client outbound.",XdriveEditorSide::Outbound=>"Mux enabled in this outbound."};
        Ok(format!("Preset staged: google-drive, eagerWindowMs=10000, TLS h2. {mux_note} Supply folder ID, ordered OAuth credentials and paired VLESS Encryption; review Preview before Save."))
    }
}
