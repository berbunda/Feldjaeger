//! Inbound Security tab drafts and apply helpers (none | tls | reality).

mod alpn;

pub use alpn::{
    ALPN_PRESETS, CERT_USAGE_PRESETS, CURVE_PRESETS, FINGERPRINT_PRESETS, TLS_VERSION_PRESETS,
};

use serde_json::{Map, Value};

use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// Transport security mode exposed in the GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundSecurityMode {
    /// `streamSettings.security = "none"` (or omit).
    None,
    /// `streamSettings.security = "tls"`.
    Tls,
    /// `streamSettings.security = "reality"`.
    Reality,
}

impl InboundSecurityMode {
    /// Wire string.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Reality => "reality",
        }
    }

    /// Parse from wire / draft string.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" | "" => Some(Self::None),
            "tls" => Some(Self::Tls),
            "reality" => Some(Self::Reality),
            _ => None,
        }
    }
}

/// Reality server fields editable in IB-L1 (Trojan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySettingsDraft {
    /// `show` (default false).
    pub show: bool,
    /// Destination `host:port` written as `target` (or preserved `dest` key).
    pub destination: String,
    /// Prefer writing `target` when creating new Reality; if disk had only `dest`, keep `dest`.
    pub destination_key: RealityDestinationKey,
    /// PROXY protocol version (optional).
    pub xver: Option<u64>,
    /// SNI list (required non-empty for G8).
    pub server_names: Vec<String>,
    /// Server private key (required).
    pub private_key: String,
    /// Short IDs (required non-empty for G8).
    pub short_ids: Vec<String>,
    /// Optional mldsa65 seed (L4; preserved if present, editable later).
    pub mldsa65_seed: Option<String>,
    /// `minClientVer` (x.y.z; empty = unset).
    pub min_client_ver: String,
    /// `maxClientVer` (x.y.z; empty = unset).
    pub max_client_ver: String,
    /// `maxTimeDiff` in milliseconds (`None` = unset).
    pub max_time_diff: Option<u64>,
    /// `limitFallbackUpload` rate limit for unverified fallback traffic.
    pub limit_fallback_upload: Option<RealityLimitFallbackDraft>,
    /// `limitFallbackDownload` rate limit for unverified fallback traffic.
    pub limit_fallback_download: Option<RealityLimitFallbackDraft>,
    /// `realitySettings.alpn` (required non-empty when fallbacks are present).
    pub alpn: Vec<String>,
    /// Unknown keys under `realitySettings` preserved on write.
    pub extras: Map<String, Value>,
}

/// `limitFallbackUpload` / `limitFallbackDownload` rate-limit sub-object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RealityLimitFallbackDraft {
    /// `afterBytes`.
    pub after_bytes: Option<u64>,
    /// `bytesPerSec`.
    pub bytes_per_sec: Option<u64>,
    /// `burstBytesPerSec`.
    pub burst_bytes_per_sec: Option<u64>,
}

/// Which JSON key holds the Reality destination on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RealityDestinationKey {
    /// Write / read `target` (preferred for new Reality).
    #[default]
    Target,
    /// Legacy `dest` key present on disk — preserve on write.
    Dest,
}

impl Default for RealitySettingsDraft {
    fn default() -> Self {
        Self {
            show: false,
            destination: String::new(),
            destination_key: RealityDestinationKey::Target,
            xver: None,
            server_names: Vec::new(),
            private_key: String::new(),
            short_ids: Vec::new(),
            mldsa65_seed: None,
            min_client_ver: String::new(),
            max_client_ver: String::new(),
            max_time_diff: None,
            limit_fallback_upload: None,
            limit_fallback_download: None,
            alpn: Vec::new(),
            extras: Map::new(),
        }
    }
}

/// One `tlsSettings.certificates[]` CertificateObject draft.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificateDraft {
    /// `certificateFile`.
    pub certificate_file: String,
    /// `keyFile`.
    pub key_file: String,
    /// Inline PEM lines (`certificate`).
    pub certificate: Vec<String>,
    /// Inline PEM lines (`key`).
    pub key: Vec<String>,
    /// `ocspStapling` (seconds; omit when None/0).
    pub ocsp_stapling: Option<u64>,
    /// `oneTimeLoading`.
    pub one_time_loading: bool,
    /// `usage` (`encipherment` | `verify` | `issue`).
    pub usage: String,
    /// `buildChain` (only meaningful when usage is `issue`).
    pub build_chain: bool,
    /// Unknown keys besides typed CertificateObject fields.
    pub extras: Map<String, Value>,
}

/// Full `tlsSettings` draft (advanced TLS), including multi-entry certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettingsDraft {
    /// Typed `certificates[]` (always ≥1 in editor / default / parse-empty).
    pub certificates: Vec<CertificateDraft>,
    /// `serverName`.
    pub server_name: String,
    /// `verifyPeerCertByName`.
    pub verify_peer_cert_by_name: String,
    /// `rejectUnknownSni`.
    pub reject_unknown_sni: bool,
    /// `allowInsecure` (client; deprecated in Xray docs).
    pub allow_insecure: bool,
    /// `alpn` array.
    pub alpn: Vec<String>,
    /// `minVersion`.
    pub min_version: String,
    /// `maxVersion`.
    pub max_version: String,
    /// `cipherSuites` (`:`-separated).
    pub cipher_suites: String,
    /// `disableSystemRoot`.
    pub disable_system_root: bool,
    /// `enableSessionResumption`.
    pub enable_session_resumption: bool,
    /// `fingerprint`.
    pub fingerprint: String,
    /// `pinnedPeerCertSha256`.
    pub pinned_peer_cert_sha256: String,
    /// `curvePreferences`.
    pub curve_preferences: Vec<String>,
    /// `masterKeyLog`.
    pub master_key_log: String,
    /// UI gate for ECH fields (true when any ECH field is non-empty on parse).
    pub enable_ech: bool,
    /// `echServerKeys` (server).
    pub ech_server_keys: String,
    /// `echConfigList` (client).
    pub ech_config_list: String,
    /// `echSockopt` raw object (structured sockopt editor is a separate roadmap item).
    pub ech_sockopt: Option<Value>,
    /// Unknown keys under `tlsSettings` (excluding `certificates` and typed keys).
    pub extras: Map<String, Value>,
}

impl Default for TlsSettingsDraft {
    fn default() -> Self {
        Self {
            certificates: vec![CertificateDraft::default()],
            server_name: String::new(),
            verify_peer_cert_by_name: String::new(),
            reject_unknown_sni: false,
            allow_insecure: false,
            alpn: Vec::new(),
            min_version: String::new(),
            max_version: String::new(),
            cipher_suites: String::new(),
            disable_system_root: false,
            enable_session_resumption: false,
            fingerprint: String::new(),
            pinned_peer_cert_sha256: String::new(),
            curve_preferences: Vec::new(),
            master_key_log: String::new(),
            enable_ech: false,
            ech_server_keys: String::new(),
            ech_config_list: String::new(),
            ech_sockopt: None,
            extras: Map::new(),
        }
    }
}

/// Security tab draft for Shell Save / Add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSecurityDraft {
    /// none | tls | reality (ignored when [`Self::security_unknown`]).
    pub mode: InboundSecurityMode,
    /// Present when mode is Reality (or when editing existing Reality extras).
    pub reality: RealitySettingsDraft,
    /// Present when mode is Tls.
    pub tls: TlsSettingsDraft,
    /// Unknown wire `security` (not none/tls/reality): open read-only; Save blocked.
    pub security_unknown: bool,
    /// Original unknown wire string (for banner / diagnostics).
    pub unknown_security_wire: Option<String>,
}

impl Default for InboundSecurityDraft {
    fn default() -> Self {
        Self {
            mode: InboundSecurityMode::None,
            reality: RealitySettingsDraft::default(),
            tls: TlsSettingsDraft::default(),
            security_unknown: false,
            unknown_security_wire: None,
        }
    }
}

impl InboundSecurityDraft {
    /// Whether Shell Security fields are editable (CQ6 / X3).
    pub fn is_editable(&self) -> bool {
        !self.security_unknown
    }

    /// Active ALPN list for the current security mode (empty for `none`).
    pub fn active_alpn(&self) -> &[String] {
        match self.mode {
            InboundSecurityMode::Tls => &self.tls.alpn,
            InboundSecurityMode::Reality => &self.reality.alpn,
            InboundSecurityMode::None => &[],
        }
    }
}

const TLS_KNOWN_KEYS: &[&str] = &[
    "serverName",
    "verifyPeerCertByName",
    "rejectUnknownSni",
    "allowInsecure",
    "alpn",
    "minVersion",
    "maxVersion",
    "cipherSuites",
    "certificates",
    "disableSystemRoot",
    "enableSessionResumption",
    "fingerprint",
    "pinnedPeerCertSha256",
    "curvePreferences",
    "masterKeyLog",
    "echServerKeys",
    "echConfigList",
    "echSockopt",
];

const CERT_KNOWN_KEYS: &[&str] = &[
    "certificateFile",
    "keyFile",
    "certificate",
    "key",
    "ocspStapling",
    "oneTimeLoading",
    "usage",
    "buildChain",
];

/// Parses Security draft from an inbound object (missing → none).
pub fn parse_inbound_security(inbound: &Value) -> InboundSecurityDraft {
    let Some(stream) = inbound.get("streamSettings").filter(|v| !v.is_null()) else {
        return InboundSecurityDraft::default();
    };

    let wire = stream
        .get("security")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("none");

    let mut draft = InboundSecurityDraft::default();

    match InboundSecurityMode::from_wire(wire) {
        Some(mode) => {
            draft.mode = mode;
        }
        None => {
            draft.security_unknown = true;
            draft.unknown_security_wire = Some(wire.to_owned());
            draft.mode = InboundSecurityMode::None;
        }
    }

    if let Some(reality) = stream.get("realitySettings").and_then(Value::as_object) {
        draft.reality = parse_reality_settings(reality);
    }
    if let Some(tls) = stream.get("tlsSettings").and_then(Value::as_object) {
        draft.tls = parse_tls_settings(tls);
    }
    draft
}

fn parse_tls_settings(tls: &Map<String, Value>) -> TlsSettingsDraft {
    let mut extras = Map::new();
    for (key, value) in tls {
        if !TLS_KNOWN_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }

    let certificates = match tls.get("certificates").and_then(Value::as_array) {
        Some(certs) if !certs.is_empty() => certs
            .iter()
            .map(|entry| {
                entry
                    .as_object()
                    .map(parse_certificate_draft)
                    .unwrap_or_default()
            })
            .collect(),
        _ => vec![CertificateDraft::default()],
    };

    let ech_server_keys = string_field(tls.get("echServerKeys"));
    let ech_config_list = string_field(tls.get("echConfigList"));
    let ech_sockopt = tls.get("echSockopt").filter(|v| v.is_object()).cloned();
    let enable_ech = !ech_server_keys.is_empty()
        || !ech_config_list.is_empty()
        || ech_sockopt.is_some();

    TlsSettingsDraft {
        certificates,
        server_name: string_field(tls.get("serverName")),
        verify_peer_cert_by_name: string_field(tls.get("verifyPeerCertByName")),
        reject_unknown_sni: bool_field(tls.get("rejectUnknownSni")),
        allow_insecure: bool_field(tls.get("allowInsecure")),
        alpn: string_array(tls.get("alpn")),
        min_version: string_field(tls.get("minVersion")),
        max_version: string_field(tls.get("maxVersion")),
        cipher_suites: string_field(tls.get("cipherSuites")),
        disable_system_root: bool_field(tls.get("disableSystemRoot")),
        enable_session_resumption: bool_field(tls.get("enableSessionResumption")),
        fingerprint: string_field(tls.get("fingerprint")),
        pinned_peer_cert_sha256: string_field(tls.get("pinnedPeerCertSha256")),
        curve_preferences: string_array(tls.get("curvePreferences")),
        master_key_log: string_field(tls.get("masterKeyLog")),
        enable_ech,
        ech_server_keys,
        ech_config_list,
        ech_sockopt,
        extras,
    }
}

fn parse_certificate_draft(cert: &Map<String, Value>) -> CertificateDraft {
    let mut extras = Map::new();
    for (key, value) in cert {
        if !CERT_KNOWN_KEYS.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }
    CertificateDraft {
        certificate_file: string_field(cert.get("certificateFile")),
        key_file: string_field(cert.get("keyFile")),
        certificate: string_array(cert.get("certificate")),
        key: string_array(cert.get("key")),
        ocsp_stapling: cert
            .get("ocspStapling")
            .and_then(Value::as_u64)
            .filter(|&v| v != 0),
        one_time_loading: cert
            .get("oneTimeLoading")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        usage: string_field(cert.get("usage")),
        build_chain: cert
            .get("buildChain")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        extras,
    }
}

fn certificate_draft_to_value(cert: &CertificateDraft) -> Value {
    let mut object = Map::new();
    object.insert(
        "certificateFile".to_owned(),
        Value::String(cert.certificate_file.trim().to_owned()),
    );
    object.insert(
        "keyFile".to_owned(),
        Value::String(cert.key_file.trim().to_owned()),
    );
    insert_string_array(&mut object, "certificate", &cert.certificate);
    insert_string_array(&mut object, "key", &cert.key);
    if let Some(ocsp) = cert.ocsp_stapling.filter(|&v| v != 0) {
        object.insert("ocspStapling".to_owned(), Value::Number(ocsp.into()));
    }
    insert_bool_true(&mut object, "oneTimeLoading", cert.one_time_loading);
    insert_non_empty_string(&mut object, "usage", &cert.usage);
    if cert.usage.trim() == "issue" {
        insert_bool_true(&mut object, "buildChain", cert.build_chain);
    }
    for (key, value) in &cert.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

fn parse_reality_settings(reality: &Map<String, Value>) -> RealitySettingsDraft {
    let mut extras = Map::new();
    let known = [
        "show",
        "target",
        "dest",
        "xver",
        "serverNames",
        "privateKey",
        "shortIds",
        "mldsa65Seed",
        "minClientVer",
        "maxClientVer",
        "maxTimeDiff",
        "limitFallbackUpload",
        "limitFallbackDownload",
        "alpn",
    ];
    for (key, value) in reality {
        if !known.contains(&key.as_str()) {
            extras.insert(key.clone(), value.clone());
        }
    }

    let (destination, destination_key) = if let Some(target) = reality
        .get("target")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        (target, RealityDestinationKey::Target)
    } else if let Some(dest) = reality.get("dest").and_then(Value::as_str).map(str::to_owned) {
        (dest, RealityDestinationKey::Dest)
    } else {
        (String::new(), RealityDestinationKey::Target)
    };

    RealitySettingsDraft {
        show: reality
            .get("show")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        destination,
        destination_key,
        xver: reality.get("xver").and_then(Value::as_u64),
        server_names: string_array(reality.get("serverNames")),
        private_key: string_field(reality.get("privateKey")),
        short_ids: string_array(reality.get("shortIds")),
        mldsa65_seed: reality
            .get("mldsa65Seed")
            .and_then(Value::as_str)
            .map(str::to_owned),
        min_client_ver: string_field(reality.get("minClientVer")),
        max_client_ver: string_field(reality.get("maxClientVer")),
        max_time_diff: reality.get("maxTimeDiff").and_then(Value::as_u64),
        limit_fallback_upload: parse_limit_fallback(reality.get("limitFallbackUpload")),
        limit_fallback_download: parse_limit_fallback(reality.get("limitFallbackDownload")),
        alpn: string_array(reality.get("alpn")),
        extras,
    }
}

fn parse_limit_fallback(value: Option<&Value>) -> Option<RealityLimitFallbackDraft> {
    let object = value?.as_object()?;
    Some(RealityLimitFallbackDraft {
        after_bytes: object.get("afterBytes").and_then(Value::as_u64),
        bytes_per_sec: object.get("bytesPerSec").and_then(Value::as_u64),
        burst_bytes_per_sec: object.get("burstBytesPerSec").and_then(Value::as_u64),
    })
}

fn string_field(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn bool_field(value: Option<&Value>) -> bool {
    value.and_then(Value::as_bool).unwrap_or(false)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.trim().to_owned()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn insert_non_empty_string(object: &mut Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        object.insert(key.to_owned(), Value::String(trimmed.to_owned()));
    }
}

fn insert_string_array(object: &mut Map<String, Value>, key: &str, values: &[String]) {
    let cleaned: Vec<Value> = values
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| Value::String(s.to_owned()))
        .collect();
    if !cleaned.is_empty() {
        object.insert(key.to_owned(), Value::Array(cleaned));
    }
}

fn insert_bool_true(object: &mut Map<String, Value>, key: &str, value: bool) {
    if value {
        object.insert(key.to_owned(), Value::Bool(true));
    }
}

fn limit_fallback_to_value(limit: &RealityLimitFallbackDraft) -> Value {
    let mut object = Map::new();
    if let Some(after_bytes) = limit.after_bytes {
        object.insert("afterBytes".to_owned(), Value::Number(after_bytes.into()));
    }
    if let Some(bytes_per_sec) = limit.bytes_per_sec {
        object.insert(
            "bytesPerSec".to_owned(),
            Value::Number(bytes_per_sec.into()),
        );
    }
    if let Some(burst_bytes_per_sec) = limit.burst_bytes_per_sec {
        object.insert(
            "burstBytesPerSec".to_owned(),
            Value::Number(burst_bytes_per_sec.into()),
        );
    }
    Value::Object(object)
}

/// Applies Security draft into `inbound` in place (step 5 of Shell Save).
///
/// - Unknown security: `ValidationFailed` (never rewrite wire as `none`).
/// - `none`: sets security none; removes `realitySettings` **and** `tlsSettings`.
/// - `tls`: ensures streamSettings, sets security, patches `tlsSettings`; strips Reality.
/// - `reality`: ensures streamSettings, patches `realitySettings`; strips TLS.
pub fn apply_inbound_security(
    inbound: &mut Value,
    draft: &InboundSecurityDraft,
) -> ConfigModifyResult<()> {
    if draft.security_unknown {
        let wire = draft
            .unknown_security_wire
            .as_deref()
            .unwrap_or("unknown");
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!(
                "Unknown streamSettings.security '{wire}'; choose none, tls, or reality before Save"
            ),
        ));
    }

    match draft.mode {
        InboundSecurityMode::None => apply_security_none(inbound),
        InboundSecurityMode::Tls => apply_security_tls(inbound, &draft.tls),
        InboundSecurityMode::Reality => apply_security_reality(inbound, &draft.reality),
    }
}

fn ensure_stream_settings(root: &mut Map<String, Value>) -> ConfigModifyResult<&mut Map<String, Value>> {
    if !root.contains_key("streamSettings") || root.get("streamSettings").is_some_and(Value::is_null)
    {
        let mut stream = Map::new();
        stream.insert("network".to_owned(), Value::String("tcp".to_owned()));
        root.insert("streamSettings".to_owned(), Value::Object(stream));
    }
    root.get_mut("streamSettings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "streamSettings must be a JSON object".to_owned(),
            )
        })
}

fn apply_security_none(inbound: &mut Value) -> ConfigModifyResult<()> {
    let Some(root) = inbound.as_object_mut() else {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        ));
    };
    if let Some(stream) = root.get_mut("streamSettings").and_then(Value::as_object_mut) {
        stream.insert("security".to_owned(), Value::String("none".to_owned()));
        stream.remove("realitySettings");
        stream.remove("tlsSettings");
    }
    Ok(())
}

fn apply_security_tls(inbound: &mut Value, tls: &TlsSettingsDraft) -> ConfigModifyResult<()> {
    let Some(root) = inbound.as_object_mut() else {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        ));
    };

    let stream = ensure_stream_settings(root)?;
    if !stream.contains_key("network") && !stream.contains_key("method") {
        stream.insert("network".to_owned(), Value::String("tcp".to_owned()));
    }
    stream.insert("security".to_owned(), Value::String("tls".to_owned()));
    stream.remove("realitySettings");

    let mut object = Map::new();
    insert_non_empty_string(&mut object, "serverName", &tls.server_name);
    insert_non_empty_string(
        &mut object,
        "verifyPeerCertByName",
        &tls.verify_peer_cert_by_name,
    );
    insert_bool_true(&mut object, "rejectUnknownSni", tls.reject_unknown_sni);
    insert_bool_true(&mut object, "allowInsecure", tls.allow_insecure);
    insert_string_array(&mut object, "alpn", &tls.alpn);
    insert_non_empty_string(&mut object, "minVersion", &tls.min_version);
    insert_non_empty_string(&mut object, "maxVersion", &tls.max_version);
    insert_non_empty_string(&mut object, "cipherSuites", &tls.cipher_suites);
    insert_bool_true(&mut object, "disableSystemRoot", tls.disable_system_root);
    insert_bool_true(
        &mut object,
        "enableSessionResumption",
        tls.enable_session_resumption,
    );
    insert_non_empty_string(&mut object, "fingerprint", &tls.fingerprint);
    insert_non_empty_string(
        &mut object,
        "pinnedPeerCertSha256",
        &tls.pinned_peer_cert_sha256,
    );
    insert_string_array(&mut object, "curvePreferences", &tls.curve_preferences);
    insert_non_empty_string(&mut object, "masterKeyLog", &tls.master_key_log);

    if tls.enable_ech {
        insert_non_empty_string(&mut object, "echServerKeys", &tls.ech_server_keys);
        insert_non_empty_string(&mut object, "echConfigList", &tls.ech_config_list);
        if let Some(sockopt) = &tls.ech_sockopt {
            if sockopt.is_object() {
                object.insert("echSockopt".to_owned(), sockopt.clone());
            }
        }
    }

    let cert_drafts = if tls.certificates.is_empty() {
        vec![CertificateDraft::default()]
    } else {
        tls.certificates.clone()
    };
    let certificates: Vec<Value> = cert_drafts
        .iter()
        .map(certificate_draft_to_value)
        .collect();
    object.insert("certificates".to_owned(), Value::Array(certificates));

    for (key, value) in &tls.extras {
        if key != "certificates" && !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }

    stream.insert("tlsSettings".to_owned(), Value::Object(object));
    Ok(())
}

fn apply_security_reality(
    inbound: &mut Value,
    reality: &RealitySettingsDraft,
) -> ConfigModifyResult<()> {
    let Some(root) = inbound.as_object_mut() else {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        ));
    };

    let stream = ensure_stream_settings(root)?;
    if !stream.contains_key("network") && !stream.contains_key("method") {
        stream.insert("network".to_owned(), Value::String("tcp".to_owned()));
    }
    stream.insert("security".to_owned(), Value::String("reality".to_owned()));
    stream.remove("tlsSettings");

    let mut object = Map::new();

    let dest_key = match reality.destination_key {
        RealityDestinationKey::Target => "target",
        RealityDestinationKey::Dest => "dest",
    };
    object.insert(
        dest_key.to_owned(),
        Value::String(reality.destination.trim().to_owned()),
    );
    object.insert("show".to_owned(), Value::Bool(reality.show));
    object.insert(
        "privateKey".to_owned(),
        Value::String(reality.private_key.trim().to_owned()),
    );
    object.insert(
        "serverNames".to_owned(),
        Value::Array(
            reality
                .server_names
                .iter()
                .map(|s| Value::String(s.trim().to_owned()))
                .filter(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                .collect(),
        ),
    );
    object.insert(
        "shortIds".to_owned(),
        Value::Array(
            reality
                .short_ids
                .iter()
                .map(|s| Value::String(s.trim().to_owned()))
                .filter(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                .collect(),
        ),
    );
    match reality.xver {
        Some(xver) => {
            object.insert("xver".to_owned(), Value::Number(xver.into()));
        }
        None => {}
    }
    match &reality.mldsa65_seed {
        Some(seed) if !seed.trim().is_empty() => {
            object.insert(
                "mldsa65Seed".to_owned(),
                Value::String(seed.trim().to_owned()),
            );
        }
        _ => {}
    }
    insert_non_empty_string(&mut object, "minClientVer", &reality.min_client_ver);
    insert_non_empty_string(&mut object, "maxClientVer", &reality.max_client_ver);
    if let Some(max_time_diff) = reality.max_time_diff {
        object.insert("maxTimeDiff".to_owned(), Value::Number(max_time_diff.into()));
    }
    if let Some(limit) = &reality.limit_fallback_upload {
        object.insert(
            "limitFallbackUpload".to_owned(),
            limit_fallback_to_value(limit),
        );
    }
    if let Some(limit) = &reality.limit_fallback_download {
        object.insert(
            "limitFallbackDownload".to_owned(),
            limit_fallback_to_value(limit),
        );
    }
    insert_string_array(&mut object, "alpn", &reality.alpn);
    for (key, value) in &reality.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }

    stream.insert("realitySettings".to_owned(), Value::Object(object));
    Ok(())
}

/// Builds the Reality `streamSettings` fragment for Trojan Add templates.
pub fn trojan_reality_stream_settings(reality: &RealitySettingsDraft) -> Value {
    let mut inbound = Value::Object(Map::new());
    apply_security_reality(&mut inbound, reality).expect("empty object apply");
    inbound
        .get("streamSettings")
        .cloned()
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_tls_reads_typed_fields() {
        let inbound = json!({
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {
                    "serverName": "example.com",
                    "alpn": ["h2", "http/1.1"],
                    "rejectUnknownSni": true,
                    "certificates": [{
                        "certificateFile": "/c.pem",
                        "keyFile": "/k.pem",
                        "usage": "encipherment",
                        "oneTimeLoading": true
                    }],
                    "customKeep": 1
                }
            }
        });
        let draft = parse_inbound_security(&inbound);
        assert_eq!(draft.mode, InboundSecurityMode::Tls);
        assert!(!draft.security_unknown);
        assert_eq!(draft.tls.certificates.len(), 1);
        assert_eq!(draft.tls.certificates[0].certificate_file, "/c.pem");
        assert_eq!(draft.tls.certificates[0].key_file, "/k.pem");
        assert_eq!(draft.tls.certificates[0].usage, "encipherment");
        assert!(draft.tls.certificates[0].one_time_loading);
        assert_eq!(draft.tls.server_name, "example.com");
        assert_eq!(draft.tls.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
        assert!(draft.tls.reject_unknown_sni);
        assert!(draft.tls.certificates[0].extras.is_empty());
        assert_eq!(draft.tls.extras.get("customKeep"), Some(&json!(1)));
    }

    #[test]
    fn apply_tls_roundtrip_typed_and_extras() {
        let mut inbound = json!({"streamSettings":{"network":"tcp"}});
        let draft = InboundSecurityDraft {
            mode: InboundSecurityMode::Tls,
            tls: TlsSettingsDraft {
                certificates: vec![CertificateDraft {
                    certificate_file: "/c.pem".into(),
                    key_file: "/k.pem".into(),
                    usage: "issue".into(),
                    build_chain: true,
                    certificate: vec!["--BEGIN CERTIFICATE--".into(), "abc".into()],
                    ..Default::default()
                }],
                server_name: "sni.example".into(),
                alpn: vec!["h2".into()],
                enable_ech: true,
                ech_server_keys: "ech-key".into(),
                extras: {
                    let mut m = Map::new();
                    m.insert("keepMe".into(), json!(true));
                    m
                },
                ..Default::default()
            },
            ..Default::default()
        };
        apply_inbound_security(&mut inbound, &draft).unwrap();
        let tls = &inbound["streamSettings"]["tlsSettings"];
        assert_eq!(tls["serverName"], "sni.example");
        assert_eq!(tls["alpn"], json!(["h2"]));
        assert_eq!(tls["echServerKeys"], "ech-key");
        assert_eq!(tls["keepMe"], true);
        assert_eq!(tls["certificates"][0]["usage"], "issue");
        assert_eq!(tls["certificates"][0]["buildChain"], true);
        assert_eq!(
            tls["certificates"][0]["certificate"],
            json!(["--BEGIN CERTIFICATE--", "abc"])
        );

        let parsed = parse_inbound_security(&inbound);
        assert_eq!(parsed.tls.server_name, "sni.example");
        assert_eq!(parsed.tls.alpn, vec!["h2".to_owned()]);
        assert!(parsed.tls.enable_ech);
        assert_eq!(parsed.tls.certificates[0].usage, "issue");
        assert!(parsed.tls.certificates[0].build_chain);
    }

    #[test]
    fn unknown_security_is_read_only_not_none() {
        let inbound = json!({"streamSettings":{"security":"foo"}});
        let draft = parse_inbound_security(&inbound);
        assert!(draft.security_unknown);
        assert!(!draft.is_editable());
        assert_eq!(draft.unknown_security_wire.as_deref(), Some("foo"));
        let mut round = inbound.clone();
        let err = apply_inbound_security(&mut round, &draft).unwrap_err();
        assert!(err.message().contains("Unknown"));
        assert_eq!(round.get("streamSettings").unwrap().get("security").unwrap(), "foo");
    }

    #[test]
    fn none_strips_tls_and_reality() {
        let mut inbound = json!({
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"certificates":[{"certificateFile":"/c","keyFile":"/k"}]},
                "realitySettings": {"privateKey":"x"}
            }
        });
        apply_inbound_security(
            &mut inbound,
            &InboundSecurityDraft {
                mode: InboundSecurityMode::None,
                ..Default::default()
            },
        )
        .unwrap();
        let stream = inbound.get("streamSettings").unwrap().as_object().unwrap();
        assert_eq!(stream.get("security").and_then(Value::as_str), Some("none"));
        assert!(!stream.contains_key("tlsSettings"));
        assert!(!stream.contains_key("realitySettings"));
    }

    #[test]
    fn tls_strips_reality_and_preserves_extra_certs() {
        let mut inbound = json!({
            "streamSettings": {
                "security": "reality",
                "realitySettings": {"privateKey":"x"},
                "tlsSettings": {
                    "certificates": [
                        {"certificateFile":"old","keyFile":"old"},
                        {"certificateFile":"keep","keyFile":"keep2"}
                    ]
                }
            }
        });
        let draft = InboundSecurityDraft {
            mode: InboundSecurityMode::Tls,
            tls: TlsSettingsDraft {
                certificates: vec![
                    CertificateDraft {
                        certificate_file: "/c.pem".into(),
                        key_file: "/k.pem".into(),
                        ..Default::default()
                    },
                    CertificateDraft {
                        certificate_file: "keep".into(),
                        key_file: "keep2".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        apply_inbound_security(&mut inbound, &draft).unwrap();
        let stream = inbound.get("streamSettings").unwrap().as_object().unwrap();
        assert_eq!(stream.get("security").and_then(Value::as_str), Some("tls"));
        assert!(!stream.contains_key("realitySettings"));
        let certs = stream
            .get("tlsSettings")
            .unwrap()
            .get("certificates")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].get("certificateFile").and_then(Value::as_str), Some("/c.pem"));
        assert_eq!(certs[1].get("certificateFile").and_then(Value::as_str), Some("keep"));
    }

    #[test]
    fn parse_tls_maps_all_certificate_entries() {
        let inbound = json!({
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {"certificateFile":"/a.pem","keyFile":"/a.key"},
                        {"certificateFile":"/b.pem","keyFile":"/b.key","usage":"verify"}
                    ]
                }
            }
        });
        let draft = parse_inbound_security(&inbound);
        assert_eq!(draft.tls.certificates.len(), 2);
        assert_eq!(draft.tls.certificates[1].usage, "verify");
        assert_eq!(draft.tls.certificates[1].certificate_file, "/b.pem");
    }

    #[test]
    fn reality_strips_tls_and_writes_alpn() {
        let mut inbound = json!({
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {"certificates":[{"certificateFile":"/c","keyFile":"/k"}]}
            }
        });
        let draft = InboundSecurityDraft {
            mode: InboundSecurityMode::Reality,
            reality: RealitySettingsDraft {
                destination: "www.example.com:443".into(),
                private_key: "k".into(),
                server_names: vec!["www.example.com".into()],
                short_ids: vec!["abcd".into()],
                alpn: vec!["h2".into(), "http/1.1".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        apply_inbound_security(&mut inbound, &draft).unwrap();
        let stream = inbound.get("streamSettings").unwrap().as_object().unwrap();
        assert_eq!(stream.get("security").and_then(Value::as_str), Some("reality"));
        assert!(!stream.contains_key("tlsSettings"));
        assert_eq!(
            stream.get("realitySettings").unwrap().get("alpn"),
            Some(&json!(["h2", "http/1.1"]))
        );
    }

    #[test]
    fn parse_reality_reads_advanced_fields() {
        let inbound = json!({
            "streamSettings": {
                "security": "reality",
                "realitySettings": {
                    "target": "www.example.com:443",
                    "privateKey": "k",
                    "serverNames": ["www.example.com"],
                    "shortIds": ["abcd"],
                    "show": true,
                    "xver": 1,
                    "minClientVer": "1.8.0",
                    "maxClientVer": "2.0.0",
                    "maxTimeDiff": 5000,
                    "limitFallbackUpload": {
                        "afterBytes": 1000,
                        "bytesPerSec": 2000,
                        "burstBytesPerSec": 3000
                    },
                    "limitFallbackDownload": {
                        "afterBytes": 4000
                    },
                    "customKeep": true
                }
            }
        });
        let draft = parse_inbound_security(&inbound);
        assert!(draft.reality.show);
        assert_eq!(draft.reality.xver, Some(1));
        assert_eq!(draft.reality.min_client_ver, "1.8.0");
        assert_eq!(draft.reality.max_client_ver, "2.0.0");
        assert_eq!(draft.reality.max_time_diff, Some(5000));
        let upload = draft.reality.limit_fallback_upload.expect("upload limit");
        assert_eq!(upload.after_bytes, Some(1000));
        assert_eq!(upload.bytes_per_sec, Some(2000));
        assert_eq!(upload.burst_bytes_per_sec, Some(3000));
        let download = draft
            .reality
            .limit_fallback_download
            .expect("download limit");
        assert_eq!(download.after_bytes, Some(4000));
        assert_eq!(download.bytes_per_sec, None);
        assert_eq!(draft.reality.extras.get("customKeep"), Some(&json!(true)));
    }

    #[test]
    fn apply_reality_roundtrip_advanced_fields() {
        let mut inbound = json!({"streamSettings":{"network":"tcp"}});
        let draft = InboundSecurityDraft {
            mode: InboundSecurityMode::Reality,
            reality: RealitySettingsDraft {
                destination: "www.example.com:443".into(),
                private_key: "k".into(),
                server_names: vec!["www.example.com".into()],
                short_ids: vec!["abcd".into()],
                show: true,
                xver: Some(2),
                min_client_ver: "1.8.0".into(),
                max_client_ver: "2.0.0".into(),
                max_time_diff: Some(1500),
                limit_fallback_upload: Some(RealityLimitFallbackDraft {
                    after_bytes: Some(100),
                    bytes_per_sec: Some(200),
                    burst_bytes_per_sec: Some(300),
                }),
                limit_fallback_download: None,
                ..Default::default()
            },
            ..Default::default()
        };
        apply_inbound_security(&mut inbound, &draft).unwrap();
        let reality = &inbound["streamSettings"]["realitySettings"];
        assert_eq!(reality["show"], true);
        assert_eq!(reality["xver"], 2);
        assert_eq!(reality["minClientVer"], "1.8.0");
        assert_eq!(reality["maxClientVer"], "2.0.0");
        assert_eq!(reality["maxTimeDiff"], 1500);
        assert_eq!(reality["limitFallbackUpload"]["afterBytes"], 100);
        assert_eq!(reality["limitFallbackUpload"]["bytesPerSec"], 200);
        assert_eq!(reality["limitFallbackUpload"]["burstBytesPerSec"], 300);
        assert!(reality.get("limitFallbackDownload").is_none());

        let parsed = parse_inbound_security(&inbound);
        assert_eq!(parsed.reality.min_client_ver, "1.8.0");
        assert_eq!(parsed.reality.max_client_ver, "2.0.0");
        assert_eq!(parsed.reality.max_time_diff, Some(1500));
        let upload = parsed.reality.limit_fallback_upload.expect("upload limit");
        assert_eq!(upload.after_bytes, Some(100));
        assert!(parsed.reality.limit_fallback_download.is_none());
    }
}
