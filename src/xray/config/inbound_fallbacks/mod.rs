//! Shared `settings.fallbacks` editor helpers (VLESS / Trojan, Wave C2).
//!
//! Official constraint: TCP (raw) + TLS or Reality only. On Shell Save,
//! incompatible stream/security strips `fallbacks`; when fallbacks remain,
//! TLS/Reality `alpn` must be non-empty (no auto-patch).

use serde_json::{Map, Number, Value};

use crate::xray::config::compatibility::{effective_security, matrix_transport, normalized_method};
use crate::xray::config::modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};

/// How `FallbackObject.dest` is represented in the GUI / draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FallbackDestKind {
    /// Port only (`80` → localhost).
    #[default]
    Port,
    /// TCP `host:port` (IPv4 / domain / IPv6).
    TcpAddr,
    /// Absolute unix path or `@` / `@@` abstract socket.
    UnixSocket,
}

impl FallbackDestKind {
    /// Short label for combo boxes.
    pub fn label(self) -> &'static str {
        match self {
            Self::Port => "Port",
            Self::TcpAddr => "TCP addr",
            Self::UnixSocket => "Unix socket",
        }
    }
}

/// Typed `dest` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackDest {
    /// Numeric / string port → localhost.
    Port(u16),
    /// `addr:port` string.
    TcpAddr(String),
    /// Absolute or abstract unix socket path.
    UnixSocket(String),
}

impl FallbackDest {
    /// Discriminator for UI.
    pub fn kind(&self) -> FallbackDestKind {
        match self {
            Self::Port(_) => FallbackDestKind::Port,
            Self::TcpAddr(_) => FallbackDestKind::TcpAddr,
            Self::UnixSocket(_) => FallbackDestKind::UnixSocket,
        }
    }

    /// Default empty value for a kind (invalid until filled).
    pub fn empty(kind: FallbackDestKind) -> Self {
        match kind {
            FallbackDestKind::Port => Self::Port(80),
            FallbackDestKind::TcpAddr => Self::TcpAddr(String::new()),
            FallbackDestKind::UnixSocket => Self::UnixSocket(String::new()),
        }
    }

    /// Single-line display for view mode.
    pub fn display(&self) -> String {
        match self {
            Self::Port(p) => p.to_string(),
            Self::TcpAddr(s) | Self::UnixSocket(s) => s.clone(),
        }
    }
}

/// One `settings.fallbacks[]` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct FallbackObject {
    /// TLS SNI match (default `""`).
    pub name: String,
    /// Negotiated ALPN match (default `""`).
    pub alpn: String,
    /// HTTP path match; empty or must start with `/`.
    pub path: String,
    /// Required redirect target.
    pub dest: FallbackDest,
    /// PROXY protocol version (`0` = off, `1` or `2`).
    pub xver: u64,
    /// Unknown keys preserved on write.
    pub extras: Map<String, Value>,
}

impl Default for FallbackObject {
    fn default() -> Self {
        Self {
            name: String::new(),
            alpn: String::new(),
            path: String::new(),
            dest: FallbackDest::Port(80),
            xver: 0,
            extras: Map::new(),
        }
    }
}

/// Whether stream × security allows `fallbacks` (TCP/raw + tls|reality).
pub fn fallbacks_transport_compatible(transport: &str, security: &str) -> bool {
    let t = matrix_transport(transport);
    let s = security.trim().to_ascii_lowercase();
    t == "tcp" && matches!(s.as_str(), "tls" | "reality")
}

/// Reads compatibility from a fully applied inbound JSON object.
pub fn fallbacks_compatible_on_inbound(inbound: &Value) -> bool {
    let protocol = inbound
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(protocol.as_str(), "vless" | "trojan") {
        return false;
    }
    fallbacks_transport_compatible(&normalized_method(inbound), &effective_security(inbound))
}

/// Parses `settings.fallbacks` (missing / null / non-array → empty).
pub fn parse_fallbacks(inbound: &Value) -> Vec<FallbackObject> {
    let Some(array) = inbound
        .get("settings")
        .and_then(|s| s.get("fallbacks"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    array.iter().filter_map(parse_fallback_object).collect()
}

fn parse_fallback_object(value: &Value) -> Option<FallbackObject> {
    let object = value.as_object()?;
    let dest = parse_dest(object.get("dest"))?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let alpn = object
        .get("alpn")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let xver = object
        .get("xver")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut extras = Map::new();
    for (key, value) in object {
        if !matches!(key.as_str(), "name" | "alpn" | "path" | "dest" | "xver") {
            extras.insert(key.clone(), value.clone());
        }
    }
    Some(FallbackObject {
        name,
        alpn,
        path,
        dest,
        xver,
        extras,
    })
}

fn parse_dest(value: Option<&Value>) -> Option<FallbackDest> {
    let value = value?;
    match value {
        Value::Number(n) => {
            let port = n.as_u64().filter(|p| *p >= 1 && *p <= 65535)? as u16;
            Some(FallbackDest::Port(port))
        }
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            if s.chars().all(|c| c.is_ascii_digit()) {
                let port: u16 = s.parse().ok()?;
                if port == 0 {
                    return None;
                }
                return Some(FallbackDest::Port(port));
            }
            if s.starts_with('/') || s.starts_with('@') {
                return Some(FallbackDest::UnixSocket(s.to_owned()));
            }
            Some(FallbackDest::TcpAddr(s.to_owned()))
        }
        _ => None,
    }
}

/// Validates a draft list before write.
pub fn validate_fallbacks(fallbacks: &[FallbackObject]) -> ConfigModifyResult<()> {
    for (idx, entry) in fallbacks.iter().enumerate() {
        validate_fallback_object(entry).map_err(|e| {
            ConfigModifyError::new(
                e.kind(),
                format!("fallbacks[{idx}]: {}", e.message()),
            )
        })?;
    }
    Ok(())
}

fn validate_fallback_object(entry: &FallbackObject) -> ConfigModifyResult<()> {
    let path = entry.path.trim();
    if !path.is_empty() && !path.starts_with('/') {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "path must be empty or start with /".to_owned(),
        ));
    }
    if !matches!(entry.xver, 0 | 1 | 2) {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "xver must be 0, 1, or 2".to_owned(),
        ));
    }
    match &entry.dest {
        FallbackDest::Port(port) => {
            if *port == 0 {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "dest port must be in 1..=65535".to_owned(),
                ));
            }
        }
        FallbackDest::TcpAddr(addr) => {
            let addr = addr.trim();
            if addr.is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "dest TCP address must not be empty".to_owned(),
                ));
            }
            if !addr.contains(':') {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "dest TCP address must be host:port".to_owned(),
                ));
            }
        }
        FallbackDest::UnixSocket(path) => {
            let path = path.trim();
            if path.is_empty() {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "dest unix socket must not be empty".to_owned(),
                ));
            }
            if !(path.starts_with('/') || path.starts_with('@')) {
                return Err(ConfigModifyError::new(
                    ConfigModifyErrorKind::ValidationFailed,
                    "dest unix socket must be an absolute path or @/@ abstract name".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// Writes `settings.fallbacks` in place (empty → remove key). Does not touch clients.
pub fn apply_fallbacks(
    inbound: &mut Value,
    fallbacks: &[FallbackObject],
) -> ConfigModifyResult<()> {
    validate_fallbacks(fallbacks)?;
    let settings = ensure_settings_object(inbound)?;
    if fallbacks.is_empty() {
        settings.remove("fallbacks");
        return Ok(());
    }
    let array: Vec<Value> = fallbacks.iter().map(write_fallback_object).collect();
    settings.insert("fallbacks".to_owned(), Value::Array(array));
    Ok(())
}

fn write_fallback_object(entry: &FallbackObject) -> Value {
    let mut object = Map::new();
    let name = entry.name.trim();
    if !name.is_empty() {
        object.insert("name".to_owned(), Value::String(name.to_owned()));
    }
    let alpn = entry.alpn.trim();
    if !alpn.is_empty() {
        object.insert("alpn".to_owned(), Value::String(alpn.to_owned()));
    }
    let path = entry.path.trim();
    if !path.is_empty() {
        object.insert("path".to_owned(), Value::String(path.to_owned()));
    }
    object.insert("dest".to_owned(), write_dest(&entry.dest));
    if entry.xver != 0 {
        object.insert("xver".to_owned(), Value::Number(entry.xver.into()));
    }
    for (key, value) in &entry.extras {
        if !object.contains_key(key) {
            object.insert(key.clone(), value.clone());
        }
    }
    Value::Object(object)
}

fn write_dest(dest: &FallbackDest) -> Value {
    match dest {
        FallbackDest::Port(port) => Value::Number(Number::from(*port)),
        FallbackDest::TcpAddr(addr) => Value::String(addr.trim().to_owned()),
        FallbackDest::UnixSocket(path) => Value::String(path.trim().to_owned()),
    }
}

/// After stream + security apply: strip incompatible fallbacks; else require ALPN.
///
/// Returns `true` when `settings.fallbacks` was removed due to incompatibility.
pub fn reconcile_inbound_fallbacks(inbound: &mut Value) -> ConfigModifyResult<bool> {
    let has_fallbacks = inbound
        .get("settings")
        .and_then(|s| s.get("fallbacks"))
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());

    if !has_fallbacks {
        // Still drop empty array / null if present.
        if let Some(settings) = inbound.get_mut("settings").and_then(Value::as_object_mut) {
            if settings
                .get("fallbacks")
                .is_some_and(|v| v.as_array().is_some_and(|a| a.is_empty()) || v.is_null())
            {
                settings.remove("fallbacks");
            }
        }
        return Ok(false);
    }

    if !fallbacks_compatible_on_inbound(inbound) {
        if let Some(settings) = inbound.get_mut("settings").and_then(Value::as_object_mut) {
            settings.remove("fallbacks");
        }
        return Ok(true);
    }

    require_alpn_for_fallbacks(inbound)?;
    Ok(false)
}

/// Ensures TLS/Reality `alpn` is non-empty when fallbacks are present.
pub fn require_alpn_for_fallbacks(inbound: &Value) -> ConfigModifyResult<()> {
    let fallbacks = parse_fallbacks(inbound);
    if fallbacks.is_empty() {
        return Ok(());
    }
    let security = effective_security(inbound);
    let settings_key = match security.as_str() {
        "tls" => "tlsSettings",
        "reality" => "realitySettings",
        _ => {
            return Err(ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "Fallbacks require TLS or Reality security with a non-empty alpn list".to_owned(),
            ));
        }
    };
    let alpn = inbound
        .get("streamSettings")
        .and_then(|s| s.get(settings_key))
        .and_then(|s| s.get("alpn"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::trim))
                .any(|s| !s.is_empty())
        })
        .unwrap_or(false);
    if !alpn {
        return Err(ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            format!(
                "Fallbacks require a non-empty {settings_key}.alpn list; select ALPN values in the Security tab"
            ),
        ));
    }
    Ok(())
}

fn ensure_settings_object(inbound: &mut Value) -> ConfigModifyResult<&mut Map<String, Value>> {
    let root = inbound.as_object_mut().ok_or_else(|| {
        ConfigModifyError::new(
            ConfigModifyErrorKind::ValidationFailed,
            "inbound must be a JSON object".to_owned(),
        )
    })?;
    if !root.contains_key("settings") || root.get("settings").is_some_and(Value::is_null) {
        root.insert("settings".to_owned(), Value::Object(Map::new()));
    }
    root.get_mut("settings")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            ConfigModifyError::new(
                ConfigModifyErrorKind::ValidationFailed,
                "settings must be a JSON object".to_owned(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_dest_variants() {
        let inbound = json!({
            "protocol": "vless",
            "settings": {
                "fallbacks": [
                    {"dest": 80},
                    {"dest": "80"},
                    {"dest": "127.0.0.1:8080", "path": "/", "name": "a", "alpn": "h2", "xver": 1},
                    {"dest": "/dev/shm/x.sock"},
                    {"dest": "@abstract", "extra": true}
                ]
            }
        });
        let list = parse_fallbacks(&inbound);
        assert_eq!(list.len(), 5);
        assert_eq!(list[0].dest, FallbackDest::Port(80));
        assert_eq!(list[1].dest, FallbackDest::Port(80));
        assert_eq!(list[2].dest, FallbackDest::TcpAddr("127.0.0.1:8080".into()));
        assert_eq!(list[2].path, "/");
        assert_eq!(list[2].alpn, "h2");
        assert_eq!(list[2].xver, 1);
        assert_eq!(list[3].dest, FallbackDest::UnixSocket("/dev/shm/x.sock".into()));
        assert_eq!(list[4].dest, FallbackDest::UnixSocket("@abstract".into()));
        assert_eq!(list[4].extras.get("extra"), Some(&json!(true)));
    }

    #[test]
    fn apply_roundtrip_preserves_extras() {
        let mut inbound = json!({
            "protocol": "trojan",
            "settings": {
                "clients": [],
                "fallbacks": [{"dest": 80, "keepMe": 1}],
                "other": "x"
            }
        });
        let draft = parse_fallbacks(&inbound);
        apply_fallbacks(&mut inbound, &draft).expect("apply");
        assert_eq!(inbound["settings"]["fallbacks"][0]["dest"], 80);
        assert_eq!(inbound["settings"]["fallbacks"][0]["keepMe"], 1);
        assert_eq!(inbound["settings"]["other"], "x");
        assert_eq!(inbound["settings"]["clients"], json!([]));
    }

    #[test]
    fn reconcile_strips_on_ws() {
        let mut inbound = json!({
            "protocol": "vless",
            "settings": {"decryption": "none", "fallbacks": [{"dest": 80}]},
            "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {}}
        });
        let stripped = reconcile_inbound_fallbacks(&mut inbound).expect("reconcile");
        assert!(stripped);
        assert!(inbound["settings"].get("fallbacks").is_none());
    }

    #[test]
    fn reconcile_requires_tls_alpn() {
        let mut inbound = json!({
            "protocol": "vless",
            "settings": {
                "decryption": "none",
                "fallbacks": [
                    {"dest": 80},
                    {"dest": 81, "alpn": "h2", "path": "/"}
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"certificates": []}
            }
        });
        let err = reconcile_inbound_fallbacks(&mut inbound).expect_err("alpn required");
        assert!(err.message().contains("alpn"));
        assert!(inbound["streamSettings"]["tlsSettings"].get("alpn").is_none());

        inbound["streamSettings"]["tlsSettings"]["alpn"] = json!(["h2", "http/1.1"]);
        let stripped = reconcile_inbound_fallbacks(&mut inbound).expect("reconcile");
        assert!(!stripped);
        assert_eq!(
            inbound["streamSettings"]["tlsSettings"]["alpn"],
            json!(["h2", "http/1.1"])
        );
    }

    #[test]
    fn reconcile_requires_reality_alpn() {
        let mut inbound = json!({
            "protocol": "trojan",
            "settings": {"fallbacks": [{"dest": 80}]},
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {"privateKey": "x"}
            }
        });
        let err = reconcile_inbound_fallbacks(&mut inbound).expect_err("alpn required");
        assert!(err.message().contains("alpn"));

        inbound["streamSettings"]["realitySettings"]["alpn"] = json!(["http/1.1"]);
        reconcile_inbound_fallbacks(&mut inbound).expect("reconcile");
        assert_eq!(
            inbound["streamSettings"]["realitySettings"]["alpn"],
            json!(["http/1.1"])
        );
    }

    #[test]
    fn path_must_start_with_slash() {
        let bad = FallbackObject {
            path: "no-slash".into(),
            ..Default::default()
        };
        assert!(validate_fallbacks(&[bad]).is_err());
    }

    #[test]
    fn transport_compat_matrix() {
        assert!(fallbacks_transport_compatible("tcp", "tls"));
        assert!(fallbacks_transport_compatible("raw", "reality"));
        assert!(!fallbacks_transport_compatible("ws", "tls"));
        assert!(!fallbacks_transport_compatible("tcp", "none"));
        assert!(!fallbacks_transport_compatible("xhttp", "reality"));
    }
}
