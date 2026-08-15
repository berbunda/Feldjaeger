//! Retained ephemeral share material (Reality PublicKey / VLESS client encryption).
//!
//! Never written into inbound JSON. Survives Shell Save session clear so Users
//! tab can still build share URIs after Generate.
//!
//! Persisted to a remote sidecar next to the Xray config:
//! - single file `{config}.feldjaeger-share.json`
//! - config dir `{dir}/feldjaeger-share.json`

use std::collections::BTreeMap;

use feldjaeger_ssh::RemotePath;
use serde::{Deserialize, Serialize};

use crate::xray::ConfigSource;

/// File suffix appended to a single-file Xray config path.
pub const SHARE_SIDECAR_SUFFIX: &str = ".feldjaeger-share.json";

/// File name used inside a config directory layout.
pub const SHARE_SIDECAR_DIR_NAME: &str = "feldjaeger-share.json";

/// Ephemeral client-facing crypto retained for Share URI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundShareMaterial {
    /// Reality public key from last `x25519` Generate for this inbound.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "publicKey")]
    pub public_key: Option<String>,
    /// Client `encryption` half from last `vlessenc` Generate.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "encryption"
    )]
    pub client_encryption: Option<String>,
    /// Client `mldsa65Verify` half from last `mldsa65` Generate.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "mldsa65Verify"
    )]
    pub mldsa65_verify: Option<String>,
    /// SHA-256 pin of the leaf TLS certificate from last "Fetch cert pin" (Hysteria2
    /// `pinSHA256`; Roadmap §3:121).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "certPinSha256"
    )]
    pub cert_pin_sha256: Option<String>,
}

/// On-disk / remote sidecar document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ShareMaterialDocument {
    version: u32,
    #[serde(default)]
    inbounds: BTreeMap<String, InboundShareMaterial>,
}

/// Store keyed by inbound identity (`tag:…` preferred, else `idx:N`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareMaterialStore {
    by_key: BTreeMap<String, InboundShareMaterial>,
}

impl ShareMaterialStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of inbound entries currently retained.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Stable key for an inbound.
    pub fn key(tag: Option<&str>, inbound_index: usize) -> String {
        match tag.map(str::trim).filter(|s| !s.is_empty()) {
            Some(tag) => format!("tag:{tag}"),
            None => format!("idx:{inbound_index}"),
        }
    }

    /// Looks up material by tag (preferred) then index.
    pub fn get(&self, tag: Option<&str>, inbound_index: usize) -> Option<&InboundShareMaterial> {
        let tag_key = Self::key(tag, inbound_index);
        self.by_key
            .get(&tag_key)
            .or_else(|| self.by_key.get(&format!("idx:{inbound_index}")))
    }

    /// Merges non-empty fields into the store entry.
    pub fn merge(
        &mut self,
        tag: Option<&str>,
        inbound_index: usize,
        public_key: Option<String>,
        client_encryption: Option<String>,
        mldsa65_verify: Option<String>,
    ) {
        let key = Self::key(tag, inbound_index);
        let entry = self.by_key.entry(key).or_default();
        if let Some(pk) = public_key.filter(|s| !s.trim().is_empty()) {
            entry.public_key = Some(pk);
        }
        if let Some(enc) = client_encryption.filter(|s| !s.trim().is_empty()) {
            entry.client_encryption = Some(enc);
        }
        if let Some(verify) = mldsa65_verify.filter(|s| !s.trim().is_empty()) {
            entry.mldsa65_verify = Some(verify);
        }
    }

    /// Merges a cert-pin SHA-256 fingerprint (Hysteria2 `pinSHA256`) into the store entry.
    pub fn merge_cert_pin(
        &mut self,
        tag: Option<&str>,
        inbound_index: usize,
        cert_pin_sha256: Option<String>,
    ) {
        let key = Self::key(tag, inbound_index);
        let entry = self.by_key.entry(key).or_default();
        if let Some(pin) = cert_pin_sha256.filter(|s| !s.trim().is_empty()) {
            entry.cert_pin_sha256 = Some(pin);
        }
    }

    /// Copies session ephemerals into the store (call before clearing editor session).
    pub fn retain_from_session(
        &mut self,
        tag: Option<&str>,
        inbound_index: usize,
        public_key: Option<&str>,
        client_encryption: Option<&str>,
        mldsa65_verify: Option<&str>,
    ) {
        self.merge(
            tag,
            inbound_index,
            public_key.map(str::to_owned),
            client_encryption.map(str::to_owned),
            mldsa65_verify.map(str::to_owned),
        );
    }

    /// Parses sidecar JSON into a store. Empty / missing-file callers pass nothing.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(Self::new());
        }
        let doc: ShareMaterialDocument = serde_json::from_slice(bytes)
            .map_err(|e| format!("invalid share material sidecar: {e}"))?;
        if doc.version == 0 {
            return Err("share material sidecar version must be >= 1".to_owned());
        }
        Ok(Self {
            by_key: doc.inbounds,
        })
    }

    /// Serializes the store for remote write.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, String> {
        let doc = ShareMaterialDocument {
            version: 1,
            inbounds: self.by_key.clone(),
        };
        let mut bytes = serde_json::to_vec_pretty(&doc)
            .map_err(|e| format!("serialize share material sidecar: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Resolves the remote sidecar path for a discovered config layout.
pub fn share_sidecar_path(source: &ConfigSource) -> Option<RemotePath> {
    match source {
        ConfigSource::SingleFile(path) => {
            let joined = format!("{}{SHARE_SIDECAR_SUFFIX}", path.as_str());
            RemotePath::new(joined).ok()
        }
        ConfigSource::ConfigDirectory(dir) => {
            let base = dir.as_str().trim_end_matches('/');
            let joined = format!("{base}/{SHARE_SIDECAR_DIR_NAME}");
            RemotePath::new(joined).ok()
        }
        ConfigSource::NotFound | ConfigSource::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_tag_key() {
        let mut store = ShareMaterialStore::new();
        store.merge(Some("in"), 0, Some("pk".to_owned()), None, None);
        assert_eq!(
            store.get(Some("in"), 99).and_then(|m| m.public_key.as_deref()),
            Some("pk")
        );
    }

    #[test]
    fn merge_cert_pin_stores_and_ignores_blank() {
        let mut store = ShareMaterialStore::new();
        store.merge_cert_pin(Some("hy"), 0, Some("deadbeef".to_owned()));
        assert_eq!(
            store.get(Some("hy"), 0).and_then(|m| m.cert_pin_sha256.as_deref()),
            Some("deadbeef")
        );
        store.merge_cert_pin(Some("hy"), 0, Some("   ".to_owned()));
        assert_eq!(
            store.get(Some("hy"), 0).and_then(|m| m.cert_pin_sha256.as_deref()),
            Some("deadbeef")
        );
    }

    #[test]
    fn retains_mldsa65_verify() {
        let mut store = ShareMaterialStore::new();
        store.merge(
            Some("in"),
            0,
            None,
            None,
            Some("verify-key".to_owned()),
        );
        assert_eq!(
            store
                .get(Some("in"), 0)
                .and_then(|m| m.mldsa65_verify.as_deref()),
            Some("verify-key")
        );
        store.retain_from_session(Some("in"), 0, None, None, Some("verify-2"));
        assert_eq!(
            store
                .get(Some("in"), 0)
                .and_then(|m| m.mldsa65_verify.as_deref()),
            Some("verify-2")
        );
    }

    #[test]
    fn roundtrip_json() {
        let mut store = ShareMaterialStore::new();
        store.merge(
            Some("vless-in"),
            0,
            Some("pk".to_owned()),
            Some("enc".to_owned()),
            Some("pqv".to_owned()),
        );
        store.merge_cert_pin(Some("vless-in"), 0, Some("deadbeef".to_owned()));
        let bytes = store.to_json_bytes().expect("serialize");
        let loaded = ShareMaterialStore::from_json_bytes(&bytes).expect("parse");
        assert_eq!(loaded, store);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"publicKey\""));
        assert!(text.contains("\"encryption\""));
        assert!(text.contains("\"mldsa65Verify\""));
        assert!(text.contains("\"certPinSha256\""));
    }

    #[test]
    fn sidecar_path_single_file() {
        let path = RemotePath::new("/usr/local/etc/xray/config.json").unwrap();
        let source = ConfigSource::SingleFile(path);
        let sidecar = share_sidecar_path(&source).unwrap();
        assert_eq!(
            sidecar.as_str(),
            "/usr/local/etc/xray/config.json.feldjaeger-share.json"
        );
    }

    #[test]
    fn sidecar_path_directory() {
        let path = RemotePath::new("/usr/local/etc/xray").unwrap();
        let source = ConfigSource::ConfigDirectory(path);
        let sidecar = share_sidecar_path(&source).unwrap();
        assert_eq!(
            sidecar.as_str(),
            "/usr/local/etc/xray/feldjaeger-share.json"
        );
    }
}
