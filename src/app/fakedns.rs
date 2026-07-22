//! Read-only FakeDNS page view model for [`super::ApplicationService`].
//!
//! The GUI consumes supported summary fields only and never inspects JSON.

use std::net::IpAddr;

use crate::app::inbounds::{
    LoadedConfigSnapshot, MISSING_FIELD, display_optional_str, display_source_file,
};
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, FakeDnsAddressFamily, FakeDnsPoolSummary, FakeDnsSummary};

/// High-level state shown by the FakeDNS page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeDnsPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded without a FakeDNS section.
    FakeDnsSectionMissing,
    /// FakeDNS configuration loaded without warnings.
    ConfigurationLoaded,
    /// Configuration loaded with non-fatal warnings.
    ConfigurationContainsWarnings,
}

impl FakeDnsPageState {
    /// User-facing explanation for this state.
    pub fn message(self) -> &'static str {
        match self {
            Self::NoSshConnection => {
                "No SSH connection. Connect to a server on the Connection page first."
            }
            Self::XrayNotDiscovered => {
                "Xray installation not discovered. Run Discover Xray on the Connection page."
            }
            Self::ConfigurationNotLoaded => {
                "Configuration not loaded. Discover Xray again after the config becomes readable."
            }
            Self::FakeDnsSectionMissing => "FakeDNS section is not configured.",
            Self::ConfigurationLoaded => "FakeDNS configuration loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the details below."
            }
        }
    }

    /// Returns whether supported FakeDNS details can be rendered.
    pub fn shows_fakedns(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings
        )
    }
}

/// Read-only model exposed to the FakeDNS page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsPageModel {
    /// Coarse page state.
    pub state: FakeDnsPageState,
    /// Supported FakeDNS data, when the section exists.
    pub summary: Option<FakeDnsSummary>,
    /// Combined non-fatal warnings (config + FakeDNS-specific).
    pub warnings: Vec<String>,
}

/// Derives the FakeDNS page state from connection, discovery, and config state.
pub fn derive_fakedns_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> FakeDnsPageState {
    if ssh != SshStatus::Connected {
        return FakeDnsPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => FakeDnsPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                FakeDnsPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded {
                fakedns, warnings, ..
            } => {
                let has_local_warnings = fakedns
                    .as_ref()
                    .is_some_and(|summary| !summary.warnings.is_empty());
                if !warnings.is_empty() || has_local_warnings {
                    FakeDnsPageState::ConfigurationContainsWarnings
                } else if fakedns.is_none() {
                    FakeDnsPageState::FakeDnsSectionMissing
                } else {
                    FakeDnsPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the read-only FakeDNS page model.
pub fn build_fakedns_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> FakeDnsPageModel {
    let summary = config.fakedns().cloned();
    let mut warnings = config.warnings().to_vec();
    if let Some(summary) = summary.as_ref() {
        warnings.extend(summary.warnings.iter().cloned());
    }
    FakeDnsPageModel {
        state: derive_fakedns_page_state(ssh, discovery, config),
        summary,
        warnings,
    }
}

/// Formatted FakeDNS pool fields for the GUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsPoolDisplay {
    /// IP pool CIDR or `—`.
    pub ip_pool: String,
    /// Configured pool size or `—`.
    pub pool_size: String,
    /// Address family label.
    pub address_family: String,
    /// Basename of the source file.
    pub source_file: String,
    /// CIDR prefix length or `—`.
    pub cidr_prefix: String,
    /// Total address capacity of the CIDR or `—`.
    pub total_address_capacity: String,
    /// Same as pool size for the derived "Configured pool size" row.
    pub configured_pool_size: String,
}

/// Formats one FakeDNS pool for display.
pub fn fakedns_pool_display(
    summary: &FakeDnsSummary,
    pool: &FakeDnsPoolSummary,
) -> FakeDnsPoolDisplay {
    let pool_size = pool
        .pool_size
        .map(|size| size.to_string())
        .unwrap_or_else(|| MISSING_FIELD.to_owned());
    let (cidr_prefix, total_address_capacity) = derive_cidr_info(pool.ip_pool.as_deref());
    FakeDnsPoolDisplay {
        ip_pool: display_optional_str(pool.ip_pool.as_deref()),
        pool_size: pool_size.clone(),
        address_family: pool.address_family.label().to_owned(),
        source_file: display_source_file(&summary.source_file).to_owned(),
        cidr_prefix,
        total_address_capacity,
        configured_pool_size: pool_size,
    }
}

/// Derives CIDR prefix and total capacity for display without new dependencies.
///
/// Unsafe or malformed values yield `—` and never panic.
fn derive_cidr_info(ip_pool: Option<&str>) -> (String, String) {
    let Some(ip_pool) = ip_pool.map(str::trim).filter(|text| !text.is_empty()) else {
        return (MISSING_FIELD.to_owned(), MISSING_FIELD.to_owned());
    };
    let Some((address_text, prefix_text)) = ip_pool.split_once('/') else {
        return (MISSING_FIELD.to_owned(), MISSING_FIELD.to_owned());
    };
    let Ok(address) = address_text.parse::<IpAddr>() else {
        return (MISSING_FIELD.to_owned(), MISSING_FIELD.to_owned());
    };
    let Ok(prefix) = prefix_text.parse::<u32>() else {
        return (MISSING_FIELD.to_owned(), MISSING_FIELD.to_owned());
    };

    let max_bits = match address {
        IpAddr::V4(_) => 32u32,
        IpAddr::V6(_) => 128u32,
    };
    if prefix > max_bits {
        return (MISSING_FIELD.to_owned(), MISSING_FIELD.to_owned());
    }

    let host_bits = max_bits - prefix;
    let capacity = if host_bits >= 64 {
        // Avoid overflowing u128 display helpers for absurdly large pools.
        // 2^host_bits fits in u128 while host_bits <= 128; compute carefully.
        match 1u128.checked_shl(host_bits) {
            Some(value) => value.to_string(),
            None => MISSING_FIELD.to_owned(),
        }
    } else {
        match 1u64.checked_shl(host_bits) {
            Some(value) => value.to_string(),
            None => MISSING_FIELD.to_owned(),
        }
    };

    (prefix.to_string(), capacity)
}

/// Formats an optional address family for tests and helpers.
pub fn display_address_family(family: FakeDnsAddressFamily) -> &'static str {
    family.label()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{ConfigSource, InitSystemKind, XrayInstallation};

    fn summary(source_file: &str, pools: Vec<FakeDnsPoolSummary>) -> FakeDnsSummary {
        FakeDnsSummary {
            pools,
            source_file: source_file.to_owned(),
            warnings: Vec::new(),
        }
    }

    fn pool(ip_pool: &str, pool_size: u64, family: FakeDnsAddressFamily) -> FakeDnsPoolSummary {
        FakeDnsPoolSummary {
            ip_pool: Some(ip_pool.to_owned()),
            pool_size: Some(pool_size),
            address_family: family,
        }
    }

    fn loaded(fakedns: Option<FakeDnsSummary>, warnings: Vec<String>) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns: None,
            fakedns,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients: Vec::new(),
            warnings,
            editable: None,
        }
    }

    fn succeeded() -> DiscoveryState {
        DiscoveryState::Succeeded(XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: None,
            version: None,
            service_name: None,
            service_state: None,
            exec_start: None,
            config_source: ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        })
    }

    #[test]
    fn no_ssh_connection_state() {
        let model = build_fakedns_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(model.state, FakeDnsPageState::NoSshConnection);
    }

    #[test]
    fn xray_not_discovered_state() {
        let model = build_fakedns_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(model.state, FakeDnsPageState::XrayNotDiscovered);
    }

    #[test]
    fn configuration_not_loaded_state() {
        let model = build_fakedns_page_model(
            SshStatus::Connected,
            &succeeded(),
            &LoadedConfigSnapshot::NotLoaded,
        );
        assert_eq!(model.state, FakeDnsPageState::ConfigurationNotLoaded);
        assert!(model.state.message().contains("Configuration not loaded"));
    }

    #[test]
    fn missing_fakedns_section_is_not_an_error() {
        let model = build_fakedns_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(None, Vec::new()),
        );
        assert_eq!(model.state, FakeDnsPageState::FakeDnsSectionMissing);
        assert_eq!(model.state.message(), "FakeDNS section is not configured.");
        assert!(model.summary.is_none());
    }

    #[test]
    fn loaded_ipv4_default_pool() {
        let model = build_fakedns_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(
                Some(summary(
                    "/etc/xray/config.json",
                    vec![pool("198.18.0.0/15", 65535, FakeDnsAddressFamily::Ipv4)],
                )),
                Vec::new(),
            ),
        );
        assert_eq!(model.state, FakeDnsPageState::ConfigurationLoaded);
        let display = fakedns_pool_display(
            model.summary.as_ref().expect("summary"),
            &model.summary.as_ref().unwrap().pools[0],
        );
        assert_eq!(display.ip_pool, "198.18.0.0/15");
        assert_eq!(display.pool_size, "65535");
        assert_eq!(display.address_family, "IPv4");
        assert_eq!(display.source_file, "config.json");
        assert_eq!(display.cidr_prefix, "15");
        assert_eq!(display.total_address_capacity, "131072");
        assert_eq!(display.configured_pool_size, "65535");
    }

    #[test]
    fn loaded_ipv6_pool() {
        let summary = summary(
            "/etc/xray/05-fakedns.json",
            vec![pool("fc00::/18", 65535, FakeDnsAddressFamily::Ipv6)],
        );
        let display = fakedns_pool_display(&summary, &summary.pools[0]);
        assert_eq!(display.address_family, "IPv6");
        assert_eq!(display.source_file, "05-fakedns.json");
        assert_eq!(display.cidr_prefix, "18");
        assert_ne!(display.total_address_capacity, MISSING_FIELD);
    }

    #[test]
    fn missing_fields_show_dash() {
        let summary = FakeDnsSummary {
            pools: vec![FakeDnsPoolSummary {
                ip_pool: None,
                pool_size: None,
                address_family: FakeDnsAddressFamily::Unknown,
            }],
            source_file: "/etc/xray/config.json".to_owned(),
            warnings: vec!["`ipPool` is missing.".to_owned()],
        };
        let display = fakedns_pool_display(&summary, &summary.pools[0]);
        assert_eq!(display.ip_pool, MISSING_FIELD);
        assert_eq!(display.pool_size, MISSING_FIELD);
        assert_eq!(display.address_family, "Unknown");
        assert_eq!(display.cidr_prefix, MISSING_FIELD);
        assert_eq!(display.total_address_capacity, MISSING_FIELD);
    }

    #[test]
    fn invalid_cidr_capacity_is_dash() {
        let (prefix, capacity) = derive_cidr_info(Some("not-a-cidr"));
        assert_eq!(prefix, MISSING_FIELD);
        assert_eq!(capacity, MISSING_FIELD);
    }

    #[test]
    fn local_warnings_mark_contains_warnings() {
        let model = build_fakedns_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(
                Some(FakeDnsSummary {
                    pools: vec![pool("198.18.0.0/16", 65535, FakeDnsAddressFamily::Ipv4)],
                    source_file: "config.json".to_owned(),
                    warnings: vec!["unknown field `futureFlag` is preserved.".to_owned()],
                }),
                Vec::new(),
            ),
        );
        assert_eq!(model.state, FakeDnsPageState::ConfigurationContainsWarnings);
        assert!(model.state.shows_fakedns());
        assert_eq!(model.warnings.len(), 1);
    }
}
