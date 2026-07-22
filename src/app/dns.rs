//! Read-only DNS page view model for [`super::ApplicationService`].
//!
//! The GUI consumes supported summary fields only and never inspects JSON.

use crate::app::inbounds::{
    LoadedConfigSnapshot, MISSING_FIELD, display_optional_str, display_source_file,
};
use crate::app::status::SshStatus;
use crate::xray::{DiscoveryState, DnsHostSummary, DnsServerSummary, DnsSummary};

/// High-level state shown by the DNS page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Xray discovery has not completed successfully.
    XrayNotDiscovered,
    /// Xray exists but its configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded without a DNS section.
    DnsSectionMissing,
    /// DNS configuration loaded without warnings.
    ConfigurationLoaded,
    /// Configuration loaded with non-fatal warnings.
    ConfigurationContainsWarnings,
}

impl DnsPageState {
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
            Self::DnsSectionMissing => "DNS section is not configured.",
            Self::ConfigurationLoaded => "DNS configuration loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the details below."
            }
        }
    }

    /// Returns whether supported DNS details can be rendered.
    pub fn shows_dns(self) -> bool {
        matches!(
            self,
            Self::ConfigurationLoaded | Self::ConfigurationContainsWarnings
        )
    }
}

/// Read-only model exposed to the DNS page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPageModel {
    /// Coarse page state.
    pub state: DnsPageState,
    /// Supported DNS data, when the section exists.
    pub summary: Option<DnsSummary>,
    /// Non-fatal configuration warnings.
    pub warnings: Vec<String>,
}

/// Derives the DNS page state from connection, discovery, and config state.
pub fn derive_dns_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> DnsPageState {
    if ssh != SshStatus::Connected {
        return DnsPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle
        | DiscoveryState::Discovering
        | DiscoveryState::NotFound { .. }
        | DiscoveryState::Failed { .. } => DnsPageState::XrayNotDiscovered,
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                DnsPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded { dns, warnings, .. } => {
                if !warnings.is_empty() {
                    DnsPageState::ConfigurationContainsWarnings
                } else if dns.is_none() {
                    DnsPageState::DnsSectionMissing
                } else {
                    DnsPageState::ConfigurationLoaded
                }
            }
        },
    }
}

/// Builds the read-only DNS page model.
pub fn build_dns_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
) -> DnsPageModel {
    DnsPageModel {
        state: derive_dns_page_state(ssh, discovery, config),
        summary: config.dns().cloned(),
        warnings: config.warnings().to_vec(),
    }
}

/// Formatted general DNS fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsGeneralDisplay {
    /// Query strategy or `—`.
    pub query_strategy: String,
    /// Disable-cache flag or `—`.
    pub disable_cache: String,
    /// Disable-fallback flag or `—`.
    pub disable_fallback: String,
    /// Disable-fallback-if-match flag or `—`.
    pub disable_fallback_if_match: String,
    /// DNS tag or `—`.
    pub tag: String,
    /// Basename of the source file.
    pub source_file: String,
}

/// Formats general DNS fields for display.
pub fn dns_general_display(summary: &DnsSummary) -> DnsGeneralDisplay {
    DnsGeneralDisplay {
        query_strategy: display_optional_str(summary.query_strategy.as_deref()),
        disable_cache: display_optional_bool(summary.disable_cache),
        disable_fallback: display_optional_bool(summary.disable_fallback),
        disable_fallback_if_match: display_optional_bool(summary.disable_fallback_if_match),
        tag: display_optional_str(summary.tag.as_deref()),
        source_file: display_source_file(&summary.source_file).to_owned(),
    }
}

/// Formatted cells for one DNS server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerRowDisplay {
    /// Address or `—`.
    pub address: String,
    /// Comma-separated domains or `—`.
    pub domains: String,
    /// Comma-separated expected IP rules or `—`.
    pub expected_ips: String,
    /// Skip-fallback flag or `—`.
    pub skip_fallback: String,
    /// Client IP or `—`.
    pub client_ip: String,
}

/// Formats one DNS server row.
pub fn dns_server_row_display(server: &DnsServerSummary) -> DnsServerRowDisplay {
    DnsServerRowDisplay {
        address: display_optional_str(server.address.as_deref()),
        domains: display_string_list(&server.domains),
        expected_ips: display_string_list(&server.expected_ips),
        skip_fallback: display_optional_bool(server.skip_fallback),
        client_ip: display_optional_str(server.client_ip.as_deref()),
    }
}

/// Formatted cells for one static host row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHostRowDisplay {
    /// Domain expression.
    pub domain: String,
    /// IP or alias target.
    pub target: String,
}

/// Formats one static host row.
pub fn dns_host_row_display(host: &DnsHostSummary) -> DnsHostRowDisplay {
    DnsHostRowDisplay {
        domain: display_optional_str(Some(&host.domain)),
        target: display_optional_str(Some(&host.target)),
    }
}

/// Formats an optional boolean using Xray's lowercase JSON spelling.
pub fn display_optional_bool(value: Option<bool>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| MISSING_FIELD.to_owned())
}

/// Formats a string list for a single table cell.
pub fn display_string_list(values: &[String]) -> String {
    if values.is_empty() {
        MISSING_FIELD.to_owned()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{ConfigSource, InitSystemKind, XrayInstallation};

    fn summary(source_file: &str) -> DnsSummary {
        DnsSummary {
            query_strategy: None,
            disable_cache: None,
            disable_fallback: None,
            disable_fallback_if_match: None,
            tag: None,
            servers: Vec::new(),
            hosts: Vec::new(),
            source_file: source_file.to_owned(),
        }
    }

    fn loaded(dns: Option<DnsSummary>, warnings: Vec<String>) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            dns,
            fakedns: None,
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
        let model = build_dns_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(model.state, DnsPageState::NoSshConnection);
    }

    #[test]
    fn xray_not_discovered_state() {
        let model = build_dns_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
        );
        assert_eq!(model.state, DnsPageState::XrayNotDiscovered);
        assert!(model.state.message().contains("not discovered"));
    }

    #[test]
    fn configuration_not_loaded_state() {
        let model = build_dns_page_model(
            SshStatus::Connected,
            &succeeded(),
            &LoadedConfigSnapshot::NotLoaded,
        );
        assert_eq!(model.state, DnsPageState::ConfigurationNotLoaded);
        assert!(model.state.message().contains("Configuration not loaded"));
    }

    #[test]
    fn missing_dns_section_is_not_an_error() {
        let model = build_dns_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(None, Vec::new()),
        );
        assert_eq!(model.state, DnsPageState::DnsSectionMissing);
        assert_eq!(model.state.message(), "DNS section is not configured.");
        assert!(model.summary.is_none());
    }

    #[test]
    fn empty_dns_section_is_loaded() {
        let model = build_dns_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(Some(summary("/etc/xray/config.json")), Vec::new()),
        );
        assert_eq!(model.state, DnsPageState::ConfigurationLoaded);
        assert!(model.summary.expect("summary").servers.is_empty());
    }

    #[test]
    fn warnings_are_shown_with_available_dns() {
        let model = build_dns_page_model(
            SshStatus::Connected,
            &succeeded(),
            &loaded(
                Some(summary("/etc/xray/02-dns.json")),
                vec!["unsupported routing value".to_owned()],
            ),
        );
        assert_eq!(model.state, DnsPageState::ConfigurationContainsWarnings);
        assert!(model.state.shows_dns());
        assert_eq!(model.warnings.len(), 1);
        assert!(model.summary.is_some());
    }

    #[test]
    fn missing_fields_and_source_file_are_formatted() {
        let summary = summary(r"C:\xray\02-dns.json");
        let display = dns_general_display(&summary);
        assert_eq!(display.query_strategy, MISSING_FIELD);
        assert_eq!(display.disable_cache, MISSING_FIELD);
        assert_eq!(display.disable_fallback, MISSING_FIELD);
        assert_eq!(display.disable_fallback_if_match, MISSING_FIELD);
        assert_eq!(display.tag, MISSING_FIELD);
        assert_eq!(display.source_file, "02-dns.json");
    }

    #[test]
    fn server_and_host_rows_are_formatted() {
        let server = DnsServerSummary {
            address: Some("https://1.1.1.1/dns-query".to_owned()),
            domains: vec!["geosite:openai".to_owned(), "domain:xray.com".to_owned()],
            expected_ips: vec!["geoip:us".to_owned()],
            skip_fallback: Some(true),
            client_ip: None,
        };
        let server_display = dns_server_row_display(&server);
        assert_eq!(server_display.address, "https://1.1.1.1/dns-query");
        assert_eq!(server_display.domains, "geosite:openai, domain:xray.com");
        assert_eq!(server_display.expected_ips, "geoip:us");
        assert_eq!(server_display.skip_fallback, "true");
        assert_eq!(server_display.client_ip, MISSING_FIELD);

        let host = DnsHostSummary {
            domain: "alias.example".to_owned(),
            target: "target.example".to_owned(),
        };
        let host_display = dns_host_row_display(&host);
        assert_eq!(host_display.domain, "alias.example");
        assert_eq!(host_display.target, "target.example");
    }
}
