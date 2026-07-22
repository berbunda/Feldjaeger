//! Xray configuration and lifecycle management.
//!
//! Uses [`crate::init::InitSystemManager`] for service control and
//! [`crate::remote::RemoteAdmin`] for configuration I/O.
//! Does not depend on SSH library APIs directly.

pub mod config;
mod discovery;
mod geodata;
mod installation;
mod installer;
pub mod logs;
mod manager;
mod validator;

pub use config::{
    AddUserRequest, BurstObservatorySummary, BurstPingConfigSummary, ConfigError, ConfigErrorKind,
    ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult, ConfigParseOutcome,
    DeleteUserRequest, DnsHostSummary, DnsServerSummary, DnsSummary, EditableXrayConfig,
    FakeDnsAddressFamily, FakeDnsPoolSummary, FakeDnsSummary, InboundLocation, InboundSummary,
    KNOWN_SECTION_NAMES, ModifyUserOutcome, ObservatorySummary, OutboundKind, OutboundSummary,
    PolicySummary, RoutingRuleSummary, RoutingSummary, SUPPORTED_USER_PROTOCOL, SourcedSection,
    SupportedUserInbound, SystemPolicySummary, UpdateUserRequest, UserPolicySummary, UserSummary,
    VlessClientSummary, XrayConfig, XrayConfigParser, XrayConfigSections, add_user,
    burst_observatory_summary, clients_for_inbound, cmp_policy_level, delete_user, dns_summary,
    extract_vless_clients, fakedns_summary, generate_client_uuid, inbound_summaries,
    observatory_summary, outbound_summaries, parse_file_roots, policy_summary, routing_summary,
    supported_user_inbounds, update_user,
};
pub use discovery::{DiscoveryResult, XrayDiscoveryService};
pub use geodata::{
    GeoDataDatabaseSummary, GeoDataError, GeoDataErrorKind, GeoDataManager, GeoDataResolveHints,
    GeoDataResult, GeoDataSummary, parse_asset_dir_from_environment,
};
pub use installation::{
    ConfigSource, DiscoveryErrorKind, DiscoveryState, DiscoveryWarning, InitSystemKind,
    XrayInstallation,
};
pub use installer::{InstallerError, InstallerErrorKind, InstallerResult, XrayInstaller};
pub use logs::{
    XrayLogAvailability, XrayLogConfigView, XrayLogDestination, XrayLogEntry, XrayLogError,
    XrayLogErrorKind, XrayLogLineLimit, XrayLogResult, XrayLogSearch, XrayLogService,
    XrayLogSourceKind, XrayLogSourceSummary, XrayLogStreamEvent, log_config_view,
};
pub use manager::XrayManager;
pub use validator::{ConfigValidator, DefaultConfigValidator};
