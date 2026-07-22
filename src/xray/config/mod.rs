//! Internal Xray configuration model and lossless parser.
//!
//! This module replaces the previous flat `XrayConfig` / `XrayConfigParser`
//! pair with a sourced section model suitable for single-file and directory
//! configs, while keeping unknown data for future write-back.

mod editable;
mod errors;
mod modify;
mod modify_error;
mod parser;
mod sections;
mod serialize;
mod sourced_section;
mod summary;
mod users;

pub use editable::{EditableXrayConfig, InboundLocation, parse_file_roots};
pub use errors::{ConfigError, ConfigErrorKind};
pub use modify::{
    AddUserRequest, DeleteUserRequest, ModifyUserOutcome, UpdateUserRequest, add_user, delete_user,
    generate_client_uuid, update_user,
};
pub use modify_error::{ConfigModifyError, ConfigModifyErrorKind, ConfigModifyResult};
pub use parser::{ConfigParseOutcome, XrayConfigParser};
pub use sections::{KNOWN_SECTION_NAMES, XrayConfig, XrayConfigSections};
pub use serialize::{serialize_json_value, validate_serialized_json};
pub use sourced_section::SourcedSection;
pub use summary::{
    BurstObservatorySummary, BurstPingConfigSummary, DnsHostSummary, DnsServerSummary, DnsSummary,
    FakeDnsAddressFamily, FakeDnsPoolSummary, FakeDnsSummary, InboundSummary, ObservatorySummary,
    OutboundKind, OutboundSummary, PolicySummary, RoutingRuleSummary, RoutingSummary,
    SystemPolicySummary, UserPolicySummary, burst_observatory_summary, cmp_policy_level,
    dns_summary, fakedns_summary, inbound_summaries, observatory_summary, outbound_summaries,
    policy_summary, routing_summary,
};
pub use users::{
    SUPPORTED_USER_PROTOCOL, SupportedUserInbound, UserSummary, VlessClientSummary,
    clients_for_inbound, extract_vless_clients, supported_user_inbounds,
};

#[cfg(test)]
mod modify_tests;
#[cfg(test)]
mod tests;
