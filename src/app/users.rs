//! Read-only Users page view model for [`super::ApplicationService`].
//!
//! Consumes [`UserSummary`] / [`VlessClientSummary`] from the Xray model layer.
//! The GUI never inspects inbound JSON directly.

use crate::app::inbounds::{LoadedConfigSnapshot, MISSING_FIELD, display_source_file};
use crate::app::status::SshStatus;
use crate::xray::{
    DiscoveryState, HysteriaClientSummary, InboundClientSummary,
    SupportedUserInbound, TrojanClientSummary, UserSummary, clients_for_inbound,
    supported_user_inbounds, supported_vless_user_inbounds, vless_clients_for_inbound,
};

/// Protocol-specific Users tab presentation (VLESS / Trojan / Hysteria).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsersProtocolUi {
    /// VLESS inbound selected.
    Vless,
    /// Trojan inbound selected.
    Trojan,
    /// Hysteria inbound selected.
    Hysteria,
}

/// Resolves the selected inbound protocol for Users tab dispatch.
pub fn selected_users_protocol(
    choices: &[SupportedUserInbound],
    selected_inbound_index: Option<usize>,
) -> Option<UsersProtocolUi> {
    let idx = selected_inbound_index?;
    let choice = choices.iter().find(|c| c.inbound_index == idx)?;
    if choice.protocol.eq_ignore_ascii_case("trojan") {
        Some(UsersProtocolUi::Trojan)
    } else if choice.protocol.eq_ignore_ascii_case("hysteria") {
        Some(UsersProtocolUi::Hysteria)
    } else if choice.protocol.eq_ignore_ascii_case("vless") {
        Some(UsersProtocolUi::Vless)
    } else {
        None
    }
}

/// Columns that support sorting on the Users table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsersSortColumn {
    /// Preserve extractor / config order within the selected inbound.
    #[default]
    Index,
    /// Sort by email (missing values sort as empty).
    Email,
    /// Sort by UUID / id (missing values sort as empty).
    Uuid,
}

/// Current sort settings for the Users table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsersSort {
    /// Active sort column.
    pub column: UsersSortColumn,
    /// `true` for ascending order.
    pub ascending: bool,
}

impl UsersSort {
    /// Default: preserve config order.
    pub fn by_index() -> Self {
        Self {
            column: UsersSortColumn::Index,
            ascending: true,
        }
    }
}

/// High-level Users page state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsersPageState {
    /// SSH is not connected.
    NoSshConnection,
    /// Discovery did not find Xray (or failed).
    XrayNotDiscovered,
    /// Xray exists but configuration was not loaded.
    ConfigurationNotLoaded,
    /// Configuration loaded but no inbound is selected on the Inbounds page.
    NoInboundSelected,
    /// Configuration loaded but the selected inbound is not Tier‑2 (VLESS) editable.
    NoSupportedInboundSelected,
    /// A supported inbound is selected but it has no users.
    SelectedInboundHasNoUsers,
    /// Users are available for the selected inbound.
    UsersLoaded,
    /// Configuration loaded with warnings (table may still show).
    ConfigurationContainsWarnings,
}

impl UsersPageState {
    /// User-facing explanation for the current state.
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
            Self::NoInboundSelected => {
                "Select an inbound in the table above to manage its clients."
            }
            Self::NoSupportedInboundSelected => {
                "Client editing is available for VLESS, Trojan, and Hysteria inbounds."
            }
            Self::SelectedInboundHasNoUsers => "Selected inbound has no users.",
            Self::UsersLoaded => "Users loaded.",
            Self::ConfigurationContainsWarnings => {
                "Configuration loaded with warnings. Review the list below."
            }
        }
    }

    /// Returns `true` when the users table should be rendered.
    pub fn shows_table(self) -> bool {
        matches!(
            self,
            Self::UsersLoaded | Self::ConfigurationContainsWarnings
        )
    }
}

/// Read-only model for the Users page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsersPageModel {
    /// Coarse page state.
    pub state: UsersPageState,
    /// Inbounds offered in the selector (VLESS + Trojan).
    pub inbound_choices: Vec<SupportedUserInbound>,
    /// Currently selected inbound index into the merged inbound list.
    pub selected_inbound_index: Option<usize>,
    /// VLESS users for the selected inbound (already sorted).
    pub rows: Vec<UserSummary>,
    /// All inbound clients (VLESS + Trojan) for the selected inbound.
    /// Populated when editable config is available; empty otherwise.
    pub inbound_clients: Vec<InboundClientSummary>,
    /// Non-fatal warnings to show above the table.
    pub warnings: Vec<String>,
    /// Active sort settings.
    pub sort: UsersSort,
}

/// Resolves which inbound index should be selected for the Users tab.
///
/// Returns `None` when nothing is selected or the preferred inbound is not Tier‑2.
pub fn resolve_selected_inbound_index(
    choices: &[SupportedUserInbound],
    preferred: Option<usize>,
) -> Option<usize> {
    let preferred = preferred?;
    choices
        .iter()
        .any(|choice| choice.inbound_index == preferred)
        .then_some(preferred)
}

/// Derives [`UsersPageState`] from SSH / discovery / config / selection.
pub fn derive_users_page_state(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    preferred_inbound_index: Option<usize>,
    choices: &[SupportedUserInbound],
    selected_users: &[UserSummary],
    inbound_clients: &[InboundClientSummary],
) -> UsersPageState {
    if ssh != SshStatus::Connected {
        return UsersPageState::NoSshConnection;
    }

    match discovery {
        DiscoveryState::Idle | DiscoveryState::Discovering => UsersPageState::XrayNotDiscovered,
        DiscoveryState::NotFound { .. } | DiscoveryState::Failed { .. } => {
            UsersPageState::XrayNotDiscovered
        }
        DiscoveryState::Succeeded(_) => match config {
            LoadedConfigSnapshot::None | LoadedConfigSnapshot::NotLoaded => {
                UsersPageState::ConfigurationNotLoaded
            }
            LoadedConfigSnapshot::Loaded { warnings, .. } => {
                let Some(preferred) = preferred_inbound_index else {
                    return UsersPageState::NoInboundSelected;
                };
                if !choices
                    .iter()
                    .any(|choice| choice.inbound_index == preferred)
                {
                    return UsersPageState::NoSupportedInboundSelected;
                }
                let has_users = !selected_users.is_empty() || !inbound_clients.is_empty();
                if !has_users {
                    return UsersPageState::SelectedInboundHasNoUsers;
                }
                if warnings.is_empty() {
                    UsersPageState::UsersLoaded
                } else {
                    UsersPageState::ConfigurationContainsWarnings
                }
            }
        },
    }
}

/// Builds the Users page model for the GUI.
pub fn build_users_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    config: &LoadedConfigSnapshot,
    preferred_inbound_index: Option<usize>,
    sort: UsersSort,
) -> UsersPageModel {
    // All clients (VLESS + Trojan) from editable when available; empty otherwise.
    let all_inbound_clients: Vec<InboundClientSummary> = config
        .editable()
        .map(|e| e.inbound_clients())
        .unwrap_or_default();

    // Choices include both VLESS and Trojan inbounds.
    let choices = supported_user_inbounds(config.inbounds(), &all_inbound_clients);

    // For tests and legacy call sites that only have vless_clients in the snapshot,
    // also include choices from the legacy VLESS-only path so inbound choices are non-empty.
    let choices = if choices.is_empty() && !config.vless_clients().is_empty() {
        supported_vless_user_inbounds(config.inbounds(), config.vless_clients())
    } else {
        choices
    };

    let selected_inbound_index = resolve_selected_inbound_index(&choices, preferred_inbound_index);

    // VLESS rows (legacy path — also populated when editable is absent).
    let mut rows = selected_inbound_index
        .map(|index| vless_clients_for_inbound(config.vless_clients(), index))
        .unwrap_or_default();
    sort_user_summaries(&mut rows, sort);

    // All clients for the selected inbound (from editable).
    let inbound_clients: Vec<InboundClientSummary> = selected_inbound_index
        .map(|index| clients_for_inbound(&all_inbound_clients, index))
        .unwrap_or_default();

    let warnings = config.warnings().to_vec();
    let state = derive_users_page_state(
        ssh,
        discovery,
        config,
        preferred_inbound_index,
        &choices,
        &rows,
        &inbound_clients,
    );

    UsersPageModel {
        state,
        inbound_choices: choices,
        selected_inbound_index,
        rows,
        inbound_clients,
        warnings,
        sort,
    }
}

/// Sorts user summaries in place according to [`UsersSort`].
pub fn sort_user_summaries(rows: &mut [UserSummary], sort: UsersSort) {
    rows.sort_by(|left, right| {
        let ordering = match sort.column {
            UsersSortColumn::Index => left.client_index.cmp(&right.client_index),
            UsersSortColumn::Email => {
                cmp_optional_str(left.email.as_deref(), right.email.as_deref())
            }
            UsersSortColumn::Uuid => cmp_optional_str(left.id.as_deref(), right.id.as_deref()),
        };
        if sort.ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

fn cmp_optional_str(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
    left.unwrap_or("").cmp(right.unwrap_or(""))
}

/// Formats optional client fields for the table (`—` when absent).
pub fn display_optional_client_field(value: Option<&str>) -> String {
    value
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| MISSING_FIELD.to_owned())
}

/// Formatted cells for one user row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRowDisplay<'a> {
    /// Email or `—`.
    pub email: String,
    /// UUID / ID or `—`.
    pub id: String,
    /// Flow or `—`.
    pub flow: String,
    /// Inbound tag or `—`.
    pub inbound_tag: String,
    /// Basename of the source file.
    pub source_file: &'a str,
}

/// Builds display cells for a user summary.
pub fn user_row_display(client: &UserSummary) -> UserRowDisplay<'_> {
    UserRowDisplay {
        email: display_optional_client_field(client.email.as_deref()),
        id: display_optional_client_field(client.id.as_deref()),
        flow: display_optional_client_field(client.flow.as_deref()),
        inbound_tag: display_optional_client_field(client.inbound_tag.as_deref()),
        source_file: display_source_file(&client.source_file),
    }
}

/// Formatted cells for one Trojan client row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanRowDisplay<'a> {
    /// Email or `—`.
    pub email: String,
    /// `"••••••"` when password is present; `—` when absent.
    pub password_masked: &'static str,
    /// Inbound tag or `—`.
    pub inbound_tag: String,
    /// Basename of the source file.
    pub source_file: &'a str,
}

/// Builds display cells for a Trojan client summary.
pub fn trojan_row_display(client: &TrojanClientSummary) -> TrojanRowDisplay<'_> {
    TrojanRowDisplay {
        email: display_optional_client_field(client.email.as_deref()),
        password_masked: if client.has_password { "••••••" } else { MISSING_FIELD },
        inbound_tag: display_optional_client_field(client.inbound_tag.as_deref()),
        source_file: display_source_file(&client.source_file),
    }
}

/// Formatted cells for one Hysteria user row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HysteriaRowDisplay<'a> {
    /// Email or `—`.
    pub email: String,
    /// `"••••••"` when auth is present; `—` when absent.
    pub auth_masked: &'static str,
    /// Policy level.
    pub level: String,
    /// Inbound tag or `—`.
    pub inbound_tag: String,
    /// Basename of the source file.
    pub source_file: &'a str,
}

/// Builds display cells for a Hysteria client summary.
pub fn hysteria_row_display(client: &HysteriaClientSummary) -> HysteriaRowDisplay<'_> {
    HysteriaRowDisplay {
        email: display_optional_client_field(client.email.as_deref()),
        auth_masked: if client.has_auth { "••••••" } else { MISSING_FIELD },
        level: client.level.to_string(),
        inbound_tag: display_optional_client_field(client.inbound_tag.as_deref()),
        source_file: display_source_file(&client.source_file),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{InboundSummary, InitSystemKind};

    fn inbound(
        index: usize,
        tag: &str,
        protocol: &str,
        port: Option<u64>,
        source: &str,
    ) -> InboundSummary {
        InboundSummary {
            index,
            tag: Some(tag.to_owned()),
            protocol: Some(protocol.to_owned()),
            listen: None,
            port,
            clients_count: None,
            source_file: source.to_owned(),
        }
    }

    fn client(
        inbound_index: usize,
        tag: &str,
        source: &str,
        client_index: usize,
        id: &str,
        email: &str,
        flow: Option<&str>,
    ) -> UserSummary {
        UserSummary {
            inbound_index,
            inbound_tag: Some(tag.to_owned()),
            source_file: source.to_owned(),
            client_index,
            id: Some(id.to_owned()),
            email: Some(email.to_owned()),
            flow: flow.map(str::to_owned),
        }
    }

    fn loaded(
        inbounds: Vec<InboundSummary>,
        vless_clients: Vec<UserSummary>,
        warnings: Vec<String>,
    ) -> LoadedConfigSnapshot {
        LoadedConfigSnapshot::Loaded {
            inbounds,
            outbounds: Vec::new(),
            dns: None,
            fakedns: None,
            observatory: None,
            burst_observatory: None,
            routing: None,
            policy: None,
            vless_clients,
            warnings,
            editable: None,
        }
    }

    fn succeeded() -> DiscoveryState {
        DiscoveryState::Succeeded(crate::xray::XrayInstallation {
            operating_system: "Debian".to_owned(),
            architecture: "x86_64".to_owned(),
            init_system: InitSystemKind::Systemd,
            binary_path: None,
            version: None,
            service_name: None,
            service_state: None,
            exec_start: None,
            config_source: crate::xray::ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        })
    }

    fn model(
        config: &LoadedConfigSnapshot,
        preferred: Option<usize>,
        sort: UsersSort,
    ) -> UsersPageModel {
        build_users_page_model(SshStatus::Connected, &succeeded(), config, preferred, sort)
    }

    #[test]
    fn no_ssh_connection_state() {
        let page = build_users_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            UsersSort::by_index(),
        );
        assert_eq!(page.state, UsersPageState::NoSshConnection);
    }

    #[test]
    fn xray_installation_not_discovered_state() {
        let page = build_users_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &LoadedConfigSnapshot::None,
            None,
            UsersSort::by_index(),
        );
        assert_eq!(page.state, UsersPageState::XrayNotDiscovered);
        assert!(
            page.state
                .message()
                .contains("Xray installation not discovered")
        );
    }

    #[test]
    fn configuration_not_loaded_state() {
        let page = build_users_page_model(
            SshStatus::Connected,
            &succeeded(),
            &LoadedConfigSnapshot::NotLoaded,
            None,
            UsersSort::by_index(),
        );
        assert_eq!(page.state, UsersPageState::ConfigurationNotLoaded);
        assert!(page.state.message().contains("Configuration not loaded"));
    }

    #[test]
    fn no_users_when_selected_inbound_empty() {
        let config = loaded(
            vec![inbound(0, "vless-in", "vless", Some(443), "/c/config.json")],
            Vec::new(),
            Vec::new(),
        );
        let page = model(&config, Some(0), UsersSort::by_index());
        assert_eq!(page.state, UsersPageState::SelectedInboundHasNoUsers);
        assert!(page.rows.is_empty());
    }

    #[test]
    fn one_user() {
        let config = loaded(
            vec![inbound(0, "vless-in", "vless", Some(443), "/c/config.json")],
            vec![client(
                0,
                "vless-in",
                "/c/config.json",
                0,
                "uuid-1",
                "one@x",
                Some("xtls-rprx-vision"),
            )],
            Vec::new(),
        );
        let page = model(&config, Some(0), UsersSort::by_index());
        assert_eq!(page.state, UsersPageState::UsersLoaded);
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].email.as_deref(), Some("one@x"));
    }

    #[test]
    fn several_users() {
        let config = loaded(
            vec![inbound(0, "vless-in", "vless", Some(443), "/c/config.json")],
            vec![
                client(0, "vless-in", "/c/config.json", 0, "id-a", "a@x", None),
                client(0, "vless-in", "/c/config.json", 1, "id-b", "b@x", None),
                client(0, "vless-in", "/c/config.json", 2, "id-c", "c@x", None),
            ],
            Vec::new(),
        );
        let page = model(&config, Some(0), UsersSort::by_index());
        assert_eq!(page.rows.len(), 3);
    }

    #[test]
    fn switching_inbound_filters_users() {
        let config = loaded(
            vec![
                inbound(0, "vless-a", "vless", Some(443), "/c/a.json"),
                inbound(1, "vless-b", "vless", Some(8443), "/c/b.json"),
            ],
            vec![
                client(0, "vless-a", "/c/a.json", 0, "id-a", "a@x", None),
                client(1, "vless-b", "/c/b.json", 0, "id-b1", "b1@x", None),
                client(1, "vless-b", "/c/b.json", 1, "id-b2", "b2@x", None),
            ],
            Vec::new(),
        );
        let page = model(&config, Some(1), UsersSort::by_index());
        assert_eq!(page.selected_inbound_index, Some(1));
        assert_eq!(page.rows.len(), 2);
        assert_eq!(page.rows[0].email.as_deref(), Some("b1@x"));
    }

    #[test]
    fn missing_fields_and_unknown_flow() {
        let summary = UserSummary {
            inbound_index: 0,
            inbound_tag: None,
            source_file: "/etc/xray/03-inbounds.json".to_owned(),
            client_index: 0,
            id: None,
            email: None,
            flow: Some("future_flow_mode".to_owned()),
        };
        let row = user_row_display(&summary);
        assert_eq!(row.email, MISSING_FIELD);
        assert_eq!(row.id, MISSING_FIELD);
        assert_eq!(row.flow, "future_flow_mode");
        assert_eq!(row.inbound_tag, MISSING_FIELD);
        assert_eq!(row.source_file, "03-inbounds.json");
    }

    #[test]
    fn sort_by_email_and_uuid() {
        let mut rows = vec![
            client(0, "in", "/c.json", 0, "uuid-z", "zeta@x", None),
            client(0, "in", "/c.json", 1, "uuid-a", "alpha@x", None),
        ];
        sort_user_summaries(
            &mut rows,
            UsersSort {
                column: UsersSortColumn::Email,
                ascending: true,
            },
        );
        assert_eq!(rows[0].email.as_deref(), Some("alpha@x"));

        sort_user_summaries(
            &mut rows,
            UsersSort {
                column: UsersSortColumn::Uuid,
                ascending: true,
            },
        );
        assert_eq!(rows[0].id.as_deref(), Some("uuid-a"));
    }

    #[test]
    fn no_supported_inbound_selected_when_only_vmess() {
        let config = loaded(
            vec![inbound(
                0,
                "vmess-in",
                "vmess",
                Some(1000),
                "/c/config.json",
            )],
            Vec::new(),
            Vec::new(),
        );
        let page = model(&config, Some(0), UsersSort::by_index());
        assert_eq!(page.state, UsersPageState::NoSupportedInboundSelected);
    }

    #[test]
    fn no_inbound_selected_when_preferred_missing() {
        let config = loaded(
            vec![inbound(0, "vless-in", "vless", Some(443), "/c/config.json")],
            vec![client(
                0,
                "vless-in",
                "/c/config.json",
                0,
                "uuid-1",
                "one@x",
                None,
            )],
            Vec::new(),
        );
        let page = model(&config, None, UsersSort::by_index());
        assert_eq!(page.state, UsersPageState::NoInboundSelected);
        assert!(page.selected_inbound_index.is_none());
        assert!(page.rows.is_empty());
    }

    #[test]
    fn source_file_basename_in_selector_label() {
        let config = loaded(
            vec![inbound(
                0,
                "vless-reality-443",
                "vless",
                Some(443),
                "/usr/local/etc/xray/03-inbounds.json",
            )],
            vec![client(
                0,
                "vless-reality-443",
                "/usr/local/etc/xray/03-inbounds.json",
                0,
                "id",
                "u@x",
                None,
            )],
            Vec::new(),
        );
        let page = model(&config, Some(0), UsersSort::by_index());
        assert_eq!(
            page.inbound_choices[0].label(),
            "vless-reality-443 · VLESS · :443"
        );
        assert_eq!(
            user_row_display(&page.rows[0]).source_file,
            "03-inbounds.json"
        );
    }

    #[test]
    fn selected_users_protocol_dispatches_hysteria() {
        let choices = vec![SupportedUserInbound {
            inbound_index: 2,
            tag: Some("hy".to_owned()),
            protocol: "hysteria".to_owned(),
            port: Some(443),
            clients_count: 0,
            source_file: "/c.json".to_owned(),
        }];
        assert_eq!(
            selected_users_protocol(&choices, Some(2)),
            Some(UsersProtocolUi::Hysteria)
        );
    }

    #[test]
    fn hysteria_row_display_masks_auth() {
        let client = HysteriaClientSummary {
            inbound_index: 0,
            inbound_tag: Some("hy".to_owned()),
            source_file: "/etc/xray/config.json".to_owned(),
            client_index: 0,
            email: Some("u@x".to_owned()),
            has_auth: true,
            level: 2,
        };
        let row = hysteria_row_display(&client);
        assert_eq!(row.auth_masked, "••••••");
        assert_eq!(row.level, "2");
    }
}
