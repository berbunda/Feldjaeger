//! Centralized navigation for the GUI.

use egui::Ui;

use crate::app::ApplicationService;
use crate::gui::pages;

/// Active content page selected in the sidebar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Page {
    /// Overview of server and service status.
    Dashboard,
    /// SSH connection settings and status.
    Connection,
    /// Confdir file add/remove management (Roadmap §2.5:107).
    ConfigFiles,
    /// List / restore previously created config backups (Roadmap §3:127).
    Backups,
    /// Inbound proxy configuration (Summary | Users under selection).
    Inbounds,
    /// Outbound proxy configuration.
    Outbounds,
    /// DNS configuration.
    Dns,
    /// FakeDNS configuration.
    FakeDns,
    /// Routing rules configuration.
    Routing,
    /// Local policy configuration.
    Policy,
    /// Background Observatory configuration.
    Observatory,
    /// Burst Observatory configuration.
    BurstObservatory,
    /// Xray top-level `stats` object settings (Roadmap §2.1:52).
    StatsSettings,
    /// Xray top-level `metrics` object settings (Roadmap §2.1:53).
    MetricsSettings,
    /// Xray top-level `env` object settings (Roadmap §2.1:55).
    EnvSettings,
    /// Xray top-level `version` object settings (Roadmap §2.1:56).
    VersionSettings,
    /// Xray top-level `geodata` object settings (Roadmap §2.1:57).
    GeodataSettings,
    /// Xray top-level `api` object settings (Roadmap §2.1:54).
    ApiSettings,
    /// Xray top-level `log` object settings.
    LogSettings,
    /// Service and application logs.
    Logs,
    /// Init-system service control.
    Service,
    /// Live `xray api` gRPC operations (Roadmap §3:128).
    ApiConsole,
    /// Live `xray api statsquery`/`statssys` read + charts (Roadmap §3:129).
    Stats,
    /// `metrics` HTTP endpoint (`/debug/vars`) scrape + dashboard (Roadmap §3:130).
    Metrics,
    /// Install / update / remove Xray binary.
    XrayManagement,
    /// Remote GeoData (`geoip.dat` / `geosite.dat`) status and update.
    GeoData,
    /// Cloudflare WARP integration.
    Warp,
    /// SNI/Dest/host search by ASN (Roadmap §3:131) — no SSH precondition, the only page that
    /// reaches the public internet rather than the managed host.
    TargetLookup,
    /// Application settings.
    Settings,
}

impl Page {
    /// All pages in sidebar display order.
    pub const ALL: &'static [Page] = &[
        Page::Dashboard,
        Page::Connection,
        Page::ConfigFiles,
        Page::Backups,
        Page::Inbounds,
        Page::Outbounds,
        Page::Dns,
        Page::FakeDns,
        Page::Routing,
        Page::Policy,
        Page::Observatory,
        Page::BurstObservatory,
        Page::StatsSettings,
        Page::MetricsSettings,
        Page::EnvSettings,
        Page::VersionSettings,
        Page::GeodataSettings,
        Page::ApiSettings,
        Page::LogSettings,
        Page::Logs,
        Page::Service,
        Page::ApiConsole,
        Page::Stats,
        Page::Metrics,
        Page::XrayManagement,
        Page::GeoData,
        Page::Warp,
        Page::TargetLookup,
        Page::Settings,
    ];

    /// Returns the human-readable label shown in the sidebar.
    pub fn label(self) -> &'static str {
        match self {
            Page::Dashboard => "Dashboard",
            Page::Connection => "Connection",
            Page::ConfigFiles => "Config Files",
            Page::Backups => "Backups",
            Page::Inbounds => "Inbounds",
            Page::Outbounds => "Outbounds",
            Page::Dns => "DNS",
            Page::FakeDns => "FakeDNS",
            Page::Routing => "Routing",
            Page::Policy => "Policy",
            Page::Observatory => "Observatory",
            Page::BurstObservatory => "BurstObservatory",
            Page::StatsSettings => "Stats Settings",
            Page::MetricsSettings => "Metrics Settings",
            Page::EnvSettings => "Env Settings",
            Page::VersionSettings => "Version Settings",
            Page::GeodataSettings => "GeoData Settings",
            Page::ApiSettings => "API Settings",
            Page::LogSettings => "Log Settings",
            Page::Logs => "Xray Logs",
            Page::Service => "Service",
            Page::ApiConsole => "API Console",
            Page::Stats => "Statistics",
            Page::Metrics => "Metrics",
            Page::XrayManagement => "Xray Management",
            Page::GeoData => "GeoData",
            Page::Warp => "Cloudflare WARP",
            Page::TargetLookup => "Target Lookup",
            Page::Settings => "Settings",
        }
    }

    /// Parses a page from its persisted label, falling back to Dashboard.
    pub fn from_label(label: &str) -> Self {
        if label.eq_ignore_ascii_case("WARP") {
            return Page::Warp;
        }
        // Legacy sidebar entry removed; Users lives under Inbounds.
        if label.eq_ignore_ascii_case("Users") {
            return Page::Inbounds;
        }
        Page::ALL
            .iter()
            .copied()
            .find(|page| page.label().eq_ignore_ascii_case(label))
            .unwrap_or(Page::Dashboard)
    }

    /// Renders the selected page in the content area.
    pub fn show(self, ui: &mut Ui, service: &mut ApplicationService) {
        match self {
            Page::Dashboard => pages::dashboard::show(ui),
            Page::Connection => pages::connection::show(ui, service),
            Page::ConfigFiles => pages::confdir_files::show(ui, service),
            Page::Backups => pages::backups::show(ui, service),
            Page::Inbounds => pages::inbounds::show(ui, service),
            Page::Outbounds => pages::outbounds::show(ui, service),
            Page::Dns => pages::dns::show(ui, service),
            Page::FakeDns => pages::fakedns::show(ui, service),
            Page::Routing => pages::routing::show(ui, service),
            Page::Policy => pages::policy::show(ui, service),
            Page::Observatory => pages::observatory::show(ui, service),
            Page::BurstObservatory => pages::burst_observatory::show(ui, service),
            Page::StatsSettings => pages::stats_settings::show(ui, service),
            Page::MetricsSettings => pages::metrics_settings::show(ui, service),
            Page::EnvSettings => pages::env_settings::show(ui, service),
            Page::VersionSettings => pages::version_settings::show(ui, service),
            Page::GeodataSettings => pages::geodata_settings::show(ui, service),
            Page::ApiSettings => pages::api_settings::show(ui, service),
            Page::LogSettings => pages::log_settings::show(ui, service),
            Page::Logs => pages::logs::show(ui, service),
            Page::Service => pages::service::show(ui, service),
            Page::ApiConsole => pages::api_console::show(ui, service),
            Page::Stats => pages::stats::show(ui, service),
            Page::Metrics => pages::metrics::show(ui, service),
            Page::XrayManagement => pages::xray_management::show(ui, service),
            Page::GeoData => pages::geodata::show(ui, service),
            Page::Warp => pages::warp::show(ui, service),
            Page::TargetLookup => pages::target_lookup::show(ui, service),
            Page::Settings => pages::settings::show(ui),
        }
    }
}