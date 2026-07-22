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
    /// Inbound proxy configuration.
    Inbounds,
    /// User account management.
    Users,
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
    /// Service and application logs.
    Logs,
    /// Init-system service control.
    Service,
    /// Install / update / remove Xray binary.
    XrayManagement,
    /// Remote GeoData (`geoip.dat` / `geosite.dat`) status and update.
    GeoData,
    /// Cloudflare WARP integration.
    Warp,
    /// Application settings.
    Settings,
}

impl Page {
    /// All pages in sidebar display order.
    pub const ALL: &'static [Page] = &[
        Page::Dashboard,
        Page::Connection,
        Page::Inbounds,
        Page::Users,
        Page::Outbounds,
        Page::Dns,
        Page::FakeDns,
        Page::Routing,
        Page::Policy,
        Page::Observatory,
        Page::BurstObservatory,
        Page::Logs,
        Page::Service,
        Page::XrayManagement,
        Page::GeoData,
        Page::Warp,
        Page::Settings,
    ];

    /// Returns the human-readable label shown in the sidebar.
    pub fn label(self) -> &'static str {
        match self {
            Page::Dashboard => "Dashboard",
            Page::Connection => "Connection",
            Page::Inbounds => "Inbounds",
            Page::Users => "Users",
            Page::Outbounds => "Outbounds",
            Page::Dns => "DNS",
            Page::FakeDns => "FakeDNS",
            Page::Routing => "Routing",
            Page::Policy => "Policy",
            Page::Observatory => "Observatory",
            Page::BurstObservatory => "BurstObservatory",
            Page::Logs => "Xray Logs",
            Page::Service => "Service",
            Page::XrayManagement => "Xray Management",
            Page::GeoData => "GeoData",
            Page::Warp => "WARP",
            Page::Settings => "Settings",
        }
    }

    /// Parses a page from its persisted label, falling back to Dashboard.
    pub fn from_label(label: &str) -> Self {
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
            Page::Inbounds => pages::inbounds::show(ui, service),
            Page::Users => pages::users::show(ui, service),
            Page::Outbounds => pages::outbounds::show(ui, service),
            Page::Dns => pages::dns::show(ui, service),
            Page::FakeDns => pages::fakedns::show(ui, service),
            Page::Routing => pages::routing::show(ui, service),
            Page::Policy => pages::policy::show(ui, service),
            Page::Observatory => pages::observatory::show(ui, service),
            Page::BurstObservatory => pages::burst_observatory::show(ui, service),
            Page::Logs => pages::logs::show(ui, service),
            Page::Service => pages::service::show(ui, service),
            Page::XrayManagement => pages::xray_management::show(ui, service),
            Page::GeoData => pages::geodata::show(ui, service),
            Page::Warp => pages::warp::show(ui),
            Page::Settings => pages::settings::show(ui),
        }
    }
}
