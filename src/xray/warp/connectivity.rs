//! WARP connectivity probing.
//!
//! Testing whether traffic sent through a *specific* Xray outbound reaches
//! Cloudflare cannot be done safely without mutating live routing, so
//! [`WarpConnectivityService::test_connectivity`] always reports the
//! outbound-specific test as unavailable. It additionally performs a safe,
//! read-only DNS reachability check of the Cloudflare WARP endpoint host —
//! this only shows the host resolves, and is never treated as proof that
//! WARP traffic is actually flowing.

use feldjaeger_ssh::{RemoteCommand, SshSession};
use tracing::info;

use super::error::WarpResult;
use super::types::WarpConnectivityResult;
use crate::logging::redact::sanitize_detail;

/// Cloudflare WARP WireGuard endpoint hostname used for the reachability probe.
const CLOUDFLARE_WARP_ENDPOINT_HOST: &str = "engage.cloudflareclient.com";

/// Fixed, safe status text for the (always unavailable) outbound-specific test.
const UNAVAILABLE_STATUS: &str = "Outbound-specific connectivity test is unavailable";

/// Probes WARP-adjacent connectivity without mutating any Xray configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct WarpConnectivityService;

impl WarpConnectivityService {
    /// Creates a new service.
    pub fn new() -> Self {
        Self
    }

    /// Runs the (always unavailable) outbound-specific test plus a safe
    /// endpoint-reachability probe, and returns a combined result.
    pub async fn test_connectivity<S: SshSession + Sync>(
        &self,
        session: &S,
        outbound_tag: Option<&str>,
    ) -> WarpResult<WarpConnectivityResult> {
        info!(
            target: "xray",
            tag = outbound_tag.unwrap_or("-"),
            "WARP connectivity probe requested"
        );

        let mut warnings = Vec::new();
        probe_endpoint_reachability(session, &mut warnings).await;

        Ok(WarpConnectivityResult {
            available: false,
            status: UNAVAILABLE_STATUS.to_owned(),
            warp_active: None,
            ipv4_available: None,
            ipv6_available: None,
            observed_public_ip: None,
            note: Some(format!("{UNAVAILABLE_STATUS}.")),
            warnings,
        })
    }
}

async fn probe_endpoint_reachability<S: SshSession + Sync>(session: &S, warnings: &mut Vec<String>) {
    let Ok(command) = RemoteCommand::new(
        "getent",
        vec!["hosts".to_owned(), CLOUDFLARE_WARP_ENDPOINT_HOST.to_owned()],
    ) else {
        return;
    };

    match session.exec(&command).await {
        Ok(result) if result.exit_code == 0 => {
            warnings.push(
                "Cloudflare WARP endpoint host resolved (this does not prove traffic is routed through WARP)."
                    .to_owned(),
            );
        }
        Ok(_) => {
            warnings.push("Cloudflare WARP endpoint host did not resolve.".to_owned());
        }
        Err(error) => {
            let message = sanitize_detail(error.message());
            let lower = message.to_ascii_lowercase();
            if lower.contains("timed out") || lower.contains("timeout") {
                warnings.push("Endpoint reachability probe timed out.".to_owned());
            } else {
                warnings.push(format!("Endpoint reachability probe failed: {message}"));
            }
        }
    }
}
