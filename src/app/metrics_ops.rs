//! `metrics` HTTP endpoint (`/debug/vars`) scrape orchestration (Roadmap §3:130 — Metrics scrape
//! / dashboard integration).
//!
//! Mirrors [`super::api_ops::run_api_call`]'s connect → call → disconnect shape, but there is
//! only one call to make (no subcommand family), so this module skips the request-builder layer
//! entirely — [`crate::xray::run_metrics_scrape`] already takes just a listen address and a path.

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::storage::StoredConnectionProfile;
use crate::xray::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult, run_metrics_scrape};

/// Path scraped on every refresh — Go's `expvar` HTTP handler, not `/debug/pprof/*` (out of
/// scope, a debugging tool rather than administration — see `xray::remote_cli::metrics` doc).
const DEBUG_VARS_PATH: &str = "/debug/vars";

/// Outcome of one `/debug/vars` scrape.
#[derive(Debug, Clone)]
pub struct MetricsScrapeOutcome {
    /// Raw response body on success; classified error otherwise.
    pub result: RemoteCliResult<String>,
}

/// Runs one metrics scrape end-to-end (connect → fetch → disconnect).
pub async fn run_metrics_scrape_op<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    listen_addr: String,
) -> MetricsScrapeOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let request = build_connect_request(profile, secrets);
    info!(target: "app", host = %request.profile.host, "metrics scrape connect");

    let session = match backend.connect(&request).await {
        Ok(session) => session,
        Err(error) => {
            return MetricsScrapeOutcome {
                result: Err(RemoteCliError::new(
                    RemoteCliErrorKind::ConnectionLost,
                    crate::logging::redact::sanitize_detail(error.message()),
                )),
            };
        }
    };

    let result = run_metrics_scrape(&session, &listen_addr, DEBUG_VARS_PATH).await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "metrics scrape disconnect warning"
        );
    }

    MetricsScrapeOutcome { result }
}
