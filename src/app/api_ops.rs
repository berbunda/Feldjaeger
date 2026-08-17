//! Live `xray api` operation orchestration (Roadmap §3:128 — a full HandlerService /
//! RoutingService / LoggerService console; scope confirmed with the user, including live
//! add/remove of inbounds, outbounds, inbound users, and routing rules).
//!
//! Every action here connects, runs exactly one `xray api <subcommand>` via
//! [`crate::xray::run_xray_api`] (SSH-exec — the command runs *on the remote host* and dials
//! `api.listen` over loopback there, so no local gRPC client or SSH port-forward is needed),
//! disconnects, and returns raw stdout for the GUI to display verbatim. **None of this touches
//! the configuration file**: no backup, no `xray run -test`, no write — the defining difference
//! from every other `*_ops.rs` module in this crate. A live add/remove is not persisted and does
//! not survive an Xray restart/reload; the GUI must keep saying so next to every action here.

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::{info, warn};

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::storage::StoredConnectionProfile;
use crate::xray::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult, run_xray_api};

/// One `xray api <subcommand>` call to make, plus a human label for the Status Bar.
#[derive(Debug, Clone)]
pub struct ApiCallRequest {
    /// Status Bar text while this call is in flight (e.g. "Adding live inbound(s)...").
    pub label: String,
    /// `xray api` subcommand name (e.g. `"lsi"`, `"adi"`, `"restartlogger"`).
    pub subcommand: &'static str,
    /// Flags/positional arguments after `-s <server>`.
    pub args: Vec<String>,
    /// JSON body piped to stdin for subcommands that take a `stdin:` positional (`adi`/`ado`/
    /// `adu`/`adrules`).
    pub stdin_body: Option<Vec<u8>>,
}

/// Outcome of one live API call.
#[derive(Debug, Clone)]
pub struct ApiCallOutcome {
    /// Echoes [`ApiCallRequest::label`], so pollers can tell which request this answers.
    pub label: String,
    /// Trimmed stdout on success; classified error otherwise.
    pub result: RemoteCliResult<String>,
}

/// Runs one live `xray api` call end-to-end (connect → call → disconnect).
pub async fn run_api_call<B>(
    backend: &B,
    profile: &StoredConnectionProfile,
    secrets: &ConnectionSecrets,
    binary_path: String,
    server_addr: String,
    request: ApiCallRequest,
) -> ApiCallOutcome
where
    B: SshBackend,
    B::Session: Sync,
{
    let ApiCallRequest {
        label,
        subcommand,
        args,
        stdin_body,
    } = request;

    let request_conn = build_connect_request(profile, secrets);
    info!(target: "app", host = %request_conn.profile.host, subcommand, "live api call connect");

    let session = match backend.connect(&request_conn).await {
        Ok(session) => session,
        Err(error) => {
            return ApiCallOutcome {
                label,
                result: Err(RemoteCliError::new(
                    RemoteCliErrorKind::ConnectionLost,
                    crate::logging::redact::sanitize_detail(error.message()),
                )),
            };
        }
    };

    let result = run_xray_api(
        &session,
        &binary_path,
        &server_addr,
        subcommand,
        args,
        stdin_body,
    )
    .await;

    if let Err(error) = session.disconnect().await {
        warn!(
            target: "app",
            detail = %crate::logging::redact::sanitize_detail(error.message()),
            "live api call disconnect warning"
        );
    }

    ApiCallOutcome { label, result }
}

// ─── Request builders ─────────────────────────────────────────────────────────
// Thin, pure constructors — one per `xray api` subcommand this panel exposes. Kept here, not in
// the GUI layer, so the GUI never assembles CLI argv itself (`rules.md`: "GUI must not execute
// raw SSH commands directly" — argv construction is the same category of concern as the command
// itself).

/// `xray api lsi` — list live inbounds.
pub fn list_inbounds_request() -> ApiCallRequest {
    ApiCallRequest {
        label: "Listing live inbounds...".to_owned(),
        subcommand: "lsi",
        args: Vec::new(),
        stdin_body: None,
    }
}

/// `xray api lso` — list live outbounds.
pub fn list_outbounds_request() -> ApiCallRequest {
    ApiCallRequest {
        label: "Listing live outbounds...".to_owned(),
        subcommand: "lso",
        args: Vec::new(),
        stdin_body: None,
    }
}

/// `xray api lsrules` — list live routing rules.
pub fn list_rules_request() -> ApiCallRequest {
    ApiCallRequest {
        label: "Listing live routing rules...".to_owned(),
        subcommand: "lsrules",
        args: Vec::new(),
        stdin_body: None,
    }
}

/// `xray api bi [balancer]` — balancer info (every balancer when `balancer_tag` is `None`).
pub fn balancer_info_request(balancer_tag: Option<String>) -> ApiCallRequest {
    ApiCallRequest {
        label: "Fetching balancer info...".to_owned(),
        subcommand: "bi",
        args: balancer_tag.into_iter().collect(),
        stdin_body: None,
    }
}

/// `xray api inbounduser -tag=<tag> [-email=<email>]` — list one inbound's users (or one user).
pub fn inbound_users_request(inbound_tag: String, email: Option<String>) -> ApiCallRequest {
    let mut args = vec!["-tag".to_owned(), inbound_tag];
    if let Some(email) = email {
        args.push("-email".to_owned());
        args.push(email);
    }
    ApiCallRequest {
        label: "Listing inbound users...".to_owned(),
        subcommand: "inbounduser",
        args,
        stdin_body: None,
    }
}

/// `xray api inboundusercount -tag=<tag>` — user count for one inbound.
pub fn inbound_user_count_request(inbound_tag: String) -> ApiCallRequest {
    ApiCallRequest {
        label: "Counting inbound users...".to_owned(),
        subcommand: "inboundusercount",
        args: vec!["-tag".to_owned(), inbound_tag],
        stdin_body: None,
    }
}

/// `xray api adi stdin:` — add one or more live inbounds from a JSON body (upstream decodes it
/// as `conf.InboundDetourConfig`; a `{"inbounds": [...]}` document works, matching what the Raw
/// JSON escape hatch already teaches users to write).
pub fn add_inbounds_request(json_body: Vec<u8>) -> ApiCallRequest {
    ApiCallRequest {
        label: "Adding live inbound(s)...".to_owned(),
        subcommand: "adi",
        args: vec!["stdin:".to_owned()],
        stdin_body: Some(json_body),
    }
}

/// `xray api rmi <tag>...` — remove live inbounds by tag.
pub fn remove_inbounds_request(tags: Vec<String>) -> ApiCallRequest {
    ApiCallRequest {
        label: "Removing live inbound(s)...".to_owned(),
        subcommand: "rmi",
        args: tags,
        stdin_body: None,
    }
}

/// `xray api ado stdin:` — add one or more live outbounds from a JSON body.
pub fn add_outbounds_request(json_body: Vec<u8>) -> ApiCallRequest {
    ApiCallRequest {
        label: "Adding live outbound(s)...".to_owned(),
        subcommand: "ado",
        args: vec!["stdin:".to_owned()],
        stdin_body: Some(json_body),
    }
}

/// `xray api rmo <tag>...` — remove live outbounds by tag.
pub fn remove_outbounds_request(tags: Vec<String>) -> ApiCallRequest {
    ApiCallRequest {
        label: "Removing live outbound(s)...".to_owned(),
        subcommand: "rmo",
        args: tags,
        stdin_body: None,
    }
}

/// `xray api adu stdin:` — add users to a live inbound from a JSON body (a whole inbound object
/// with its `settings.clients`/`settings.users`, matching upstream `adu`'s contract — Xray reads
/// the users out of it and adds them to the already-running inbound with that tag).
pub fn add_inbound_users_request(json_body: Vec<u8>) -> ApiCallRequest {
    ApiCallRequest {
        label: "Adding live inbound user(s)...".to_owned(),
        subcommand: "adu",
        args: vec!["stdin:".to_owned()],
        stdin_body: Some(json_body),
    }
}

/// `xray api rmu -tag=<tag> <email>...` — remove users from a live inbound by email.
pub fn remove_inbound_users_request(inbound_tag: String, emails: Vec<String>) -> ApiCallRequest {
    let mut args = vec!["-tag".to_owned(), inbound_tag];
    args.extend(emails);
    ApiCallRequest {
        label: "Removing live inbound user(s)...".to_owned(),
        subcommand: "rmu",
        args,
        stdin_body: None,
    }
}

/// `xray api adrules [-append] stdin:` — add live routing rules from a JSON body (a `routing`
/// object with a `rules` array). `append` merges with the existing live rule set instead of
/// replacing it.
pub fn add_rules_request(json_body: Vec<u8>, append: bool) -> ApiCallRequest {
    let mut args = Vec::new();
    if append {
        args.push("-append".to_owned());
    }
    args.push("stdin:".to_owned());
    ApiCallRequest {
        label: "Adding live routing rule(s)...".to_owned(),
        subcommand: "adrules",
        args,
        stdin_body: Some(json_body),
    }
}

/// `xray api rmrules <ruleTag>...` — remove live routing rules by tag.
pub fn remove_rules_request(rule_tags: Vec<String>) -> ApiCallRequest {
    ApiCallRequest {
        label: "Removing live routing rule(s)...".to_owned(),
        subcommand: "rmrules",
        args: rule_tags,
        stdin_body: None,
    }
}

/// `xray api bo -b=<balancer> [outboundTag|-r]` — pin (or, with `remove = true`, unpin) a
/// balancer's live selection to `outbound_tag`. Requires `RoutingService`.
pub fn balancer_override_request(
    balancer_tag: String,
    outbound_tag: Option<String>,
    remove: bool,
) -> ApiCallRequest {
    let mut args = vec!["-b".to_owned(), balancer_tag];
    if remove {
        args.push("-r".to_owned());
    } else if let Some(outbound_tag) = outbound_tag {
        args.push(outbound_tag);
    }
    ApiCallRequest {
        label: "Overriding balancer selection...".to_owned(),
        subcommand: "bo",
        args,
        stdin_body: None,
    }
}

/// `xray api sib -outbound=<outbound> [-inbound=<inbound>] [-ruletag=<tag>] [-reset] <ip>...` —
/// route one or more source IPs to `outbound_tag` (emergency block/redirect), or clear a
/// previous block with `reset = true`. Requires `RoutingService`.
pub fn source_ip_block_request(
    outbound_tag: String,
    inbound_tag: Option<String>,
    rule_tag: Option<String>,
    reset: bool,
    ips: Vec<String>,
) -> ApiCallRequest {
    let mut args = vec!["-outbound".to_owned(), outbound_tag];
    if let Some(inbound_tag) = inbound_tag {
        args.push("-inbound".to_owned());
        args.push(inbound_tag);
    }
    if let Some(rule_tag) = rule_tag {
        args.push("-ruletag".to_owned());
        args.push(rule_tag);
    }
    if reset {
        args.push("-reset".to_owned());
    }
    args.extend(ips);
    ApiCallRequest {
        label: "Applying source IP block...".to_owned(),
        subcommand: "sib",
        args,
        stdin_body: None,
    }
}

/// `xray api restartlogger` — restart the built-in logger (useful alongside external
/// `logrotate`).
pub fn restart_logger_request() -> ApiCallRequest {
    ApiCallRequest {
        label: "Restarting Xray logger...".to_owned(),
        subcommand: "restartlogger",
        args: Vec::new(),
        stdin_body: None,
    }
}

/// `xray api statsquery` — fetch every counter (empty `-pattern` matches everything via the
/// server's `strings.Contains`; grouping/filtering by inbound/outbound/user tag happens
/// client-side, `app::stats_console`). Never passes `-reset`: a passive dashboard must not
/// zero counters another tool might also be polling (Roadmap §3:129).
pub fn stats_query_all_request() -> ApiCallRequest {
    ApiCallRequest {
        label: "Fetching statistics...".to_owned(),
        subcommand: "statsquery",
        args: Vec::new(),
        stdin_body: None,
    }
}

/// `xray api statssys` — process-level runtime statistics (uptime, goroutines, memory).
pub fn stats_sys_request() -> ApiCallRequest {
    ApiCallRequest {
        label: "Fetching system statistics...".to_owned(),
        subcommand: "statssys",
        args: Vec::new(),
        stdin_body: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_inbounds_passes_tags_as_positional_args() {
        let request = remove_inbounds_request(vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(request.subcommand, "rmi");
        assert_eq!(request.args, vec!["a".to_owned(), "b".to_owned()]);
        assert!(request.stdin_body.is_none());
    }

    #[test]
    fn add_inbounds_pipes_body_via_stdin_sentinel() {
        let request = add_inbounds_request(b"{}".to_vec());
        assert_eq!(request.subcommand, "adi");
        assert_eq!(request.args, vec!["stdin:".to_owned()]);
        assert_eq!(request.stdin_body.as_deref(), Some(b"{}".as_slice()));
    }

    #[test]
    fn add_rules_append_flag_precedes_body() {
        let request = add_rules_request(b"{}".to_vec(), true);
        assert_eq!(
            request.args,
            vec!["-append".to_owned(), "stdin:".to_owned()]
        );
        let without_append = add_rules_request(b"{}".to_vec(), false);
        assert_eq!(without_append.args, vec!["stdin:".to_owned()]);
    }

    #[test]
    fn balancer_override_remove_omits_outbound_tag() {
        let request = balancer_override_request("b1".to_owned(), Some("direct".to_owned()), true);
        assert_eq!(
            request.args,
            vec!["-b".to_owned(), "b1".to_owned(), "-r".to_owned()]
        );
    }

    #[test]
    fn balancer_override_apply_includes_outbound_tag() {
        let request =
            balancer_override_request("b1".to_owned(), Some("direct".to_owned()), false);
        assert_eq!(
            request.args,
            vec!["-b".to_owned(), "b1".to_owned(), "direct".to_owned()]
        );
    }

    #[test]
    fn source_ip_block_builds_flags_before_ips() {
        let request = source_ip_block_request(
            "blocked".to_owned(),
            Some("socks-in".to_owned()),
            None,
            false,
            vec!["1.2.3.4".to_owned()],
        );
        assert_eq!(
            request.args,
            vec![
                "-outbound".to_owned(),
                "blocked".to_owned(),
                "-inbound".to_owned(),
                "socks-in".to_owned(),
                "1.2.3.4".to_owned(),
            ]
        );
    }

    #[test]
    fn stats_query_all_never_passes_reset_or_pattern() {
        let request = stats_query_all_request();
        assert_eq!(request.subcommand, "statsquery");
        assert!(request.args.is_empty());
        assert!(request.stdin_body.is_none());
    }

    #[test]
    fn stats_sys_takes_no_arguments() {
        let request = stats_sys_request();
        assert_eq!(request.subcommand, "statssys");
        assert!(request.args.is_empty());
    }

    #[test]
    fn remove_inbound_users_tag_precedes_emails() {
        let request =
            remove_inbound_users_request("vless-in".to_owned(), vec!["a@example.com".to_owned()]);
        assert_eq!(
            request.args,
            vec![
                "-tag".to_owned(),
                "vless-in".to_owned(),
                "a@example.com".to_owned()
            ]
        );
    }
}
