//! Xray Logs page model and async workers for [`super::ApplicationService`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use feldjaeger_ssh::{SshBackend, SshSession};
use tracing::info;

use crate::app::connection_secrets::ConnectionSecrets;
use crate::app::connection_test::build_connect_request;
use crate::app::status::SshStatus;
use crate::storage::StoredConnectionProfile;
use crate::xray::{
    DiscoveryState, XrayLogAvailability, XrayLogEntry, XrayLogError, XrayLogErrorKind,
    XrayLogLineLimit, XrayLogSearch, XrayLogService, XrayLogSourceKind, XrayLogSourceSummary,
    XrayLogStreamEvent,
};

/// Coarse GUI lifecycle for the Xray Logs page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayLogsPageState {
    /// SSH not connected.
    NoSshConnection,
    /// Discovery has not found Xray.
    XrayNotDiscovered,
    /// Selected source cannot be read.
    SourceUnavailable,
    /// Selected source is disabled in config.
    SourceDisabled,
    /// Remote read in progress.
    Loading,
    /// Content loaded (may be empty).
    Loaded,
    /// Loaded with zero lines.
    EmptyLog,
    /// Follow mode active.
    Following,
    /// Follow stopped due to error.
    FollowInterrupted,
    /// Last operation failed.
    Error,
}

impl XrayLogsPageState {
    /// Short banner label.
    pub fn label(self) -> &'static str {
        match self {
            Self::NoSshConnection => "No SSH connection",
            Self::XrayNotDiscovered => "Xray not discovered",
            Self::SourceUnavailable => "Source unavailable",
            Self::SourceDisabled => "Source disabled",
            Self::Loading => "Loading",
            Self::Loaded => "Loaded",
            Self::EmptyLog => "Empty log",
            Self::Following => "Following",
            Self::FollowInterrupted => "Follow interrupted",
            Self::Error => "Error",
        }
    }
}

/// Async control state for log operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum XrayLogsUiState {
    /// Idle.
    #[default]
    Idle,
    /// Probing sources or reading content.
    Loading,
    /// Follow session active.
    Following,
    /// Last failure.
    Failed {
        /// Classified kind.
        kind: XrayLogErrorKind,
        /// Safe detail.
        detail: String,
    },
}

impl XrayLogsUiState {
    /// Returns `true` while a conflicting remote op should disable controls.
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Loading | Self::Following)
    }

    /// Returns `true` while follow is active.
    pub fn is_following(&self) -> bool {
        matches!(self, Self::Following)
    }
}

/// Read-only page model for the Xray Logs GUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayLogsPageModel {
    /// Coarse page state.
    pub page_state: XrayLogsPageState,
    /// Selectable sources (always three when discovery succeeded).
    pub sources: Vec<XrayLogSourceSummary>,
    /// Currently selected source.
    pub selected: XrayLogSourceKind,
    /// Selected line limit.
    pub line_limit: XrayLogLineLimit,
    /// Loaded / followed entries.
    pub entries: Vec<XrayLogEntry>,
    /// Local search state.
    pub search: XrayLogSearch,
    /// Async UI state.
    pub ui_state: XrayLogsUiState,
    /// Whether Refresh may start.
    pub can_refresh: bool,
    /// Whether Follow may start.
    pub can_follow: bool,
    /// Whether Follow may stop.
    pub can_stop_follow: bool,
    /// Optional blocked reason.
    pub blocked_reason: Option<String>,
    /// Privacy notice for the page.
    pub privacy_notice: String,
    /// Selected source summary when present.
    pub selected_source: Option<XrayLogSourceSummary>,
}

/// Owned runtime state for Xray log viewing inside [`super::ApplicationService`].
#[derive(Debug)]
pub struct XrayLogsRuntime {
    /// Source summaries from last resolve/probe.
    pub sources: Vec<XrayLogSourceSummary>,
    /// Selected source kind.
    pub selected: XrayLogSourceKind,
    /// Line limit for reads.
    pub line_limit: XrayLogLineLimit,
    /// Loaded entries.
    pub entries: Vec<XrayLogEntry>,
    /// Local search.
    pub search: XrayLogSearch,
    /// Async UI state.
    pub ui_state: XrayLogsUiState,
    /// Event receiver for workers.
    pub event_rx: Option<Receiver<XrayLogStreamEvent>>,
    /// Probe receiver.
    pub probe_rx: Option<Receiver<XrayLogProbeOutcome>>,
    /// Stop flag for the active follow session.
    pub follow_stop: Option<Arc<AtomicBool>>,
    /// Generation counter for stale rejection.
    pub generation: u64,
    /// Last error retained for banners (content preserved).
    pub last_error: Option<XrayLogError>,
    /// Whether remote source probing has completed at least once.
    pub sources_probed: bool,
}

impl Default for XrayLogsRuntime {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            selected: XrayLogSourceKind::ErrorFile,
            line_limit: XrayLogLineLimit::DEFAULT,
            entries: Vec::new(),
            search: XrayLogSearch::default(),
            ui_state: XrayLogsUiState::Idle,
            event_rx: None,
            probe_rx: None,
            follow_stop: None,
            generation: 0,
            last_error: None,
            sources_probed: false,
        }
    }
}

impl XrayLogsRuntime {
    /// Clears session-specific state (disconnect / rediscovery).
    pub fn reset(&mut self) {
        self.stop_follow();
        *self = Self::default();
    }

    /// Requests the follow worker to stop and drops the stop handle.
    pub fn stop_follow(&mut self) {
        if let Some(flag) = self.follow_stop.take() {
            flag.store(true, Ordering::SeqCst);
        }
        if matches!(self.ui_state, XrayLogsUiState::Following) {
            self.ui_state = XrayLogsUiState::Idle;
        }
    }
}

/// Builds the page model from SSH, discovery, and runtime state.
pub fn build_xray_logs_page_model(
    ssh: SshStatus,
    discovery: &DiscoveryState,
    runtime: &XrayLogsRuntime,
    remote_busy: bool,
) -> XrayLogsPageModel {
    let privacy_notice =
        "Xray logs may contain sensitive connection information.".to_owned();

    let (page_state, blocked_reason, sources) = match ssh {
        SshStatus::Connected => match discovery {
            DiscoveryState::Succeeded(installation) => {
                let sources = if runtime.sources.is_empty() {
                    XrayLogService::new().resolve_sources(Some(installation), None)
                } else {
                    runtime.sources.clone()
                };
                let selected_summary = sources.iter().find(|s| s.kind == runtime.selected);
                let state = derive_content_state(runtime, selected_summary);
                (state, None, sources)
            }
            DiscoveryState::NotFound { .. } | DiscoveryState::Failed { .. } => (
                XrayLogsPageState::XrayNotDiscovered,
                Some("Xray not discovered. Run discovery on the Connection page.".to_owned()),
                Vec::new(),
            ),
            DiscoveryState::Idle | DiscoveryState::Discovering => (
                XrayLogsPageState::XrayNotDiscovered,
                Some("Run discovery on the Connection page first.".to_owned()),
                Vec::new(),
            ),
        },
        _ => (
            XrayLogsPageState::NoSshConnection,
            Some("Connect over SSH first.".to_owned()),
            Vec::new(),
        ),
    };

    let selected_source = sources
        .iter()
        .find(|s| s.kind == runtime.selected)
        .cloned();
    let source_readable = selected_source
        .as_ref()
        .map(|s| s.availability.is_readable())
        .unwrap_or(false);

    let can_act = ssh == SshStatus::Connected
        && matches!(discovery, DiscoveryState::Succeeded(_))
        && !remote_busy
        && !matches!(runtime.ui_state, XrayLogsUiState::Loading);

    let can_refresh = can_act && source_readable && !runtime.ui_state.is_following();
    let can_follow = can_act && source_readable && !runtime.ui_state.is_following();
    let can_stop_follow = runtime.ui_state.is_following();

    XrayLogsPageModel {
        page_state,
        sources,
        selected: runtime.selected,
        line_limit: runtime.line_limit,
        entries: runtime.entries.clone(),
        search: runtime.search.clone(),
        ui_state: runtime.ui_state.clone(),
        can_refresh,
        can_follow,
        can_stop_follow,
        blocked_reason,
        privacy_notice,
        selected_source,
    }
}

fn derive_content_state(
    runtime: &XrayLogsRuntime,
    selected: Option<&XrayLogSourceSummary>,
) -> XrayLogsPageState {
    match &runtime.ui_state {
        XrayLogsUiState::Loading => return XrayLogsPageState::Loading,
        XrayLogsUiState::Following => return XrayLogsPageState::Following,
        XrayLogsUiState::Failed { kind, .. } => {
            if *kind == XrayLogErrorKind::FollowSessionInterrupted {
                return XrayLogsPageState::FollowInterrupted;
            }
            if *kind == XrayLogErrorKind::LogSourceDisabled {
                return XrayLogsPageState::SourceDisabled;
            }
            return XrayLogsPageState::Error;
        }
        XrayLogsUiState::Idle => {}
    }

    match selected.map(|s| s.availability) {
        Some(XrayLogAvailability::Disabled) => XrayLogsPageState::SourceDisabled,
        Some(XrayLogAvailability::Available) => {
            if runtime.generation == 0 {
                XrayLogsPageState::Loaded
            } else if runtime.entries.is_empty() {
                XrayLogsPageState::EmptyLog
            } else {
                XrayLogsPageState::Loaded
            }
        }
        Some(_) => XrayLogsPageState::SourceUnavailable,
        None => XrayLogsPageState::SourceUnavailable,
    }
}

/// Applies a stream event when its generation matches.
pub fn apply_xray_log_event(runtime: &mut XrayLogsRuntime, event: XrayLogStreamEvent) {
    let generation = match &event {
        XrayLogStreamEvent::Replace { generation, .. }
        | XrayLogStreamEvent::Append { generation, .. }
        | XrayLogStreamEvent::Failed { generation, .. }
        | XrayLogStreamEvent::FollowStopped { generation } => *generation,
    };
    if generation != runtime.generation {
        return;
    }

    match event {
        XrayLogStreamEvent::Replace { kind, entries, .. } => {
            if kind != runtime.selected {
                return;
            }
            runtime.entries = entries;
            let query = runtime.search.query.clone();
            runtime.search.recompute(&runtime.entries, &query);
            if !matches!(runtime.ui_state, XrayLogsUiState::Following) {
                runtime.ui_state = XrayLogsUiState::Idle;
            }
            runtime.last_error = None;
        }
        XrayLogStreamEvent::Append { kind, entries, .. } => {
            if kind != runtime.selected {
                return;
            }
            runtime.entries.extend(entries);
            trim_follow_buffer(runtime);
            let query = runtime.search.query.clone();
            runtime.search.recompute(&runtime.entries, &query);
        }
        XrayLogStreamEvent::Failed { error, .. } => {
            runtime.last_error = Some(error.clone());
            runtime.ui_state = XrayLogsUiState::Failed {
                kind: error.kind,
                detail: error.detail,
            };
            runtime.follow_stop = None;
        }
        XrayLogStreamEvent::FollowStopped { .. } => {
            runtime.follow_stop = None;
            if matches!(runtime.ui_state, XrayLogsUiState::Following) {
                runtime.ui_state = XrayLogsUiState::Idle;
            }
        }
    }
}

/// Keeps at most `line_limit * 2` entries while following to bound GUI memory.
fn trim_follow_buffer(runtime: &mut XrayLogsRuntime) {
    let max = (runtime.line_limit.as_u32() as usize).saturating_mul(2).max(100);
    if runtime.entries.len() > max {
        let drop_count = runtime.entries.len() - max;
        runtime.entries.drain(0..drop_count);
    }
}

/// Spawns a one-shot read worker (refresh / initial load).
pub fn spawn_xray_log_read<B>(
    backend: B,
    profile: StoredConnectionProfile,
    secrets: ConnectionSecrets,
    installation: crate::xray::XrayInstallation,
    editable: Option<crate::xray::config::EditableXrayConfig>,
    kind: XrayLogSourceKind,
    limit: XrayLogLineLimit,
    generation: u64,
    tx: Sender<XrayLogStreamEvent>,
) where
    B: SshBackend + Send + 'static,
    B::Session: Sync + 'static,
{
    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = tx.send(XrayLogStreamEvent::Failed {
                    generation,
                    error: XrayLogError::new(
                        XrayLogErrorKind::RemoteReadFailed,
                        format!("failed to start async runtime: {error}"),
                    ),
                });
                return;
            }
        };

        runtime.block_on(async move {
            let request = build_connect_request(&profile, &secrets);
            let session = match backend.connect(&request).await {
                Ok(session) => session,
                Err(_) => {
                    let _ = tx.send(XrayLogStreamEvent::Failed {
                        generation,
                        error: XrayLogError::new(
                            XrayLogErrorKind::NoSshConnection,
                            crate::logging::redact::user_message_see_log(
                                "Unable to connect to server.",
                            ),
                        ),
                    });
                    return;
                }
            };

            let service = XrayLogService::new();
            let result = service
                .read_tail(&session, &installation, editable.as_ref(), kind, limit)
                .await;

            let _ = session.disconnect().await;

            match result {
                Ok(entries) => {
                    let _ = tx.send(XrayLogStreamEvent::Replace {
                        generation,
                        kind,
                        entries,
                    });
                }
                Err(error) => {
                    let _ = tx.send(XrayLogStreamEvent::Failed { generation, error });
                }
            }
        });
    });
}

/// Spawns a follow worker that keeps one SSH session open and polls for new lines.
pub fn spawn_xray_log_follow<B>(
    backend: B,
    profile: StoredConnectionProfile,
    secrets: ConnectionSecrets,
    installation: crate::xray::XrayInstallation,
    editable: Option<crate::xray::config::EditableXrayConfig>,
    kind: XrayLogSourceKind,
    limit: XrayLogLineLimit,
    generation: u64,
    stop: Arc<AtomicBool>,
    tx: Sender<XrayLogStreamEvent>,
) where
    B: SshBackend + Send + 'static,
    B::Session: Sync + 'static,
{
    info!(
        target: "xray_logs",
        source = ?kind,
        "Xray log follow worker starting"
    );

    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = tx.send(XrayLogStreamEvent::Failed {
                    generation,
                    error: XrayLogError::new(
                        XrayLogErrorKind::FollowSessionInterrupted,
                        format!("failed to start async runtime: {error}"),
                    ),
                });
                return;
            }
        };

        runtime.block_on(async move {
            let request = build_connect_request(&profile, &secrets);
            let session = match backend.connect(&request).await {
                Ok(session) => session,
                Err(_) => {
                    let _ = tx.send(XrayLogStreamEvent::Failed {
                        generation,
                        error: XrayLogError::new(
                            XrayLogErrorKind::NoSshConnection,
                            crate::logging::redact::user_message_see_log(
                                "Unable to connect to server.",
                            ),
                        ),
                    });
                    return;
                }
            };

            let service = XrayLogService::new();
            let tx_clone = tx.clone();
            service
                .follow(
                    &session,
                    &installation,
                    editable.as_ref(),
                    kind,
                    limit,
                    generation,
                    stop,
                    move |event| {
                        let _ = tx_clone.send(event);
                    },
                )
                .await;

            let _ = session.disconnect().await;
        });
    });
}

/// Spawns a source-probe worker.
pub fn spawn_xray_log_probe<B>(
    backend: B,
    profile: StoredConnectionProfile,
    secrets: ConnectionSecrets,
    installation: crate::xray::XrayInstallation,
    editable: Option<crate::xray::config::EditableXrayConfig>,
    generation: u64,
    tx: Sender<XrayLogProbeOutcome>,
) where
    B: SshBackend + Send + 'static,
    B::Session: Sync + 'static,
{
    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = tx.send(XrayLogProbeOutcome {
                    generation,
                    result: Err(XrayLogError::new(
                        XrayLogErrorKind::RemoteReadFailed,
                        format!("failed to start async runtime: {error}"),
                    )),
                });
                return;
            }
        };

        runtime.block_on(async move {
            let request = build_connect_request(&profile, &secrets);
            let session = match backend.connect(&request).await {
                Ok(session) => session,
                Err(_) => {
                    let _ = tx.send(XrayLogProbeOutcome {
                        generation,
                        result: Err(XrayLogError::new(
                            XrayLogErrorKind::NoSshConnection,
                            crate::logging::redact::user_message_see_log(
                                "Unable to connect to server.",
                            ),
                        )),
                    });
                    return;
                }
            };

            let service = XrayLogService::new();
            let result = service
                .probe_sources(&session, &installation, editable.as_ref())
                .await;
            let _ = session.disconnect().await;
            let _ = tx.send(XrayLogProbeOutcome { generation, result });
        });
    });
}

/// Outcome of a source probe worker.
#[derive(Debug)]
pub struct XrayLogProbeOutcome {
    /// Generation for stale rejection.
    pub generation: u64,
    /// Probed summaries or error.
    pub result: Result<Vec<XrayLogSourceSummary>, XrayLogError>,
}

/// Helper to create an event channel.
pub fn xray_log_event_channel() -> (Sender<XrayLogStreamEvent>, Receiver<XrayLogStreamEvent>) {
    mpsc::channel()
}

/// Helper to create a probe channel.
pub fn xray_log_probe_channel() -> (Sender<XrayLogProbeOutcome>, Receiver<XrayLogProbeOutcome>) {
    mpsc::channel()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{
        ConfigSource, InitSystemKind, XrayInstallation, XrayLogAvailability, XrayLogEntry,
    };
    use feldjaeger_ssh::RemotePath;

    fn installation() -> XrayInstallation {
        XrayInstallation {
            operating_system: "Debian".into(),
            architecture: "x86_64".into(),
            init_system: InitSystemKind::Systemd,
            binary_path: RemotePath::new("/usr/local/bin/xray").ok(),
            version: Some("1.8.0".into()),
            service_name: Some("xray.service".into()),
            service_state: None,
            exec_start: None,
            config_source: ConfigSource::NotFound,
            config_readable: false,
            config_files: Vec::new(),
            discovery_warnings: Vec::new(),
        }
    }

    #[test]
    fn rejects_stale_generation() {
        let mut runtime = XrayLogsRuntime {
            generation: 2,
            selected: XrayLogSourceKind::ErrorFile,
            ..XrayLogsRuntime::default()
        };
        apply_xray_log_event(
            &mut runtime,
            XrayLogStreamEvent::Replace {
                generation: 1,
                kind: XrayLogSourceKind::ErrorFile,
                entries: vec![XrayLogEntry::plain("stale")],
            },
        );
        assert!(runtime.entries.is_empty());
    }

    #[test]
    fn rejects_stale_source_on_replace() {
        let mut runtime = XrayLogsRuntime {
            generation: 1,
            selected: XrayLogSourceKind::AccessFile,
            ..XrayLogsRuntime::default()
        };
        apply_xray_log_event(
            &mut runtime,
            XrayLogStreamEvent::Replace {
                generation: 1,
                kind: XrayLogSourceKind::ErrorFile,
                entries: vec![XrayLogEntry::plain("wrong source")],
            },
        );
        assert!(runtime.entries.is_empty());
    }

    #[test]
    fn append_preserves_prior_lines() {
        let mut runtime = XrayLogsRuntime {
            generation: 1,
            selected: XrayLogSourceKind::Journal,
            entries: vec![XrayLogEntry::plain("old")],
            ..XrayLogsRuntime::default()
        };
        apply_xray_log_event(
            &mut runtime,
            XrayLogStreamEvent::Append {
                generation: 1,
                kind: XrayLogSourceKind::Journal,
                entries: vec![XrayLogEntry::plain("new")],
            },
        );
        assert_eq!(runtime.entries.len(), 2);
        assert_eq!(runtime.entries[0].message, "old");
        assert_eq!(runtime.entries[1].message, "new");
    }

    #[test]
    fn failed_refresh_keeps_prior_content() {
        let mut runtime = XrayLogsRuntime {
            generation: 1,
            selected: XrayLogSourceKind::ErrorFile,
            entries: vec![XrayLogEntry::plain("kept")],
            ..XrayLogsRuntime::default()
        };
        apply_xray_log_event(
            &mut runtime,
            XrayLogStreamEvent::Failed {
                generation: 1,
                error: XrayLogError::new(XrayLogErrorKind::RemoteReadFailed, "boom"),
            },
        );
        assert_eq!(runtime.entries.len(), 1);
        assert_eq!(runtime.entries[0].message, "kept");
        assert!(matches!(runtime.ui_state, XrayLogsUiState::Failed { .. }));
    }

    #[test]
    fn page_model_no_ssh() {
        let model = build_xray_logs_page_model(
            SshStatus::Disconnected,
            &DiscoveryState::Idle,
            &XrayLogsRuntime::default(),
            false,
        );
        assert_eq!(model.page_state, XrayLogsPageState::NoSshConnection);
        assert!(!model.can_refresh);
    }

    #[test]
    fn page_model_not_discovered() {
        let model = build_xray_logs_page_model(
            SshStatus::Connected,
            &DiscoveryState::Idle,
            &XrayLogsRuntime::default(),
            false,
        );
        assert_eq!(model.page_state, XrayLogsPageState::XrayNotDiscovered);
    }

    #[test]
    fn local_search_does_not_need_remote() {
        let mut runtime = XrayLogsRuntime {
            entries: vec![
                XrayLogEntry::plain("alpha"),
                XrayLogEntry::plain("Bravo"),
                XrayLogEntry::plain("charlie"),
            ],
            ..XrayLogsRuntime::default()
        };
        runtime.search.recompute(&runtime.entries, "BRA");
        assert_eq!(runtime.search.match_count(), 1);
        assert_eq!(runtime.search.current_entry_index(), Some(1));
    }

    #[test]
    fn follow_append_trims_to_twice_line_limit() {
        let mut runtime = XrayLogsRuntime {
            generation: 1,
            selected: XrayLogSourceKind::Journal,
            line_limit: XrayLogLineLimit::Hundred,
            entries: (0..150)
                .map(|i| XrayLogEntry::plain(format!("old-{i}")))
                .collect(),
            ..XrayLogsRuntime::default()
        };
        apply_xray_log_event(
            &mut runtime,
            XrayLogStreamEvent::Append {
                generation: 1,
                kind: XrayLogSourceKind::Journal,
                entries: (0..60)
                    .map(|i| XrayLogEntry::plain(format!("new-{i}")))
                    .collect(),
            },
        );
        assert_eq!(runtime.entries.len(), 200);
        assert_eq!(runtime.entries[0].message, "old-10");
        assert_eq!(runtime.entries.last().unwrap().message, "new-59");
    }

    #[test]
    fn source_change_stops_follow_flag() {
        let mut runtime = XrayLogsRuntime::default();
        let flag = Arc::new(AtomicBool::new(false));
        runtime.follow_stop = Some(Arc::clone(&flag));
        runtime.ui_state = XrayLogsUiState::Following;
        runtime.stop_follow();
        assert!(flag.load(Ordering::SeqCst));
        assert!(!runtime.ui_state.is_following());
        let _ = installation(); // keep helper used / compile Installation shape
        let _ = XrayLogAvailability::Available;
    }
}
