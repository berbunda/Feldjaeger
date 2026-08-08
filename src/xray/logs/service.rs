//! Read-only remote access to Xray runtime logs.
//!
//! Resolves destinations from the loaded Xray configuration and Discovery
//! service name. Never edits log configuration, truncates files, or writes
//! remote log bodies into application logs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use feldjaeger_ssh::{ExecResult, RemoteCommand, RemotePath, SshSession};
use tracing::{info, warn};

use super::destination::{XrayLogConfigView, log_config_view};
use super::error::{XrayLogError, XrayLogErrorKind, XrayLogResult};
use super::model::{
    XrayLogAvailability, XrayLogDestination, XrayLogEntry, XrayLogLineLimit, XrayLogSourceKind,
    XrayLogSourceSummary,
};
use crate::init::ServiceName;
use crate::logging::redact::{sanitize_detail, user_message_see_log};
use crate::xray::config::EditableXrayConfig;
use crate::xray::{InitSystemKind, XrayInstallation};

/// Event emitted by a follow session or one-shot read worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrayLogStreamEvent {
    /// Full replacement of the view (initial read / refresh).
    Replace {
        /// Monotonic generation used to reject stale async results.
        generation: u64,
        /// Source that produced this payload.
        kind: XrayLogSourceKind,
        /// Lines in order.
        entries: Vec<XrayLogEntry>,
    },
    /// Newly observed lines while following.
    Append {
        /// Monotonic generation used to reject stale async results.
        generation: u64,
        /// Source that produced this payload.
        kind: XrayLogSourceKind,
        /// New lines in order.
        entries: Vec<XrayLogEntry>,
    },
    /// Follow or read failed.
    Failed {
        /// Monotonic generation used to reject stale async results.
        generation: u64,
        /// Classified error.
        error: XrayLogError,
    },
    /// Follow ended cleanly (stop requested).
    FollowStopped {
        /// Monotonic generation used to reject stale async results.
        generation: u64,
    },
}

/// Dedicated service for Xray runtime log access.
#[derive(Debug, Clone, Default)]
pub struct XrayLogService;

impl XrayLogService {
    /// Creates a new log service.
    pub fn new() -> Self {
        Self
    }

    /// Resolves static source summaries from config + installation (no SSH).
    pub fn resolve_sources(
        &self,
        installation: Option<&XrayInstallation>,
        editable: Option<&EditableXrayConfig>,
    ) -> Vec<XrayLogSourceSummary> {
        let view = config_view_from_editable(editable);
        let access = summary_for_file_destination(
            XrayLogSourceKind::AccessFile,
            &view.access,
            installation,
        );
        let error =
            summary_for_file_destination(XrayLogSourceKind::ErrorFile, &view.error, installation);
        let journal = summary_for_journal(installation);
        vec![access, error, journal]
    }

    /// Probes remote availability for file and journal sources.
    pub async fn probe_sources<S: SshSession + Sync>(
        &self,
        session: &S,
        installation: &XrayInstallation,
        editable: Option<&EditableXrayConfig>,
    ) -> XrayLogResult<Vec<XrayLogSourceSummary>> {
        let mut sources = self.resolve_sources(Some(installation), editable);
        for source in &mut sources {
            match source.kind {
                XrayLogSourceKind::AccessFile | XrayLogSourceKind::ErrorFile => {
                    if source.availability == XrayLogAvailability::Unknown
                        && source.source.starts_with('/')
                    {
                        *source = probe_file_source(session, source.kind, &source.source).await?;
                    }
                }
                XrayLogSourceKind::Journal => {
                    *source = probe_journal_source(session, installation).await?;
                }
            }
        }
        Ok(sources)
    }

    /// Reads the last `limit` lines from the selected source.
    pub async fn read_tail<S: SshSession + Sync>(
        &self,
        session: &S,
        installation: &XrayInstallation,
        editable: Option<&EditableXrayConfig>,
        kind: XrayLogSourceKind,
        limit: XrayLogLineLimit,
    ) -> XrayLogResult<Vec<XrayLogEntry>> {
        info!(
            target: "xray_logs",
            source = ?kind,
            limit = limit.as_u32(),
            "Xray log read started"
        );

        let result = match kind {
            XrayLogSourceKind::AccessFile | XrayLogSourceKind::ErrorFile => {
                let path = require_file_path(editable, kind)?;
                read_file_tail(session, &path, limit.as_u32()).await
            }
            XrayLogSourceKind::Journal => {
                let unit = require_journal_unit(installation)?;
                read_journal_tail(session, &unit, limit.as_u32()).await
            }
        };

        match &result {
            Ok(entries) => {
                info!(
                    target: "xray_logs",
                    source = ?kind,
                    lines = entries.len(),
                    "Xray log read completed"
                );
            }
            Err(error) => {
                warn!(
                    target: "xray_logs",
                    source = ?kind,
                    error_kind = ?error.kind,
                    detail = %sanitize_detail(&error.detail),
                    "Xray log read failed"
                );
            }
        }

        result
    }

    /// Follows a source, sending replace/append events until `stop` is set.
    pub async fn follow<S: SshSession + Sync, F>(
        &self,
        session: &S,
        installation: &XrayInstallation,
        editable: Option<&EditableXrayConfig>,
        kind: XrayLogSourceKind,
        limit: XrayLogLineLimit,
        generation: u64,
        stop: Arc<AtomicBool>,
        mut emit: F,
    ) where
        F: FnMut(XrayLogStreamEvent),
    {
        info!(
            target: "xray_logs",
            source = ?kind,
            "Xray log follow started"
        );

        let follow_result = match kind {
            XrayLogSourceKind::AccessFile | XrayLogSourceKind::ErrorFile => {
                let path = match require_file_path(editable, kind) {
                    Ok(path) => path,
                    Err(error) => {
                        emit(XrayLogStreamEvent::Failed { generation, error });
                        return;
                    }
                };
                match self
                    .read_tail(session, installation, editable, kind, limit)
                    .await
                {
                    Ok(entries) => emit(XrayLogStreamEvent::Replace {
                        generation,
                        kind,
                        entries,
                    }),
                    Err(error) => {
                        emit(XrayLogStreamEvent::Failed { generation, error });
                        return;
                    }
                }
                follow_file(session, &path, generation, kind, &stop, &mut emit).await
            }
            XrayLogSourceKind::Journal => {
                let unit = match require_journal_unit(installation) {
                    Ok(unit) => unit,
                    Err(error) => {
                        emit(XrayLogStreamEvent::Failed { generation, error });
                        return;
                    }
                };
                // Cursor comes from the same journalctl call as the replace payload
                // so lines between an initial read and follow start are not skipped.
                let cursor = match read_journal_tail_with_cursor(session, &unit, limit.as_u32()).await
                {
                    Ok((entries, cursor)) => {
                        emit(XrayLogStreamEvent::Replace {
                            generation,
                            kind,
                            entries,
                        });
                        cursor
                    }
                    Err(error) => {
                        emit(XrayLogStreamEvent::Failed { generation, error });
                        return;
                    }
                };
                follow_journal(session, &unit, generation, kind, cursor, &stop, &mut emit).await
            }
        };

        if let Err(error) = follow_result {
            if !stop.load(Ordering::SeqCst) {
                warn!(
                    target: "xray_logs",
                    source = ?kind,
                    error_kind = ?error.kind,
                    detail = %sanitize_detail(&error.detail),
                    "Xray log follow interrupted"
                );
                emit(XrayLogStreamEvent::Failed { generation, error });
            }
        }

        emit(XrayLogStreamEvent::FollowStopped { generation });
        info!(
            target: "xray_logs",
            source = ?kind,
            "Xray log follow stopped"
        );
    }
}

fn config_view_from_editable(editable: Option<&EditableXrayConfig>) -> XrayLogConfigView {
    match editable {
        Some(config) => log_config_view(config.sections().log()),
        None => XrayLogConfigView::defaults(),
    }
}

fn summary_for_file_destination(
    kind: XrayLogSourceKind,
    destination: &XrayLogDestination,
    installation: Option<&XrayInstallation>,
) -> XrayLogSourceSummary {
    let mut warnings = Vec::new();
    if installation.is_none() {
        return XrayLogSourceSummary {
            kind,
            display_name: kind.display_name().to_owned(),
            source: "—".to_owned(),
            availability: XrayLogAvailability::Unknown,
            warnings,
        };
    }

    let (availability, source) = match destination {
        XrayLogDestination::File { path } => (XrayLogAvailability::Unknown, path.clone()),
        XrayLogDestination::Disabled => (XrayLogAvailability::Disabled, "none".to_owned()),
        XrayLogDestination::Stdout => {
            warnings.push(
                "Configured for stdout. Use System Journal for process output captured by systemd."
                    .to_owned(),
            );
            (XrayLogAvailability::Unsupported, "stdout".to_owned())
        }
        XrayLogDestination::Stderr => {
            warnings.push(
                "Configured for stderr. Use System Journal for process output captured by systemd."
                    .to_owned(),
            );
            (XrayLogAvailability::Unsupported, "stderr".to_owned())
        }
        XrayLogDestination::Unsupported { raw } => {
            warnings.push(format!("Unsupported log destination: {raw}"));
            (XrayLogAvailability::Unsupported, raw.clone())
        }
    };

    XrayLogSourceSummary {
        kind,
        display_name: kind.display_name().to_owned(),
        source,
        availability,
        warnings,
    }
}

fn summary_for_journal(installation: Option<&XrayInstallation>) -> XrayLogSourceSummary {
    let kind = XrayLogSourceKind::Journal;
    let Some(installation) = installation else {
        return XrayLogSourceSummary {
            kind,
            display_name: kind.display_name().to_owned(),
            source: "—".to_owned(),
            availability: XrayLogAvailability::Unknown,
            warnings: Vec::new(),
        };
    };

    let mut warnings = Vec::new();
    warnings.push(
        "System journal includes service lifecycle and process stdout/stderr; it is not equivalent to configured access or error log files.".to_owned(),
    );

    if installation.init_system != InitSystemKind::Systemd {
        return XrayLogSourceSummary {
            kind,
            display_name: kind.display_name().to_owned(),
            source: installation
                .service_name
                .clone()
                .unwrap_or_else(|| "—".to_owned()),
            availability: XrayLogAvailability::Unsupported,
            warnings: {
                warnings.push(format!(
                    "Init system {:?} is not supported for journal access (systemd only).",
                    installation.init_system
                ));
                warnings
            },
        };
    }

    match installation.service_name.as_deref() {
        Some(name) if !name.is_empty() => XrayLogSourceSummary {
            kind,
            display_name: kind.display_name().to_owned(),
            source: name.to_owned(),
            availability: XrayLogAvailability::Unknown,
            warnings,
        },
        _ => XrayLogSourceSummary {
            kind,
            display_name: kind.display_name().to_owned(),
            source: "—".to_owned(),
            availability: XrayLogAvailability::Missing,
            warnings: {
                warnings.push("Discovery did not return a systemd service name.".to_owned());
                warnings
            },
        },
    }
}

async fn probe_file_source<S: SshSession + Sync>(
    session: &S,
    kind: XrayLogSourceKind,
    path: &str,
) -> XrayLogResult<XrayLogSourceSummary> {
    let exists = exec_test(session, "-e", path).await?;
    if !exists {
        return Ok(XrayLogSourceSummary {
            kind,
            display_name: kind.display_name().to_owned(),
            source: path.to_owned(),
            availability: XrayLogAvailability::Missing,
            warnings: vec![format!("Log file does not exist: {path}")],
        });
    }

    let is_file = exec_test(session, "-f", path).await?;
    if !is_file {
        return Ok(XrayLogSourceSummary {
            kind,
            display_name: kind.display_name().to_owned(),
            source: path.to_owned(),
            availability: XrayLogAvailability::Unsupported,
            warnings: vec![format!("Path is not a regular file: {path}")],
        });
    }

    let readable = exec_test(session, "-r", path).await?;
    if !readable {
        return Ok(XrayLogSourceSummary {
            kind,
            display_name: kind.display_name().to_owned(),
            source: path.to_owned(),
            availability: XrayLogAvailability::PermissionDenied,
            warnings: vec![format!("Permission denied reading: {path}")],
        });
    }

    Ok(XrayLogSourceSummary {
        kind,
        display_name: kind.display_name().to_owned(),
        source: path.to_owned(),
        availability: XrayLogAvailability::Available,
        warnings: Vec::new(),
    })
}

async fn probe_journal_source<S: SshSession + Sync>(
    session: &S,
    installation: &XrayInstallation,
) -> XrayLogResult<XrayLogSourceSummary> {
    let mut base = summary_for_journal(Some(installation));
    if base.availability != XrayLogAvailability::Unknown {
        return Ok(base);
    }

    let unit = installation
        .service_name
        .as_deref()
        .ok_or_else(|| {
            XrayLogError::new(
                XrayLogErrorKind::ServiceNotFound,
                "No systemd service name from Discovery.",
            )
        })?;
    let service = ServiceName::new(unit).map_err(|error| {
        XrayLogError::new(
            XrayLogErrorKind::ServiceNotFound,
            sanitize_detail(error.message()),
        )
    })?;

    let journalctl = exec_program(session, "command", &["-v", "journalctl"]).await?;
    if journalctl.exit_code != 0 {
        base.availability = XrayLogAvailability::Unsupported;
        base.warnings
            .push("journalctl is not available on this host.".to_owned());
        return Ok(base);
    }

    let result = exec_program(
        session,
        "journalctl",
        &[
            "-u",
            service.as_str(),
            "-n",
            "0",
            "--no-pager",
            "-q",
        ],
    )
    .await?;

    if result.exit_code != 0 {
        let stderr = String::from_utf8_lossy(&result.stderr).to_ascii_lowercase();
        if stderr.contains("permission") || stderr.contains("access denied") {
            base.availability = XrayLogAvailability::PermissionDenied;
        } else if stderr.contains("not found") || stderr.contains("could not find unit") {
            base.availability = XrayLogAvailability::Missing;
        } else {
            base.availability = XrayLogAvailability::Unsupported;
            base.warnings.push(user_message_see_log(
                "Unable to query systemd journal for this unit.",
            ));
        }
        return Ok(base);
    }

    base.availability = XrayLogAvailability::Available;
    Ok(base)
}

fn require_file_path(
    editable: Option<&EditableXrayConfig>,
    kind: XrayLogSourceKind,
) -> XrayLogResult<String> {
    let view = config_view_from_editable(editable);
    let destination = match kind {
        XrayLogSourceKind::AccessFile => &view.access,
        XrayLogSourceKind::ErrorFile => &view.error,
        XrayLogSourceKind::Journal => {
            return Err(XrayLogError::new(
                XrayLogErrorKind::UnsupportedLogDestination,
                "Journal source does not use a file path.",
            ));
        }
    };

    match destination {
        XrayLogDestination::File { path } => {
            RemotePath::new(path.as_str()).map_err(|error| {
                XrayLogError::new(
                    XrayLogErrorKind::UnsupportedLogDestination,
                    sanitize_detail(error.message()),
                )
            })?;
            Ok(path.clone())
        }
        XrayLogDestination::Disabled => Err(XrayLogError::new(
            XrayLogErrorKind::LogSourceDisabled,
            format!("{} is disabled in Xray configuration.", kind.display_name()),
        )),
        XrayLogDestination::Stdout | XrayLogDestination::Stderr => Err(XrayLogError::new(
            XrayLogErrorKind::UnsupportedLogDestination,
            format!(
                "{} is configured for {}; use System Journal.",
                kind.display_name(),
                destination.display_source()
            ),
        )),
        XrayLogDestination::Unsupported { raw } => Err(XrayLogError::new(
            XrayLogErrorKind::UnsupportedLogDestination,
            format!("Unsupported destination for {}: {raw}", kind.display_name()),
        )),
    }
}

fn require_journal_unit(installation: &XrayInstallation) -> XrayLogResult<ServiceName> {
    if installation.init_system != InitSystemKind::Systemd {
        return Err(XrayLogError::new(
            XrayLogErrorKind::UnsupportedInitSystem,
            format!(
                "Journal access requires systemd; found {:?}.",
                installation.init_system
            ),
        ));
    }

    let name = installation.service_name.as_deref().ok_or_else(|| {
        XrayLogError::new(
            XrayLogErrorKind::ServiceNotFound,
            "Discovery did not return a service name.",
        )
    })?;

    ServiceName::new(name).map_err(|error| {
        XrayLogError::new(
            XrayLogErrorKind::ServiceNotFound,
            sanitize_detail(error.message()),
        )
    })
}

async fn read_file_tail<S: SshSession + Sync>(
    session: &S,
    path: &str,
    lines: u32,
) -> XrayLogResult<Vec<XrayLogEntry>> {
    RemotePath::new(path).map_err(|error| {
        XrayLogError::new(
            XrayLogErrorKind::UnsupportedLogDestination,
            sanitize_detail(error.message()),
        )
    })?;

    let exists = exec_test(session, "-e", path).await?;
    if !exists {
        return Err(XrayLogError::new(
            XrayLogErrorKind::LogFileMissing,
            format!("Log file does not exist: {path}"),
        ));
    }

    let is_file = exec_test(session, "-f", path).await?;
    if !is_file {
        return Err(XrayLogError::new(
            XrayLogErrorKind::UnsupportedLogDestination,
            format!("Path is not a regular file: {path}"),
        ));
    }

    let readable = exec_test(session, "-r", path).await?;
    if !readable {
        return Err(XrayLogError::new(
            XrayLogErrorKind::PermissionDenied,
            format!("Permission denied reading: {path}"),
        ));
    }

    let result = exec_program(
        session,
        "tail",
        &["-n", &lines.to_string(), "--", path],
    )
    .await?;

    if result.exit_code != 0 {
        return Err(map_remote_failure(
            XrayLogErrorKind::RemoteReadFailed,
            &result,
            "Failed to read log file tail.",
        ));
    }

    Ok(entries_from_bytes(&result.stdout))
}

async fn read_journal_tail<S: SshSession + Sync>(
    session: &S,
    unit: &ServiceName,
    lines: u32,
) -> XrayLogResult<Vec<XrayLogEntry>> {
    Ok(read_journal_tail_with_cursor(session, unit, lines).await?.0)
}

async fn read_journal_tail_with_cursor<S: SshSession + Sync>(
    session: &S,
    unit: &ServiceName,
    lines: u32,
) -> XrayLogResult<(Vec<XrayLogEntry>, Option<String>)> {
    let result = exec_program(
        session,
        "journalctl",
        &[
            "-u",
            unit.as_str(),
            "-n",
            &lines.to_string(),
            "--no-pager",
            "-o",
            "short-iso",
            "--show-cursor",
        ],
    )
    .await?;

    if result.exit_code != 0 {
        return Err(classify_journal_failure(&result));
    }

    Ok(split_journal_output(&result.stdout))
}

async fn follow_file<S: SshSession + Sync, F>(
    session: &S,
    path: &str,
    generation: u64,
    kind: XrayLogSourceKind,
    stop: &AtomicBool,
    emit: &mut F,
) -> XrayLogResult<()>
where
    F: FnMut(XrayLogStreamEvent),
{
    let mut offset = file_size(session, path).await?;

    while !stop.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(750)).await;
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let size = file_size(session, path).await?;
        if size < offset {
            // Rotation / truncation: reload is left to the next manual refresh;
            // reset offset and skip to avoid duplicates from a partial re-read.
            offset = size;
            continue;
        }
        if size == offset {
            continue;
        }

        let start = offset.saturating_add(1);
        let result = exec_program(
            session,
            "tail",
            &["-c", &format!("+{start}"), "--", path],
        )
        .await?;
        if result.exit_code != 0 {
            return Err(map_remote_failure(
                XrayLogErrorKind::FollowSessionInterrupted,
                &result,
                "Failed while following log file.",
            ));
        }

        let entries = entries_from_bytes(&result.stdout);
        if !entries.is_empty() {
            emit(XrayLogStreamEvent::Append {
                generation,
                kind,
                entries,
            });
        }
        offset = size;
    }

    Ok(())
}

async fn follow_journal<S: SshSession + Sync, F>(
    session: &S,
    unit: &ServiceName,
    generation: u64,
    kind: XrayLogSourceKind,
    mut cursor: Option<String>,
    stop: &AtomicBool,
    emit: &mut F,
) -> XrayLogResult<()>
where
    F: FnMut(XrayLogStreamEvent),
{
    while !stop.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(750)).await;
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let Some(current_cursor) = cursor.clone() else {
            cursor = read_journal_cursor(session, unit).await?;
            continue;
        };

        let result = exec_program(
            session,
            "journalctl",
            &[
                "-u",
                unit.as_str(),
                "--after-cursor",
                &current_cursor,
                "-n",
                "500",
                "--no-pager",
                "-o",
                "short-iso",
                "--show-cursor",
            ],
        )
        .await?;

        if result.exit_code != 0 {
            return Err(classify_journal_failure(&result));
        }

        let (entries, next_cursor) = split_journal_output(&result.stdout);
        if !entries.is_empty() {
            emit(XrayLogStreamEvent::Append {
                generation,
                kind,
                entries,
            });
        }
        if let Some(next) = next_cursor {
            cursor = Some(next);
        }
    }

    Ok(())
}

async fn file_size<S: SshSession + Sync>(session: &S, path: &str) -> XrayLogResult<u64> {
    let result = exec_program(session, "stat", &["-c", "%s", "--", path]).await?;
    if result.exit_code != 0 {
        return Err(map_remote_failure(
            XrayLogErrorKind::RemoteReadFailed,
            &result,
            "Failed to stat log file.",
        ));
    }
    let text = String::from_utf8_lossy(&result.stdout).trim().to_owned();
    text.parse::<u64>().map_err(|_| {
        XrayLogError::new(
            XrayLogErrorKind::RemoteReadFailed,
            "Unexpected stat output for log file size.",
        )
    })
}

async fn read_journal_cursor<S: SshSession + Sync>(
    session: &S,
    unit: &ServiceName,
) -> XrayLogResult<Option<String>> {
    let result = exec_program(
        session,
        "journalctl",
        &[
            "-u",
            unit.as_str(),
            "-n",
            "1",
            "--no-pager",
            "-o",
            "cat",
            "--show-cursor",
            "-q",
        ],
    )
    .await?;
    if result.exit_code != 0 {
        return Err(classify_journal_failure(&result));
    }
    Ok(extract_cursor(&result.stdout))
}

fn entries_from_bytes(bytes: &[u8]) -> Vec<XrayLogEntry> {
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .map(|line| XrayLogEntry::plain(line.to_owned()))
        .collect()
}

fn split_journal_output(bytes: &[u8]) -> (Vec<XrayLogEntry>, Option<String>) {
    let text = String::from_utf8_lossy(bytes);
    let mut entries = Vec::new();
    let mut cursor = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("-- cursor: ") {
            cursor = Some(rest.trim().to_owned());
            continue;
        }
        if line.starts_with("-- No entries") {
            continue;
        }
        entries.push(XrayLogEntry::plain(line.to_owned()));
    }
    (entries, cursor)
}

fn extract_cursor(bytes: &[u8]) -> Option<String> {
    split_journal_output(bytes).1
}

async fn exec_test<S: SshSession + Sync>(
    session: &S,
    flag: &str,
    path: &str,
) -> XrayLogResult<bool> {
    let result = exec_program(session, "test", &[flag, path]).await?;
    Ok(result.exit_code == 0)
}

async fn exec_program<S: SshSession + Sync>(
    session: &S,
    program: &str,
    args: &[&str],
) -> XrayLogResult<ExecResult> {
    let command = RemoteCommand::new(
        program,
        args.iter().map(|arg| (*arg).to_owned()).collect(),
    )
    .map_err(|error| {
        XrayLogError::new(
            XrayLogErrorKind::RemoteReadFailed,
            sanitize_detail(error.message()),
        )
    })?;

    session.exec(&command).await.map_err(|error| {
        warn!(
            target: "xray_logs",
            detail = %sanitize_detail(error.message()),
            "remote log SSH error"
        );
        XrayLogError::new(
            XrayLogErrorKind::RemoteReadFailed,
            user_message_see_log("SSH command failed while reading Xray logs."),
        )
    })
}

fn map_remote_failure(
    kind: XrayLogErrorKind,
    result: &ExecResult,
    summary: &str,
) -> XrayLogError {
    let stderr = String::from_utf8_lossy(&result.stderr);
    let detail = sanitize_detail(stderr.trim());
    warn!(
        target: "xray_logs",
        exit_code = result.exit_code,
        detail = %detail,
        "remote log command failed"
    );
    XrayLogError::new(kind, user_message_see_log(summary))
}

fn classify_journal_failure(result: &ExecResult) -> XrayLogError {
    let stderr = String::from_utf8_lossy(&result.stderr).to_ascii_lowercase();
    let kind = if stderr.contains("permission") || stderr.contains("access denied") {
        XrayLogErrorKind::PermissionDenied
    } else if stderr.contains("not found") || stderr.contains("could not find unit") {
        XrayLogErrorKind::ServiceNotFound
    } else {
        XrayLogErrorKind::JournalUnavailable
    };
    map_remote_failure(kind, result, "Failed to read systemd journal.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::ServiceState;
    use crate::xray::config::{SourcedSection, XrayConfigSections};
    use crate::xray::{ConfigSource, DiscoveryWarning};
    use feldjaeger_ssh::{ConnectionProfile, SshError, SshResult};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockSession {
        profile: ConnectionProfile,
        exec_results: Arc<Mutex<HashMap<String, ExecResult>>>,
        exec_calls: Arc<Mutex<Vec<String>>>,
    }

    impl MockSession {
        fn new() -> Self {
            Self {
                profile: ConnectionProfile::new("example.test", 22, "root"),
                exec_results: Arc::new(Mutex::new(HashMap::new())),
                exec_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn with_result(self, key: &str, result: ExecResult) -> Self {
            self.exec_results
                .lock()
                .expect("lock")
                .insert(key.to_owned(), result);
            self
        }

        fn key(program: &str, args: &[String]) -> String {
            format!("{program} {}", args.join(" "))
        }
    }

    impl SshSession for MockSession {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        async fn read_file(&self, _path: &RemotePath) -> SshResult<Vec<u8>> {
            Err(SshError::new("not supported"))
        }

        async fn write_file(&self, _path: &RemotePath, _contents: &[u8]) -> SshResult<()> {
            Err(SshError::new("not supported"))
        }

        async fn write_file_atomic(&self, _path: &RemotePath, _contents: &[u8]) -> SshResult<()> {
            Err(SshError::new("not supported"))
        }

        async fn rename_file(&self, _from: &RemotePath, _to: &RemotePath) -> SshResult<()> {
            Err(SshError::new("not supported"))
        }

        async fn remove_file(&self, _path: &RemotePath) -> SshResult<()> {
            Err(SshError::new("not supported"))
        }

        async fn path_is_file(&self, _path: &RemotePath) -> SshResult<bool> {
            Ok(true)
        }

        async fn exec(&self, command: &RemoteCommand) -> SshResult<ExecResult> {
            let key = Self::key(command.program(), command.args());
            self.exec_calls.lock().expect("lock").push(key.clone());
            let map = self.exec_results.lock().expect("lock");
            Ok(map.get(&key).cloned().unwrap_or_else(|| {
                ExecResult::new(Vec::new(), format!("no mock for {key}").into_bytes(), 1)
            }))
        }

    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
        let _ = stdin;
        self.exec(command)
    }

        async fn disconnect(self) -> SshResult<()> {
            Ok(())
        }
    }

    fn installation(service: Option<&str>, init: InitSystemKind) -> XrayInstallation {
        XrayInstallation {
            operating_system: "Debian".into(),
            architecture: "x86_64".into(),
            init_system: init,
            binary_path: RemotePath::new("/usr/local/bin/xray").ok(),
            version: Some("1.8.0".into()),
            service_name: service.map(str::to_owned),
            service_state: Some(ServiceState::Running),
            exec_start: None,
            config_source: ConfigSource::SingleFile(
                RemotePath::new("/etc/xray/config.json").expect("path"),
            ),
            config_readable: true,
            config_files: Vec::new(),
            discovery_warnings: Vec::<DiscoveryWarning>::new(),
        }
    }

    fn editable_with_log(value: Value) -> EditableXrayConfig {
        let root = json!({ "log": value.clone() });
        let mut sections = XrayConfigSections::empty();
        sections.set_log(Some(SourcedSection::new(
            "/etc/xray/config.json",
            value,
        )));
        EditableXrayConfig::from_single_file("/etc/xray/config.json", root, sections)
    }

    #[test]
    fn resolves_access_and_error_from_config() {
        let service = XrayLogService::new();
        let editable = editable_with_log(json!({
            "access": "/var/log/xray/access.log",
            "error": "none"
        }));
        let sources = service.resolve_sources(
            Some(&installation(Some("xray.service"), InitSystemKind::Systemd)),
            Some(&editable),
        );
        assert_eq!(sources[0].kind, XrayLogSourceKind::AccessFile);
        assert_eq!(sources[0].source, "/var/log/xray/access.log");
        assert_eq!(sources[0].availability, XrayLogAvailability::Unknown);
        assert_eq!(sources[1].availability, XrayLogAvailability::Disabled);
        assert_eq!(sources[2].source, "xray.service");
    }

    #[test]
    fn disabled_and_stdout_sources() {
        let service = XrayLogService::new();
        let editable = editable_with_log(json!({
            "access": "none",
            "error": ""
        }));
        let sources = service.resolve_sources(
            Some(&installation(Some("xray.service"), InitSystemKind::Systemd)),
            Some(&editable),
        );
        assert_eq!(sources[0].availability, XrayLogAvailability::Disabled);
        assert_eq!(sources[1].availability, XrayLogAvailability::Unsupported);
        assert!(sources[1].warnings.iter().any(|w| w.contains("stdout")));
    }

    #[test]
    fn journal_unsupported_for_openrc() {
        let service = XrayLogService::new();
        let sources = service.resolve_sources(
            Some(&installation(Some("xray"), InitSystemKind::OpenRC)),
            None,
        );
        assert_eq!(sources[2].availability, XrayLogAvailability::Unsupported);
    }

    #[test]
    fn journal_missing_without_service_name() {
        let service = XrayLogService::new();
        let sources =
            service.resolve_sources(Some(&installation(None, InitSystemKind::Systemd)), None);
        assert_eq!(sources[2].availability, XrayLogAvailability::Missing);
    }

    #[tokio::test]
    async fn reads_file_tail_with_limit() {
        let path = "/var/log/xray/access.log";
        let session = MockSession::new()
            .with_result(
                &format!("test -e {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("test -f {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("test -r {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("tail -n 100 -- {path}"),
                ExecResult::new(b"line-a\nline-b\n".to_vec(), Vec::new(), 0),
            );

        let editable = editable_with_log(json!({ "access": path }));
        let service = XrayLogService::new();
        let entries = service
            .read_tail(
                &session,
                &installation(Some("xray.service"), InitSystemKind::Systemd),
                Some(&editable),
                XrayLogSourceKind::AccessFile,
                XrayLogLineLimit::Hundred,
            )
            .await
            .expect("read");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "line-a");
    }

    #[tokio::test]
    async fn missing_file_classified() {
        let path = "/var/log/xray/missing.log";
        let session = MockSession::new().with_result(
            &format!("test -e {path}"),
            ExecResult::new(Vec::new(), Vec::new(), 1),
        );
        let editable = editable_with_log(json!({ "error": path }));
        let err = XrayLogService::new()
            .read_tail(
                &session,
                &installation(Some("xray.service"), InitSystemKind::Systemd),
                Some(&editable),
                XrayLogSourceKind::ErrorFile,
                XrayLogLineLimit::TwoHundred,
            )
            .await
            .expect_err("missing");
        assert_eq!(err.kind, XrayLogErrorKind::LogFileMissing);
    }

    #[tokio::test]
    async fn permission_denied_classified() {
        let path = "/var/log/xray/error.log";
        let session = MockSession::new()
            .with_result(
                &format!("test -e {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("test -f {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("test -r {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 1),
            );
        let editable = editable_with_log(json!({ "error": path }));
        let err = XrayLogService::new()
            .read_tail(
                &session,
                &installation(Some("xray.service"), InitSystemKind::Systemd),
                Some(&editable),
                XrayLogSourceKind::ErrorFile,
                XrayLogLineLimit::TwoHundred,
            )
            .await
            .expect_err("perm");
        assert_eq!(err.kind, XrayLogErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn journal_tail_uses_discovery_unit() {
        let session = MockSession::new().with_result(
            "journalctl -u custom-xray.service -n 200 --no-pager -o short-iso --show-cursor",
            ExecResult::new(
                b"2024-01-01T00:00:00+00:00 host xray[1]: hello\n-- cursor: abc\n".to_vec(),
                Vec::new(),
                0,
            ),
        );
        let entries = XrayLogService::new()
            .read_tail(
                &session,
                &installation(Some("custom-xray.service"), InitSystemKind::Systemd),
                None,
                XrayLogSourceKind::Journal,
                XrayLogLineLimit::TwoHundred,
            )
            .await
            .expect("journal");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].message.contains("hello"));
        assert!(!session
            .exec_calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.contains("xray.service") && !c.contains("custom-xray.service")));
    }

    #[tokio::test]
    async fn empty_log_is_ok() {
        let path = "/var/log/xray/access.log";
        let session = MockSession::new()
            .with_result(
                &format!("test -e {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("test -f {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("test -r {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("tail -n 200 -- {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            );
        let editable = editable_with_log(json!({ "access": path }));
        let entries = XrayLogService::new()
            .read_tail(
                &session,
                &installation(Some("xray.service"), InitSystemKind::Systemd),
                Some(&editable),
                XrayLogSourceKind::AccessFile,
                XrayLogLineLimit::TwoHundred,
            )
            .await
            .expect("empty");
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn unknown_line_format_kept_as_text() {
        let path = "/var/log/xray/error.log";
        let session = MockSession::new()
            .with_result(
                &format!("test -e {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("test -f {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("test -r {path}"),
                ExecResult::new(Vec::new(), Vec::new(), 0),
            )
            .with_result(
                &format!("tail -n 200 -- {path}"),
                ExecResult::new(b"??? totally unknown !!!\n".to_vec(), Vec::new(), 0),
            );
        let editable = editable_with_log(json!({ "error": path }));
        let entries = XrayLogService::new()
            .read_tail(
                &session,
                &installation(Some("xray.service"), InitSystemKind::Systemd),
                Some(&editable),
                XrayLogSourceKind::ErrorFile,
                XrayLogLineLimit::TwoHundred,
            )
            .await
            .expect("read");
        assert_eq!(entries[0].message, "??? totally unknown !!!");
        assert!(entries[0].timestamp.is_none());
        assert!(entries[0].level.is_none());
    }

    #[test]
    fn remote_log_body_not_in_app_error_detail_on_tail_failure() {
        // map_remote_failure must not embed stdout bodies; only sanitized stderr summary.
        let result = ExecResult::new(
            b"SECRET_IP 1.2.3.4 appeared here\n".to_vec(),
            b"tail: cannot open\n".to_vec(),
            1,
        );
        let err = map_remote_failure(
            XrayLogErrorKind::RemoteReadFailed,
            &result,
            "Failed to read log file tail.",
        );
        assert!(!err.detail.contains("1.2.3.4"));
        assert!(!err.detail.contains("SECRET_IP"));
    }
}
