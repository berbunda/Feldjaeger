//! Application logging for Feldjäger.
//!
//! Initializes a `tracing` subscriber that writes to a platform log file
//! (`feldjaeger.log`). Secrets must never appear in log messages; use
//! [`redact::sanitize_detail`] before logging external error strings.

mod format;
pub mod redact;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing::info;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

use crate::error::{AppError, AppResult};
use crate::storage::{AppPaths, LOG_FILE_NAME};

use self::format::FeldjaegerFormat;

/// Where application logs are written after initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogDestination {
    /// Primary platform data-local log file.
    PlatformFile(PathBuf),
    /// Fallback: stderr plus a log file next to the executable.
    ExecutableDir {
        /// Fallback log file path.
        file: PathBuf,
    },
    /// Last-resort destination when no file could be opened.
    StderrOnly,
}

impl LogDestination {
    /// Returns the log file path when one is in use.
    pub fn file_path(&self) -> Option<&Path> {
        match self {
            Self::PlatformFile(path) | Self::ExecutableDir { file: path } => Some(path),
            Self::StderrOnly => None,
        }
    }

    /// Human-readable description for startup diagnostics.
    pub fn description(&self) -> String {
        match self {
            Self::PlatformFile(path) => format!("file {}", path.display()),
            Self::ExecutableDir { file } => {
                format!("stderr and executable-dir file {}", file.display())
            }
            Self::StderrOnly => "stderr only".to_owned(),
        }
    }
}

/// Handle that keeps the non-blocking log writer alive for the process lifetime.
#[derive(Debug)]
pub struct LoggingHandle {
    destination: LogDestination,
    _guard: Option<WorkerGuard>,
}

impl LoggingHandle {
    /// Returns the active log destination.
    pub fn destination(&self) -> &LogDestination {
        &self.destination
    }
}

static LOGGING_INITIALIZED: OnceLock<()> = OnceLock::new();

/// Initializes application logging using the platform log directory.
///
/// Fallback order when the primary file cannot be created:
/// 1. stderr + `feldjaeger.log` next to the executable
/// 2. stderr only
///
/// Safe to call once per process. Subsequent calls return an error.
pub fn init() -> AppResult<LoggingHandle> {
    let primary = match AppPaths::resolve() {
        Ok(paths) => paths.log_file(),
        Err(_) => {
            // Platform dirs unavailable — skip straight to executable-dir / stderr.
            executable_dir_log_file().unwrap_or_else(|| PathBuf::from(LOG_FILE_NAME))
        }
    };
    init_with_primary_path(primary)
}

/// Initializes logging with an explicit primary log file path (tests / custom roots).
pub fn init_with_primary_path(primary_log_file: PathBuf) -> AppResult<LoggingHandle> {
    if LOGGING_INITIALIZED.set(()).is_err() {
        return Err(AppError::new("application logging is already initialized"));
    }

    let (writer, destination, guard) = open_log_writer(&primary_log_file)?;
    install_subscriber(writer)?;

    let handle = LoggingHandle {
        destination,
        _guard: guard,
    };

    log_startup(&handle);
    Ok(handle)
}

/// Returns the default platform log file path without initializing logging.
pub fn default_log_file() -> AppResult<PathBuf> {
    Ok(AppPaths::resolve()?.log_file())
}

/// Returns the default platform log directory without initializing logging.
pub fn default_log_dir() -> AppResult<PathBuf> {
    Ok(AppPaths::resolve()?.log_dir().to_path_buf())
}

/// Resolves the primary log destination without installing a subscriber.
///
/// Used by tests to verify fallback selection logic.
pub fn resolve_destination(primary_log_file: &Path) -> LogDestination {
    if can_create_log_file(primary_log_file) {
        return LogDestination::PlatformFile(primary_log_file.to_path_buf());
    }
    if let Some(fallback) = executable_dir_log_file()
        && can_create_log_file(&fallback)
    {
        return LogDestination::ExecutableDir { file: fallback };
    }
    LogDestination::StderrOnly
}

/// Formats a single log line the same way the subscriber does (for tests).
pub fn format_log_line_for_test(level: &str, module: &str, message: &str) -> String {
    format::format_line_for_test(level, module, message)
}

/// Writes sample events through a temporary subscriber and returns the log file contents.
///
/// Intended for integration-style unit tests. Does not touch the process-global
/// once-lock used by [`init`].
pub fn write_sample_log_file(log_dir: &Path) -> AppResult<PathBuf> {
    fs::create_dir_all(log_dir).map_err(|error| {
        AppError::new(format!(
            "failed to create log directory {}: {error}",
            log_dir.display()
        ))
    })?;
    let log_file = log_dir.join(LOG_FILE_NAME);
    let file = open_append_file(&log_file).map_err(|error| {
        AppError::new(format!(
            "failed to open log file {}: {error}",
            log_file.display()
        ))
    })?;

    let (non_blocking, guard) = tracing_appender::non_blocking(file);
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .event_format(FeldjaegerFormat)
        .with_writer(non_blocking)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        tracing::error!(target: "app", "sample error event");
        tracing::warn!(target: "app", "sample warn event");
        tracing::info!(target: "ssh", "sample info event");
        tracing::debug!(target: "discovery", "sample debug event");
    });
    drop(guard);

    Ok(log_file)
}

fn open_log_writer(
    primary_log_file: &Path,
) -> AppResult<(Box<dyn Write + Send>, LogDestination, Option<WorkerGuard>)> {
    match try_open_file_writer(primary_log_file) {
        Ok((non_blocking, guard)) => Ok((
            Box::new(non_blocking),
            LogDestination::PlatformFile(primary_log_file.to_path_buf()),
            Some(guard),
        )),
        Err(_primary_error) => match executable_dir_log_file() {
            Some(fallback_file) => match try_open_file_writer(&fallback_file) {
                Ok((non_blocking, guard)) => {
                    let tee = TeeWriter {
                        file: non_blocking,
                        stderr: io::stderr(),
                    };
                    Ok((
                        Box::new(tee),
                        LogDestination::ExecutableDir {
                            file: fallback_file,
                        },
                        Some(guard),
                    ))
                }
                Err(_) => Ok((Box::new(io::stderr()), LogDestination::StderrOnly, None)),
            },
            None => Ok((Box::new(io::stderr()), LogDestination::StderrOnly, None)),
        },
    }
}

fn try_open_file_writer(path: &Path) -> io::Result<(NonBlocking, WorkerGuard)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = open_append_file(path)?;
    Ok(tracing_appender::non_blocking(file))
}

fn open_append_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn executable_dir_log_file() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.to_path_buf();
    Some(dir.join(LOG_FILE_NAME))
}

fn install_subscriber(writer: Box<dyn Write + Send>) -> AppResult<()> {
    let filter = env_filter();
    let make_writer = SharedWriter::new(writer);
    let subscriber = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .event_format(FeldjaegerFormat)
        .with_writer(make_writer)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|error| AppError::new(format!("failed to install tracing subscriber: {error}")))
}

fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

fn log_startup(handle: &LoggingHandle) {
    info!(
        target: "app",
        version = env!("CARGO_PKG_VERSION"),
        destination = %handle.destination().description(),
        "application started"
    );
}

fn can_create_log_file(path: &Path) -> bool {
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    open_append_file(path).is_ok()
}

/// Thread-safe maker that clones a shared writer handle for each event.
#[derive(Clone)]
struct SharedWriter {
    inner: std::sync::Arc<std::sync::Mutex<Box<dyn Write + Send>>>,
}

impl SharedWriter {
    fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(writer)),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedWriterGuard {
            inner: std::sync::Arc::clone(&self.inner),
        }
    }
}

struct SharedWriterGuard {
    inner: std::sync::Arc<std::sync::Mutex<Box<dyn Write + Send>>>,
}

impl Write for SharedWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("log writer lock poisoned"))?;
        guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("log writer lock poisoned"))?;
        guard.flush()
    }
}

/// Writes each log line to both a file writer and stderr.
struct TeeWriter<F, S> {
    file: F,
    stderr: S,
}

impl<F: Write, S: Write> Write for TeeWriter<F, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let file_result = self.file.write(buf);
        let stderr_result = self.stderr.write(buf);
        match (file_result, stderr_result) {
            (Ok(n), Ok(_)) => Ok(n),
            (Ok(n), Err(_)) => Ok(n),
            (Err(_), Ok(n)) => Ok(n),
            (Err(error), Err(_)) => Err(error),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let file_result = self.file.flush();
        let stderr_result = self.stderr.flush();
        file_result.or(stderr_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "feldjaeger-logging-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn default_log_paths_include_feldjaeger_and_log_name() {
        let dir = default_log_dir().expect("log dir");
        let file = default_log_file().expect("log file");
        let dir_s = dir.to_string_lossy().to_ascii_lowercase();
        assert!(dir_s.contains("feldjaeger"));
        assert!(dir_s.contains("logs"));
        assert_eq!(
            file.file_name().and_then(|n| n.to_str()),
            Some(LOG_FILE_NAME)
        );
    }

    #[test]
    fn resolve_destination_prefers_writable_primary() {
        let dir = unique_temp_dir("primary");
        let file = dir.join(LOG_FILE_NAME);
        let destination = resolve_destination(&file);
        assert_eq!(destination, LogDestination::PlatformFile(file));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn format_contains_timestamp_level_module_message() {
        let line = format_log_line_for_test("INFO", "ssh", "Connected to server");
        assert!(line.contains(" INFO "));
        assert!(line.contains(" ssh "));
        assert!(line.contains("Connected to server"));
        let date = line.split_whitespace().next().expect("date");
        assert_eq!(date.len(), 10);
        assert!(date.contains('-'));
    }

    #[test]
    fn format_supports_all_levels() {
        for level in ["ERROR", "WARN", "INFO", "DEBUG"] {
            let line = format_log_line_for_test(level, "app", "message");
            assert!(line.contains(&format!(" {level} ")), "{line}");
        }
    }

    #[test]
    fn write_sample_creates_log_file_with_levels() {
        let dir = unique_temp_dir("sample");
        let file = write_sample_log_file(&dir).expect("write sample");
        assert!(file.exists());
        let contents = fs::read_to_string(&file).expect("read");
        assert!(contents.contains(" ERROR "));
        assert!(contents.contains(" WARN "));
        assert!(contents.contains(" INFO "));
        assert!(contents.contains(" DEBUG "));
        assert!(contents.contains("sample info event"));
        let _ = fs::remove_dir_all(dir);
    }
}
