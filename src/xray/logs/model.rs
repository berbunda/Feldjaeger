//! Shared types for read-only Xray runtime log viewing.

/// Kind of Xray log source exposed to the GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrayLogSourceKind {
    /// Access log destination from the Xray `log.access` field.
    AccessFile,
    /// Error log destination from the Xray `log.error` field.
    ErrorFile,
    /// systemd journal for the discovered Xray unit.
    Journal,
}

impl XrayLogSourceKind {
    /// Short display name for selectors and source info.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::AccessFile => "Access Log",
            Self::ErrorFile => "Error Log",
            Self::Journal => "System Journal",
        }
    }

    /// Type label for the source-info panel.
    pub fn type_label(self) -> &'static str {
        match self {
            Self::AccessFile => "Access log",
            Self::ErrorFile => "Error log",
            Self::Journal => "System journal",
        }
    }
}

/// Availability of a resolved log source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrayLogAvailability {
    /// Source can be read.
    Available,
    /// Logging disabled (`none` / `loglevel: none`).
    Disabled,
    /// Configured file path does not exist.
    Missing,
    /// File or journal exists but is not readable.
    PermissionDenied,
    /// Destination is stdout/stderr/unknown or init system unsupported.
    Unsupported,
    /// Destination not yet resolved (config not loaded).
    Unknown,
}

impl XrayLogAvailability {
    /// Short status label for the GUI.
    pub fn label(self) -> &'static str {
        match self {
            Self::Available => "Available",
            Self::Disabled => "Disabled",
            Self::Missing => "Missing",
            Self::PermissionDenied => "Permission denied",
            Self::Unsupported => "Unsupported",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns `true` when the source may be opened for reading.
    pub fn is_readable(self) -> bool {
        matches!(self, Self::Available | Self::Unknown)
    }
}

/// Selectable line-count limits for initial / refresh reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrayLogLineLimit {
    /// Last 100 lines.
    Hundred = 100,
    /// Last 200 lines (default).
    TwoHundred = 200,
    /// Last 500 lines.
    FiveHundred = 500,
    /// Last 1000 lines.
    Thousand = 1000,
}

impl XrayLogLineLimit {
    /// All selectable limits in display order.
    pub const ALL: &'static [Self] = &[
        Self::Hundred,
        Self::TwoHundred,
        Self::FiveHundred,
        Self::Thousand,
    ];

    /// Default limit for first read.
    pub const DEFAULT: Self = Self::TwoHundred;

    /// Numeric line count passed to remote tools.
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Label for the limit selector.
    pub fn label(self) -> String {
        self.as_u32().to_string()
    }
}

impl Default for XrayLogLineLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Summary of one log source for selectors and source-info panels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayLogSourceSummary {
    /// Source kind.
    pub kind: XrayLogSourceKind,
    /// Human-readable name (`Access Log`, …).
    pub display_name: String,
    /// Path or systemd unit name shown to the user.
    pub source: String,
    /// Current availability.
    pub availability: XrayLogAvailability,
    /// Non-fatal warnings for this source.
    pub warnings: Vec<String>,
}

/// One display line from a remote log stream.
///
/// Access and error logs may omit timestamps or levels; unknown lines stay
/// visible as plain text in [`message`](Self::message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayLogEntry {
    /// Optional timestamp when the source provides one.
    pub timestamp: Option<String>,
    /// Optional severity when the source provides one.
    pub level: Option<String>,
    /// Full line text (always present).
    pub message: String,
}

impl XrayLogEntry {
    /// Builds an entry that keeps the entire line as the message.
    pub fn plain(message: impl Into<String>) -> Self {
        Self {
            timestamp: None,
            level: None,
            message: message.into(),
        }
    }

    /// Text used for display and local search.
    pub fn display_text(&self) -> &str {
        &self.message
    }
}

/// How an access/error field resolves before remote probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrayLogDestination {
    /// Explicit file path from configuration.
    File {
        /// Absolute remote path.
        path: String,
    },
    /// Empty / unspecified / `stdout` — Xray writes to standard output.
    Stdout,
    /// Explicit `stderr` value (non-standard but observed).
    Stderr,
    /// `none` or forced off by `loglevel: none`.
    Disabled,
    /// Relative path, empty-after-trim edge cases, or unknown token.
    Unsupported {
        /// Raw configured value for diagnostics.
        raw: String,
    },
}

impl XrayLogDestination {
    /// Value shown in the Path / service field before probing.
    pub fn display_source(&self) -> String {
        match self {
            Self::File { path } => path.clone(),
            Self::Stdout => "stdout".to_owned(),
            Self::Stderr => "stderr".to_owned(),
            Self::Disabled => "none".to_owned(),
            Self::Unsupported { raw } => raw.clone(),
        }
    }
}
