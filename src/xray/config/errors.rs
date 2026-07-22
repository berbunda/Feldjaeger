//! Typed errors produced while parsing Xray configuration.

use std::fmt;

/// Classification of configuration parse problems.
///
/// Soft issues (duplicate tags, invalid optional sections) do not abort parsing;
/// the outcome remains usable with [`super::ConfigParseOutcome::is_partial`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigErrorKind {
    /// Root document or a directory fragment is not valid JSON.
    InvalidJson,
    /// A required or expected section is absent.
    MissingSection,
    /// A top-level key is not among the known section names (still preserved).
    UnknownSection,
    /// An inbound entry could not be interpreted as an object.
    InvalidInbound,
    /// An outbound entry could not be interpreted as an object.
    InvalidOutbound,
    /// Document shape is unsupported (for example a non-object root).
    UnsupportedStructure,
    /// Two or more inbounds or outbounds share the same non-empty tag.
    DuplicateTags,
}

impl ConfigErrorKind {
    /// Stable machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid json",
            Self::MissingSection => "missing section",
            Self::UnknownSection => "unknown section",
            Self::InvalidInbound => "invalid inbound",
            Self::InvalidOutbound => "invalid outbound",
            Self::UnsupportedStructure => "unsupported structure",
            Self::DuplicateTags => "duplicate tags",
        }
    }

    /// Returns `true` when this kind indicates an unusable JSON document.
    ///
    /// Soft structural problems on individual sections use
    /// [`UnsupportedStructure`](Self::UnsupportedStructure) but are not fatal
    /// when other sections were recovered.
    pub fn is_fatal(self) -> bool {
        matches!(self, Self::InvalidJson)
    }
}

impl fmt::Display for ConfigErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A single parse problem with optional source-file context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    kind: ConfigErrorKind,
    message: String,
    source_file: Option<String>,
    section: Option<String>,
}

impl ConfigError {
    /// Creates an error of the given kind.
    pub fn new(kind: ConfigErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source_file: None,
            section: None,
        }
    }

    /// Attaches the configuration file path related to this error.
    pub fn with_source_file(mut self, source_file: impl Into<String>) -> Self {
        self.source_file = Some(source_file.into());
        self
    }

    /// Attaches the top-level section name related to this error.
    pub fn with_section(mut self, section: impl Into<String>) -> Self {
        self.section = Some(section.into());
        self
    }

    /// Error classification.
    pub fn kind(&self) -> ConfigErrorKind {
        self.kind
    }

    /// Human-readable detail.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Source file path, when known.
    pub fn source_file(&self) -> Option<&str> {
        self.source_file.as_deref()
    }

    /// Section name, when known.
    pub fn section(&self) -> Option<&str> {
        self.section.as_deref()
    }

    /// Returns `true` when this error alone makes a document unusable.
    pub fn is_fatal(&self) -> bool {
        self.kind.is_fatal()
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)?;
        if let Some(source_file) = &self.source_file {
            write!(f, " (file: {source_file})")?;
        }
        if let Some(section) = &self.section {
            write!(f, " (section: {section})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}
