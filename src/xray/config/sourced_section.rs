//! Section value paired with its originating configuration file.

/// A typed configuration fragment together with the file it was read from.
///
/// Future write-back uses [`source_file`](Self::source_file) to decide which
/// remote (or local) path should receive updates for this fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcedSection<T> {
    source_file: String,
    value: T,
}

impl<T> SourcedSection<T> {
    /// Creates a sourced section.
    pub fn new(source_file: impl Into<String>, value: T) -> Self {
        Self {
            source_file: source_file.into(),
            value,
        }
    }

    /// Absolute or relative path of the file that provided this value.
    pub fn source_file(&self) -> &str {
        &self.source_file
    }

    /// Borrowed section value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Mutable section value (for future editors; read path leaves it untouched).
    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Consumes the wrapper and returns the inner value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Maps the inner value while preserving the source file.
    pub fn map<U, F>(self, f: F) -> SourcedSection<U>
    where
        F: FnOnce(T) -> U,
    {
        SourcedSection {
            source_file: self.source_file,
            value: f(self.value),
        }
    }
}
