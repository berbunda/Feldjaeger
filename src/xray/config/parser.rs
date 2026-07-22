//! Lossless Xray configuration parser.
//!
//! Builds [`XrayConfigSections`] from a single JSON file or a config directory.
//! Does not rewrite JSON, reorder arrays, or drop unknown fields during parse.
//! Write-back goes through [`super::editable::EditableXrayConfig`] and
//! [`super::modify`] so only the affected source file is serialized.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use super::errors::{ConfigError, ConfigErrorKind};
use super::sections::XrayConfigSections;
use super::sourced_section::SourcedSection;

/// Outcome of a (possibly partial) configuration parse.
///
/// Fatal problems such as invalid JSON for a whole document are reported in
/// [`errors`](Self::errors). Soft problems (corrupt optional sections, duplicate
/// tags) set [`partial`](Self::is_partial) while still returning usable sections.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigParseOutcome {
    sections: XrayConfigSections,
    errors: Vec<ConfigError>,
    partial: bool,
}

impl ConfigParseOutcome {
    fn new(sections: XrayConfigSections, errors: Vec<ConfigError>) -> Self {
        // Partial = recovered usable data despite one or more problems.
        let partial = !sections.is_empty() && !errors.is_empty();
        Self {
            sections,
            errors,
            partial,
        }
    }

    fn failed(errors: Vec<ConfigError>) -> Self {
        Self {
            sections: XrayConfigSections::empty(),
            errors,
            partial: false,
        }
    }

    /// Parsed sections (may be incomplete when [`is_partial`](Self::is_partial)).
    pub fn sections(&self) -> &XrayConfigSections {
        &self.sections
    }

    /// Consumes the outcome and returns the sections.
    pub fn into_sections(self) -> XrayConfigSections {
        self.sections
    }

    /// Collected parse errors (fatal and soft).
    pub fn errors(&self) -> &[ConfigError] {
        &self.errors
    }

    /// Returns `true` when some sections were recovered despite errors.
    pub fn is_partial(&self) -> bool {
        self.partial
    }

    /// Returns `true` when there are no errors.
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns `true` when errors left no usable sections.
    pub fn has_fatal_errors(&self) -> bool {
        self.sections.is_empty() && !self.errors.is_empty()
    }
}

/// Parses Xray JSON configuration into [`XrayConfigSections`].
///
/// Unknown protocols and unknown top-level sections never abort parsing; they
/// are preserved in the model for future GUI / write-back support.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XrayConfigParser;

impl XrayConfigParser {
    /// Creates a new parser instance.
    pub fn new() -> Self {
        Self
    }

    /// Parses a single configuration file from UTF-8 JSON text.
    pub fn parse_single_file(&self, source_file: &str, input: &str) -> ConfigParseOutcome {
        let value = match serde_json::from_str::<Value>(input) {
            Ok(value) => value,
            Err(error) => {
                return ConfigParseOutcome::failed(vec![
                    ConfigError::new(
                        ConfigErrorKind::InvalidJson,
                        format!("invalid Xray JSON: {error}"),
                    )
                    .with_source_file(source_file),
                ]);
            }
        };

        let mut sections = XrayConfigSections::empty();
        let mut errors = Vec::new();
        self.merge_object(source_file, value, &mut sections, &mut errors);
        self.check_duplicate_tags(&sections, &mut errors);
        ConfigParseOutcome::new(sections, errors)
    }

    /// Parses a single configuration file from bytes.
    pub fn parse_single_file_bytes(&self, source_file: &str, input: &[u8]) -> ConfigParseOutcome {
        match std::str::from_utf8(input) {
            Ok(text) => self.parse_single_file(source_file, text),
            Err(error) => ConfigParseOutcome::failed(vec![
                ConfigError::new(
                    ConfigErrorKind::InvalidJson,
                    format!("Xray config is not valid UTF-8: {error}"),
                )
                .with_source_file(source_file),
            ]),
        }
    }

    /// Parses an in-memory JSON string without a real path (source = `"<memory>"`).
    pub fn parse_str(&self, input: &str) -> ConfigParseOutcome {
        self.parse_single_file("<memory>", input)
    }

    /// Parses in-memory JSON bytes without a real path.
    pub fn parse_bytes(&self, input: &[u8]) -> ConfigParseOutcome {
        self.parse_single_file_bytes("<memory>", input)
    }

    /// Parses a config directory from `(source_file, contents)` pairs.
    ///
    /// Files are processed in ascending path order (Xray confdir convention).
    /// Object sections from later files override earlier ones; `inbounds` /
    /// `outbounds` arrays are concatenated in file and entry order.
    pub fn parse_directory<I, S, C>(&self, files: I) -> ConfigParseOutcome
    where
        I: IntoIterator<Item = (S, C)>,
        S: AsRef<str>,
        C: AsRef<str>,
    {
        let mut entries: Vec<(String, String)> = files
            .into_iter()
            .map(|(path, contents)| (path.as_ref().to_owned(), contents.as_ref().to_owned()))
            .collect();

        entries.sort_by(|a, b| a.0.cmp(&b.0));

        if entries.is_empty() {
            return ConfigParseOutcome::new(XrayConfigSections::empty(), Vec::new());
        }

        let mut sections = XrayConfigSections::empty();
        let mut errors = Vec::new();
        let mut parsed_any_object = false;

        for (source_file, contents) in &entries {
            let value = match serde_json::from_str::<Value>(contents) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(
                        ConfigError::new(
                            ConfigErrorKind::InvalidJson,
                            format!("invalid Xray JSON: {error}"),
                        )
                        .with_source_file(source_file.as_str()),
                    );
                    continue;
                }
            };

            let error_count_before = errors.len();
            self.merge_object(source_file, value, &mut sections, &mut errors);
            let rejected_root = errors[error_count_before..]
                .iter()
                .any(|error| error.kind() == ConfigErrorKind::UnsupportedStructure);
            if !rejected_root {
                parsed_any_object = true;
            }
        }

        self.check_duplicate_tags(&sections, &mut errors);

        if !parsed_any_object && sections.is_empty() {
            return ConfigParseOutcome::failed(errors);
        }

        ConfigParseOutcome::new(sections, errors)
    }

    /// Loads a local single file from disk (tests / tooling).
    pub fn parse_path(&self, path: &Path) -> ConfigParseOutcome {
        let source_file = path.to_string_lossy().into_owned();
        match std::fs::read_to_string(path) {
            Ok(contents) => self.parse_single_file(&source_file, &contents),
            Err(error) => ConfigParseOutcome::failed(vec![
                ConfigError::new(
                    ConfigErrorKind::InvalidJson,
                    format!("failed to read config file: {error}"),
                )
                .with_source_file(source_file),
            ]),
        }
    }

    /// Loads all `*.json` files from a local directory (sorted by path).
    pub fn parse_directory_path(&self, dir: &Path) -> ConfigParseOutcome {
        let read = match std::fs::read_dir(dir) {
            Ok(read) => read,
            Err(error) => {
                return ConfigParseOutcome::failed(vec![
                    ConfigError::new(
                        ConfigErrorKind::UnsupportedStructure,
                        format!("failed to read config directory: {error}"),
                    )
                    .with_source_file(dir.to_string_lossy()),
                ]);
            }
        };

        let mut files = Vec::new();
        let mut preload_errors = Vec::new();

        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let source_file = path.to_string_lossy().into_owned();
            match std::fs::read_to_string(&path) {
                Ok(contents) => files.push((source_file, contents)),
                Err(error) => preload_errors.push(
                    ConfigError::new(
                        ConfigErrorKind::InvalidJson,
                        format!("failed to read config file: {error}"),
                    )
                    .with_source_file(source_file),
                ),
            }
        }

        let mut outcome = self.parse_directory(files);
        if !preload_errors.is_empty() {
            let mut errors = preload_errors;
            errors.extend(outcome.errors().iter().cloned());
            outcome = ConfigParseOutcome::new(outcome.into_sections(), errors);
        }
        outcome
    }

    fn merge_object(
        &self,
        source_file: &str,
        value: Value,
        sections: &mut XrayConfigSections,
        errors: &mut Vec<ConfigError>,
    ) {
        let Some(object) = value.as_object() else {
            errors.push(
                ConfigError::new(
                    ConfigErrorKind::UnsupportedStructure,
                    "Xray config root value must be a JSON object",
                )
                .with_source_file(source_file),
            );
            return;
        };

        for (key, section_value) in object {
            match key.as_str() {
                "log" => self.assign_object_section(
                    source_file,
                    "log",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_log(Some(v)),
                ),
                "api" => self.assign_object_section(
                    source_file,
                    "api",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_api(Some(v)),
                ),
                "dns" => self.assign_object_section(
                    source_file,
                    "dns",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_dns(Some(v)),
                ),
                "fakedns" => {
                    // Official FakeDNS accepts either a FakeDnsObject or an array of
                    // pools. Store the raw value losslessly; summary extraction is
                    // tolerant of both shapes.
                    if section_value.is_null() {
                        errors.push(
                            ConfigError::new(
                                ConfigErrorKind::MissingSection,
                                "section `fakedns` is null",
                            )
                            .with_source_file(source_file)
                            .with_section("fakedns"),
                        );
                    } else {
                        if matches!(
                            section_value,
                            Value::Bool(_) | Value::Number(_) | Value::String(_)
                        ) {
                            errors.push(
                                ConfigError::new(
                                    ConfigErrorKind::UnsupportedStructure,
                                    "section `fakedns` has unsupported primitive type; value preserved",
                                )
                                .with_source_file(source_file)
                                .with_section("fakedns"),
                            );
                        }
                        sections.set_fakedns(Some(SourcedSection::new(
                            source_file,
                            section_value.clone(),
                        )));
                    }
                }
                "routing" => self.assign_object_section(
                    source_file,
                    "routing",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_routing(Some(v)),
                ),
                "policy" => self.assign_object_section(
                    source_file,
                    "policy",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_policy(Some(v)),
                ),
                "stats" => {
                    sections.set_stats(Some(SourcedSection::new(
                        source_file,
                        section_value.clone(),
                    )));
                }
                "reverse" => self.assign_object_section(
                    source_file,
                    "reverse",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_reverse(Some(v)),
                ),
                "observatory" => self.assign_object_section(
                    source_file,
                    "observatory",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_observatory(Some(v)),
                ),
                "burstObservatory" => self.assign_object_section(
                    source_file,
                    "burstObservatory",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_burst_observatory(Some(v)),
                ),
                "metrics" => self.assign_object_section(
                    source_file,
                    "metrics",
                    section_value,
                    sections,
                    errors,
                    |s, v| s.set_metrics(Some(v)),
                ),
                "inbounds" => {
                    self.merge_inbounds(source_file, section_value, sections, errors);
                }
                "outbounds" => {
                    self.merge_outbounds(source_file, section_value, sections, errors);
                }
                other => {
                    // Preserve unknown top-level keys losslessly. They are not
                    // parse failures; callers can classify them with
                    // ConfigErrorKind::UnknownSection when reporting.
                    sections.push_extra(
                        other.to_owned(),
                        SourcedSection::new(source_file, section_value.clone()),
                    );
                }
            }
        }
    }

    fn assign_object_section<F>(
        &self,
        source_file: &str,
        section_name: &str,
        section_value: &Value,
        sections: &mut XrayConfigSections,
        errors: &mut Vec<ConfigError>,
        assign: F,
    ) where
        F: FnOnce(&mut XrayConfigSections, SourcedSection<Value>),
    {
        if section_value.is_null() {
            errors.push(
                ConfigError::new(
                    ConfigErrorKind::MissingSection,
                    format!("section `{section_name}` is null"),
                )
                .with_source_file(source_file)
                .with_section(section_name),
            );
            return;
        }

        // Primitive values are structurally wrong for object sections but are
        // still stored so future write-back can round-trip the raw JSON.
        if matches!(
            section_value,
            Value::Bool(_) | Value::Number(_) | Value::String(_)
        ) {
            errors.push(
                ConfigError::new(
                    ConfigErrorKind::UnsupportedStructure,
                    format!(
                        "section `{section_name}` has unsupported primitive type; value preserved"
                    ),
                )
                .with_source_file(source_file)
                .with_section(section_name),
            );
        }

        assign(
            sections,
            SourcedSection::new(source_file, section_value.clone()),
        );
    }

    fn merge_inbounds(
        &self,
        source_file: &str,
        section_value: &Value,
        sections: &mut XrayConfigSections,
        errors: &mut Vec<ConfigError>,
    ) {
        let Some(items) = section_value.as_array() else {
            errors.push(
                ConfigError::new(
                    ConfigErrorKind::InvalidInbound,
                    "inbounds must be a JSON array",
                )
                .with_source_file(source_file)
                .with_section("inbounds"),
            );
            sections.push_extra(
                "inbounds".to_owned(),
                SourcedSection::new(source_file, section_value.clone()),
            );
            return;
        };

        for (index, item) in items.iter().enumerate() {
            if !item.is_object() {
                errors.push(
                    ConfigError::new(
                        ConfigErrorKind::InvalidInbound,
                        format!("inbound at index {index} is not a JSON object"),
                    )
                    .with_source_file(source_file)
                    .with_section("inbounds"),
                );
            }
            sections.push_inbound(SourcedSection::new(source_file, item.clone()));
        }
    }

    fn merge_outbounds(
        &self,
        source_file: &str,
        section_value: &Value,
        sections: &mut XrayConfigSections,
        errors: &mut Vec<ConfigError>,
    ) {
        let Some(items) = section_value.as_array() else {
            errors.push(
                ConfigError::new(
                    ConfigErrorKind::InvalidOutbound,
                    "outbounds must be a JSON array",
                )
                .with_source_file(source_file)
                .with_section("outbounds"),
            );
            sections.push_extra(
                "outbounds".to_owned(),
                SourcedSection::new(source_file, section_value.clone()),
            );
            return;
        };

        for (index, item) in items.iter().enumerate() {
            if !item.is_object() {
                errors.push(
                    ConfigError::new(
                        ConfigErrorKind::InvalidOutbound,
                        format!("outbound at index {index} is not a JSON object"),
                    )
                    .with_source_file(source_file)
                    .with_section("outbounds"),
                );
            }
            sections.push_outbound(SourcedSection::new(source_file, item.clone()));
        }
    }

    fn check_duplicate_tags(&self, sections: &XrayConfigSections, errors: &mut Vec<ConfigError>) {
        let mut inbound_tags: HashMap<&str, &str> = HashMap::new();
        for inbound in sections.inbounds() {
            let Some(tag) = inbound.value().get("tag").and_then(Value::as_str) else {
                continue;
            };
            if tag.is_empty() {
                continue;
            }
            if inbound_tags.insert(tag, inbound.source_file()).is_some() {
                errors.push(
                    ConfigError::new(
                        ConfigErrorKind::DuplicateTags,
                        format!("duplicate inbound tag `{tag}`"),
                    )
                    .with_source_file(inbound.source_file())
                    .with_section("inbounds"),
                );
            }
        }

        let mut outbound_tags: HashMap<&str, &str> = HashMap::new();
        for outbound in sections.outbounds() {
            let Some(tag) = outbound.value().get("tag").and_then(Value::as_str) else {
                continue;
            };
            if tag.is_empty() {
                continue;
            }
            if outbound_tags.insert(tag, outbound.source_file()).is_some() {
                errors.push(
                    ConfigError::new(
                        ConfigErrorKind::DuplicateTags,
                        format!("duplicate outbound tag `{tag}`"),
                    )
                    .with_source_file(outbound.source_file())
                    .with_section("outbounds"),
                );
            }
        }
    }
}
