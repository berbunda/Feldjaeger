//! Compact Feldjäger log line formatter (no ANSI escapes).

use std::fmt;

use chrono::Local;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::registry::LookupSpan;

/// Formats events as: `YYYY-MM-DD HH:MM:SS LEVEL module message`.
#[derive(Debug, Default)]
pub(crate) struct FeldjaegerFormat;

impl FeldjaegerFormat {
    fn level_label(level: &tracing::Level) -> &'static str {
        match *level {
            tracing::Level::ERROR => "ERROR",
            tracing::Level::WARN => "WARN",
            tracing::Level::INFO => "INFO",
            tracing::Level::DEBUG => "DEBUG",
            tracing::Level::TRACE => "TRACE",
        }
    }

    fn short_target(target: &str) -> &str {
        target.rsplit("::").next().unwrap_or(target)
    }
}

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for FeldjaegerFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        LocalTimestamp.format_time(&mut writer)?;
        let meta = event.metadata();
        write!(
            writer,
            " {} {} ",
            Self::level_label(meta.level()),
            Self::short_target(meta.target())
        )?;
        // Plain field formatting — never emit ANSI (file/UI logs stay readable).
        let mut fields = String::new();
        let mut visitor = PlainFields {
            out: &mut fields,
            first: true,
        };
        event.record(&mut visitor);
        write!(writer, "{fields}")?;
        writeln!(writer)
    }
}

struct PlainFields<'a> {
    out: &'a mut String,
    first: bool,
}

impl Visit for PlainFields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.write_field(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.write_field(field.name(), value.to_owned());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.write_field(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.write_field(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.write_field(field.name(), value.to_string());
    }
}

impl PlainFields<'_> {
    fn write_field(&mut self, name: &str, value: String) {
        if !self.first {
            self.out.push(' ');
        }
        self.first = false;
        if name == "message" {
            self.out.push_str(&value);
        } else {
            self.out.push_str(name);
            self.out.push('=');
            self.out.push_str(&value);
        }
    }
}

#[derive(Debug, Default)]
struct LocalTimestamp;

impl FormatTime for LocalTimestamp {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        write!(w, "{}", Local::now().format("%Y-%m-%d %H:%M:%S"))
    }
}

pub(crate) fn format_line_for_test(level: &str, module: &str, message: &str) -> String {
    format!(
        "{} {level} {module} {message}",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_target_uses_last_segment() {
        assert_eq!(
            FeldjaegerFormat::short_target("feldjaeger_ssh::russh::client"),
            "client"
        );
        assert_eq!(FeldjaegerFormat::short_target("ssh"), "ssh");
    }
}
