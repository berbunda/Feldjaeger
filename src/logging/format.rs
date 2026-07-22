//! Compact Feldjäger log line formatter.

use std::fmt;

use chrono::Local;
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::FormatFields;
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
        ctx: &FmtContext<'_, S, N>,
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
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
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
