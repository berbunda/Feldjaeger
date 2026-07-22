//! Read-only Xray runtime log access.
//!
//! Application logs (`src/logging`) and Xray runtime logs stay separate.
//! This module never writes remote log bodies into the application log file.

mod destination;
mod error;
mod model;
mod search;
mod service;

pub use destination::{XrayLogConfigView, log_config_view};
pub use error::{XrayLogError, XrayLogErrorKind, XrayLogResult};
pub use model::{
    XrayLogAvailability, XrayLogDestination, XrayLogEntry, XrayLogLineLimit, XrayLogSourceKind,
    XrayLogSourceSummary,
};
pub use search::XrayLogSearch;
pub use service::{XrayLogService, XrayLogStreamEvent};
