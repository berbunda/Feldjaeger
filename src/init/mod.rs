//! Init system abstraction layer.
//!
//! All service control must go through [`InitSystemManager`].
//! GUI code must not contain init-system-specific logic.

mod error;
mod manager;
mod service_name;
mod systemd;
mod systemd_probe;

pub use error::{
    ServiceControlError, ServiceControlResult, ServiceOperationErrorKind, classify_systemctl_failure,
};
pub use manager::{InitSystemManager, ServiceState};
pub use service_name::{ServiceName, validate_service_name};
pub use systemd::{SystemdManager, SystemdManagerOptions};
pub use systemd_probe::{
    ExecStartConfigArg, SystemdUnitProbe, XRAY_UNIT_CANDIDATES, extract_config_arg,
    parse_exec_start_argv,
};
