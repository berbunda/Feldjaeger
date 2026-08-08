//! Init system abstraction layer.
//!
//! All service control must go through [`InitSystemManager`].
//! GUI code must not contain init-system-specific logic.
//! Unit file Create/Edit is systemd-only via [`unit`] (not on the trait).

mod error;
mod manager;
mod service_name;
mod systemd;
mod systemd_probe;
pub mod unit;

pub use error::{
    ServiceControlError, ServiceControlResult, ServiceOperationErrorKind, UnitFileError,
    UnitFileErrorKind, UnitFileResult, classify_systemctl_failure,
};
pub use manager::{InitSystemManager, ServiceState};
pub use service_name::{ServiceName, validate_service_name};
pub use systemd::{SystemdManager, SystemdManagerOptions};
pub use systemd_probe::{
    ExecStartConfigArg, SystemdUnitProbe, XRAY_UNIT_CANDIDATES, extract_config_arg,
    parse_exec_start_argv,
};
pub use unit::{
    DEFAULT_UNIT_DESCRIPTION, DEFAULT_WANTED_BY, InstallUnitOptions, UnitConfigLayout,
    UnitHostProbe, UnitRunUser, UnitSpec, install_or_replace_unit, is_instance_unit_name,
    preview_exec_start, probe_unit_host, render_unit, unit_file_path,
};
