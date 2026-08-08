//! Remote `xray` CLI wrappers (keygen / encryption helpers / config test).
//!
//! Parsers are fixture-driven (`tests/fixtures/xray/cli/`). Never log secrets.

mod config_test;
mod error;
mod exec;
mod mldsa65;
mod vlessenc;
mod x25519;

pub use config_test::{ConfigTestTarget, run_config_test};
pub use error::{RemoteCliError, RemoteCliErrorKind, RemoteCliResult};
pub use mldsa65::{Mldsa65KeyPair, parse_mldsa65_stdout, run_mldsa65};
pub use vlessenc::{
    VlessEncAuthKind, VlessEncOutput, VlessEncPair, parse_vlessenc_stdout, run_vlessenc,
};
pub use x25519::{X25519KeyPair, parse_x25519_stdout, run_x25519};
