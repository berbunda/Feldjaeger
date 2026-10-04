//! A local Xray executable for tests that check Feldjäger against the real core.
//!
//! `XRAY_BIN` wins when set; otherwise `xray-bin/xray(.exe)` in the crate root is used when it
//! exists (the directory is git-ignored — each developer drops their own build there). Without
//! either, those tests are no-ops, so a clean clone and CI stay green.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The Xray executable to test against, or `None` (the caller skips with a note).
pub(crate) fn local_xray_bin() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XRAY_BIN").filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    let bundled = Path::new(env!("CARGO_MANIFEST_DIR")).join("xray-bin").join(name);
    bundled.is_file().then_some(bundled)
}

/// Stdout of `xray <args>` from the local executable, for CLI-parser tests; `None` (with a note)
/// when there is no local Xray. Panics when the command fails — that is a test failure.
pub(crate) fn local_xray_stdout(args: &[&str]) -> Option<String> {
    let Some(xray) = local_xray_bin() else {
        eprintln!("no local Xray (XRAY_BIN / xray-bin) — skipping `xray {}`", args.join(" "));
        return None;
    };
    let output = Command::new(&xray)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", xray.display()));
    assert!(
        output.status.success(),
        "xray {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}
