//! Feldjaeger desktop entry point.

// Hide the console window on Windows; application logs go to a file.
#![windows_subsystem = "windows"]

use feldjaeger::gui::run;
use feldjaeger::logging;

fn main() -> eframe::Result {
    // Keep the logging handle alive for the process lifetime so the
    // non-blocking writer flushes on shutdown.
    let _logging = match logging::init() {
        Ok(handle) => Some(handle),
        Err(error) => {
            eprintln!("failed to initialize application logging ({error}); continuing");
            None
        }
    };

    run()
}
