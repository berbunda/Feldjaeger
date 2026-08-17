//! AS-range REALITY candidate scan loop (Roadmap §3:131 follow-up).
//!
//! Unlike every other background operation in this crate, this never touches the managed SSH
//! host — `netinfo::probe_scan_candidate` is purely local (`std::net` + `rustls`), so this loop
//! needs no `SshBackend`/connect/disconnect, just a cancellable pacing loop calling straight into
//! `netinfo`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use rustls::ClientConfig;

use crate::netinfo::{ScanCandidateRow, probe_scan_candidate};

/// Pause between probes — courtesy to the network being scanned, independent of where the scan
/// runs from (agreed with the user as sufficient; local execution was chosen specifically so this
/// traffic never comes from the production VPS). Now the default only — user-configurable per run,
/// see `TargetScanPageModel`/`start_target_scan`.
pub const PROBE_PAUSE: Duration = Duration::from_secs(10);

/// Default worker count for a scan run — matches the historical strictly-sequential behavior.
pub const DEFAULT_SCAN_THREADS: usize = 1;

const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// One update from a running scan.
pub enum ScanEvent {
    /// A candidate passed every check.
    Row(ScanCandidateRow),
    /// Progress update — number of addresses checked so far.
    Progress(usize),
    /// The scan finished (ran out of addresses or was cancelled).
    Done,
}

/// Runs the scan loop: `thread_count` workers pull hosts off a shared queue and probe them
/// concurrently, each pacing itself with `pause` (cancellable, in [`CANCEL_POLL_INTERVAL`]
/// increments so Stop takes effect quickly) between its own successive probes — parallelism
/// multiplies throughput while every individual worker still extends the same courtesy pause to
/// the network being scanned. Reports every valid candidate and a running total-checked count
/// over `tx`. Stops early if `cancel` is set. Always sends [`ScanEvent::Done`] last, once every
/// worker has stopped, whether finished or cancelled.
pub fn run_target_scan(
    hosts: Vec<Ipv4Addr>,
    tls_config: Arc<ClientConfig>,
    cancel: Arc<AtomicBool>,
    tx: Sender<ScanEvent>,
    pause: Duration,
    thread_count: usize,
) {
    let hosts = Arc::new(hosts);
    let next_index = Arc::new(AtomicUsize::new(0));
    let checked = Arc::new(AtomicUsize::new(0));

    let workers: Vec<_> = (0..thread_count.max(1))
        .map(|_| {
            let hosts = Arc::clone(&hosts);
            let next_index = Arc::clone(&next_index);
            let checked = Arc::clone(&checked);
            let tls_config = Arc::clone(&tls_config);
            let cancel = Arc::clone(&cancel);
            let tx = tx.clone();
            thread::spawn(move || scan_worker(&hosts, &next_index, &checked, &tls_config, &cancel, &tx, pause))
        })
        .collect();

    for worker in workers {
        let _ = worker.join();
    }
    let _ = tx.send(ScanEvent::Done);
}

/// One worker's loop: atomically claim the next host index, probe it, report, pace, repeat —
/// until the queue is exhausted or `cancel` is set.
fn scan_worker(
    hosts: &[Ipv4Addr],
    next_index: &AtomicUsize,
    checked: &AtomicUsize,
    tls_config: &Arc<ClientConfig>,
    cancel: &Arc<AtomicBool>,
    tx: &Sender<ScanEvent>,
    pause: Duration,
) {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let index = next_index.fetch_add(1, Ordering::Relaxed);
        let Some(&ip) = hosts.get(index) else {
            return; // queue exhausted
        };

        if let Some(row) = probe_scan_candidate(ip, tls_config)
            && tx.send(ScanEvent::Row(row)).is_err()
        {
            return; // receiver gone (app closing) — stop working
        }

        let checked_count = checked.fetch_add(1, Ordering::Relaxed) + 1;
        if tx.send(ScanEvent::Progress(checked_count)).is_err() {
            return;
        }

        if cancel.load(Ordering::Relaxed) {
            return;
        }
        sleep_cancellable(pause, cancel);
    }
}

fn sleep_cancellable(total: Duration, cancel: &AtomicBool) {
    let mut remaining = total;
    while remaining > Duration::ZERO {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let step = remaining.min(CANCEL_POLL_INTERVAL);
        thread::sleep(step);
        remaining -= step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_cancellable_runs_full_duration_when_not_cancelled() {
        let cancel = AtomicBool::new(false);
        let start = std::time::Instant::now();
        sleep_cancellable(Duration::from_millis(20), &cancel);
        assert!(start.elapsed() >= Duration::from_millis(15));
    }

    #[test]
    fn sleep_cancellable_returns_early_once_cancelled() {
        let cancel = AtomicBool::new(true);
        let start = std::time::Instant::now();
        sleep_cancellable(Duration::from_secs(10), &cancel);
        assert!(start.elapsed() < Duration::from_millis(250));
    }
}
