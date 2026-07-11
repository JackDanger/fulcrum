//! occupancy.rs — per-WORKER pool-thread OCCUPANCY decomposition.
//!
//! The worker-pool counterpart to [`crate::consumer`] (which decomposes the
//! single in-order consumer thread). Answers: *when the parallel pipeline's
//! scaling lags, are the worker threads DECODING, BLOCKED on a dependency
//! (e.g. waiting on a predecessor's window), or IDLE with no work assigned?*
//!
//! ## Why this exists
//!
//! A naive "sum every span's duration by name, per thread" double-counts nested
//! spans (a `worker.block_body` inside `worker.decode_chunk` inside
//! `pool.run_task` gets added three times), so the per-thread "busy" total
//! exceeds the wall — `scripts/timeline_analyze.py` reports 300–400 ms of
//! per-worker busy on a 72 ms wall. This view uses ONLY the top-level (depth-0)
//! spans on each worker thread, so each instant of wall-clock on that thread is
//! counted exactly once, and asserts `decode + idle + other + gap == window`.
//!
//! ## The worker model (gzippy `thread_pool.rs`)
//!
//! Each pooled worker loops:
//!   `pool.pick`  (depth 0) — parked on a condvar waiting for a task to be
//!                            submitted (contains `pool.pick.lock` +
//!                            `pool.pick.wait`). This is IDLE-no-work.
//!   `pool.run_task` (depth 0) — executing a submitted task: the actual chunk
//!                            decode (`worker.decode_chunk` / `worker.block_*`)
//!                            or a post-process/apply-window task. This is BUSY.
//!
//! Window/marker resolution that DEPENDS on the predecessor chunk would show up
//! as a `wait.*` / `*recv*` span NESTED inside `pool.run_task` (the worker has a
//! task but is blocked on a dependency). If that bucket is ~0, the workers never
//! block on window propagation during decode — the scaling cap is NOT
//! window-propagation but dispatch/horizon or in-order consumer backpressure.
//!
//! ## The four per-worker classes (conserved against the thread's live window)
//!
//! - DECODE: depth-0 `pool.run_task` inclusive — real work.
//! - IDLE-no-work: depth-0 `pool.pick` inclusive — parked waiting for a task.
//! - OTHER: any other depth-0 span (should be tiny / absent).
//! - GAP: window − Σ(depth-0 inclusive) — thread-alive time inside no top-level
//!   span (spawn lag, teardown). Folded into idle for the headline.
//!
//! BLOCKED-on-dependency is reported SEPARATELY as a re-attribution of DECODE:
//! the sum of `is_wait()` spans nested inside `pool.run_task` (excluding the
//! `pool.pick.*` parked-wait spans, which are IDLE not blocked-on-dependency).
//!
//! ## Headline concurrency
//!
//! mean_busy_workers = Σ_workers DECODE / decode_wall, where decode_wall is the
//! union span of all `pool.run_task` intervals. This is the "X / N workers busy"
//! number. peak_concurrency is the max simultaneous `pool.run_task` overlap.

use crate::trace::{fmt_us, pair_spans, Event, Span};
use std::collections::BTreeMap;

/// Per-worker occupancy row. All times in microseconds.
#[derive(Debug, Clone)]
pub struct WorkerRow {
    pub tid: u64,
    /// Live window of the thread: last_end − first_start over all its spans.
    pub window_us: f64,
    /// Σ depth-0 `pool.run_task` inclusive (BUSY / decode).
    pub decode_us: f64,
    /// Σ depth-0 `pool.pick` inclusive (parked, no task — IDLE).
    pub idle_pick_us: f64,
    /// Σ depth-0 spans that are neither run_task nor pick.
    pub other_us: f64,
    /// window − Σ(depth-0 inclusive): un-instrumented thread-alive gap.
    pub gap_us: f64,
    /// Σ `is_wait()` spans nested inside a `pool.run_task` (NOT pick.*): a worker
    /// holding a task but blocked on a dependency (window propagation candidate).
    pub blocked_dep_us: f64,
    pub run_tasks: usize,
    /// decode + idle_pick + other + gap == window within epsilon.
    pub reconciled: bool,
}

impl WorkerRow {
    pub fn idle_total_us(&self) -> f64 {
        self.idle_pick_us + self.gap_us
    }
    pub fn decode_pct(&self) -> f64 {
        100.0 * self.decode_us / self.window_us.max(1.0)
    }
    pub fn idle_pct(&self) -> f64 {
        100.0 * self.idle_total_us() / self.window_us.max(1.0)
    }
    pub fn blocked_pct(&self) -> f64 {
        100.0 * self.blocked_dep_us / self.window_us.max(1.0)
    }
}

#[derive(Debug, Clone)]
pub struct OccReport {
    pub wall_us: f64,
    pub parallelization: Option<u64>,
    pub consumer_tid: Option<u64>,
    pub n_workers: usize,
    pub workers: Vec<WorkerRow>,
    /// Union span of all run_task intervals across workers.
    pub decode_wall_us: f64,
    pub total_decode_us: f64,
    /// Σ DECODE / decode_wall: the "X / N busy" headline.
    pub mean_busy_workers: f64,
    pub peak_concurrency: usize,
    pub total_blocked_dep_us: f64,
    pub all_reconciled: bool,
}

const EPS_US: f64 = 1.0; // 1 µs reconciliation tolerance per worker.

fn detect_parallelization(events: &[Event]) -> Option<u64> {
    for e in events {
        if e.name == "drive" {
            if let Some(serde_json::Value::Number(n)) = e.args.get("parallelization") {
                return n.as_u64();
            }
        }
    }
    None
}

/// The consumer thread is the one running the `drive` span (or `consumer.iter`).
fn detect_consumer_tid(spans: &[Span]) -> Option<u64> {
    for s in spans {
        if s.name == "drive" {
            return Some(s.tid);
        }
    }
    // Fallback: tid owning the most `consumer.*` inclusive time.
    let mut by_tid: BTreeMap<u64, f64> = BTreeMap::new();
    for s in spans {
        if s.name.starts_with("consumer.") {
            *by_tid.entry(s.tid).or_default() += s.dur;
        }
    }
    by_tid
        .into_iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(t, _)| t)
}

fn is_decode(name: &str) -> bool {
    name == "pool.run_task"
}
fn is_pick(name: &str) -> bool {
    name == "pool.pick"
}
fn is_pick_internal(name: &str) -> bool {
    name == "pool.pick" || name == "pool.pick.wait" || name == "pool.pick.lock"
}

/// Build the occupancy report from raw trace events.
pub fn analyze(events: &[Event]) -> OccReport {
    let spans = pair_spans(events);
    let wall_us = crate::trace::wall_us(&spans);
    let parallelization = detect_parallelization(events);
    let consumer_tid = detect_consumer_tid(&spans);

    // Worker tids: any tid that ran at least one `pool.run_task`, excluding the
    // consumer tid (the consumer never runs pool.run_task, but guard anyway).
    let mut worker_tids: Vec<u64> = Vec::new();
    {
        let mut seen = std::collections::BTreeSet::new();
        for s in &spans {
            if s.name == "pool.run_task" && Some(s.tid) != consumer_tid && seen.insert(s.tid) {
                worker_tids.push(s.tid);
            }
        }
        worker_tids.sort_unstable();
    }

    let mut workers: Vec<WorkerRow> = Vec::new();
    let mut run_intervals: Vec<(f64, f64)> = Vec::new();

    for &tid in &worker_tids {
        let tspans: Vec<&Span> = spans.iter().filter(|s| s.tid == tid).collect();
        if tspans.is_empty() {
            continue;
        }
        let first = tspans
            .iter()
            .map(|s| s.ts_start)
            .fold(f64::INFINITY, f64::min);
        let last = tspans
            .iter()
            .map(|s| s.ts_end)
            .fold(f64::NEG_INFINITY, f64::max);
        let window = last - first;

        let mut decode = 0.0;
        let mut idle_pick = 0.0;
        let mut other = 0.0;
        let mut top_incl = 0.0;
        let mut run_tasks = 0usize;
        for s in &tspans {
            if s.depth == 0 {
                top_incl += s.dur;
                if is_decode(&s.name) {
                    decode += s.dur;
                    run_tasks += 1;
                    run_intervals.push((s.ts_start, s.ts_end));
                } else if is_pick(&s.name) {
                    idle_pick += s.dur;
                } else {
                    other += s.dur;
                }
            }
        }
        let gap = (window - top_incl).max(0.0);

        // Blocked-on-dependency: wait spans nested (depth>=1) that are NOT the
        // pool.pick parked-wait machinery. These are dependency stalls held
        // while a task is in flight (the window-propagation candidate).
        let blocked_dep: f64 = tspans
            .iter()
            .filter(|s| s.depth >= 1 && s.is_wait() && !is_pick_internal(&s.name))
            .map(|s| s.dur)
            .sum();

        let reconciled = ((decode + idle_pick + other + gap) - window).abs() <= EPS_US;
        workers.push(WorkerRow {
            tid,
            window_us: window,
            decode_us: decode,
            idle_pick_us: idle_pick,
            other_us: other,
            gap_us: gap,
            blocked_dep_us: blocked_dep,
            run_tasks,
            reconciled,
        });
    }

    // decode_wall = union span of run_task intervals; peak concurrency = max
    // simultaneous overlap via a sweep line.
    let (decode_wall_us, peak_concurrency) = if run_intervals.is_empty() {
        (0.0, 0)
    } else {
        let min_s = run_intervals
            .iter()
            .map(|i| i.0)
            .fold(f64::INFINITY, f64::min);
        let max_e = run_intervals
            .iter()
            .map(|i| i.1)
            .fold(f64::NEG_INFINITY, f64::max);
        let mut pts: Vec<(f64, i32)> = Vec::with_capacity(run_intervals.len() * 2);
        for (s, e) in &run_intervals {
            pts.push((*s, 1));
            pts.push((*e, -1));
        }
        // Sort by ts; on ties, process ends (-1) before starts (+1) so abutting
        // intervals don't falsely report overlap.
        pts.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        let mut cur = 0i32;
        let mut peak = 0i32;
        for (_, d) in pts {
            cur += d;
            peak = peak.max(cur);
        }
        (max_e - min_s, peak.max(0) as usize)
    };

    let total_decode_us: f64 = workers.iter().map(|w| w.decode_us).sum();
    let total_blocked_dep_us: f64 = workers.iter().map(|w| w.blocked_dep_us).sum();
    let mean_busy_workers = if decode_wall_us > 0.0 {
        total_decode_us / decode_wall_us
    } else {
        0.0
    };
    let all_reconciled = workers.iter().all(|w| w.reconciled);

    OccReport {
        wall_us,
        parallelization,
        consumer_tid,
        n_workers: workers.len(),
        workers,
        decode_wall_us,
        total_decode_us,
        mean_busy_workers,
        peak_concurrency,
        total_blocked_dep_us,
        all_reconciled,
    }
}

/// Render the human report. Returns the report for the caller to also serialize.
pub fn print_report(path: &str, r: &OccReport) {
    let tlabel = r
        .parallelization
        .map(|p| format!("T{p}"))
        .unwrap_or_else(|| "T?".to_string());
    println!("\n========  WORKER OCCUPANCY  {tlabel}  ({path})  ========");
    println!(
        "wall            : {}   workers {}   consumer tid {}   decode-wall {}",
        fmt_us(r.wall_us),
        r.n_workers,
        r.consumer_tid
            .map(|t| t.to_string())
            .unwrap_or_else(|| "?".into()),
        fmt_us(r.decode_wall_us),
    );

    let n = r.n_workers.max(1) as f64;
    let busy_frac = r.mean_busy_workers / n;
    println!(
        "\n  >>> MEAN BUSY WORKERS = {:.2} / {}  ({:.1}% occupancy)   peak concurrency = {} / {}",
        r.mean_busy_workers,
        r.n_workers,
        100.0 * busy_frac,
        r.peak_concurrency,
        r.n_workers,
    );
    println!(
        "      total DECODE = {}   total BLOCKED-on-dependency (nested wait in run_task) = {} ({:.2}% of decode)",
        fmt_us(r.total_decode_us),
        fmt_us(r.total_blocked_dep_us),
        100.0 * r.total_blocked_dep_us / r.total_decode_us.max(1.0),
    );

    println!(
        "\n  per-worker (decode + idle == window; blocked-dep is a re-attribution of decode):"
    );
    println!(
        "  {:>6}  {:>9}  {:>9} {:>6}  {:>9} {:>6}  {:>9} {:>6}  {:>6}  {:>5}",
        "tid", "window", "DECODE", "%", "IDLE", "%", "BLK-dep", "%", "tasks", "recon",
    );
    for w in &r.workers {
        println!(
            "  {:>6}  {:>9}  {:>9} {:>5.1}  {:>9} {:>5.1}  {:>9} {:>5.2}  {:>6}  {:>5}",
            w.tid,
            fmt_us(w.window_us),
            fmt_us(w.decode_us),
            w.decode_pct(),
            fmt_us(w.idle_total_us()),
            w.idle_pct(),
            fmt_us(w.blocked_dep_us),
            w.blocked_pct(),
            w.run_tasks,
            if w.reconciled { "OK" } else { "BAD" },
        );
    }

    // VERDICT — discriminate the cap class.
    let occ = 100.0 * busy_frac;
    let blocked_share = 100.0 * r.total_blocked_dep_us / r.total_decode_us.max(1.0);
    println!(
        "\n  GATE-0 conservation (per worker decode+idle==window): {}",
        if r.all_reconciled {
            "PASS (all workers reconcile within 1µs)"
        } else {
            "FAIL — pairing unsound, numbers suspect"
        }
    );
    let verdict = if blocked_share >= 5.0 {
        "WINDOW-DEPENDENCY: workers hold tasks but block on a nested dependency (port window prefetch / out-of-order resolve)"
    } else if occ >= 85.0 {
        "DECODE-BOUND: workers are near-saturated; the cap is decode throughput or chunk-count, not idle/blocking"
    } else {
        "IDLE-DISPATCH: workers sit in pool.pick (no task), NOT blocked on a dependency — the cap is dispatch/horizon or in-order consumer backpressure, NOT window propagation"
    };
    println!("  VERDICT: {verdict}");
}

/// Serialize the report as a JSON value for an artifact file.
pub fn to_json(path: &str, r: &OccReport) -> serde_json::Value {
    let workers: Vec<serde_json::Value> = r
        .workers
        .iter()
        .map(|w| {
            serde_json::json!({
                "tid": w.tid,
                "window_us": w.window_us,
                "decode_us": w.decode_us,
                "decode_pct": w.decode_pct(),
                "idle_us": w.idle_total_us(),
                "idle_pct": w.idle_pct(),
                "idle_pick_us": w.idle_pick_us,
                "gap_us": w.gap_us,
                "other_us": w.other_us,
                "blocked_dep_us": w.blocked_dep_us,
                "blocked_pct": w.blocked_pct(),
                "run_tasks": w.run_tasks,
                "reconciled": w.reconciled,
            })
        })
        .collect();
    serde_json::json!({
        "trace": path,
        "wall_us": r.wall_us,
        "parallelization": r.parallelization,
        "consumer_tid": r.consumer_tid,
        "n_workers": r.n_workers,
        "decode_wall_us": r.decode_wall_us,
        "total_decode_us": r.total_decode_us,
        "total_blocked_dep_us": r.total_blocked_dep_us,
        "mean_busy_workers": r.mean_busy_workers,
        "occupancy_pct": 100.0 * r.mean_busy_workers / r.n_workers.max(1) as f64,
        "peak_concurrency": r.peak_concurrency,
        "all_reconciled": r.all_reconciled,
        "workers": workers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::Event;

    fn ev(name: &str, ph: &str, ts: f64, tid: u64) -> Event {
        Event {
            name: name.to_string(),
            ph: ph.to_string(),
            ts,
            pid: 1,
            tid,
            args: serde_json::Value::Null,
        }
    }

    #[test]
    fn two_workers_decode_and_idle_reconcile() {
        // Consumer tid 1 runs `drive`. Worker tid 2: run_task [0,40], pick [40,100].
        // Worker tid 3: pick [0,30], run_task [30,100].
        let mut events = vec![ev("drive", "B", 0.0, 1), ev("drive", "E", 100.0, 1)];
        // worker 2
        events.push(ev("pool.run_task", "B", 0.0, 2));
        events.push(ev("pool.run_task", "E", 40.0, 2));
        events.push(ev("pool.pick", "B", 40.0, 2));
        events.push(ev("pool.pick.wait", "B", 41.0, 2));
        events.push(ev("pool.pick.wait", "E", 99.0, 2));
        events.push(ev("pool.pick", "E", 100.0, 2));
        // worker 3
        events.push(ev("pool.pick", "B", 0.0, 3));
        events.push(ev("pool.pick", "E", 30.0, 3));
        events.push(ev("pool.run_task", "B", 30.0, 3));
        events.push(ev("pool.run_task", "E", 100.0, 3));

        let r = analyze(&events);
        assert_eq!(r.n_workers, 2);
        assert!(r.all_reconciled, "workers must reconcile");
        // total decode = 40 + 70 = 110; decode_wall = [0,100] = 100 → mean busy 1.1
        assert!((r.total_decode_us - 110.0).abs() < 1e-6);
        assert!((r.decode_wall_us - 100.0).abs() < 1e-6);
        assert!((r.mean_busy_workers - 1.1).abs() < 1e-6);
        // run_task [0,40] and [30,100] overlap on [30,40] → peak 2.
        assert_eq!(r.peak_concurrency, 2);
        // No nested wait inside run_task → blocked_dep == 0.
        assert!(r.total_blocked_dep_us.abs() < 1e-6);
    }

    #[test]
    fn nested_wait_in_run_task_is_blocked_dep() {
        let mut events = vec![ev("drive", "B", 0.0, 1), ev("drive", "E", 100.0, 1)];
        events.push(ev("pool.run_task", "B", 0.0, 2));
        events.push(ev("wait.future_recv", "B", 10.0, 2));
        events.push(ev("wait.future_recv", "E", 30.0, 2)); // 20us blocked
        events.push(ev("pool.run_task", "E", 100.0, 2));
        let r = analyze(&events);
        assert!((r.total_blocked_dep_us - 20.0).abs() < 1e-6);
        assert!(r.all_reconciled);
    }
}
