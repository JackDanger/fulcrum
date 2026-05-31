//! flow.rs — multi-stage pipeline flow view for an in-order streaming decoder.
//!
//! Answers, without guessing: *what happens upstream and downstream of the
//! parallel worker threads, and which single-thread stage is the bottleneck?*
//!
//! ## Why two numbers per stage (and not one)
//!
//! The wall of an in-order pipeline IS the consumer thread's timeline (see
//! [`crate::critpath`]): output leaves in order, so `wall ≈ Σ(consumer
//! self-work) + Σ(consumer waits)`, and each wait is blamed on the worker span
//! that was producing the awaited item. That gives **WALL-CRITICAL** time per
//! stage — time that, if removed, shortens the wall.
//!
//! Separately, each stage has **TOTAL-BUSY** time — Σ span-duration across all
//! threads. The gap `busy - wall_critical` is **SLACK**: work that is large but
//! fully overlapped and therefore wall-dead. Speeding a slack-heavy stage does
//! nothing to the wall. This campaign has repeatedly burned work-stretches on
//! slack (copy-elimination, FastBootstrap) precisely because a one-number view
//! (busy OR critical alone) hides it. The flow view shows both, so a lever can
//! be pre-killed on paper: a stage with huge busy but ~0 wall-critical is not a
//! lever, no matter how much CPU it burns.
//!
//! ## Serial vs starved
//!
//! - **SERIAL**: the stage runs on exactly one thread. A single-thread stage on
//!   the critical path is an Amdahl wall — adding cores cannot help it.
//! - **STARVED**: the stage has thread capacity but low occupancy
//!   (`busy / (threads · window)` below a threshold) — workers sit idle,
//!   a dispatch/feeding problem, not a compute problem.
//!
//! These are distinct failure modes (the advisor's correction to a single
//! "concurrency" metric): a fix for one does not fix the other.

use crate::critpath::{self, CritPath};
use crate::trace::{pair_spans, wall_us, Event};
use std::collections::{HashMap, HashSet};

/// Occupancy below this (for a multi-thread stage) flags STARVED.
pub const STARVED_OCCUPANCY: f64 = 0.75;

/// One pipeline stage's flow accounting.
#[derive(Debug, Clone)]
pub struct StageRow {
    pub name: &'static str,
    /// Time on the consumer's in-order critical path attributed to this stage
    /// (consumer self-work in the stage + consumer waits blamed on this
    /// stage's worker spans). Cutting this shortens the wall.
    pub wall_critical_us: f64,
    /// Σ span-duration across ALL threads for this stage's WORK spans
    /// (waits excluded — a wait is idle, not work).
    pub total_busy_us: f64,
    /// Distinct threads that ran a work span in this stage.
    pub threads: usize,
    /// Wall window the stage's work spans span (max_end − min_start).
    pub window_us: f64,
    /// busy / (threads · window) — 1.0 = every thread fully busy the whole window.
    pub occupancy: f64,
    pub serial: bool,
    pub starved: bool,
}

impl StageRow {
    /// SLACK: busy that is NOT on the wall. Large slack ⇒ speeding this stage
    /// is wall-dead.
    pub fn slack_us(&self) -> f64 {
        (self.total_busy_us - self.wall_critical_us).max(0.0)
    }
}

/// Full flow report.
pub struct FlowReport {
    pub wall_us: f64,
    pub stages: Vec<StageRow>,
    /// Span names that matched no stage — printed loudly so a missing
    /// chokepoint is never silently dropped.
    pub unclassified: Vec<(String, f64)>,
}

/// Map a span name to a pipeline stage. Order of the returned label is also the
/// pipeline order used for rendering. Unknown names return `None` →
/// UNCLASSIFIED.
///
/// Tuned for gzippy's parallel single-member span vocabulary, but the buckets
/// are generic pipeline roles (dispatch → decode → find → resolve → write).
pub fn classify(name: &str) -> Option<&'static str> {
    // Waits are handled via critpath attribution, not as a stage of their own;
    // they carry no busy work. Classify by the conventional wait names so they
    // are not dumped into UNCLASSIFIED.
    let n = name;
    let stage = if n.starts_with("coord.")
        || n == "pool.submit"
        || n.starts_with("pool.pick")
        || n == "consumer.process_prefetches"
        || n == "consumer.block_finder_get"
        || n == "consumer.try_take_prefetched"
    {
        "1·dispatch (upstream)"
    } else if n == "worker.bootstrap" || n == "worker.block_body" || n == "worker.block_header" {
        "2·worker bootstrap (window-absent)"
    } else if n == "worker.isal_stream_inflate" || n == "worker.absorb_isal_tail" {
        "3·worker ISA-L (clean tail)"
    } else if n == "consumer.wait_replaced_markers"
        || n == "consumer.publish_windows"
        || n.starts_with("consumer.window_")
        || n == "consumer.dispatch_post_process"
        || n.starts_with("post_process.")
    {
        "5·consumer resolve (markers/window)"
    } else if n == "consumer.write_data"
        || n == "consumer.write_narrowed"
        || n == "consumer.combine_crc"
        || n == "consumer.drain"
        || n == "consumer.arc_take_or_clone"
    {
        "6·consumer write (output)"
    } else if n.starts_with("wait.")
        || n.ends_with(".wait")
        || n == "ttp.rx_recv_block"
        || n == "future.recv"
        || n.starts_with("chan_recv")
        || n.starts_with("ttp.")
    {
        // A named wait: belongs to no busy stage; its wall cost is attributed
        // to a blocker via critpath. Tag it so it isn't UNCLASSIFIED.
        "·wait"
    } else if n.starts_with("consumer.") {
        // Any other consumer self-work.
        "6·consumer write (output)"
    } else if n.starts_with("lock.")
        || n == "consumer.iter"
        || n == "drive"
        || n == "pool.run_task"
        || n == "worker.decode_chunk"
        || n.starts_with("worker.scan")
        || n == "worker.seed_first"
    {
        // Umbrella / lock-held markers: not a stage. Excluded so blame lands on
        // the INNER LEAF decode phases (block_body/bootstrap = window-absent;
        // isal = clean tail), not the wrapper. `worker.scan_candidate` /
        // `worker.scan_run` / `worker.seed_first` WRAP a full candidate decode
        // (all 39 chunks take the slow path), so crediting them as a
        // "block-find" stage double-counts the enclosed decode and manufactures
        // a phantom block-finder bottleneck. The pure find_blocks scan is cheap
        // (failed candidates waste ~2.6KB total) — the cost inside is the
        // productive decode.
        "·umbrella"
    } else {
        return None;
    };
    Some(stage)
}

/// Pipeline order for rendering (stages not present are skipped).
const STAGE_ORDER: &[&str] = &[
    "1·dispatch (upstream)",
    "2·worker bootstrap (window-absent)",
    "3·worker ISA-L (clean tail)",
    "5·consumer resolve (markers/window)",
    "6·consumer write (output)",
];

/// Worker inner-phase span names to prefer as wait blockers, so the consumer's
/// stall is attributed to the real inner phase (block-find vs bootstrap vs
/// ISA-L) instead of the `pool.run_task` / `worker.decode_chunk` umbrella that
/// wraps the whole task and would otherwise win on overlap.
///
/// CRITICAL: this set must include EVERY inner phase, NOT just the decode
/// phases. Listing only decode phases (bootstrap/ISA-L) biases the attribution
/// — it forces blame onto decode even when `worker.scan_candidate`
/// (block-finding) had more overlap with the consumer's wait, manufacturing a
/// false "decode is the lever" conclusion. (Learned the hard way: a
/// decode-only preferred set reported bootstrap=209ms wall-critical; with
/// block-find included the honest answer is scan=156ms, bootstrap=27ms — and
/// the latter reconciles the FastBootstrap TIE.)
pub const INNER_DECODE_BLOCKERS: &[&str] = &[
    "worker.bootstrap",
    "worker.block_body",
    "worker.block_header",
    "worker.isal_stream_inflate",
    "worker.absorb_isal_tail",
];

/// Given a critpath entry label, return the stage it belongs to. Labels are
/// either a raw span name (consumer self-work) or `"blocked-on:<span>"` (a
/// consumer wait blamed on a worker span) — in the latter case the stage is
/// that of the blocker span, so consumer stall lands on the stage that caused
/// it.
fn stage_of_label(label: &str) -> Option<&'static str> {
    let span_name = label.strip_prefix("blocked-on:").unwrap_or(label);
    classify(span_name).filter(|s| !s.starts_with('·'))
}

/// Build the flow report from a Chrome-trace event stream.
pub fn analyze_flow(events: &[Event], preferred_blockers: &[String]) -> FlowReport {
    let spans = pair_spans(events);
    let wall = wall_us(&spans);
    let cp: CritPath = critpath::analyze(events, f64::INFINITY, preferred_blockers);

    // --- WALL-CRITICAL per stage (from the consumer-anchored decomposition) ---
    let mut wall_crit: HashMap<&'static str, f64> = HashMap::new();
    for e in &cp.entries {
        if let Some(stage) = stage_of_label(&e.label) {
            *wall_crit.entry(stage).or_default() += e.on_path_us;
        }
    }

    // --- TOTAL-BUSY / threads / window per stage (from raw work spans) ---
    let mut busy: HashMap<&'static str, f64> = HashMap::new();
    let mut tids: HashMap<&'static str, HashSet<(u64, u64)>> = HashMap::new();
    let mut win: HashMap<&'static str, (f64, f64)> = HashMap::new();
    let mut unclassified: HashMap<String, f64> = HashMap::new();
    for s in &spans {
        match classify(&s.name) {
            Some(stage) if !stage.starts_with('·') => {
                *busy.entry(stage).or_default() += s.dur;
                tids.entry(stage).or_default().insert((s.pid, s.tid));
                let w = win.entry(stage).or_insert((f64::INFINITY, f64::NEG_INFINITY));
                w.0 = w.0.min(s.ts_start);
                w.1 = w.1.max(s.ts_end);
            }
            Some(_) => {} // wait / umbrella: no busy contribution
            None => *unclassified.entry(s.name.clone()).or_default() += s.dur,
        }
    }

    let mut stages = Vec::new();
    for &name in STAGE_ORDER {
        let b = busy.get(name).copied().unwrap_or(0.0);
        let wc = wall_crit.get(name).copied().unwrap_or(0.0);
        if b == 0.0 && wc == 0.0 {
            continue;
        }
        let threads = tids.get(name).map(|t| t.len()).unwrap_or(0);
        let (lo, hi) = win.get(name).copied().unwrap_or((0.0, 0.0));
        let window = (hi - lo).max(0.0);
        let occupancy = if threads > 0 && window > 0.0 {
            b / (threads as f64 * window)
        } else {
            0.0
        };
        stages.push(StageRow {
            name,
            wall_critical_us: wc,
            total_busy_us: b,
            threads,
            window_us: window,
            occupancy,
            serial: threads == 1,
            starved: threads > 1 && occupancy < STARVED_OCCUPANCY,
        });
    }

    let mut unclassified: Vec<(String, f64)> = unclassified.into_iter().collect();
    unclassified.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    FlowReport {
        wall_us: wall,
        stages,
        unclassified,
    }
}

/// Amdahl/critical-path upper bound on the wall after speeding `stage` by
/// `factor` (e.g. 2.0 = twice as fast). Only the stage's WALL-CRITICAL portion
/// moves; SLACK does not — so a slack-heavy stage shows ~no wall benefit, which
/// is the whole point. Returns `(predicted_wall_us, wall_saved_us)`.
///
/// This is an upper bound (true Coz virtual-speedup re-simulation could reveal
/// a *new* bottleneck the simple model misses, but never a *larger* saving).
pub fn whatif(report: &FlowReport, stage: &str, factor: f64) -> Option<(f64, f64)> {
    let f = if factor <= 0.0 { 1.0 } else { factor };
    let s = report.stages.iter().find(|s| s.name == stage)?;
    let saved = s.wall_critical_us * (1.0 - 1.0 / f);
    Some((report.wall_us - saved, saved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(name: &str, ph: &str, ts: f64, tid: u64) -> Event {
        Event {
            name: name.to_string(),
            ph: ph.to_string(),
            ts,
            pid: 1,
            tid,
            args: json!({}),
        }
    }

    #[test]
    fn classify_covers_gzippy_vocabulary() {
        // A regression guard: every span name gzippy actually emits must map to
        // a stage (or a `·wait`/`·umbrella` non-stage), never UNCLASSIFIED.
        let vocab = [
            "coord.prefetch_call",
            "pool.submit",
            "pool.pick",
            "pool.pick.lock",
            "pool.run_task",
            "worker.bootstrap",
            "worker.block_body",
            "worker.block_header",
            "worker.decode_chunk",
            "worker.isal_stream_inflate",
            "worker.absorb_isal_tail",
            "pool.run_task",
            "worker.scan_candidate",
            "worker.seed_first",
            "consumer.process_prefetches",
            "consumer.block_finder_get",
            "consumer.try_take_prefetched",
            "consumer.wait_replaced_markers",
            "consumer.publish_windows",
            "consumer.window_publish_clean",
            "consumer.dispatch_post_process",
            "consumer.write_data",
            "consumer.write_narrowed",
            "consumer.combine_crc",
            "consumer.drain",
            "consumer.arc_take_or_clone",
            "post_process.crc_narrowed",
            "wait.block_fetcher_get",
            "ttp.rx_recv_block",
            "consumer.iter",
        ];
        for v in vocab {
            assert!(classify(v).is_some(), "unclassified gzippy span: {v}");
        }
        assert!(classify("totally.unknown.span").is_none());
    }

    #[test]
    fn slack_is_busy_minus_wall_critical() {
        let r = StageRow {
            name: "x",
            wall_critical_us: 30.0,
            total_busy_us: 1000.0,
            threads: 8,
            window_us: 200.0,
            occupancy: 0.625,
            serial: false,
            starved: true,
        };
        assert_eq!(r.slack_us(), 970.0);
    }

    #[test]
    fn overlapped_worker_decode_is_slack_not_wall() {
        // Consumer does a tiny write then blocks waiting for a long worker
        // decode. The decode is huge in BUSY but only the consumer's WAIT for
        // it is wall-critical → slack ≈ busy − that wait. This is the trap the
        // two-number view exists to expose.
        let mut events = vec![
            // consumer timeline
            ev("consumer.write_data", "B", 0.0, 1),
            ev("consumer.write_data", "E", 10.0, 1),
            ev("wait.block_fetcher_get", "B", 10.0, 1),
            ev("wait.block_fetcher_get", "E", 100.0, 1),
        ];
        // a long worker decode overlapping the wait (the blocker)
        events.push(ev("worker.block_body", "B", 12.0, 2));
        events.push(ev("worker.block_body", "E", 98.0, 2));
        // a SECOND worker decoding fully in parallel (pure slack, off-path)
        events.push(ev("worker.block_body", "B", 12.0, 3));
        events.push(ev("worker.block_body", "E", 98.0, 3));

        let r = analyze_flow(&events, &[]);
        let decode = r
            .stages
            .iter()
            .find(|s| s.name == "2·worker bootstrap (window-absent)")
            .expect("decode stage present");
        // busy = two 86us spans = 172us
        assert!((decode.total_busy_us - 172.0).abs() < 1e-6);
        // wall-critical = the 90us consumer wait blamed on decode (one blocker)
        assert!(decode.wall_critical_us > 80.0 && decode.wall_critical_us <= 90.0);
        // → most of the busy is SLACK (the second parallel decode)
        assert!(decode.slack_us() > 70.0);
        assert_eq!(decode.threads, 2);
    }

    #[test]
    fn whatif_only_credits_wall_critical() {
        let report = FlowReport {
            wall_us: 1000.0,
            stages: vec![
                StageRow {
                    name: "2·worker bootstrap (window-absent)",
                    wall_critical_us: 100.0,
                    total_busy_us: 900.0,
                    threads: 8,
                    window_us: 130.0,
                    occupancy: 0.86,
                    serial: false,
                    starved: false,
                },
                StageRow {
                    name: "6·consumer write (output)",
                    wall_critical_us: 200.0,
                    total_busy_us: 200.0,
                    threads: 1,
                    window_us: 1000.0,
                    occupancy: 0.2,
                    serial: true,
                    starved: false,
                },
            ],
            unclassified: vec![],
        };
        // 2x the decode (100us critical): saves 50us → wall 950.
        let (w, saved) = whatif(&report, "2·worker bootstrap (window-absent)", 2.0).unwrap();
        assert!((saved - 50.0).abs() < 1e-6);
        assert!((w - 950.0).abs() < 1e-6);
        // Infinitely fast consumer write (200us, all critical, serial): saves
        // the full 200us → the Amdahl bound for that serial stage.
        let (w2, saved2) = whatif(&report, "6·consumer write (output)", 1e9).unwrap();
        assert!((saved2 - 200.0).abs() < 1e-3);
        assert!((w2 - 800.0).abs() < 1e-3);
    }
}
