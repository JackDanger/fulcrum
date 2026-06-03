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

use crate::config::{Config, StageDef};
use crate::critpath::{self, CritPath};
use crate::trace::{pair_spans, wall_us, Event};
use std::collections::{HashMap, HashSet};

/// Occupancy below this (for a multi-thread stage) flags STARVED.
pub const STARVED_OCCUPANCY: f64 = 0.75;

/// One pipeline stage's flow accounting.
#[derive(Debug, Clone)]
pub struct StageRow {
    pub name: String,
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

/// Map a span name to a pipeline stage NAME, using the configured stage list.
/// Stages are tried in DECLARATION ORDER and the FIRST match wins — so a
/// catch-all stage (e.g. a `consumer.` prefix) must be declared AFTER the more
/// specific ones. A returned name beginning with `·` (e.g. `·wait`,
/// `·umbrella`) is a non-stage: recognized so it isn't UNCLASSIFIED, but it
/// carries no busy work and never renders as a row. `None` ⇒ UNCLASSIFIED
/// (surfaced loudly).
///
/// The semantics are vocabulary-agnostic; the gzippy stage set lives in
/// [`Config::gzippy`] (`dispatch → bootstrap → ISA-L → resolve → write`). A
/// pipeline with no configured stages gets an all-UNCLASSIFIED report whose
/// vocabulary dump tells the user what to turn into stages.
pub fn classify<'a>(name: &str, stages: &'a [StageDef]) -> Option<&'a str> {
    stages
        .iter()
        .find(|s| s.matcher.matches(name))
        .map(|s| s.name.as_str())
}

/// Given a critpath entry label, return the stage it belongs to. Labels are
/// either a raw span name (consumer self-work) or `"blocked-on:<span>"` (a
/// consumer wait blamed on a worker span) — in the latter case the stage is
/// that of the blocker span, so consumer stall lands on the stage that caused
/// it.
fn stage_of_label<'a>(label: &str, stages: &'a [StageDef]) -> Option<&'a str> {
    let span_name = label.strip_prefix("blocked-on:").unwrap_or(label);
    classify(span_name, stages).filter(|s| !s.starts_with('·'))
}

/// Build the flow report from a Chrome-trace event stream, using `cfg.stages`
/// for the stage vocabulary + render order and `preferred_blockers` for
/// critical-path attribution (the caller passes `cfg.inner_blockers`, which
/// biases blame onto the real inner phase rather than the task umbrella).
pub fn analyze_flow(events: &[Event], cfg: &Config, preferred_blockers: &[String]) -> FlowReport {
    let stages_cfg = &cfg.stages;
    let spans = pair_spans(events);
    let wall = wall_us(&spans);
    let cp: CritPath = critpath::analyze_with(
        events,
        f64::INFINITY,
        preferred_blockers,
        &cfg.consumer.thread_prefix,
    );

    // --- WALL-CRITICAL per stage (from the consumer-anchored decomposition) ---
    let mut wall_crit: HashMap<String, f64> = HashMap::new();
    for e in &cp.entries {
        if let Some(stage) = stage_of_label(&e.label, stages_cfg) {
            *wall_crit.entry(stage.to_string()).or_default() += e.on_path_us;
        }
    }

    // --- TOTAL-BUSY / threads / window per stage (from raw work spans) ---
    let mut busy: HashMap<String, f64> = HashMap::new();
    let mut tids: HashMap<String, HashSet<(u64, u64)>> = HashMap::new();
    let mut win: HashMap<String, (f64, f64)> = HashMap::new();
    let mut unclassified: HashMap<String, f64> = HashMap::new();
    for s in &spans {
        match classify(&s.name, stages_cfg) {
            Some(stage) if !stage.starts_with('·') => {
                let stage = stage.to_string();
                *busy.entry(stage.clone()).or_default() += s.dur;
                tids.entry(stage.clone())
                    .or_default()
                    .insert((s.pid, s.tid));
                let w = win
                    .entry(stage)
                    .or_insert((f64::INFINITY, f64::NEG_INFINITY));
                w.0 = w.0.min(s.ts_start);
                w.1 = w.1.max(s.ts_end);
            }
            Some(_) => {} // wait / umbrella: no busy contribution
            None => *unclassified.entry(s.name.clone()).or_default() += s.dur,
        }
    }

    // Render in configured stage order, skipping non-stages (`·…`) and any
    // stage with neither busy nor wall-critical time.
    let mut stages = Vec::new();
    for sd in stages_cfg {
        let name = &sd.name;
        if name.starts_with('·') {
            continue;
        }
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
            name: name.clone(),
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
    use crate::config::Config;
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
            "worker.stream_inflate",
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
            assert!(
                classify(v, &Config::gzippy().stages).is_some(),
                "unclassified gzippy span: {v}"
            );
        }
        assert!(classify("totally.unknown.span", &Config::gzippy().stages).is_none());
    }

    #[test]
    fn slack_is_busy_minus_wall_critical() {
        let r = StageRow {
            name: "x".to_string(),
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

        let r = analyze_flow(&events, &Config::gzippy(), &[]);
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
                    name: "2·worker bootstrap (window-absent)".to_string(),
                    wall_critical_us: 100.0,
                    total_busy_us: 900.0,
                    threads: 8,
                    window_us: 130.0,
                    occupancy: 0.86,
                    serial: false,
                    starved: false,
                },
                StageRow {
                    name: "6·consumer write (output)".to_string(),
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
