//! model.rs — the PARALLEL-SM QUANTITATIVE-MODEL view (INDEPENDENT-parameter
//! edition).
//!
//! Populates, from a single Chrome-trace timeline, the parameters of the
//! advisor-validated wall model in `gzippy/plans/parallel-sm-model.md`,
//! computes a PREDICTED wall, and reports the residual against the observed
//! wall. Given two traces (gzippy + rapidgzip) it prints the per-parameter
//! DELTA and names the implied lever.
//!
//! ## The tautology this edition exists to kill
//!
//! The previous edition defined `L_resolve` as the MEAN inter-publish gap =
//! `(last_publish − first_publish)/(N−1)`. Then the publish-chain term was
//! `frontier + (N−1)·L_resolve = frontier + (last − first) = last_publish`,
//! and `wall_pred = max(·, last_publish) + tail`. When publish-chain bound,
//! `wall_pred = last_publish + (wall_end − last_publish) = wall_end = wall` BY
//! CONSTRUCTION — a telescoping identity, not a prediction. Its residual was
//! +0.0% always, which "confirmed" nothing.
//!
//! ## The fix: measure each parameter from its OWN independent signal
//!
//! - `d_w` — median DURATION of WINDOW-ABSENT worker decode spans. Independent.
//! - `d_c` — median DURATION of CLEAN worker decode spans (report its n; if n
//!   is tiny it is cold-start garbage and is flagged unreliable). Independent.
//! - `L_resolve` — **the per-link SERIAL resolve/publish WORK**, measured as the
//!   median DURATION of the in-order consumer's publish span (the B/E span that
//!   wraps `apply_window`/marker-resolution/`getLastWindow`+emplace), NOT the
//!   inter-publish gap. This is a busy-duration the consumer actually spends,
//!   so it is INDEPENDENT of where the publishes land in time. The wall is then
//!   a genuine PREDICTION whose residual is nonzero and meaningful.
//! - `frontier` — first publish ts − trace start. `tail` — wall-end − last
//!   publish ts. `N`, `T`, window-absent fraction `f` — independent.
//!
//! `chain_gap` (mean inter-publish gap) is RETAINED but DEMOTED to a purely
//! DESCRIPTIVE decomposition of the observed publish stream — it is NEVER fed
//! into `wall_pred`. It is reported alongside `L_resolve` so the analyst can
//! see how much of the inter-publish time is real resolve work (`L_resolve`)
//! vs idle/overlap (`chain_gap − L_resolve`).
//!
//! ```text
//! wall_pred ≈ max( worker-bound:  frontier + (N/T)·d_w_eff ,
//!                  publish-chain: frontier + (N−1)·L_resolve_independent )  + tail
//! residual  = (wall_pred − wall_observed) / wall_observed     (NONZERO = GOOD)
//! ```
//!
//! ## Span-name ingestion (both tools, one view)
//!
//! Decode spans (d_c/d_w):
//!   - rapidgzip: `worker.decode`, arg `mode` ∈ {clean, window_absent}.
//!   - gzippy:    `worker.decode_chunk`, arg `mode` when present, else derived
//!                from `speculative` (true ⇒ window_absent bootstrap).
//!
//! Publish spans (L_resolve, frontier, tail, N) — the in-order consumer publish:
//!   - rapidgzip: `causal.window_publish` — a B/E SPAN (its duration is the
//!     emplace/getLastWindow serial work) when the trace patch wraps it; an
//!     instant (ph="i") is still accepted for ordering/frontier/tail but yields
//!     NO independent L_resolve (flagged).
//!   - gzippy:    `consumer.window_publish_clean` / `consumer.window_publish_marker`
//!     — B/E spans whose duration is the serial resolve work.

use crate::trace::{pair_spans, wall_us, Event, Span};

/// Span names that carry per-chunk worker decode duration.
const DECODE_SPAN_NAMES: &[&str] = &["worker.decode", "worker.decode_chunk"];

/// Span/event names for the in-order consumer tail-window publish.
const PUBLISH_NAMES: &[&str] = &[
    "causal.window_publish",
    "consumer.window_publish",
    "consumer.window_publish_clean",
    "consumer.window_publish_marker",
];

/// One tool's populated parameter set + the model's prediction.
#[derive(Debug, Clone)]
pub struct ModelParams {
    pub label: String,
    /// Worker count T (from --workers or detected).
    pub workers: u64,
    /// Number of chunks (distinct publishes in consumer order).
    pub n_chunks: usize,
    /// Window-absent decode latency/chunk, µs (median of window_absent decode
    /// span durations). INDEPENDENT.
    pub d_w_us: Option<f64>,
    /// Number of window-absent decode spans the median is over.
    pub n_d_w: usize,
    /// Clean decode latency/chunk, µs (median of clean decode span durations).
    /// INDEPENDENT.
    pub d_c_us: Option<f64>,
    /// Number of clean decode spans the median is over. Small n ⇒ cold-start
    /// garbage; see `d_c_reliable`.
    pub n_d_c: usize,
    /// False when `n_d_c` is too small to trust d_c (cold-start chunk-0 only).
    pub d_c_reliable: bool,
    /// Runtime window-absent fraction f (window_absent decodes / total decodes).
    pub window_absent_frac: f64,
    /// Effective per-chunk decode latency d_w_eff = f·d_w + (1−f)·d_c, µs.
    pub d_w_eff_us: Option<f64>,
    /// THE parameter, measured INDEPENDENTLY: per-link serial resolve/publish
    /// WORK = median DURATION of the consumer publish span. None when the trace
    /// only has instant publishes (no duration to measure) — then the model
    /// CANNOT predict the publish-chain term and says so.
    pub l_resolve_us: Option<f64>,
    /// Number of consumer publish SPANS (with duration) the median is over.
    pub n_publish_spans: usize,
    /// p95 of the consumer publish span duration (tail resolve stalls).
    pub l_resolve_p95_us: Option<f64>,
    /// DESCRIPTIVE ONLY (never fed into wall_pred): MEAN inter-publish gap =
    /// (last − first)/(N−1). The OLD edition mislabeled this "L_resolve" and
    /// built the tautology on it. Kept so the analyst sees how much of the
    /// inter-publish time is real resolve work (l_resolve_us) vs idle/overlap.
    pub chain_gap_mean_us: Option<f64>,
    /// DESCRIPTIVE: median inter-publish gap.
    pub chain_gap_median_us: Option<f64>,
    /// Startup before steady state: first publish ts − trace start, µs.
    pub frontier_us: f64,
    /// Drain after the last publish: wall-end − last publish ts, µs.
    pub tail_us: f64,
    /// Observed wall, µs (max span end − min span start).
    pub observed_wall_us: f64,
    /// Predicted worker-bound term: frontier + (N/T)·d_w_eff, µs.
    pub worker_bound_us: Option<f64>,
    /// Predicted publish-chain term: frontier + (N−1)·L_resolve_independent, µs.
    pub publish_chain_us: Option<f64>,
    /// wall_pred = max(worker_bound, publish_chain) + tail, µs.
    pub wall_pred_us: Option<f64>,
    /// Which term binds the prediction.
    pub binding: Binding,
    /// Number of decode spans seen (decode-mode coverage).
    pub n_decode_spans: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    WorkerBound,
    PublishChain,
    Unknown,
}

impl Binding {
    pub fn label(self) -> &'static str {
        match self {
            Binding::WorkerBound => "worker-bound",
            Binding::PublishChain => "publish-chain",
            Binding::Unknown => "unknown",
        }
    }
}

/// Minimum clean-decode span count below which d_c is cold-start garbage.
const MIN_RELIABLE_DC: usize = 4;

/// Median of a slice (sorted copy). None if empty.
pub fn median(xs: &[f64]) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    })
}

/// p-th percentile (0..=100) via nearest-rank on a sorted copy.
pub fn percentile(xs: &[f64], p: f64) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = (p / 100.0 * (v.len() as f64 - 1.0)).round() as usize;
    Some(v[rank.min(v.len() - 1)])
}

fn arg_u64(args: &serde_json::Value, key: &str) -> Option<u64> {
    match args.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

fn arg_str(args: &serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn arg_bool(args: &serde_json::Value, key: &str) -> Option<bool> {
    match args.get(key) {
        Some(serde_json::Value::Bool(b)) => Some(*b),
        Some(serde_json::Value::String(s)) => match s.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Decode mode for one decode span. Prefers an explicit `mode` arg (rapidgzip
/// patch + any gzippy span tagged with it); falls back to gzippy's
/// `speculative` arg (a speculative prefetch decodes WITHOUT the predecessor
/// window ⇒ window_absent bootstrap).
#[derive(PartialEq, Eq, Clone, Copy)]
enum DecodeMode {
    Clean,
    WindowAbsent,
    Unknown,
}

fn decode_mode(args: &serde_json::Value) -> DecodeMode {
    match arg_str(args, "mode").as_deref() {
        Some("clean") => return DecodeMode::Clean,
        Some("window_absent") => return DecodeMode::WindowAbsent,
        _ => {}
    }
    match arg_bool(args, "speculative") {
        Some(true) => DecodeMode::WindowAbsent,
        Some(false) => DecodeMode::Clean,
        None => DecodeMode::Unknown,
    }
}

/// A single in-order publish, with its serial-work DURATION.
#[derive(Debug, Clone)]
struct Publish {
    ts: f64,
    /// Span duration (the independent serial resolve work). 0.0 if the publish
    /// was an instant (no duration available).
    dur: f64,
    /// True iff this publish came from a B/E span (so `dur` is a real measured
    /// serial cost, not a synthetic 0).
    has_duration: bool,
    end_bit: Option<u64>,
}

// (collect_window_publishes removed — publish collection is now inline in
// analyze(), using B/E spans first to capture independent resolve durations.)

/// Populate the parameter set + prediction for one trace.
///
/// `workers` overrides the detected T when `Some`.
pub fn analyze(events: &[Event], label: &str, workers: Option<u64>) -> ModelParams {
    let spans: Vec<Span> = pair_spans(events);
    let observed_wall_us = wall_us(&spans);
    let trace_start = spans
        .iter()
        .map(|s| s.ts_start)
        .fold(f64::INFINITY, f64::min);
    let trace_start = if trace_start.is_finite() {
        trace_start
    } else {
        0.0
    };

    // ── decode-mode JOIN map: `worker.decode_mode` instant (gzippy authoritative)
    //    overrides the span's `speculative` / `mode` arg. Build start_bit → mode.
    let mut mode_by_start_bit: std::collections::HashMap<u64, DecodeMode> =
        std::collections::HashMap::new();
    for e in events {
        if e.ph == "i" && e.name == "worker.decode_mode" {
            if let (Some(sb), Some(m)) = (arg_u64(&e.args, "start_bit"), arg_str(&e.args, "mode")) {
                let dm = match m.as_str() {
                    "clean" => DecodeMode::Clean,
                    "window_absent" => DecodeMode::WindowAbsent,
                    _ => DecodeMode::Unknown,
                };
                mode_by_start_bit.insert(sb, dm);
            }
        }
    }

    // ── d_c / d_w from decode span durations, split by mode ──────────────────
    let mut clean_durs: Vec<f64> = Vec::new();
    let mut absent_durs: Vec<f64> = Vec::new();
    for s in &spans {
        if !DECODE_SPAN_NAMES.contains(&s.name.as_str()) {
            continue;
        }
        // Prefer the authoritative joined mode (worker.decode_mode instant),
        // then the span's own `mode`/`speculative` arg (rapidgzip + fallback).
        let mode = s
            .arg_u64("start_bit")
            .and_then(|sb| mode_by_start_bit.get(&sb).copied())
            .unwrap_or_else(|| decode_mode(&s.args));
        match mode {
            DecodeMode::Clean => clean_durs.push(s.dur),
            DecodeMode::WindowAbsent => absent_durs.push(s.dur),
            DecodeMode::Unknown => {}
        }
    }
    let n_decode_spans = clean_durs.len() + absent_durs.len();
    let n_d_c = clean_durs.len();
    let n_d_w = absent_durs.len();
    let d_c_reliable = n_d_c >= MIN_RELIABLE_DC;

    // Runtime window-absent fraction: `causal.decode_decision` is authoritative
    // (one instant per worker decode start, gzippy-only); fall back to span classification.
    let mut n_clean_decisions = 0usize;
    let mut n_absent_decisions = 0usize;
    for e in events {
        if e.ph == "i" && e.name == "causal.decode_decision" {
            match arg_str(&e.args, "mode").as_deref() {
                Some("clean") => n_clean_decisions += 1,
                Some("window_absent") => n_absent_decisions += 1,
                _ => {}
            }
        }
    }
    let n_mode_decisions = n_clean_decisions + n_absent_decisions;
    let window_absent_frac = if n_mode_decisions > 0 {
        n_absent_decisions as f64 / n_mode_decisions as f64
    } else if n_decode_spans > 0 {
        absent_durs.len() as f64 / n_decode_spans as f64
    } else {
        0.0
    };

    // Per-mode decode latency: prefer joined `worker.decode_chunk`; fall back to
    // the phase spans gzippy actually emits (bootstrap = marker, stream_inflate =
    // clean tail on pure-Rust builds).
    let mut bootstrap_durs: Vec<f64> = Vec::new();
    let mut clean_tail_durs: Vec<f64> = Vec::new();
    for s in &spans {
        match s.name.as_str() {
            "worker.bootstrap" => bootstrap_durs.push(s.dur),
            "worker.stream_inflate" | "worker.isal_stream_inflate" => clean_tail_durs.push(s.dur),
            _ => {}
        }
    }
    let d_c_us = median(&clean_durs).or_else(|| median(&clean_tail_durs));
    let d_w_us = median(&absent_durs).or_else(|| median(&bootstrap_durs));
    // d_w_eff weights the two decode latencies by the runtime window-absent
    // fraction. If only one mode exists, fall back to whichever exists.
    let d_w_eff_us = match (d_w_us, d_c_us) {
        (Some(dw), Some(dc)) => Some(window_absent_frac * dw + (1.0 - window_absent_frac) * dc),
        (Some(dw), None) => Some(dw),
        (None, Some(dc)) => Some(dc),
        (None, None) => None,
    };

    // ── publishes: prefer B/E SPANS (carry the independent resolve DURATION for
    //    L_resolve), fall back to instant events (ordering/frontier/tail only). ─
    let mut publishes: Vec<Publish> = Vec::new();
    for s in &spans {
        if PUBLISH_NAMES.contains(&s.name.as_str()) {
            publishes.push(Publish {
                ts: s.ts_start,
                dur: s.dur,
                has_duration: true,
                end_bit: arg_u64(&s.args, "end_bit"),
            });
        }
    }
    if publishes.is_empty() {
        // No B/E publish spans — accept instant publishes for ordering only.
        for e in events {
            if e.ph == "i" && PUBLISH_NAMES.contains(&e.name.as_str()) {
                publishes.push(Publish {
                    ts: e.ts,
                    dur: 0.0,
                    has_duration: false,
                    end_bit: arg_u64(&e.args, "end_bit"),
                });
            }
        }
    }
    // The in-order consumer emits publishes in chunk-index order; sort by ts to
    // recover the true publish sequence regardless of file interleave.
    publishes.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap_or(std::cmp::Ordering::Equal));
    // De-dup identical end_bit (an eager-early + later redundant publish of the
    // SAME chunk would double-count a link). Keep the FIRST (earliest unblocks
    // the successor).
    let mut seen_endbits: std::collections::HashSet<u64> = std::collections::HashSet::new();
    publishes.retain(|p| match p.end_bit {
        Some(eb) => seen_endbits.insert(eb),
        None => true,
    });

    let n_chunks = if !publishes.is_empty() {
        publishes.len()
    } else {
        // Fallback: count distinct decode_chunk spans, or causal.decode_decision
        // instants if decode spans aren't present (prefetch-only traces).
        let from_decode = spans
            .iter()
            .filter(|s| s.name == "worker.decode_chunk")
            .count();
        if from_decode > 0 {
            from_decode
        } else if n_mode_decisions > 0 {
            n_mode_decisions
        } else {
            0
        }
    };
    let frontier_us = publishes.first().map(|p| p.ts - trace_start).unwrap_or(0.0);
    let last_publish_ts = publishes.last().map(|p| p.ts);
    let tail_us = match last_publish_ts {
        Some(lp) => (trace_start + observed_wall_us) - lp,
        None => 0.0,
    };

    // ── L_resolve: INDEPENDENT serial resolve WORK = publish span durations ───
    // Only spans with a real measured duration count. If none, L_resolve is
    // None and the publish-chain term is unpopulated — we DO NOT fall back to
    // the inter-publish gap (that is the tautology).
    let resolve_durs: Vec<f64> = publishes
        .iter()
        .filter(|p| p.has_duration)
        .map(|p| p.dur)
        .collect();
    let n_publish_spans = resolve_durs.len();
    let l_resolve_us = median(&resolve_durs);
    let l_resolve_p95_us = percentile(&resolve_durs, 95.0);

    // ── chain_gap: DESCRIPTIVE ONLY (never fed into wall_pred) ────────────────
    let mut gaps: Vec<f64> = Vec::new();
    for w in publishes.windows(2) {
        let g = w[1].ts - w[0].ts;
        if g >= 0.0 {
            gaps.push(g);
        }
    }
    let chain_gap_mean_us = if gaps.is_empty() {
        None
    } else {
        Some(gaps.iter().sum::<f64>() / gaps.len() as f64)
    };
    let chain_gap_median_us = median(&gaps);

    // ── T ────────────────────────────────────────────────────────────────────
    let workers = workers
        .or_else(|| detect_parallelization(events))
        .unwrap_or(1)
        .max(1);

    // ── prediction (uses the INDEPENDENT L_resolve) ───────────────────────────
    let n = n_chunks as f64;
    let worker_bound_us = d_w_eff_us.map(|dwe| frontier_us + (n / workers as f64) * dwe);
    // Publish-chain: the in-order consumer pays L_resolve of SERIAL work per
    // link, over (N−1) links after the frontier. Because L_resolve is measured
    // independently (span duration, not the inter-publish gap), this is a
    // genuine prediction: if the consumer's serial work doesn't reconstruct the
    // first→last publish span, the residual is NONZERO — telling us how much of
    // the chain is overlap/slack the simple serial-sum model omits.
    let n_links = (n - 1.0).max(0.0);
    let publish_chain_us = l_resolve_us.map(|lr| frontier_us + n_links * lr);
    let (wall_pred_us, binding) = match (worker_bound_us, publish_chain_us) {
        (Some(wb), Some(pc)) => {
            if pc >= wb {
                (Some(pc + tail_us), Binding::PublishChain)
            } else {
                (Some(wb + tail_us), Binding::WorkerBound)
            }
        }
        (Some(wb), None) => (Some(wb + tail_us), Binding::WorkerBound),
        (None, Some(pc)) => (Some(pc + tail_us), Binding::PublishChain),
        (None, None) => (None, Binding::Unknown),
    };

    ModelParams {
        label: label.to_string(),
        workers,
        n_chunks,
        d_w_us,
        n_d_w,
        d_c_us,
        n_d_c,
        d_c_reliable,
        window_absent_frac,
        d_w_eff_us,
        l_resolve_us,
        n_publish_spans,
        l_resolve_p95_us,
        chain_gap_mean_us,
        chain_gap_median_us,
        frontier_us,
        tail_us,
        observed_wall_us,
        worker_bound_us,
        publish_chain_us,
        wall_pred_us,
        binding,
        n_decode_spans,
    }
}

/// Read T off a `drive` span's `parallelization` arg, if present.
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

/// Residual = (wall_pred − observed) / observed, as a signed fraction. With
/// INDEPENDENT parameters this is genuinely nonzero — its sign tells you
/// whether the serial-sum model OVER-predicts (serial work overlaps in
/// reality ⇒ positive) or UNDER-predicts (unmodeled serial term ⇒ negative).
pub fn residual_frac(p: &ModelParams) -> Option<f64> {
    p.wall_pred_us
        .map(|pred| (pred - p.observed_wall_us) / p.observed_wall_us.max(1.0))
}

/// The gzippy−rapidgzip delta + named lever.
#[derive(Debug, Clone)]
pub struct ModelDelta {
    pub a_label: String,
    pub b_label: String,
    /// ratio b/a for each parameter (>1 ⇒ b is larger/slower).
    pub d_w_ratio: Option<f64>,
    pub d_c_ratio: Option<f64>,
    pub l_resolve_ratio: Option<f64>,
    pub frac_a: f64,
    pub frac_b: f64,
    pub wall_ratio: f64,
    /// The lever: which parameter's delta most explains the wall gap.
    pub lever: String,
    /// Which single INDEPENDENT parameter the slower tool is WORST on relative
    /// to the reference — for the holistic design step.
    pub worst_param: String,
}

/// Compare two populated parameter sets. `a` is the baseline (gzippy), `b` the
/// faster reference (rapidgzip). The lever is whichever model term binds the
/// SLOWER tool AND differs most between tools.
pub fn delta(a: &ModelParams, b: &ModelParams) -> ModelDelta {
    let ratio = |x: Option<f64>, y: Option<f64>| match (x, y) {
        (Some(x), Some(y)) if x > 0.0 => Some(y / x),
        _ => None,
    };
    let wall_ratio = a.observed_wall_us / b.observed_wall_us.max(1.0);

    let (slower, faster) = if a.observed_wall_us >= b.observed_wall_us {
        (a, b)
    } else {
        (b, a)
    };
    let l_ratio = ratio(a.l_resolve_us, b.l_resolve_us);
    let dw_ratio = ratio(a.d_w_us, b.d_w_us);
    let dc_ratio = ratio(a.d_c_us, b.d_c_us);

    let lever = match slower.binding {
        Binding::PublishChain => {
            let gap_us = match (a.l_resolve_us, b.l_resolve_us) {
                (Some(la), Some(lb)) => (la - lb).abs() * (slower.n_chunks as f64 - 1.0).max(0.0),
                _ => 0.0,
            };
            format!(
                "L_resolve (publish-chain binds the slower tool {}): {} vs {} per link \
                 ⇒ ~{} of wall on {} links{}",
                slower.label,
                slower
                    .l_resolve_us
                    .map(crate::trace::fmt_us)
                    .unwrap_or_else(|| "?".into()),
                faster
                    .l_resolve_us
                    .map(crate::trace::fmt_us)
                    .unwrap_or_else(|| "?".into()),
                crate::trace::fmt_us(gap_us),
                (slower.n_chunks as i64 - 1).max(0),
                knee_caveat(slower, faster),
            )
        }
        Binding::WorkerBound => {
            let gap_us = match (a.d_w_eff_us, b.d_w_eff_us) {
                (Some(da), Some(db)) => {
                    (da - db).abs() * slower.n_chunks as f64 / slower.workers as f64
                }
                _ => 0.0,
            };
            format!(
                "d_w_eff (worker-bound binds the slower tool {}): {} vs {} per chunk \
                 ⇒ ~{} of wall over N/T={:.1} serial decode-slots",
                slower.label,
                slower
                    .d_w_eff_us
                    .map(crate::trace::fmt_us)
                    .unwrap_or_else(|| "?".into()),
                faster
                    .d_w_eff_us
                    .map(crate::trace::fmt_us)
                    .unwrap_or_else(|| "?".into()),
                crate::trace::fmt_us(gap_us),
                slower.n_chunks as f64 / slower.workers as f64,
            )
        }
        Binding::Unknown => "indeterminate (a term could not be populated — \
            missing decode spans or publish spans/instants)"
            .to_string(),
    };

    // Worst parameter: the largest slower/faster ratio among the independently
    // measured ones. Drives the holistic design step.
    let worst_param = {
        let cand: [(&str, Option<f64>); 3] = [
            (
                "d_w",
                ratio(b.d_w_us, a.d_w_us).or(ratio(a.d_w_us, b.d_w_us)),
            ),
            (
                "d_c",
                ratio(b.d_c_us, a.d_c_us).or(ratio(a.d_c_us, b.d_c_us)),
            ),
            (
                "L_resolve",
                ratio(b.l_resolve_us, a.l_resolve_us).or(ratio(a.l_resolve_us, b.l_resolve_us)),
            ),
        ];
        cand.iter()
            .filter_map(|(n, r)| r.map(|r| (*n, (r - 1.0).abs())))
            .max_by(|x, y| x.1.partial_cmp(&y.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(n, _)| n.to_string())
            .unwrap_or_else(|| "indeterminate".into())
    };

    ModelDelta {
        a_label: a.label.clone(),
        b_label: b.label.clone(),
        d_w_ratio: dw_ratio,
        d_c_ratio: dc_ratio,
        l_resolve_ratio: l_ratio,
        frac_a: a.window_absent_frac,
        frac_b: b.window_absent_frac,
        wall_ratio,
        lever,
        worst_param,
    }
}

/// If reducing the slower tool's L_resolve to the faster tool's value would
/// push the publish-chain term BELOW the slower tool's own worker-bound term,
/// the worker-bound knee caps the win — say so.
fn knee_caveat(slower: &ModelParams, faster: &ModelParams) -> String {
    match (faster.l_resolve_us, slower.worker_bound_us) {
        (Some(target_lr), Some(wb)) => {
            let projected_chain =
                slower.frontier_us + (slower.n_chunks as f64 - 1.0).max(0.0) * target_lr;
            if projected_chain < wb {
                format!(
                    " — BUT the worker-bound knee caps it: at the faster L_resolve the \
                     publish-chain term ({}) drops below the slower tool's worker-bound term \
                     ({}), so cutting L_resolve stops paying there",
                    crate::trace::fmt_us(projected_chain),
                    crate::trace::fmt_us(wb),
                )
            } else {
                " — worker-bound knee is above the target, so the full L_resolve cut pays"
                    .to_string()
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_span(name: &str, mode: &str, tid: u64, t0: f64, t1: f64) -> [Event; 2] {
        let args = serde_json::json!({ "mode": mode, "start_bit": (t0 as u64) });
        [
            Event {
                name: name.into(),
                ph: "B".into(),
                ts: t0,
                pid: 1,
                tid,
                args: args.clone(),
            },
            Event {
                name: name.into(),
                ph: "E".into(),
                ts: t1,
                pid: 1,
                tid,
                args,
            },
        ]
    }

    /// A consumer publish as a B/E SPAN whose DURATION is the serial resolve
    /// work (the independent L_resolve signal).
    fn publish_span(t0: f64, dur: f64, end_bit: u64) -> [Event; 2] {
        let args = serde_json::json!({ "start_bit": end_bit - 100, "end_bit": end_bit, "site": "consumer" });
        [
            Event {
                name: "consumer.window_publish_marker".into(),
                ph: "B".into(),
                ts: t0,
                pid: 1,
                tid: 1,
                args: args.clone(),
            },
            Event {
                name: "consumer.window_publish_marker".into(),
                ph: "E".into(),
                ts: t0 + dur,
                pid: 1,
                tid: 1,
                args,
            },
        ]
    }

    /// Anti-tautology synthetic trace. The hand-known INDEPENDENT parameters
    /// DIFFER from the inter-publish gap, so a tautological (gap-based) model
    /// would produce a DIFFERENT prediction and FAIL the asserts below.
    ///
    /// Setup: T=4, N=8, all window-absent (f=1), d_w=40ms.
    ///   Publishes at t = 20,30,40,50,60,70,80,90 ms ⇒ inter-publish GAP = 10ms.
    ///   Each publish SPAN duration (independent L_resolve) = 2ms — DELIBERATELY
    ///     != the 10ms gap. The serial resolve work is only 2ms/link; the other
    ///     8ms/link is overlap/idle.
    ///   Wall anchored 0..100ms ⇒ tail = 100 − 90 = 10ms.
    /// Expected (independent model):
    ///   worker-bound  = frontier + (N/T)·d_w       = 20 + (8/4)·40 = 100ms
    ///   publish-chain = frontier + (N−1)·L_resolve = 20 + 7·2       = 34ms
    ///   max = worker-bound 100ms ⇒ wall_pred = 100 + tail(10) = 110ms.
    /// A TAUTOLOGICAL model would compute publish-chain = 20 + 7·10 = 90ms =
    /// last_publish, and (if it bound) wall_pred = 90 + 10 = 100ms = wall
    /// EXACTLY (residual +0.0%). The asserts below pin L_resolve=2ms (NOT 10ms)
    /// and publish-chain=34ms (NOT 90ms) — so re-introducing the gap-as-
    /// L_resolve tautology breaks this test.
    /// `causal.decode_decision` is authoritative for window_absent_frac even when
    /// decode spans are also present: 9 absent + 1 clean decisions ⇒ frac = 0.9,
    /// regardless of what the span's mode arg says. The decode span DOES get
    /// classified via its own `mode` arg (branch behavior: decode_mode fallback),
    /// so n_decode_spans = 1 even though its start_bit has no decision event.
    #[test]
    fn window_absent_frac_from_decode_decisions_not_chunk_join() {
        let mut events: Vec<Event> = Vec::new();
        for i in 0..9u64 {
            events.push(Event {
                name: "causal.decode_decision".into(),
                ph: "i".into(),
                ts: 1000.0 + i as f64,
                pid: 1,
                tid: 2,
                args: serde_json::json!({ "start_bit": i * 1000, "mode": "window_absent" }),
            });
        }
        events.push(Event {
            name: "causal.decode_decision".into(),
            ph: "i".into(),
            ts: 2000.0,
            pid: 1,
            tid: 2,
            args: serde_json::json!({ "start_bit": 9000u64, "mode": "clean" }),
        });
        // decode_chunk with its own mode arg — start_bit reset to 999_999 (no
        // matching decision event). The span IS classified via decode_mode()
        // reading its `mode` arg → n_decode_spans = 1.
        events.extend(decode_span("worker.decode_chunk", "window_absent", 2, 0.0, 10_000.0));
        for e in &mut events {
            if e.name == "worker.decode_chunk" {
                if let Some(o) = e.args.as_object_mut() {
                    o.insert("start_bit".into(), serde_json::json!(999_999u64));
                }
            }
        }
        // One instant publish so n_chunks > 0.
        events.push(Event {
            name: "causal.window_publish".into(),
            ph: "i".into(),
            ts: 50_000.0,
            pid: 1,
            tid: 1,
            args: serde_json::json!({ "end_bit": 100u64 }),
        });
        events.push(Event {
            name: "drive".into(),
            ph: "B".into(),
            ts: 0.0,
            pid: 1,
            tid: 1,
            args: serde_json::Value::Null,
        });
        events.push(Event {
            name: "drive".into(),
            ph: "E".into(),
            ts: 100_000.0,
            pid: 1,
            tid: 1,
            args: serde_json::Value::Null,
        });
        let p = analyze(&events, "decisions_frac", Some(4));
        assert!(
            (p.window_absent_frac - 0.9).abs() < 1e-9,
            "window_absent_frac={} (expected 0.9 from decisions)",
            p.window_absent_frac
        );
        // Branch approach: span IS classified via decode_mode() fallback → n_decode_spans=1
        assert_eq!(p.n_decode_spans, 1);
    }

    #[test]
    fn independent_l_resolve_is_not_the_publish_gap() {
        let mut events: Vec<Event> = Vec::new();
        for i in 0..8u64 {
            let tid = 2 + (i % 4);
            let t0 = 1000.0 + i as f64 * 1000.0;
            events.extend(decode_span(
                "worker.decode_chunk",
                "window_absent",
                tid,
                t0,
                t0 + 40_000.0,
            ));
        }
        // Publishes 10ms apart, each a 2ms span. First at 20ms.
        for i in 0..8u64 {
            events.extend(publish_span(
                20_000.0 + i as f64 * 10_000.0,
                2_000.0,
                1000 + i * 100,
            ));
        }
        // Wall anchor 0..100ms.
        events.push(Event {
            name: "drive".into(),
            ph: "B".into(),
            ts: 0.0,
            pid: 1,
            tid: 1,
            args: serde_json::json!({ "parallelization": 4 }),
        });
        events.push(Event {
            name: "drive".into(),
            ph: "E".into(),
            ts: 100_000.0,
            pid: 1,
            tid: 1,
            args: serde_json::Value::Null,
        });

        let p = analyze(&events, "synthetic", Some(4));
        assert_eq!(p.workers, 4);
        assert_eq!(p.n_chunks, 8);
        assert_eq!(p.n_decode_spans, 8);
        assert_eq!(p.d_w_us, Some(40_000.0), "d_w median");
        assert!((p.window_absent_frac - 1.0).abs() < 1e-9);
        assert_eq!(p.d_w_eff_us, Some(40_000.0));

        // THE anti-tautology assertions: L_resolve is the SPAN DURATION (2ms),
        // NOT the inter-publish gap (10ms).
        assert_eq!(
            p.l_resolve_us,
            Some(2_000.0),
            "L_resolve = independent span duration, not gap"
        );
        assert_eq!(p.n_publish_spans, 8, "all 8 publishes are B/E spans");
        assert_eq!(
            p.chain_gap_mean_us,
            Some(10_000.0),
            "chain_gap is descriptive = 10ms gap"
        );
        // The two MUST differ — that is the whole point.
        assert_ne!(
            p.l_resolve_us, p.chain_gap_mean_us,
            "tautology returned: L_resolve == gap"
        );

        // frontier = 20ms, tail = 100−90 = 10ms.
        assert!(
            (p.frontier_us - 20_000.0).abs() < 1.0,
            "frontier {}",
            p.frontier_us
        );
        assert!((p.tail_us - 10_000.0).abs() < 1.0, "tail {}", p.tail_us);

        // publish-chain = 20 + 7·2 = 34ms (NOT the tautological 90ms).
        assert!(
            (p.publish_chain_us.unwrap() - 34_000.0).abs() < 1.0,
            "publish_chain {} (tautology would give 90ms)",
            p.publish_chain_us.unwrap()
        );
        // worker-bound = 20 + 2·40 = 100ms; binds.
        assert!((p.worker_bound_us.unwrap() - 100_000.0).abs() < 1.0);
        assert_eq!(p.binding, Binding::WorkerBound);
        // wall_pred = 100 + 10 = 110ms ≠ wall(100ms) ⇒ residual = +10% (REAL,
        // nonzero — proves the prediction is not a telescoping identity).
        assert!(
            (p.wall_pred_us.unwrap() - 110_000.0).abs() < 1.0,
            "wall_pred {}",
            p.wall_pred_us.unwrap()
        );
        let r = residual_frac(&p).unwrap();
        assert!(
            (r - 0.10).abs() < 1e-3,
            "residual {r} should be +10% (nonzero)"
        );
        assert!(
            r.abs() > 1e-6,
            "residual must be NONZERO — a +0.0% is the tautology"
        );
    }

    /// When publish-chain binds, the independent model must STILL yield a
    /// nonzero residual (the tautology guard for the publish-chain branch).
    #[test]
    fn publish_chain_binds_with_nonzero_residual() {
        let mut events: Vec<Event> = Vec::new();
        // Slow resolve: L_resolve span = 20ms each; fast decode 10ms, T=8, N=10.
        for i in 0..10u64 {
            let t0 = i as f64 * 100.0;
            events.extend(decode_span(
                "worker.decode_chunk",
                "window_absent",
                2 + i % 8,
                t0,
                t0 + 10_000.0,
            ));
        }
        // Publishes 25ms apart (gap), each a 20ms span (independent L_resolve).
        // gap(25ms) != L_resolve(20ms) ⇒ a gap-tautology would mispredict.
        for i in 0..10u64 {
            events.extend(publish_span(i as f64 * 25_000.0, 20_000.0, 1000 + i * 100));
        }
        let p = analyze(&events, "slow", Some(8));
        // worker-bound  = 0 + (10/8)·10 = 12.5ms
        // publish-chain = 0 + 9·20      = 180ms  ⇒ binds.
        assert_eq!(p.binding, Binding::PublishChain, "publish-chain binds");
        assert_eq!(p.l_resolve_us, Some(20_000.0), "L_resolve = span duration");
        assert_ne!(
            p.l_resolve_us, p.chain_gap_mean_us,
            "L_resolve must differ from gap"
        );
        // wall_pred = 180 + tail (NONZERO residual since 180 != first→last span).
        let r = residual_frac(&p).unwrap();
        assert!(
            r.abs() > 1e-3,
            "residual {r} must be nonzero (not a tautology)"
        );
    }

    /// Delta names L_resolve as lever when publish-chain binds the slower tool.
    #[test]
    fn delta_names_l_resolve_lever() {
        let mut a_events: Vec<Event> = Vec::new();
        for i in 0..10u64 {
            let t0 = i as f64 * 100.0;
            a_events.extend(decode_span(
                "worker.decode_chunk",
                "window_absent",
                2 + i % 8,
                t0,
                t0 + 10_000.0,
            ));
        }
        for i in 0..10u64 {
            a_events.extend(publish_span(i as f64 * 25_000.0, 20_000.0, 1000 + i * 100));
        }
        let a = analyze(&a_events, "slow", Some(8));
        assert_eq!(a.binding, Binding::PublishChain);

        let mut b_events: Vec<Event> = Vec::new();
        for i in 0..10u64 {
            let t0 = i as f64 * 100.0;
            b_events.extend(decode_span(
                "worker.decode_chunk",
                "window_absent",
                2 + i % 8,
                t0,
                t0 + 10_000.0,
            ));
        }
        // Fast resolve: 4ms spans, 5ms gaps.
        for i in 0..10u64 {
            b_events.extend(publish_span(i as f64 * 5_000.0, 4_000.0, 1000 + i * 100));
        }
        let b = analyze(&b_events, "fast", Some(8));

        let d = delta(&a, &b);
        assert!(d.lever.contains("L_resolve"), "lever: {}", d.lever);
        // L_resolve ratio b/a = 4/20 = 0.2.
        assert!((d.l_resolve_ratio.unwrap() - 0.2).abs() < 1e-6);
    }

    /// Instant-only publishes (old rapidgzip patch) ⇒ NO independent L_resolve.
    /// The model must NOT fabricate one from the gap; publish-chain unpopulated.
    #[test]
    fn instant_publishes_yield_no_independent_l_resolve() {
        let mut events: Vec<Event> = Vec::new();
        for i in 0..4u64 {
            let t0 = i as f64 * 100.0;
            events.extend(decode_span(
                "worker.decode",
                "window_absent",
                2 + i,
                t0,
                t0 + 10_000.0,
            ));
        }
        for i in 0..4u64 {
            events.push(Event {
                name: "causal.window_publish".into(),
                ph: "i".into(),
                ts: i as f64 * 5_000.0,
                pid: 1,
                tid: 1,
                args: serde_json::json!({ "end_bit": 1000 + i * 100 }),
            });
        }
        let p = analyze(&events, "instant-only", Some(4));
        assert_eq!(
            p.n_chunks, 4,
            "instant publishes still counted for N/frontier/tail"
        );
        assert_eq!(p.n_publish_spans, 0, "no B/E publish spans");
        assert_eq!(
            p.l_resolve_us, None,
            "no independent L_resolve from instants"
        );
        assert_eq!(
            p.publish_chain_us, None,
            "publish-chain cannot be predicted"
        );
        // chain_gap IS available (descriptive) but must not leak into the model.
        assert_eq!(p.chain_gap_mean_us, Some(5_000.0));
        assert_eq!(
            p.binding,
            Binding::WorkerBound,
            "only worker-bound is populated"
        );
    }

    /// gzippy derives decode mode from `speculative` when `mode` is absent.
    #[test]
    fn gzippy_speculative_arg_drives_mode() {
        let mut events: Vec<Event> = Vec::new();
        for i in 0..4u64 {
            let t0 = i as f64 * 1000.0;
            let spec = i % 2 == 0; // alternate
            let args = serde_json::json!({ "speculative": spec, "start_bit": t0 as u64 });
            events.push(Event {
                name: "worker.decode_chunk".into(),
                ph: "B".into(),
                ts: t0,
                pid: 1,
                tid: 2 + i,
                args: args.clone(),
            });
            events.push(Event {
                name: "worker.decode_chunk".into(),
                ph: "E".into(),
                ts: t0 + 5_000.0,
                pid: 1,
                tid: 2 + i,
                args,
            });
        }
        let p = analyze(&events, "gz", Some(4));
        assert_eq!(p.n_decode_spans, 4);
        assert_eq!(p.n_d_w, 2, "two speculative=true ⇒ window_absent");
        assert_eq!(p.n_d_c, 2, "two speculative=false ⇒ clean");
    }

    /// The `worker.decode_mode` instant (gzippy's authoritative mode) OVERRIDES
    /// the span's `speculative` arg when they disagree (a prefetch that raced
    /// the publish and ran CLEAN despite speculative=true).
    #[test]
    fn decode_mode_instant_overrides_speculative_arg() {
        let mut events: Vec<Event> = Vec::new();
        // Span at start_bit=500 tagged speculative=true (intent) but the
        // authoritative instant says it ran CLEAN.
        let span_args = serde_json::json!({ "speculative": true, "start_bit": 500u64 });
        events.push(Event {
            name: "worker.decode_chunk".into(),
            ph: "B".into(),
            ts: 0.0,
            pid: 1,
            tid: 2,
            args: span_args.clone(),
        });
        events.push(Event {
            name: "worker.decode_chunk".into(),
            ph: "E".into(),
            ts: 7_000.0,
            pid: 1,
            tid: 2,
            args: span_args,
        });
        events.push(Event {
            name: "worker.decode_mode".into(),
            ph: "i".into(),
            ts: 1.0,
            pid: 1,
            tid: 2,
            args: serde_json::json!({ "start_bit": 500u64, "mode": "clean" }),
        });
        let p = analyze(&events, "gz", Some(4));
        assert_eq!(p.n_d_c, 1, "instant mode=clean wins over speculative=true");
        assert_eq!(p.n_d_w, 0);
        assert_eq!(p.d_c_us, Some(7_000.0));
    }

    #[test]
    fn median_and_percentile_basic() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), Some(2.5));
        assert_eq!(median(&[]), None);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0, 5.0], 100.0), Some(5.0));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0, 5.0], 0.0), Some(1.0));
    }
}
