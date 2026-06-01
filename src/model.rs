//! model.rs — the PARALLEL-SM QUANTITATIVE-MODEL view.
//!
//! Populates, from a single Chrome-trace timeline, the parameters of the
//! advisor-validated wall model in
//! `gzippy/plans/parallel-sm-model.md`, computes the predicted wall, and
//! reports the residual against the observed wall. Given two traces (gzippy +
//! rapidgzip) it prints the per-parameter DELTA and names the implied lever.
//!
//! ## The model (verbatim from the spec)
//!
//! In-order parallel pipeline: `N` chunks, `T` workers decode in parallel, ONE
//! in-order consumer publishes each chunk's 32 KiB tail-window. A chunk decodes
//! CLEAN (fast windowed ISA-L) iff its predecessor's window is PUBLISHED when a
//! worker STARTS it, else WINDOW-ABSENT (slow bootstrap → u16 markers →
//! resolve).
//!
//! ```text
//! wall ≈ max( worker-bound:  frontier + (N/T)·d_w_eff ,
//!             publish-chain: frontier + N·L_resolve  )  + tail
//! ```
//!
//! - `d_w_eff` = per-chunk decode latency, weighted by the window-absent
//!   fraction f: `d_w_eff = f·d_w + (1−f)·d_c`.
//! - `L_resolve` = per-link publish latency = the inter-publish gap
//!   `t_publish(i) − t_publish(i−1)` on steady-state chunks. **This is the
//!   parameter the whole campaign is about** — the catch-up term is a LATENCY,
//!   not a throughput.
//! - There is a worker-bound KNEE: cutting `L_resolve` lowers the wall only
//!   until the worker-bound term becomes the max. The model PREDICTS the
//!   FastBootstrap TIE (decode sped, wall flat) when worker-bound binds.
//!
//! ## How the parameters are read off the trace (instrument-agnostic)
//!
//! Both gzippy and the patched rapidgzip emit the SAME shapes:
//!   - `worker.decode` B/E spans, args `{start_bit, mode}` where mode is
//!     `clean`|`window_absent` — split into d_c / d_w by median.
//!   - `causal.window_publish` instant events, args `{start_bit, end_bit,
//!     site, had_markers}`, emitted on the in-order consumer so trace order =
//!     chunk-index order. Consecutive-gap = L_resolve; first = frontier
//!     anchor; last → wall-end = tail.
//!
//! No code reading required: the same view runs on either tool, so the
//! gzippy−rapidgzip parameter delta is apples-to-apples.

use crate::trace::{pair_spans, wall_us, Event, Span};

/// One tool's populated parameter set + the model's prediction.
#[derive(Debug, Clone)]
pub struct ModelParams {
    pub label: String,
    /// Worker count T (from --workers or detected).
    pub workers: u64,
    /// Number of chunks (distinct window_publish events in consumer order).
    pub n_chunks: usize,
    /// Window-absent decode latency/chunk, µs (median of mode=window_absent
    /// `worker.decode` spans).
    pub d_w_us: Option<f64>,
    /// Clean decode latency/chunk, µs (median of mode=clean `worker.decode`).
    pub d_c_us: Option<f64>,
    /// Runtime window-absent fraction f (window_absent decodes / total decodes).
    pub window_absent_frac: f64,
    /// Effective per-chunk decode latency d_w_eff = f·d_w + (1−f)·d_c, µs.
    pub d_w_eff_us: Option<f64>,
    /// THE parameter: per-link publish latency, µs. MEAN inter-publish gap =
    /// (last_publish − first_publish)/(N−1) — the bimodal-robust summary the
    /// wall actually obeys (the publish distribution is bimodal: many ~0 gaps
    /// from eagerly-resolved chunks punctuated by a few large resolve stalls,
    /// so the MEDIAN understates the chain by an order of magnitude — see the
    /// 2026-05-31 <BENCH_HOST> measurement where rapidgzip's gap_median was 0.04ms
    /// but gap_mean 7.74ms). The publish-chain term uses this mean.
    pub l_resolve_us: Option<f64>,
    /// MEDIAN inter-publish gap, µs (diagnostic — typical fast-resolve link).
    pub l_resolve_median_us: Option<f64>,
    /// p95 of the inter-publish gap (tail-of-distribution diagnostic — the
    /// large resolve stalls that dominate the mean).
    pub l_resolve_p95_us: Option<f64>,
    /// Startup before steady state: first publish ts − trace start, µs.
    pub frontier_us: f64,
    /// Drain after the last publish: wall-end − last publish ts, µs.
    pub tail_us: f64,
    /// Observed wall, µs (max span end − min span start).
    pub observed_wall_us: f64,
    /// Predicted worker-bound term: frontier + (N/T)·d_w_eff, µs.
    pub worker_bound_us: Option<f64>,
    /// Predicted publish-chain term: frontier + N·L_resolve, µs.
    pub publish_chain_us: Option<f64>,
    /// wall_pred = max(worker_bound, publish_chain) + tail, µs.
    pub wall_pred_us: Option<f64>,
    /// Which term binds the prediction.
    pub binding: Binding,
    /// Number of `worker.decode` spans seen (decode-mode coverage).
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
    args.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// A single window-publish, in trace (= consumer = chunk-index) order.
#[derive(Debug, Clone)]
struct Publish {
    ts: f64,
    end_bit: Option<u64>,
}

/// Populate the parameter set + prediction for one trace.
///
/// `workers` overrides the detected T when `Some`. Steady-state for L_resolve
/// trims the first `frontier_skip` publishes (startup ramp) and the last
/// publish (tail), so the median reflects the link latency of the in-order
/// catch-up, not the cold ramp.
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

    // ── d_c / d_w from worker.decode span durations, split by mode ────────────
    let mut clean_durs: Vec<f64> = Vec::new();
    let mut absent_durs: Vec<f64> = Vec::new();
    for s in &spans {
        if s.name != "worker.decode" {
            continue;
        }
        match arg_str(&s.args, "mode").as_deref() {
            Some("clean") => clean_durs.push(s.dur),
            Some("window_absent") => absent_durs.push(s.dur),
            _ => {}
        }
    }
    let n_decode_spans = clean_durs.len() + absent_durs.len();
    let d_c_us = median(&clean_durs);
    let d_w_us = median(&absent_durs);
    let window_absent_frac = if n_decode_spans > 0 {
        absent_durs.len() as f64 / n_decode_spans as f64
    } else {
        0.0
    };
    // d_w_eff weights the two decode latencies by the runtime window-absent
    // fraction. If only one mode was seen, fall back to whichever exists.
    let d_w_eff_us = match (d_w_us, d_c_us) {
        (Some(dw), Some(dc)) => Some(window_absent_frac * dw + (1.0 - window_absent_frac) * dc),
        (Some(dw), None) => Some(dw),
        (None, Some(dc)) => Some(dc),
        (None, None) => None,
    };

    // ── window_publish events in consumer (= chunk-index) order ───────────────
    let mut publishes: Vec<Publish> = Vec::new();
    for e in events {
        if e.ph == "i" && e.name == "causal.window_publish" {
            publishes.push(Publish {
                ts: e.ts,
                end_bit: arg_u64(&e.args, "end_bit"),
            });
        }
    }
    // The events are appended to the trace in emit order; the in-order consumer
    // emits them in chunk-index order. A multi-threaded writer interleaves
    // lines but each event's ts is the publish instant, so sort by ts to
    // recover the true publish sequence (the consumer is serial ⇒ its publishes
    // are monotonic in ts regardless of file interleave).
    publishes.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap_or(std::cmp::Ordering::Equal));
    // De-duplicate identical (ts,end_bit) — a worker-early + later redundant
    // consumer publish of the SAME chunk would otherwise double-count a link.
    // Keep the first occurrence per end_bit (earliest publish unblocks the
    // successor; the redundant re-publish is not a new link).
    let mut seen_endbits: std::collections::HashSet<u64> = std::collections::HashSet::new();
    publishes.retain(|p| match p.end_bit {
        Some(eb) => seen_endbits.insert(eb),
        None => true,
    });

    let n_chunks = publishes.len();
    let frontier_us = publishes
        .first()
        .map(|p| p.ts - trace_start)
        .unwrap_or(0.0);
    let last_publish_ts = publishes.last().map(|p| p.ts);
    let tail_us = match last_publish_ts {
        Some(lp) => (trace_start + observed_wall_us) - lp,
        None => 0.0,
    };

    // L_resolve = median steady-state inter-publish gap. Trim the first publish
    // (frontier ramp folds into `frontier`) — every subsequent gap is a link.
    let mut gaps: Vec<f64> = Vec::new();
    for w in publishes.windows(2) {
        let g = w[1].ts - w[0].ts;
        if g >= 0.0 {
            gaps.push(g);
        }
    }
    // MEAN gap is the publish-chain rate the wall obeys: Σgaps = the whole
    // first→last publish span, so N·mean reconstructs that span exactly. The
    // median is a diagnostic only (bimodal distribution — see field doc).
    let l_resolve_us = if gaps.is_empty() {
        None
    } else {
        Some(gaps.iter().sum::<f64>() / gaps.len() as f64)
    };
    let l_resolve_median_us = median(&gaps);
    let l_resolve_p95_us = percentile(&gaps, 95.0);

    // ── T ────────────────────────────────────────────────────────────────────
    let workers = workers
        .or_else(|| detect_parallelization(events))
        .unwrap_or(1)
        .max(1);

    // ── prediction ────────────────────────────────────────────────────────────
    let n = n_chunks as f64;
    let worker_bound_us =
        d_w_eff_us.map(|dwe| frontier_us + (n / workers as f64) * dwe);
    // The chain is the first→last publish span anchored at `frontier` (=
    // first publish), so it spans (N−1) links of mean latency, not N. Using
    // mean L_resolve, frontier + (N−1)·L_resolve reconstructs last_publish
    // exactly; + tail then reconstructs the wall.
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
        d_c_us,
        window_absent_frac,
        d_w_eff_us,
        l_resolve_us,
        l_resolve_median_us,
        l_resolve_p95_us,
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

/// Read T off a `drive` span's `parallelization` arg, if present (mirrors
/// consumer::detect_parallelization so the two views agree on T).
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

/// Residual = (wall_pred − observed) / observed, as a signed fraction.
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
    /// The lever: which parameter's delta most explains the wall gap, with the
    /// magnitude (wall-µs attributable).
    pub lever: String,
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

    // The lever lives on whatever term binds the SLOWER tool. If publish-chain
    // binds the slower tool and L_resolve differs, L_resolve is the lever; if
    // worker-bound binds, the decode latency (d_w_eff) is the lever.
    let (slower, faster) = if a.observed_wall_us >= b.observed_wall_us {
        (a, b)
    } else {
        (b, a)
    };
    let l_ratio = ratio(a.l_resolve_us, b.l_resolve_us);
    let dw_ratio = ratio(a.d_w_us, b.d_w_us);

    let lever = match slower.binding {
        Binding::PublishChain => {
            let gap_us = match (a.l_resolve_us, b.l_resolve_us) {
                (Some(la), Some(lb)) => (la - lb).abs() * (slower.n_chunks as f64 - 1.0).max(0.0),
                _ => 0.0,
            };
            format!(
                "L_resolve (publish-chain binds the slower tool {}): {} vs {} per link \
                 ⇒ ~{} of wall on N={} links{}",
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
                slower.n_chunks,
                // Knee caveat: if the faster tool's worker-bound term is above
                // the slower's publish-chain target, cutting L_resolve hits the
                // knee before parity.
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
            missing worker.decode or window_publish events)"
            .to_string(),
    };

    ModelDelta {
        a_label: a.label.clone(),
        b_label: b.label.clone(),
        d_w_ratio: dw_ratio,
        d_c_ratio: ratio(a.d_c_us, b.d_c_us),
        l_resolve_ratio: l_ratio,
        frac_a: a.window_absent_frac,
        frac_b: b.window_absent_frac,
        wall_ratio,
        lever,
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

    fn span(name: &str, mode: &str, tid: u64, t0: f64, t1: f64) -> [Event; 2] {
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

    fn publish(ts: f64, end_bit: u64) -> Event {
        Event {
            name: "causal.window_publish".into(),
            ph: "i".into(),
            ts,
            pid: 1,
            tid: 1,
            args: serde_json::json!({ "start_bit": end_bit - 100, "end_bit": end_bit, "site": "consumer" }),
        }
    }

    /// Synthetic trace with HAND-KNOWN parameters:
    ///   T = 4 workers, N = 8 chunks.
    ///   d_c = 10ms (clean), d_w = 40ms (window-absent), all 8 window-absent
    ///     ⇒ f = 1.0, d_w_eff = 40ms.
    ///   window_publish every 5ms starting at t=20ms ⇒ frontier=20ms,
    ///     L_resolve=5ms, 8 chunks ⇒ last publish at 20+35=55ms.
    ///   Construct so the WALL is 60ms (tail = 5ms).
    /// Expected:
    ///   worker-bound  = frontier + (N/T)·d_w_eff   = 20 + (8/4)·40   = 100ms
    ///   publish-chain = frontier + (N−1)·L_resolve = 20 + 7·5        = 55ms
    ///   max = worker-bound 100ms ⇒ binding = WorkerBound
    ///   wall_pred = 100 + tail(5) = 105ms
    #[test]
    fn synthetic_known_params_populate_and_predict() {
        let mut events: Vec<Event> = Vec::new();
        // 8 window-absent decode spans, each 40ms, spread across 4 worker tids.
        for i in 0..8u64 {
            let tid = 2 + (i % 4); // tids 2..=5 (consumer is tid 1)
            let t0 = 1000.0 + i as f64 * 1000.0;
            events.extend(span("worker.decode", "window_absent", tid, t0, t0 + 40_000.0));
        }
        // 8 publishes, 5ms apart, first at 20ms, end_bits distinct.
        for i in 0..8u64 {
            events.push(publish(20_000.0 + i as f64 * 5_000.0, 1000 + i * 100));
        }
        // Anchor wall: a consumer span from t=0 to t=60ms so observed wall=60ms.
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
            ts: 60_000.0,
            pid: 1,
            tid: 1,
            args: serde_json::Value::Null,
        });

        let p = analyze(&events, "synthetic", Some(4));
        assert_eq!(p.workers, 4);
        assert_eq!(p.n_chunks, 8);
        assert_eq!(p.n_decode_spans, 8);
        assert_eq!(p.d_w_us, Some(40_000.0), "d_w median");
        assert_eq!(p.d_c_us, None, "no clean spans");
        assert!((p.window_absent_frac - 1.0).abs() < 1e-9);
        assert_eq!(p.d_w_eff_us, Some(40_000.0));
        assert_eq!(p.l_resolve_us, Some(5_000.0), "L_resolve = 5ms gap");
        // frontier = first publish (20ms) − trace start (0) = 20ms.
        assert!((p.frontier_us - 20_000.0).abs() < 1.0, "frontier {}", p.frontier_us);
        // observed wall = 60ms (drive span 0..60ms).
        assert!((p.observed_wall_us - 60_000.0).abs() < 1.0);
        // tail = wall-end (60ms) − last publish (55ms) = 5ms.
        assert!((p.tail_us - 5_000.0).abs() < 1.0, "tail {}", p.tail_us);
        // worker-bound = 20 + (8/4)·40 = 100ms.
        assert!(
            (p.worker_bound_us.unwrap() - 100_000.0).abs() < 1.0,
            "worker_bound {}",
            p.worker_bound_us.unwrap()
        );
        // publish-chain = frontier + (N−1)·L_resolve = 20 + 7·5 = 55ms.
        assert!(
            (p.publish_chain_us.unwrap() - 55_000.0).abs() < 1.0,
            "publish_chain {}",
            p.publish_chain_us.unwrap()
        );
        // max(100,60)=100 ⇒ worker-bound; wall_pred = 100+5 = 105ms.
        assert_eq!(p.binding, Binding::WorkerBound);
        assert!(
            (p.wall_pred_us.unwrap() - 105_000.0).abs() < 1.0,
            "wall_pred {}",
            p.wall_pred_us.unwrap()
        );
    }

    /// A publish-chain-bound trace: slow L_resolve so N·L_resolve dominates,
    /// and the delta vs a faster tool names L_resolve as the lever.
    #[test]
    fn publish_chain_binds_and_delta_names_l_resolve() {
        // Tool A (slow): L_resolve = 20ms, d_w = 10ms, T=8, N=10.
        // worker-bound  = 0 + (10/8)·10 = 12.5ms
        // publish-chain = 0 + 10·20     = 200ms  ⇒ binds.
        let mut a_events: Vec<Event> = Vec::new();
        for i in 0..10u64 {
            let t0 = i as f64 * 100.0;
            a_events.extend(span("worker.decode", "window_absent", 2 + i % 8, t0, t0 + 10_000.0));
        }
        for i in 0..10u64 {
            a_events.push(publish(i as f64 * 20_000.0, 1000 + i * 100));
        }
        let a = analyze(&a_events, "slow", Some(8));
        assert_eq!(a.binding, Binding::PublishChain, "A publish-chain binds");

        // Tool B (fast): L_resolve = 4ms (5× faster resolve), same decode/T/N.
        let mut b_events: Vec<Event> = Vec::new();
        for i in 0..10u64 {
            let t0 = i as f64 * 100.0;
            b_events.extend(span("worker.decode", "window_absent", 2 + i % 8, t0, t0 + 10_000.0));
        }
        for i in 0..10u64 {
            b_events.push(publish(i as f64 * 4_000.0, 1000 + i * 100));
        }
        let b = analyze(&b_events, "fast", Some(8));

        let d = delta(&a, &b);
        assert!(d.lever.contains("L_resolve"), "lever: {}", d.lever);
        // L_resolve ratio b/a = 4/20 = 0.2.
        assert!((d.l_resolve_ratio.unwrap() - 0.2).abs() < 1e-6);
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
