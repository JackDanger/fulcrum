//! causal.rs — the speculation-interconnectedness view.
//!
//! Answers, from a single enriched trace and WITHOUT reading code: *why does
//! gzippy's parallel decoder go window-absent (speculate) the amount it does,
//! and what does that cost?*
//!
//! ## The causal chain this view reconstructs
//!
//! gzippy decodes chunks in parallel. Each chunk, at the instant its worker
//! STARTS, checks the WindowMap for its predecessor's 32 KiB tail-window:
//!
//! - present ⇒ CLEAN decode: fast windowed ISA-L, no markers, no tax.
//! - absent ⇒ WINDOW-ABSENT decode: slow `deflate_block` bootstrap that emits
//!   u16 markers, then a 3-pass data-model tax later (decode→u16 write,
//!   replace_markers read+write, narrow u16→u8 read+write) to resolve them once
//!   the window arrives.
//!
//! The predecessor's window is PUBLISHED either early on the worker (clean
//! tail) or serially on the in-order consumer. So there is a COUPLED chain:
//!
//!   consumer serial-advance(N) → window-publish-time(N)
//!     → was N+1's predecessor window present when N+1's worker started?
//!     → N+1's decode-MODE → N+1's latency + tax → consumer wait → ...
//!
//! This view emits, from the `causal.*` instant events
//! ([`crate::trace`] tolerates them as `ph:"i"`):
//!
//!   1. The RUNTIME window-absent fraction (how many chunks actually went
//!      window-absent) vs the STATIC boundary fraction the campaign cites
//!      (~31%). If runtime ≫ static, windows are publishing LATE.
//!   2. The window-publish LATENCY per window-absent chunk: the time between
//!      its predecessor's window_publish event and its own decode_start.
//!      Negative latency (start before publish) IS the cause of speculation.
//!   3. The per-chunk DEPENDENCY timeline: a swimlane of decode-start /
//!      publish / consume, so the serial window-chain and its stalls are
//!      visible, not inferred.
//!   4. The DATA-MODEL TAX: bytes + µs of each of the 3 buffer passes a
//!      window-absent chunk pays that a clean chunk never does.

use crate::trace::{pair_spans, Event, Span};
use std::collections::HashMap;

/// One chunk's reconstructed lifecycle, keyed by its decode start_bit.
#[derive(Debug, Clone, Default)]
pub struct ChunkLife {
    pub start_bit: u64,
    pub end_bit: Option<u64>,
    /// Worker decode-decision timestamp (µs).
    pub decode_start_ts: Option<f64>,
    /// Was the predecessor window present at decode-start? (the speculation
    /// decision). None if we never saw a decode_decision for this chunk.
    pub window_present: Option<bool>,
    pub mode: Option<String>,
    pub speculative: Option<bool>,
    /// When THIS chunk published its tail-window (keyed at end_bit).
    pub publish_ts: Option<f64>,
    pub publish_site: Option<String>,
    /// When the in-order consumer reached this chunk.
    pub consume_ts: Option<f64>,
    pub had_markers: Option<bool>,
    /// Data-model tax (window-absent chunks only).
    pub tax_marker_bytes: Option<u64>,
    pub tax_resolve_us: Option<f64>,
    pub tax_narrow_us: Option<f64>,
    pub tax_materialize_us: Option<f64>,
    pub tax_fused: Option<bool>,
    /// worker.bootstrap span duration (µs) — the decode→u16-write pass.
    pub bootstrap_us: Option<f64>,
}

/// The full causal dataset.
pub struct CausalReport {
    pub wall_us: f64,
    /// Lifecycles sorted by start_bit (= pipeline order).
    pub chunks: Vec<ChunkLife>,
    pub n_decode_decisions: usize,
    pub n_window_absent: usize,
    pub n_clean: usize,
    /// Publish-latency samples for window-absent chunks (µs):
    /// `decode_start(N) − publish(predecessor)`. Negative ⇒ N started before
    /// its predecessor published ⇒ that is WHY N went window-absent.
    pub publish_latency_us: Vec<f64>,
    /// Of the window-absent chunks, how many had a predecessor whose publish
    /// we observed at all (so the latency is meaningful).
    pub window_absent_with_pred_publish: usize,
    pub window_absent_pred_never_published_at_start: usize,
    /// Window-absent chunks whose decode start_bit is a PARTITION SEED that no
    /// publish key ever matches exactly, yet a real predecessor boundary was
    /// published NEARBY (largest end_bit < start_bit). This is the key-mismatch
    /// cause: the window exists but under a different key than the speculative
    /// lookup uses, so the worker is STRUCTURALLY forced window-absent
    /// regardless of timing.
    pub window_absent_key_mismatch: usize,
    /// Of those key-mismatch chunks, how many had the nearby predecessor
    /// boundary published BEFORE the chunk's own decode start (so timing alone
    /// would have allowed a clean decode at the real boundary key).
    pub key_mismatch_pred_ready_in_time: usize,
}

fn arg_f64(args: &serde_json::Value, key: &str) -> Option<f64> {
    match args.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_f64(),
        Some(serde_json::Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}
fn arg_u64(args: &serde_json::Value, key: &str) -> Option<u64> {
    match args.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => s.parse().ok(),
        _ => None,
    }
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
fn arg_str(args: &serde_json::Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Build the causal report from a raw event stream.
pub fn analyze(events: &[Event]) -> CausalReport {
    let spans: Vec<Span> = pair_spans(events);
    let wall_us = crate::trace::wall_us(&spans);

    // Per-chunk lifecycle keyed on start_bit.
    let mut by_start: HashMap<u64, ChunkLife> = HashMap::new();
    // window_publish events keyed on END bit (= successor's start_bit), so a
    // chunk can look up "when was MY predecessor window published" by its own
    // start_bit. We keep the EARLIEST publish per end_bit (worker_early beats a
    // later redundant consumer publish — it is what unblocks successors).
    let mut publish_at_endbit: HashMap<u64, (f64, String)> = HashMap::new();

    for e in events {
        if e.ph != "i" || !e.name.starts_with("causal.") {
            continue;
        }
        let phase = &e.name["causal.".len()..];
        let a = &e.args;
        match phase {
            "decode_decision" => {
                let Some(sb) = arg_u64(a, "start_bit") else {
                    continue;
                };
                let c = by_start.entry(sb).or_default();
                c.start_bit = sb;
                c.decode_start_ts = Some(e.ts);
                c.window_present = arg_bool(a, "window_present");
                c.mode = arg_str(a, "mode");
                c.speculative = arg_bool(a, "speculative");
            }
            "window_publish" => {
                let Some(sb) = arg_u64(a, "start_bit") else {
                    continue;
                };
                let eb = arg_u64(a, "end_bit");
                let site = arg_str(a, "site").unwrap_or_default();
                let c = by_start.entry(sb).or_default();
                c.start_bit = sb;
                c.end_bit = eb;
                // Earliest publish wins (first to unblock the successor).
                if c.publish_ts.map(|t| e.ts < t).unwrap_or(true) {
                    c.publish_ts = Some(e.ts);
                    c.publish_site = Some(site.clone());
                }
                if let Some(eb) = eb {
                    publish_at_endbit
                        .entry(eb)
                        .and_modify(|(t, s)| {
                            if e.ts < *t {
                                *t = e.ts;
                                *s = site.clone();
                            }
                        })
                        .or_insert((e.ts, site));
                }
            }
            "tax" => {
                let Some(sb) = arg_u64(a, "start_bit") else {
                    continue;
                };
                let c = by_start.entry(sb).or_default();
                c.start_bit = sb;
                c.tax_marker_bytes = arg_u64(a, "marker_bytes");
                c.tax_resolve_us = arg_f64(a, "resolve_us");
                c.tax_narrow_us = arg_f64(a, "narrow_us");
                c.tax_materialize_us = arg_f64(a, "materialize_us");
                c.tax_fused = arg_bool(a, "fused");
            }
            "consume" => {
                let Some(sb) = arg_u64(a, "start_bit") else {
                    continue;
                };
                let c = by_start.entry(sb).or_default();
                c.start_bit = sb;
                c.end_bit = c.end_bit.or_else(|| arg_u64(a, "end_bit"));
                c.consume_ts = Some(e.ts);
                c.had_markers = arg_bool(a, "had_markers");
            }
            _ => {}
        }
    }

    // Join worker.bootstrap span durations onto their chunk by start_bit.
    // The bootstrap span carries args `start_bit`.
    for s in &spans {
        if s.name == "worker.bootstrap" {
            if let Some(sb) = s.arg_u64("start_bit") {
                if let Some(c) = by_start.get_mut(&sb) {
                    // Sum (a chunk may bootstrap once; keep the max as the
                    // decode→u16 pass duration).
                    c.bootstrap_us = Some(c.bootstrap_us.unwrap_or(0.0).max(s.dur));
                }
            }
        }
    }

    let mut chunks: Vec<ChunkLife> = by_start.into_values().collect();
    chunks.sort_by_key(|c| c.start_bit);

    // Sorted publish keys (end_bits) for "nearest predecessor boundary"
    // lookups — the speculative seed rarely equals a real boundary, so an
    // exact-key join misses; the nearest published boundary BELOW the seed is
    // the predecessor the chunk would have keyed on at the real boundary.
    let mut publish_keys: Vec<(u64, f64)> = publish_at_endbit
        .iter()
        .map(|(&k, &(t, _))| (k, t))
        .collect();
    publish_keys.sort_by_key(|(k, _)| *k);
    let nearest_below = |start: u64| -> Option<(u64, f64)> {
        // largest end_bit strictly below start.
        let idx = publish_keys.partition_point(|(k, _)| *k < start);
        if idx == 0 {
            None
        } else {
            Some(publish_keys[idx - 1])
        }
    };

    // Decision tallies + publish-latency for window-absent chunks.
    let mut n_decode_decisions = 0usize;
    let mut n_window_absent = 0usize;
    let mut n_clean = 0usize;
    let mut publish_latency_us = Vec::new();
    let mut window_absent_with_pred_publish = 0usize;
    let mut window_absent_pred_never = 0usize;
    let mut window_absent_key_mismatch = 0usize;
    let mut key_mismatch_pred_ready_in_time = 0usize;

    for c in &chunks {
        match c.window_present {
            Some(true) => {
                n_decode_decisions += 1;
                n_clean += 1;
            }
            Some(false) => {
                n_decode_decisions += 1;
                n_window_absent += 1;
                // Exact-key join: this chunk's start_bit == predecessor's
                // end_bit (the on-demand / confirmed-boundary case).
                if let (Some(start_ts), Some((pub_ts, _))) =
                    (c.decode_start_ts, publish_at_endbit.get(&c.start_bit))
                {
                    publish_latency_us.push(start_ts - pub_ts);
                    window_absent_with_pred_publish += 1;
                } else if let (Some(start_ts), Some((_, pub_ts))) =
                    (c.decode_start_ts, nearest_below(c.start_bit))
                {
                    // No publish at the EXACT seed key, but a real predecessor
                    // boundary was published nearby. The window EXISTS — under
                    // a different key than this speculative seed. The worker's
                    // exact `window_map.get(seed)` cannot see it ⇒ structurally
                    // forced window-absent. If that boundary was published
                    // before this chunk's decode start, timing alone would have
                    // permitted a clean decode at the real boundary key — so
                    // the cause is the KEY, not lateness.
                    window_absent_key_mismatch += 1;
                    if pub_ts <= start_ts {
                        key_mismatch_pred_ready_in_time += 1;
                    }
                } else {
                    window_absent_pred_never += 1;
                }
            }
            None => {}
        }
    }

    CausalReport {
        wall_us,
        chunks,
        n_decode_decisions,
        n_window_absent,
        n_clean,
        publish_latency_us,
        window_absent_with_pred_publish,
        window_absent_pred_never_published_at_start: window_absent_pred_never,
        window_absent_key_mismatch,
        key_mismatch_pred_ready_in_time,
    }
}

/// Percentile of a sorted-or-unsorted sample (linear interpolation).
pub fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let rank = p / 100.0 * (v.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        v[lo]
    } else {
        let frac = rank - lo as f64;
        v[lo] * (1.0 - frac) + v[hi] * frac
    }
}

/// Aggregate data-model tax across all window-absent chunks.
pub struct TaxTotals {
    pub n_taxed_chunks: usize,
    pub total_marker_bytes: u64,
    /// First pass: decode → u16 write (worker.bootstrap span time).
    pub total_decode_us: f64,
    /// Second pass: replace_markers / apply_window (read+write u16).
    pub total_resolve_us: f64,
    /// Third pass: narrow u16 → u8 (read 2N + write N). 0 on the fused path
    /// (fused folds narrow into resolve).
    pub total_narrow_us: f64,
    pub total_materialize_us: f64,
    pub n_fused: usize,
    pub n_two_pass: usize,
}

pub fn tax_totals(report: &CausalReport) -> TaxTotals {
    let mut t = TaxTotals {
        n_taxed_chunks: 0,
        total_marker_bytes: 0,
        total_decode_us: 0.0,
        total_resolve_us: 0.0,
        total_narrow_us: 0.0,
        total_materialize_us: 0.0,
        n_fused: 0,
        n_two_pass: 0,
    };
    for c in &report.chunks {
        // A taxed chunk is one that emitted marker bytes (it paid the model).
        let Some(mb) = c.tax_marker_bytes else {
            continue;
        };
        if mb == 0 {
            continue;
        }
        t.n_taxed_chunks += 1;
        t.total_marker_bytes += mb;
        t.total_decode_us += c.bootstrap_us.unwrap_or(0.0);
        t.total_resolve_us += c.tax_resolve_us.unwrap_or(0.0);
        t.total_narrow_us += c.tax_narrow_us.unwrap_or(0.0);
        t.total_materialize_us += c.tax_materialize_us.unwrap_or(0.0);
        match c.tax_fused {
            Some(true) => t.n_fused += 1,
            _ => t.n_two_pass += 1,
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inst(name: &str, ts: f64, tid: u64, args: serde_json::Value) -> Event {
        Event {
            name: name.to_string(),
            ph: "i".to_string(),
            ts,
            pid: 1,
            tid,
            args,
        }
    }

    #[test]
    fn runtime_window_absent_fraction_and_latency() {
        // Chunk A (start=0) clean, publishes its window at end_bit=100 at ts=50.
        // Chunk B (start=100) decode-decision at ts=40 — BEFORE A published
        // (50) — so B went window-absent. Its publish latency = 40 − 50 = −10
        // (started 10µs before the window existed). This is the causal core.
        let events = vec![
            inst(
                "causal.decode_decision",
                10.0,
                2,
                json!({"start_bit":0,"window_present":true,"mode":"clean","stop_hint":100,"speculative":false}),
            ),
            inst(
                "causal.window_publish",
                50.0,
                2,
                json!({"start_bit":0,"end_bit":100,"site":"worker_early"}),
            ),
            inst(
                "causal.decode_decision",
                40.0,
                3,
                json!({"start_bit":100,"window_present":false,"mode":"window_absent","stop_hint":200,"speculative":true}),
            ),
            inst(
                "causal.tax",
                90.0,
                3,
                json!({"start_bit":100,"marker_bytes":4096,"resolve_us":12.0,"narrow_us":3.0,"materialize_us":1.0,"populate_us":0.5,"fused":false}),
            ),
        ];
        let r = analyze(&events);
        assert_eq!(r.n_decode_decisions, 2);
        assert_eq!(r.n_clean, 1);
        assert_eq!(r.n_window_absent, 1);
        // runtime window-absent fraction = 1/2 = 50%.
        let frac = r.n_window_absent as f64 / r.n_decode_decisions as f64;
        assert!((frac - 0.5).abs() < 1e-9);
        // latency = decode_start(40) − pred_publish(50) = −10.
        assert_eq!(r.publish_latency_us.len(), 1);
        assert!((r.publish_latency_us[0] - (-10.0)).abs() < 1e-9);
        assert_eq!(r.window_absent_with_pred_publish, 1);

        let tax = tax_totals(&r);
        assert_eq!(tax.n_taxed_chunks, 1);
        assert_eq!(tax.total_marker_bytes, 4096);
        assert!((tax.total_resolve_us - 12.0).abs() < 1e-9);
        assert_eq!(tax.n_two_pass, 1);
    }

    #[test]
    fn pred_never_published_counts_separately() {
        // A window-absent chunk whose predecessor publish we never observed
        // (the strongest "window was not there") is tallied apart from the
        // latency distribution.
        let events = vec![inst(
            "causal.decode_decision",
            5.0,
            2,
            json!({"start_bit":500,"window_present":false,"mode":"window_absent"}),
        )];
        let r = analyze(&events);
        assert_eq!(r.n_window_absent, 1);
        assert_eq!(r.window_absent_pred_never_published_at_start, 1);
        assert_eq!(r.publish_latency_us.len(), 0);
    }

    #[test]
    fn percentiles() {
        let s = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&s, 50.0) - 3.0).abs() < 1e-9);
        assert!((percentile(&s, 0.0) - 1.0).abs() < 1e-9);
        assert!((percentile(&s, 100.0) - 5.0).abs() < 1e-9);
    }
}

// ===========================================================================
// Knob A/B verdicts — the causal core (CAUSAL-OR-HYPOTHESIS).
//
// A faithful Rust port of `decide/fulcrum/core/causal.py` (module-name parity:
// this file IS `causal`). Attribution (busy time, latency share, critical-path
// blame) repeatedly manufactures levers that never convert at the wall. The
// only causal currency here is a same-binary kill-switch A/B whose effect is
// counter-verified by the SPREAD-RESOLUTION margin.
//
// Convention: min-based ratio + max-spread margin (the same-binary kill-switch
// instrument that separates layout wobble from behavior).
// ===========================================================================

use crate::stats::{bimodal, resolution, sample_stats, Resolution, SampleStats, BIMODAL_K};

/// The causal A/B status. Tokens match `causal.py` exactly via
/// [`KnobStatus::token`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnobStatus {
    /// The altered arm (kill-switch thrown) is faster ⇒ the shipped default
    /// COSTS wall in this cell (`delta < 0`). Actionable.
    VerifiedCosts,
    /// The altered arm is slower ⇒ the feature PAYS (`delta > 0`).
    VerifiedPays,
    /// `|delta|` within the spread margin — no causal effect resolved.
    Null,
    /// One or both arms had no samples.
    NoData,
}

impl KnobStatus {
    /// The literal token the Python oracle emits.
    pub fn token(self) -> &'static str {
        match self {
            KnobStatus::VerifiedCosts => "CAUSAL-VERIFIED-COSTS",
            KnobStatus::VerifiedPays => "CAUSAL-VERIFIED-PAYS",
            KnobStatus::Null => "CAUSAL-NULL",
            KnobStatus::NoData => "NO-DATA",
        }
    }
}

/// The full knob A/B verdict. Mirrors the dict `causal.knob_verdict` returns.
#[derive(Debug, Clone)]
pub struct KnobVerdict {
    pub status: KnobStatus,
    /// `(knob_min - base_min) * 1000` (ms). `< 0` ⇒ altered arm faster.
    pub delta_ms: f64,
    /// The spread margin in ms (`max(spread_pct)/100 * base_min * 1000`).
    pub margin_ms: f64,
    pub base: Option<SampleStats>,
    pub knob: Option<SampleStats>,
    /// Either arm flagged bimodal.
    pub bimodal: bool,
    pub resolution: Option<Resolution>,
    pub n_needed: Option<usize>,
}

/// Knob A/B verdict over two wall-sample lists (seconds).
///
/// `knob` is the FEATURE-ALTERED arm (kill-switch thrown / opt-in enabled).
/// `delta = knob_min - base_min`: `delta < 0` ⇒ altered arm faster ⇒ the
/// shipped default COSTS wall in this cell (actionable). A `|delta|` within the
/// max-spread margin is [`KnobStatus::Null`].
///
/// Faithful port of `causal.knob_verdict` — same min-based delta, same
/// `max(spread_pct)/100 * base_min` margin, same branch order.
pub fn knob_verdict(base: &[f64], knob: &[f64]) -> KnobVerdict {
    let sb = sample_stats(base);
    let sk = sample_stats(knob);
    let (sb, sk) = match (sb, sk) {
        (Some(b), Some(k)) => (b, k),
        _ => {
            return KnobVerdict {
                status: KnobStatus::NoData,
                delta_ms: 0.0,
                margin_ms: 0.0,
                base: sb,
                knob: sk,
                bimodal: false,
                resolution: None,
                n_needed: None,
            };
        }
    };
    let delta = sk.min - sb.min;
    let margin = sb.spread_pct.max(sk.spread_pct) / 100.0 * sb.min;
    let (res, n_need) = resolution(delta, margin, margin, sb.n);
    let status = if delta.abs() > margin {
        if delta < 0.0 {
            KnobStatus::VerifiedCosts
        } else {
            KnobStatus::VerifiedPays
        }
    } else {
        KnobStatus::Null
    };
    KnobVerdict {
        status,
        delta_ms: delta * 1000.0,
        margin_ms: margin * 1000.0,
        base: Some(sb),
        knob: Some(sk),
        bimodal: bimodal(base, BIMODAL_K) || bimodal(knob, BIMODAL_K),
        resolution: Some(res),
        n_needed: n_need,
    }
}

#[cfg(test)]
mod knob_tests {
    use super::*;

    // The knob harness contract from test_decide.py §1.
    #[test]
    fn known_null_knob_is_causal_null() {
        let base = [1.000, 1.002, 1.001, 1.003, 1.002, 1.001, 1.004];
        let v = knob_verdict(&base, &base);
        assert_eq!(v.status, KnobStatus::Null, "{:?}", v.status);
    }

    #[test]
    fn minus_50ms_shift_is_costs() {
        let base = [1.000, 1.002, 1.001, 1.003, 1.002, 1.001, 1.004];
        let knob: Vec<f64> = base.iter().map(|x| x - 0.050).collect();
        let v = knob_verdict(&base, &knob);
        assert_eq!(v.status, KnobStatus::VerifiedCosts);
        assert!(v.delta_ms < 0.0, "delta {} should be negative", v.delta_ms);
    }

    #[test]
    fn plus_50ms_shift_is_pays() {
        let base = [1.000, 1.002, 1.001, 1.003, 1.002, 1.001, 1.004];
        let knob: Vec<f64> = base.iter().map(|x| x + 0.050).collect();
        let v = knob_verdict(&base, &knob);
        assert_eq!(v.status, KnobStatus::VerifiedPays);
    }

    #[test]
    fn sub_spread_shift_is_null() {
        // +10ms on an 8% spread is below the margin => CAUSAL-NULL.
        let wide = [1.00, 1.05, 1.02, 1.08, 1.01, 1.06, 1.03];
        let knob: Vec<f64> = wide.iter().map(|x| x + 0.01).collect();
        let v = knob_verdict(&wide, &knob);
        assert_eq!(
            v.status,
            KnobStatus::Null,
            "delta_ms={} margin_ms={}",
            v.delta_ms,
            v.margin_ms
        );
    }

    #[test]
    fn empty_arm_is_no_data() {
        let v = knob_verdict(&[], &[1.0, 2.0]);
        assert_eq!(v.status, KnobStatus::NoData);
        let v2 = knob_verdict(&[1.0, 2.0], &[]);
        assert_eq!(v2.status, KnobStatus::NoData);
    }

    #[test]
    fn status_tokens_match_python() {
        assert_eq!(KnobStatus::VerifiedCosts.token(), "CAUSAL-VERIFIED-COSTS");
        assert_eq!(KnobStatus::VerifiedPays.token(), "CAUSAL-VERIFIED-PAYS");
        assert_eq!(KnobStatus::Null.token(), "CAUSAL-NULL");
        assert_eq!(KnobStatus::NoData.token(), "NO-DATA");
    }
}
