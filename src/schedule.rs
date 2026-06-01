#![allow(dead_code)]
//! schedule.rs — S1, the PLACEMENT-vs-RATE arbiter (pure trace arithmetic).
//!
//! ## The question this view answers (and the disagreement it settles)
//!
//! gzippy's wall is the in-order consumer thread. Whenever the consumer must
//! emit chunk `i` but `i` is not ready, it blocks in a `wait.block_fetcher_get`
//! span. Two competing notes explain that stall:
//!
//!  - PLACEMENT ([[project_wall_is_consumer_critical_path]]): the stall
//!    coincides with *admissible, ready-to-decode work going unused* — a free
//!    worker existed that could have been decoding chunk `i` (or a successor)
//!    earlier. Lever: port rapidgzip's `queuePrefetchedChunkPostProcessing` /
//!    better placement.
//!  - RATE ([[project_t8_saturated_pool_diag]]): the stall coincides with *the
//!    frontier simply not being decoded yet* — every worker was busy and the
//!    decode of `i` could not have finished sooner. Lever: raw decode speed
//!    (bounded ~15%).
//!
//! S1 classifies EACH consumer stall by comparing the stall's start time to two
//! trace-derived moments:
//!
//!  - `decode_complete(i)` — the end of `worker.decode_chunk{chunk_id=i}`.
//!  - `earliest_free_worker_after_admissible(i)` — the earliest instant at
//!    which (a) chunk `i` was ADMISSIBLE (its decode could begin — for the
//!    in-order frontier, all predecessors `< i` already decoded) AND (b) some
//!    worker was idle (`pool.pick.wait`).
//!
//! Verdict per stall:
//!  - RATE: `decode_complete(i)` is AT OR AFTER the stall end, i.e. the
//!    consumer was genuinely waiting on the decode to finish; AND no free
//!    worker sat idle while `i` was admissible-and-undecoded during the stall.
//!    The frontier was rate-bound.
//!  - PLACEMENT: while the consumer was stalled on `i`, `i` was admissible and
//!    a worker was idle for a non-trivial slice — ready work (capacity) went
//!    unused. The decode COULD have been placed earlier.
//!  - SPECULATION-INVALID: `i`'s decode was speculative and its window/markers
//!    forced a re-decode (the chunk was decoded but not usable in order),
//!    so the stall is neither pure-rate nor pure-placement.
//!
//! This is DESCRIPTIVE (it does not perturb the wall). The frontier-placement
//! ORACLE already gave the CAUSAL answer (PLACEMENT-refuted ⇒ RATE, via a TIE).
//! S1's job is the per-stall confirmation: if S1 also says RATE-dominant, the
//! descriptive and causal instruments CONVERGE = confidence.

use crate::trace::Span;
use std::collections::BTreeMap;

/// How a single consumer stall is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallClass {
    /// Frontier not decoded — no idle capacity was wasted; raw rate bound.
    Rate,
    /// Admissible work + idle worker during the stall — placement/scheduling miss.
    Placement,
    /// The chunk's decode was speculative and invalidated; re-decode tax.
    SpeculationInvalid,
}

/// One classified consumer stall.
#[derive(Debug, Clone)]
pub struct Stall {
    pub partition_idx: u64,
    pub ts_start: f64,
    pub ts_end: f64,
    pub dur_us: f64,
    pub class: StallClass,
    /// µs of the stall during which a worker was idle while chunk i was
    /// admissible-and-undecoded (the "ready work unused" measure).
    pub idle_admissible_us: f64,
    /// decode_complete(i) − stall_start; positive = decode finished after the
    /// stall began (consumer genuinely waited on it).
    pub decode_lag_us: f64,
}

/// The S1 verdict over a whole run.
#[derive(Debug, Clone, Default)]
pub struct ScheduleVerdict {
    pub n_stalls: usize,
    pub total_stall_us: f64,
    pub rate_us: f64,
    pub placement_us: f64,
    pub speculation_us: f64,
    pub stalls: Vec<Stall>,
}

impl ScheduleVerdict {
    pub fn placement_frac(&self) -> f64 {
        if self.total_stall_us <= 0.0 {
            return 0.0;
        }
        self.placement_us / self.total_stall_us
    }
    pub fn rate_frac(&self) -> f64 {
        if self.total_stall_us <= 0.0 {
            return 0.0;
        }
        self.rate_us / self.total_stall_us
    }
    /// Which note wins, as a printable string.
    pub fn winner(&self) -> &'static str {
        if self.placement_frac() > self.rate_frac() {
            "PLACEMENT"
        } else {
            "RATE"
        }
    }
}

/// A decoded interval for one chunk: the `worker.decode_chunk` span.
struct DecodeInterval {
    partition_idx: u64,
    ts_start: f64,
    ts_end: f64,
    speculative: bool,
}

/// Extract per-chunk decode intervals (latest-ending wins if a chunk was
/// decoded more than once, e.g. a speculative attempt plus a real one — we key
/// the "complete" time on the LAST decode that produced the in-order result;
/// but we also remember whether ANY decode of this chunk was speculative).
fn decode_intervals(spans: &[Span]) -> BTreeMap<u64, DecodeInterval> {
    let mut map: BTreeMap<u64, DecodeInterval> = BTreeMap::new();
    let mut any_spec: BTreeMap<u64, bool> = BTreeMap::new();
    for s in spans {
        if s.name != "worker.decode_chunk" {
            continue;
        }
        let Some(idx) = s.arg_u64("chunk_id").or_else(|| s.arg_u64("partition_idx")) else {
            continue;
        };
        let spec = s.arg_u64("speculative").map(|v| v != 0).unwrap_or(false)
            || matches!(s.args.get("speculative"), Some(serde_json::Value::Bool(true)));
        *any_spec.entry(idx).or_insert(false) |= spec;
        // keep the decode that ENDS latest (the one the consumer ultimately waits on)
        match map.get(&idx) {
            Some(d) if d.ts_end >= s.ts_end => {}
            _ => {
                map.insert(
                    idx,
                    DecodeInterval {
                        partition_idx: idx,
                        ts_start: s.ts_start,
                        ts_end: s.ts_end,
                        speculative: spec,
                    },
                );
            }
        }
    }
    for (idx, d) in map.iter_mut() {
        d.speculative = *any_spec.get(idx).unwrap_or(&false);
    }
    map
}

/// Idle-worker intervals: `pool.pick.wait` spans (a pooled worker sitting with
/// no task). Each is a [start,end) window during which capacity was free.
fn idle_worker_intervals(spans: &[Span]) -> Vec<(f64, f64)> {
    let mut v: Vec<(f64, f64)> = spans
        .iter()
        .filter(|s| s.name == "pool.pick.wait")
        .map(|s| (s.ts_start, s.ts_end))
        .collect();
    v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    v
}

/// µs of overlap between [a0,a1) and the union of `windows`.
fn overlap_union(a0: f64, a1: f64, windows: &[(f64, f64)]) -> f64 {
    if a1 <= a0 {
        return 0.0;
    }
    let mut total = 0.0;
    for &(w0, w1) in windows {
        let lo = a0.max(w0);
        let hi = a1.min(w1);
        if hi > lo {
            total += hi - lo;
        }
    }
    total
}

/// Classify all consumer stalls in the trace.
///
/// Admissibility for the in-order frontier: chunk `i` is admissible from the
/// moment all predecessors are decoded — but the consumer stalls on `i` in
/// order, so at the stall we treat `i` as the live frontier and admissible iff
/// its decode could have started, which the trace witnesses as: a free worker
/// existed AND `i` had not yet completed. We measure the µs during the stall
/// where a worker was idle while `i` was still undecoded — that is the
/// ready-capacity-unused measure that distinguishes PLACEMENT from RATE.
pub fn classify_stalls(spans: &[Span]) -> ScheduleVerdict {
    let decodes = decode_intervals(spans);
    let idle = idle_worker_intervals(spans);

    let mut verdict = ScheduleVerdict::default();

    for s in spans {
        if s.name != "wait.block_fetcher_get" {
            continue;
        }
        let Some(idx) = s.arg_u64("chunk_id").or_else(|| s.arg_u64("partition_idx")) else {
            continue;
        };
        let stall_start = s.ts_start;
        let stall_end = s.ts_end;
        let dur = s.dur;
        if dur <= 0.0 {
            continue;
        }

        let dec = decodes.get(&idx);
        // decode_complete(i): when did the in-order decode of i finish?
        let decode_complete = dec.map(|d| d.ts_end).unwrap_or(f64::INFINITY);
        let decode_lag = decode_complete - stall_start;
        let speculative = dec.map(|d| d.speculative).unwrap_or(false);

        // The window during the stall in which chunk i was still undecoded:
        // [stall_start, min(stall_end, decode_complete)). Capacity that sat
        // idle in THAT window is "ready work unused" → PLACEMENT evidence.
        let undecoded_hi = stall_end.min(decode_complete);
        let idle_admissible = overlap_union(stall_start, undecoded_hi, &idle);

        // Heuristic threshold: a stall is PLACEMENT-flavored if a worker was
        // idle for a meaningful slice (>10% of the stall) while i was
        // undecoded — capacity existed and was not used to finish i sooner.
        let placement_evidence = idle_admissible > 0.10 * dur;

        let class = if speculative && decode_complete > stall_end {
            // i was (also) decoded speculatively yet the in-order decode still
            // finished after the stall — the speculation didn't help in order.
            StallClass::SpeculationInvalid
        } else if placement_evidence {
            StallClass::Placement
        } else {
            StallClass::Rate
        };

        match class {
            StallClass::Rate => verdict.rate_us += dur,
            StallClass::Placement => verdict.placement_us += dur,
            StallClass::SpeculationInvalid => verdict.speculation_us += dur,
        }
        verdict.total_stall_us += dur;
        verdict.n_stalls += 1;
        verdict.stalls.push(Stall {
            partition_idx: idx,
            ts_start: stall_start,
            ts_end: stall_end,
            dur_us: dur,
            class,
            idle_admissible_us: idle_admissible,
            decode_lag_us: decode_lag,
        });
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sp(name: &str, tid: u64, start: f64, end: f64, args: serde_json::Value) -> Span {
        Span {
            name: name.into(),
            parent: String::new(),
            pid: 1,
            tid,
            ts_start: start,
            ts_end: end,
            dur: end - start,
            args,
        }
    }

    /// RATE: consumer stalls on chunk 5; chunk 5's decode is still running
    /// (finishes after the stall) and NO worker was idle during the stall.
    /// All capacity busy → rate-bound.
    #[test]
    fn rate_when_frontier_undecoded_and_no_idle() {
        let spans = vec![
            sp("wait.block_fetcher_get", 1, 100.0, 200.0, json!({"chunk_id":5})),
            // chunk 5 decoded on a worker, finishing at 250 (after stall end).
            sp("worker.decode_chunk", 2, 50.0, 250.0, json!({"chunk_id":5,"speculative":false})),
            // another worker busy the whole time (no pool.pick.wait).
            sp("worker.decode_chunk", 3, 50.0, 260.0, json!({"chunk_id":6,"speculative":false})),
        ];
        let v = classify_stalls(&spans);
        assert_eq!(v.n_stalls, 1);
        assert_eq!(v.stalls[0].class, StallClass::Rate);
        assert_eq!(v.winner(), "RATE");
    }

    /// PLACEMENT: consumer stalls on chunk 5 which is undecoded, AND a worker
    /// sat idle (pool.pick.wait) for most of the stall — ready capacity unused.
    #[test]
    fn placement_when_idle_worker_while_undecoded() {
        let spans = vec![
            sp("wait.block_fetcher_get", 1, 100.0, 200.0, json!({"chunk_id":5})),
            sp("worker.decode_chunk", 2, 150.0, 250.0, json!({"chunk_id":5,"speculative":false})),
            // worker idle for [100,190] during the stall.
            sp("pool.pick.wait", 3, 100.0, 190.0, json!({})),
        ];
        let v = classify_stalls(&spans);
        assert_eq!(v.stalls[0].class, StallClass::Placement);
        assert!(v.placement_frac() > 0.99);
    }

    /// SPECULATION-INVALID: chunk decoded speculatively but in-order decode
    /// completes after the stall end.
    #[test]
    fn speculation_invalid_flagged() {
        let spans = vec![
            sp("wait.block_fetcher_get", 1, 100.0, 200.0, json!({"chunk_id":5})),
            sp("worker.decode_chunk", 2, 150.0, 260.0, json!({"chunk_id":5,"speculative":true})),
        ];
        let v = classify_stalls(&spans);
        assert_eq!(v.stalls[0].class, StallClass::SpeculationInvalid);
    }
}
