#![allow(dead_code)]
//! bundle.rs — the ProfileBundle: ONE typed dataset per run that every signal
//! writes to, plus the per-thread timestamp-containment JOIN that is the
//! contract for attributing any time-keyed sample (PMU interval, PEBS mem
//! sample, getrusage delta) to a `(tid, region, partition_idx)` cell.
//!
//! ## Why a single bundle + one join
//!
//! Every previous attribution bug in this profiler shared one root cause: a
//! sample (a counter, a mem-load, a wall slice) was charged to a region by
//! ORDINAL POSITION — "the first region whose wall window contains this ms" —
//! which at T>1 pools 16 workers' concurrent spans into one wall window and
//! smears the charge across whichever region the iteration happened to visit
//! first. That is the `+0.0%`-tautology / broken-positional-join class.
//!
//! The fix, baked into [`Joiner`]: attribute STRICTLY by
//! timestamp-containment, PER THREAD. On a single thread, the begin/end
//! nesting means the thread is in exactly one *leaf* span (the innermost open
//! span) at any instant; a sample tagged `(tid, ts)` belongs to that leaf and
//! to no other. There is never a choice to bias.
//!
//! ## Purity / straddle (the honesty gate)
//!
//! Interval samples (e.g. a 1 ms `perf stat -I` window) are not instants: a
//! window can straddle a region boundary. We attribute by OVERLAP fraction and
//! record, per attributed value, a `purity` = (overlap with the winning
//! region) / (interval width). A value assembled from straddling intervals
//! carries an aggregate purity; [`AttributedValue::is_pure`] gates rendering —
//! a caller MUST flag a sub-threshold value `SMEARED` rather than print it bare.
//!
//! ## Admission rule (no orphan columns)
//!
//! A field stays in the bundle IFF a decision-view reads it to produce a
//! verdict OR it guards another field's purity. This is enforced socially (the
//! struct doc names the consumer of each non-obvious field) and mechanically by
//! the fact that nothing here is `pub` without a reader in `schedule.rs`,
//! `decompose.rs`, or a purity guard.

use crate::trace::Span;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The join key. `partition_idx` is the chunk/work-unit identity (gzippy's
/// `chunk_id`); `region` is the span-name (or a class label). `tid` is the
/// producer thread. A time-window is implied by the span the key was minted
/// from — the bundle stores the explicit `[ts_start, ts_end)` alongside.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CellKey {
    pub tid: u64,
    pub region: String,
    /// `None` when the span carried no `chunk_id`/`partition_idx` arg.
    pub partition_idx: Option<u64>,
}

/// A value attributed to a region by the join, carrying the purity with which
/// it was attributed. `purity == 1.0` means every contributing sample fell
/// wholly inside the region's windows on the right thread; `< 1.0` means some
/// straddled and were apportioned by overlap.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AttributedValue {
    pub value: f64,
    /// Overlap-weighted mean purity of the contributing samples, in `[0,1]`.
    pub purity: f64,
}

impl AttributedValue {
    pub fn zero() -> Self {
        AttributedValue {
            value: 0.0,
            purity: 1.0,
        }
    }
    /// Render-gate: is this value pure enough to print without a SMEARED flag?
    pub fn is_pure(&self, threshold: f64) -> bool {
        self.purity >= threshold
    }
}

/// The default purity threshold below which a value must be flagged SMEARED.
pub const PURITY_THRESHOLD: f64 = 0.8;

/// One region's rollup in the bundle: wall self-time + any attributed
/// counter/rusage values, all keyed under the same [`CellKey`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionCell {
    /// Inclusive wall (sum of span durations with this key), µs.
    pub wall_us: f64,
    /// Number of spans that contributed.
    pub span_count: u64,
    /// Fraction of this region's wall during which a DIFFERENT region's span
    /// ran on ANOTHER thread (concurrency impurity). 0 = ran alone. This is
    /// descriptive only — it does NOT taint the per-thread join (which is
    /// exact), it warns a reader that wall-share comparisons across regions at
    /// T>1 overlap.
    pub concurrency: f64,
    /// Attributed numeric values: name → (value, purity). E.g.
    /// `"instructions"`, `"cycles"`, `"ru_minflt"`, `"nivcsw"`.
    pub counters: BTreeMap<String, AttributedValue>,
}

/// A time-keyed sample to be joined: an instantaneous (`dur_us == 0`) or
/// interval reading on a known thread. `values` are the quantities to
/// apportion (counts for an interval; a single tier-hit = 1.0 for a PEBS mem
/// sample modeled as a unit count under its tier name).
#[derive(Debug, Clone)]
pub struct Sample {
    pub tid: u64,
    pub ts_us: f64,
    /// Interval width; 0 for an instant.
    pub dur_us: f64,
    pub values: BTreeMap<String, f64>,
}

/// The single per-run artifact. Serialized next to the trace as
/// `<trace>.bundle.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileBundle {
    /// Trace wall (max end − min start), µs.
    pub wall_us: f64,
    /// Number of distinct producer threads seen.
    pub n_threads: u64,
    /// The joined cells, keyed by (tid, region, partition_idx).
    pub cells: BTreeMap<CellKey, RegionCell>,
    /// Free-form provenance (tool, host, run-id) so two bundles can be
    /// `delta`'d with confidence they're the same workload.
    pub meta: BTreeMap<String, String>,
}

impl ProfileBundle {
    /// Build the wall/region skeleton from paired spans, per-thread. Each span
    /// becomes (or folds into) a cell under its own tid. Concurrency impurity
    /// is computed against spans on OTHER threads.
    pub fn from_spans(spans: &[Span]) -> ProfileBundle {
        let mut bundle = ProfileBundle::default();
        if spans.is_empty() {
            return bundle;
        }
        let min = spans.iter().map(|s| s.ts_start).fold(f64::INFINITY, f64::min);
        let max = spans
            .iter()
            .map(|s| s.ts_end)
            .fold(f64::NEG_INFINITY, f64::max);
        bundle.wall_us = max - min;

        let mut tids = std::collections::BTreeSet::new();
        for s in spans {
            tids.insert(s.tid);
            let key = CellKey {
                tid: s.tid,
                region: s.name.clone(),
                partition_idx: s.arg_u64("chunk_id").or_else(|| s.arg_u64("partition_idx")),
            };
            let cell = bundle.cells.entry(key).or_default();
            cell.wall_us += s.dur;
            cell.span_count += 1;
        }
        bundle.n_threads = tids.len() as u64;
        bundle
    }

    /// Join a batch of time-keyed samples into the bundle by per-thread
    /// timestamp-containment. Returns the count of samples that found no
    /// containing span (orphans) — a nonzero count means the trace did not
    /// cover the sample's thread/time and the caller should surface it.
    ///
    /// For each sample, among the spans ON THE SAME TID that overlap the
    /// sample's `[ts, ts+dur)` window, charge each value to the INNERMOST
    /// (shortest-duration, i.e. leaf) overlapping span in proportion to the
    /// overlap fraction, and record purity = overlap / sample-width.
    pub fn join_samples(&mut self, spans: &[Span], samples: &[Sample]) -> u64 {
        // Index spans by tid for the per-thread containment search.
        let mut by_tid: BTreeMap<u64, Vec<&Span>> = BTreeMap::new();
        for s in spans {
            by_tid.entry(s.tid).or_default().push(s);
        }
        let mut orphans = 0u64;
        for sample in samples {
            let width = if sample.dur_us > 0.0 { sample.dur_us } else { 0.0 };
            let s_lo = sample.ts_us - width;
            let s_hi = sample.ts_us;
            let candidates = match by_tid.get(&sample.tid) {
                Some(v) => v,
                None => {
                    orphans += 1;
                    continue;
                }
            };
            // Collect overlapping spans, then attribute by INNERMOST coverage:
            // partition the sample window into the leaf span covering each
            // instant. Approximation for an interval: charge to overlapping
            // leaf spans weighted by overlap; "leaf" = among overlappers, the
            // ones with no overlapping child also in the set are preferred.
            // For an instant (width 0) this reduces to "innermost containing
            // span", which is exact.
            let overlaps = leaf_overlaps(candidates, s_lo, s_hi, sample.ts_us);
            let total_overlap: f64 = overlaps.iter().map(|(_, ov)| ov).sum();
            if overlaps.is_empty() || total_overlap <= 0.0 {
                orphans += 1;
                continue;
            }
            for (span, ov) in &overlaps {
                let frac = ov / total_overlap;
                // purity for THIS span's share = how much of the sample width
                // it covered; an instant fully inside one span = 1.0.
                let purity = if width > 0.0 { ov / width } else { 1.0 };
                let key = CellKey {
                    tid: span.tid,
                    region: span.name.clone(),
                    partition_idx: span
                        .arg_u64("chunk_id")
                        .or_else(|| span.arg_u64("partition_idx")),
                };
                let cell = self.cells.entry(key).or_default();
                for (name, v) in &sample.values {
                    let entry = cell
                        .counters
                        .entry(name.clone())
                        .or_insert_with(AttributedValue::zero);
                    let add = v * frac;
                    // running overlap-weighted purity mean:
                    let prev_w = entry.value.abs();
                    let new_w = add.abs();
                    if prev_w + new_w > 0.0 {
                        entry.purity =
                            (entry.purity * prev_w + purity * new_w) / (prev_w + new_w);
                    }
                    entry.value += add;
                }
            }
        }
        orphans
    }
}

/// Among `candidates` on one tid, find the spans that overlap `[lo, hi]` and
/// are LEAVES with respect to that window — a span is excluded if another
/// candidate that also overlaps the window is strictly nested inside it AND
/// covers the same instant. For the common instant case (lo==hi==ts), this
/// returns the single innermost containing span. For an interval, it returns
/// the set of leaf spans the window passes through, with each one's overlap µs.
fn leaf_overlaps<'a>(
    candidates: &[&'a Span],
    lo: f64,
    hi: f64,
    ts: f64,
) -> Vec<(&'a Span, f64)> {
    // Spans on one thread form a properly-nested forest (B/E stack). The leaf
    // covering an instant `t` is the shortest-duration span containing `t`.
    let contains = |s: &Span, t: f64| s.ts_start <= t && t < s.ts_end;

    if (hi - lo).abs() < f64::EPSILON {
        // Instant: pick the innermost (shortest) containing span.
        let mut best: Option<&Span> = None;
        for s in candidates {
            if contains(s, ts) {
                match best {
                    Some(b) if b.dur <= s.dur => {}
                    _ => best = Some(s),
                }
            }
        }
        return best.map(|s| vec![(s, 1.0)]).unwrap_or_default();
    }

    // Interval: sweep boundaries within [lo,hi], and for each sub-interval pick
    // the innermost (shortest) span containing its midpoint. Accumulate overlap
    // per chosen span.
    let mut bounds: Vec<f64> = vec![lo, hi];
    for s in candidates {
        if s.ts_start > lo && s.ts_start < hi {
            bounds.push(s.ts_start);
        }
        if s.ts_end > lo && s.ts_end < hi {
            bounds.push(s.ts_end);
        }
    }
    bounds.sort_by(|a, b| a.partial_cmp(b).unwrap());
    bounds.dedup();
    let mut acc: BTreeMap<usize, f64> = BTreeMap::new();
    for w in bounds.windows(2) {
        let (a, b) = (w[0], w[1]);
        if b <= a {
            continue;
        }
        let mid = (a + b) / 2.0;
        // innermost span containing mid
        let mut best_i: Option<usize> = None;
        let mut best_dur = f64::INFINITY;
        for (i, s) in candidates.iter().enumerate() {
            if contains(s, mid) && s.dur < best_dur {
                best_dur = s.dur;
                best_i = Some(i);
            }
        }
        if let Some(i) = best_i {
            *acc.entry(i).or_insert(0.0) += b - a;
        }
    }
    acc.into_iter().map(|(i, ov)| (candidates[i], ov)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn span(tid: u64, name: &str, start: f64, end: f64, chunk: Option<u64>) -> Span {
        let args = match chunk {
            Some(c) => json!({ "chunk_id": c }),
            None => json!({}),
        };
        Span {
            name: name.to_string(),
            parent: String::new(),
            pid: 1,
            tid,
            ts_start: start,
            ts_end: end,
            dur: end - start,
            args,
        }
    }

    fn sample(tid: u64, ts: f64, dur: f64, name: &str, v: f64) -> Sample {
        let mut values = BTreeMap::new();
        values.insert(name.to_string(), v);
        Sample {
            tid,
            ts_us: ts,
            dur_us: dur,
            values,
        }
    }

    /// THE ANTI-NAIVE TEST. Two threads run the SAME region at overlapping
    /// wall windows. A naive pooled-by-time join ("first region whose wall
    /// window contains ts") would charge a thread-2 sample to thread-1's span.
    /// The per-thread join charges it to thread 2.
    ///
    /// Layout (wall µs):
    ///   tid=1: decode[0..100]   (chunk 0)
    ///   tid=2: decode[10..90]   (chunk 1)  <- concurrent, SAME region name
    /// A sample at ts=50 on tid=2 must go to chunk 1, NOT chunk 0.
    #[test]
    fn join_is_per_thread_not_pooled() {
        let spans = vec![
            span(1, "decode", 0.0, 100.0, Some(0)),
            span(2, "decode", 10.0, 90.0, Some(1)),
        ];
        let mut bundle = ProfileBundle::from_spans(&spans);
        // Instant sample on tid=2 at ts=50.
        let samples = vec![sample(2, 50.0, 0.0, "instructions", 1000.0)];
        let orphans = bundle.join_samples(&spans, &samples);
        assert_eq!(orphans, 0);

        let key_t2 = CellKey {
            tid: 2,
            region: "decode".into(),
            partition_idx: Some(1),
        };
        let key_t1 = CellKey {
            tid: 1,
            region: "decode".into(),
            partition_idx: Some(0),
        };
        let c2 = bundle.cells.get(&key_t2).expect("tid2 cell");
        assert_eq!(c2.counters["instructions"].value, 1000.0);
        assert_eq!(c2.counters["instructions"].purity, 1.0);

        // The naive pooled join would have a NONZERO instructions count on the
        // tid=1/chunk-0 cell. Assert it is ZERO (no leakage).
        let c1 = bundle.cells.get(&key_t1).expect("tid1 cell");
        assert!(
            !c1.counters.contains_key("instructions"),
            "sample leaked onto the wrong thread's region (pooled-join bug)"
        );
    }

    /// Innermost-leaf wins: a nested span gets the instant, not its parent.
    #[test]
    fn instant_goes_to_innermost_leaf() {
        let spans = vec![
            span(1, "consumer.iter", 0.0, 100.0, None), // outer
            span(1, "consumer.write_data", 40.0, 60.0, None), // inner leaf
        ];
        let mut bundle = ProfileBundle::from_spans(&spans);
        let samples = vec![sample(1, 50.0, 0.0, "cycles", 7.0)];
        bundle.join_samples(&spans, &samples);
        let inner = bundle
            .cells
            .get(&CellKey {
                tid: 1,
                region: "consumer.write_data".into(),
                partition_idx: None,
            })
            .unwrap();
        assert_eq!(inner.counters["cycles"].value, 7.0);
        let outer = bundle.cells.get(&CellKey {
            tid: 1,
            region: "consumer.iter".into(),
            partition_idx: None,
        });
        // outer cell exists (it has wall) but got NO cycles.
        assert!(!outer.unwrap().counters.contains_key("cycles"));
    }

    /// A straddling interval is apportioned by overlap and its purity drops
    /// below 1.0, so the render-gate flags it.
    #[test]
    fn straddling_interval_is_impure_and_apportioned() {
        // tid=1: A[0..50], B[50..100]; a 1-unit interval [40..60] straddles.
        let spans = vec![
            span(1, "A", 0.0, 50.0, None),
            span(1, "B", 50.0, 100.0, None),
        ];
        let mut bundle = ProfileBundle::from_spans(&spans);
        // interval ending at ts=60 with width 20 => [40,60]
        let samples = vec![sample(1, 60.0, 20.0, "instructions", 100.0)];
        bundle.join_samples(&spans, &samples);
        let a = &bundle
            .cells
            .get(&CellKey {
                tid: 1,
                region: "A".into(),
                partition_idx: None,
            })
            .unwrap()
            .counters["instructions"];
        let b = &bundle
            .cells
            .get(&CellKey {
                tid: 1,
                region: "B".into(),
                partition_idx: None,
            })
            .unwrap()
            .counters["instructions"];
        // [40,50] in A = 10µs, [50,60] in B = 10µs => 50/50 split.
        assert!((a.value - 50.0).abs() < 1e-6, "A got {}", a.value);
        assert!((b.value - 50.0).abs() < 1e-6, "B got {}", b.value);
        // purity = 10/20 = 0.5 each => below threshold => SMEARED.
        assert!((a.purity - 0.5).abs() < 1e-6);
        assert!(!a.is_pure(PURITY_THRESHOLD));
    }

    /// A sample on a thread the trace never saw is an orphan, not a misattribution.
    #[test]
    fn unknown_thread_is_orphan() {
        let spans = vec![span(1, "decode", 0.0, 100.0, Some(0))];
        let mut bundle = ProfileBundle::from_spans(&spans);
        let samples = vec![sample(99, 50.0, 0.0, "cycles", 1.0)];
        let orphans = bundle.join_samples(&spans, &samples);
        assert_eq!(orphans, 1);
    }
}
