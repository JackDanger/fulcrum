#![allow(dead_code)]
//! alloc.rs — the `fulcrum alloc` view: make ALLOCATION fully describable from
//! ONE traced run, per `(tid, region)`, and LOCALIZE page-faults to the
//! region the consumer blocks on — WITHOUT the CPU-sum-over-wall lie that
//! `decompose`'s "36.9% of wall" fell into.
//!
//! ## What it reads
//!
//! gzippy emits, at each region boundary, an `alloc.region` instant (see
//! `src/decompress/parallel/rpmalloc_stats.rs`) carrying the rpmalloc
//! allocator's OWN per-thread counters plus process-wide huge-alloc churn:
//!
//!  - `spans_warm` / `map_calls` — span-cache REUSE vs cold OS mmap. The reuse
//!    rate `warm/(warm+map_calls)` is the rapidgzip-delta signal FOR THE
//!    SPAN-CACHE PATH (<2 MiB allocations). **gzippy's hot buffers are >2 MiB,
//!    so they bypass the span cache entirely** — these read ZERO, which is
//!    itself the finding (no span reuse to measure; the action is in the huge
//!    path below).
//!  - `mapped_total_d` / `unmapped_total_d` / `huge_alloc` — the >2 MiB
//!    monolithic buffer (ChunkData ~12 MiB, output 503 MiB) churn. These are
//!    PROCESS-WIDE; this view treats them as run-level context and NEVER sums
//!    them across threads (they'd over-count concurrent mappers).
//!  - `anon_thp_kib` — AnonHugePages backing. A first-touch-cost multiplier: a
//!    2 MiB THP fault covers 512 base pages, so THP=0 means every page is a
//!    separate minor fault (the TLB-page-walk amplifier).
//!
//! and (from `residual.rs`) `ru_minflt` — the HONEST kernel minor-fault count,
//! per `(tid, region)`.
//!
//! ## The critical-path filter (NOT the CPU-sum trap)
//!
//! `decompose` summed faults across 8 workers and divided by single-thread
//! wall → a 36.9%-of-wall phantom. This view does NOT model faults as wall
//! time. It reports:
//!   1. WHERE the faults land — the fraction of minor faults inside the
//!      frontier-decode region (`worker.decode_chunk`/`worker.bootstrap`) the
//!      schedule (S1) view + frontier-placement oracle established the consumer
//!      blocks ON. A fault concentration there is *consistent with* the stall
//!      being fault-driven; a concentration in slack regions is not.
//!   2. The descriptive allocation shape (reuse / churn / THP) so the
//!      compute-vs-memory call from S3 can be LOCALIZED to a mechanism.
//! It NEVER claims a wall cost from these counts — only S3 (mem-stall cycles)
//! + a warm-buffer PERTURBATION can do that (the HONEST CEILING).

use crate::bundle::ProfileBundle;
use std::collections::BTreeMap;

/// Counter keys gzippy's `alloc.region` instant carries (must match producer).
pub const C_SPANS_WARM: &str = "spans_warm";
pub const C_MAP_CALLS: &str = "map_calls";
pub const C_MAPPED_D: &str = "mapped_total_d";
pub const C_UNMAPPED_D: &str = "unmapped_total_d";
pub const C_HUGE_ALLOC: &str = "huge_alloc";
pub const C_THP_KIB: &str = "anon_thp_kib";
/// From residual.rs — the honest kernel minor-fault count.
pub const C_MINFLT: &str = "ru_minflt";

/// Region-name substrings that constitute the FRONTIER DECODE the consumer
/// blocks on (S1 RATE + frontier-placement oracle). Faults here are
/// critical-path-consistent; faults elsewhere are slack-consistent.
pub const FRONTIER_REGIONS: &[&str] = &["worker.decode_chunk", "worker.bootstrap"];

#[derive(Debug, Clone, Default)]
pub struct RegionAlloc {
    pub region: String,
    pub minflt: f64,
    pub spans_warm: f64,
    pub map_calls: f64,
    /// Max observed (not summed) huge_alloc bytes — a peak proxy.
    pub huge_alloc_peak: f64,
    /// Max observed THP-backed KiB.
    pub thp_kib: f64,
    /// Number of contributing cells (tid×region instances).
    pub cells: u64,
    /// Whether every contribution was pure (per the join).
    pub pure: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AllocReport {
    pub regions: Vec<RegionAlloc>,
    pub total_minflt: f64,
    /// Fraction of minor faults inside the frontier-decode regions.
    pub frontier_fault_frac: f64,
    /// Span-cache reuse rate across all regions (NaN if no span activity).
    pub span_reuse_rate: f64,
    /// Whether ANY region showed THP backing.
    pub any_thp: bool,
}

fn is_frontier(region: &str) -> bool {
    FRONTIER_REGIONS.iter().any(|f| region.contains(f))
}

/// Roll the bundle's per-`(tid,region)` cells up to per-REGION allocation rows,
/// keeping faults per-region (NOT summed-then-divided-by-wall).
pub fn analyze(bundle: &ProfileBundle) -> AllocReport {
    let mut by_region: BTreeMap<String, RegionAlloc> = BTreeMap::new();
    for (key, cell) in &bundle.cells {
        let entry = by_region.entry(key.region.clone()).or_insert_with(|| RegionAlloc {
            region: key.region.clone(),
            pure: true,
            ..Default::default()
        });
        let mut add = |name: &str, into: &mut f64| {
            if let Some(v) = cell.counters.get(name) {
                *into += v.value;
                if v.purity < 0.999 {
                    entry.pure = false;
                }
            }
        };
        add(C_MINFLT, &mut entry.minflt);
        add(C_SPANS_WARM, &mut entry.spans_warm);
        add(C_MAP_CALLS, &mut entry.map_calls);
        // huge_alloc / thp are levels not deltas: take the max seen, don't sum.
        if let Some(v) = cell.counters.get(C_HUGE_ALLOC) {
            entry.huge_alloc_peak = entry.huge_alloc_peak.max(v.value);
        }
        if let Some(v) = cell.counters.get(C_THP_KIB) {
            entry.thp_kib = entry.thp_kib.max(v.value);
        }
        entry.cells += 1;
    }

    let total_minflt: f64 = by_region.values().map(|r| r.minflt).sum();
    let frontier_minflt: f64 = by_region
        .values()
        .filter(|r| is_frontier(&r.region))
        .map(|r| r.minflt)
        .sum();
    let warm: f64 = by_region.values().map(|r| r.spans_warm).sum();
    let maps: f64 = by_region.values().map(|r| r.map_calls).sum();
    let span_reuse_rate = if warm + maps > 0.0 {
        warm / (warm + maps)
    } else {
        f64::NAN
    };
    let any_thp = by_region.values().any(|r| r.thp_kib > 0.0);

    let mut regions: Vec<RegionAlloc> = by_region.into_values().collect();
    regions.sort_by(|a, b| b.minflt.partial_cmp(&a.minflt).unwrap());

    AllocReport {
        regions,
        total_minflt,
        frontier_fault_frac: if total_minflt > 0.0 {
            frontier_minflt / total_minflt
        } else {
            0.0
        },
        span_reuse_rate,
        any_thp,
    }
}

pub fn render(r: &AllocReport) -> String {
    let mut s = String::new();
    s.push_str("fulcrum alloc — per-(tid,region) allocation, fault-localized (NO CPU-sum)\n\n");
    s.push_str(&format!(
        "  {:<22} {:>6} {:>10} {:>9} {:>10} {:>9} {:>8}\n",
        "region", "cells", "minflt", "%faults", "huge_peak", "thp", "pure"
    ));
    for rg in &r.regions {
        let frac = if r.total_minflt > 0.0 {
            100.0 * rg.minflt / r.total_minflt
        } else {
            0.0
        };
        let frontier = if is_frontier(&rg.region) { "*" } else { " " };
        s.push_str(&format!(
            "  {}{:<21} {:>6} {:>10.0} {:>8.1}% {:>9.0}M {:>8.1}M {:>8}\n",
            frontier,
            rg.region,
            rg.cells,
            rg.minflt,
            frac,
            rg.huge_alloc_peak / 1e6,
            rg.thp_kib / 1024.0,
            if rg.pure { "y" } else { "SMEAR" },
        ));
    }
    s.push_str("  (* = frontier-decode region the consumer blocks on; S1 RATE + oracle)\n\n");

    // VERDICT lines — describe + localize; never claim a wall lever.
    s.push_str("  VERDICT (descriptive — locates, does NOT confirm a lever):\n");
    s.push_str(&format!(
        "  • {:.1}% of minor faults land in the FRONTIER-DECODE region.\n",
        100.0 * r.frontier_fault_frac
    ));
    if r.span_reuse_rate.is_nan() {
        s.push_str(
            "  • span-cache reuse: N/A — the hot buffers are >2 MiB (huge path), so they\n      \
             BYPASS the span cache. Reuse must be judged on the HUGE path (huge_peak / churn),\n      \
             NOT this rate. (rapidgzip's 128 KiB sub-buffers DO use the span cache — that is\n      \
             the structural divergence.)\n",
        );
    } else {
        s.push_str(&format!(
            "  • span-cache reuse rate = {:.3} (warm spans / (warm + cold-map)).\n",
            r.span_reuse_rate
        ));
    }
    s.push_str(&format!(
        "  • THP backing the output region: {}.{}\n",
        if r.any_thp { "YES" } else { "NONE" },
        if r.any_thp {
            ""
        } else {
            " ⇒ every output page is a separate 4 KiB minor fault + TLB walk (no 512×\n      \
             hugepage amortization) — the page-walk amplifier."
        }
    ));
    s.push_str(
        "\n  HONEST CEILING: a fault concentration in the frontier region is CONSISTENT with\n  \
         the stall being fault-driven, but does NOT prove the reuse-pool moves the wall.\n  \
         Confirm with S3 (mem-stall cycles on the blocking decode) + a warm/THP-buffer\n  \
         PERTURBATION (decode rate held, interleaved wall). Description locates; it never confirms.\n",
    );
    s
}

/// Pull alloc + minflt counters out of the trace into zero-width samples
/// (same join contract `decompose` uses for the residual tier).
pub fn alloc_samples(events: &[crate::trace::Event]) -> Vec<crate::bundle::Sample> {
    let keys = [
        C_SPANS_WARM,
        C_MAP_CALLS,
        C_MAPPED_D,
        C_UNMAPPED_D,
        C_HUGE_ALLOC,
        C_THP_KIB,
        C_MINFLT,
    ];
    let mut out = Vec::new();
    for e in events {
        if e.ph != "i" {
            continue;
        }
        let mut values = BTreeMap::new();
        for k in keys {
            if let Some(v) = e.args.get(k).and_then(|x| match x {
                serde_json::Value::Number(n) => n.as_f64(),
                serde_json::Value::String(s) => s.parse().ok(),
                _ => None,
            }) {
                values.insert(k.to_string(), v);
            }
        }
        if !values.is_empty() {
            out.push(crate::bundle::Sample {
                tid: e.tid,
                ts_us: e.ts,
                dur_us: 0.0,
                values,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{Event, Span};

    fn ev(name: &str, ph: &str, ts: f64, tid: u64, args: serde_json::Value) -> Event {
        Event {
            name: name.to_string(),
            ph: ph.to_string(),
            ts,
            tid,
            pid: 1,
            args,
        }
    }

    /// A synthetic trace where ALL faults land in the frontier-decode span on
    /// one worker, and a tiny number in the consumer span: the view must
    /// report ~100% frontier-fault-frac, NaN span-reuse (no span activity),
    /// NONE THP — and never sum across threads into a wall %.
    #[test]
    fn frontier_fault_localization_no_cpu_sum() {
        // worker.decode_chunk span [0,100) on tid 7, with an alloc.region
        // instant at t=50 carrying 1000 faults; consumer.iter [0,200) on tid 1
        // with 10 faults at t=100.
        let mkspan = |name: &str, tid: u64, a: f64, b: f64| Span {
            name: name.to_string(),
            parent: String::new(),
            pid: 1,
            tid,
            ts_start: a,
            ts_end: b,
            dur: b - a,
            args: serde_json::json!({}),
        };
        let spans = vec![
            mkspan("worker.decode_chunk", 7, 0.0, 100.0),
            mkspan("consumer.iter", 1, 0.0, 200.0),
        ];
        let events = vec![
            ev(
                "alloc.region",
                "i",
                50.0,
                7,
                serde_json::json!({"ru_minflt": 1000, "spans_warm": 0, "map_calls": 0, "anon_thp_kib": 0, "huge_alloc": 671000000}),
            ),
            ev(
                "alloc.region",
                "i",
                100.0,
                1,
                serde_json::json!({"ru_minflt": 10, "spans_warm": 0, "map_calls": 0, "anon_thp_kib": 0, "huge_alloc": 671000000}),
            ),
        ];
        let mut bndl = ProfileBundle::from_spans(&spans);
        let samples = alloc_samples(&events);
        bndl.join_samples(&spans, &samples);
        let r = analyze(&bndl);
        assert!(
            (r.frontier_fault_frac - 1000.0 / 1010.0).abs() < 1e-6,
            "frontier fault frac {} != ~0.990",
            r.frontier_fault_frac
        );
        assert!(r.span_reuse_rate.is_nan(), "no span activity ⇒ reuse NaN");
        assert!(!r.any_thp, "THP=0 in fixture");
        assert_eq!(r.total_minflt, 1010.0);
    }
}
