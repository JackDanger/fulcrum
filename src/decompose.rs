#![allow(dead_code)]
//! decompose.rs — the `fulcrum decompose` view: NAME the model residual.
//!
//! The model (`model.rs`) historically left a 17–41% "residual" — wall the
//! named regions didn't explain. That residual is not noise; it is page-fault
//! servicing, allocator zeroing, involuntary context switches (preemption /
//! blocked-on-host), and runnable-but-not-running queueing. This view turns
//!
//!     wall = Σ(named regions) + 17% UNEXPLAINED
//!
//! into
//!
//!     wall = Σ(named regions) + page-fault X% + ctxsw Y% + alloc Z% + blocked-on-host W%
//!
//! using PERF-FREE, self-keyed counters that gzippy emits at region
//! boundaries via getrusage(RUSAGE_THREAD) and /proc/self/task/<tid>/schedstat:
//!
//!  - `ru_minflt` / `ru_majflt`  — minor/major page faults (alloc zeroing,
//!    first-touch, file-backed faults).
//!  - `nvcsw` / `nivcsw`         — voluntary / INvoluntary context switches.
//!    INvoluntary ctxsw is the "blocked-on-host / preempted" signal (a noisy
//!    neighbor or the hypervisor stole the CPU) that perf can't easily give.
//!  - schedstat run / runnable    — runnable-but-waiting-for-CPU µs (queueing).
//!  - `VmRSS` / `maxrss` delta    — resident growth = allocator/zeroing pressure.
//!
//! gzippy emits these as DELTAS over each region, as trace counter values on
//! the producing thread (so the per-thread join in `bundle.rs` attributes them
//! to the right `(tid, region)` cell with no sampling error).
//!
//! The decompose view models each fault/ctxsw class as a TIME cost using
//! conservative per-event service times and reports the residual SPLIT. The
//! per-event costs are intentionally conservative midpoints; the OUTPUT is the
//! RANKING + rough magnitude (page-fault-dominant vs ctxsw-dominant vs
//! alloc-dominant), which is what arbitrates the compute-vs-memory question —
//! not a to-the-µs cost model.

use crate::bundle::ProfileBundle;

/// Conservative per-event service-time midpoints (µs). Used only to RANK the
/// residual contributors, not to claim an exact wall cost.
pub mod cost {
    /// Minor page fault: TLB miss + zero-fill / map. ~1µs is a common midpoint
    /// on a warm Linux box; clear_page of a 4K page + fault handler.
    pub const MINFLT_US: f64 = 1.0;
    /// Major page fault: backing-store I/O. Orders larger.
    pub const MAJFLT_US: f64 = 50.0;
    /// One context switch: save/restore + scheduler + cache-warmup tax. A
    /// voluntary switch (blocked on I/O/lock) and an involuntary (preempted)
    /// both cost roughly this in direct + indirect terms.
    pub const CTXSW_US: f64 = 3.0;
}

/// The counter names gzippy emits per region (must match the producer side).
pub const C_MINFLT: &str = "ru_minflt";
pub const C_MAJFLT: &str = "ru_majflt";
pub const C_NVCSW: &str = "nvcsw";
pub const C_NIVCSW: &str = "nivcsw";
/// schedstat: runnable-but-not-running nanoseconds (queueing latency).
pub const C_RUNNABLE_NS: &str = "sched_runnable_ns";
/// VmRSS delta in bytes over the region (allocator/zeroing proxy).
pub const C_RSS_DELTA: &str = "rss_delta_bytes";

/// One named residual contributor.
#[derive(Debug, Clone)]
pub struct ResidualTerm {
    pub name: &'static str,
    /// Modeled time cost, µs.
    pub modeled_us: f64,
    /// Raw event count / bytes (for context).
    pub raw: f64,
    /// Whether the contributing counter values were pure (per the join).
    pub pure: bool,
}

/// The decompose result.
#[derive(Debug, Clone, Default)]
pub struct Decomposition {
    pub wall_us: f64,
    /// Sum of named-region self-time (the spans the model accounts for).
    pub named_region_us: f64,
    /// The residual = wall − named_region (what the model left unexplained).
    pub residual_us: f64,
    /// The residual, split into named contributors.
    pub terms: Vec<ResidualTerm>,
    /// Residual µs the terms below could NOT name.
    pub unnamed_residual_us: f64,
}

impl Decomposition {
    /// Fraction of the residual that we managed to NAME.
    pub fn named_residual_frac(&self) -> f64 {
        if self.residual_us <= 0.0 {
            return 1.0;
        }
        let named: f64 = self.terms.iter().map(|t| t.modeled_us).sum();
        (named / self.residual_us).min(1.0)
    }
}

/// Sum a counter across all cells, tracking whether every contribution was
/// pure (purity == 1.0 within epsilon).
fn sum_counter(bundle: &ProfileBundle, name: &str) -> (f64, bool) {
    let mut total = 0.0;
    let mut pure = true;
    for cell in bundle.cells.values() {
        if let Some(v) = cell.counters.get(name) {
            total += v.value;
            if v.purity < 0.999 {
                pure = false;
            }
        }
    }
    (total, pure)
}

/// Decompose the run's wall into Σ(named regions) + named residual.
///
/// `named_region_us` is supplied by the caller (the model's accounted self-time
/// — typically the sum of consumer-thread self-time + the irreducible output
/// floor, however the model defines "named"). decompose then NAMES the gap.
pub fn decompose(bundle: &ProfileBundle, named_region_us: f64) -> Decomposition {
    let mut d = Decomposition {
        wall_us: bundle.wall_us,
        named_region_us,
        residual_us: (bundle.wall_us - named_region_us).max(0.0),
        ..Default::default()
    };

    let (minflt, p1) = sum_counter(bundle, C_MINFLT);
    let (majflt, p2) = sum_counter(bundle, C_MAJFLT);
    let (nvcsw, p3) = sum_counter(bundle, C_NVCSW);
    let (nivcsw, p4) = sum_counter(bundle, C_NIVCSW);
    let (runnable_ns, p5) = sum_counter(bundle, C_RUNNABLE_NS);
    let (rss_delta, p6) = sum_counter(bundle, C_RSS_DELTA);

    if minflt > 0.0 {
        d.terms.push(ResidualTerm {
            name: "page-fault (minor)",
            modeled_us: minflt * cost::MINFLT_US,
            raw: minflt,
            pure: p1,
        });
    }
    if majflt > 0.0 {
        d.terms.push(ResidualTerm {
            name: "page-fault (major)",
            modeled_us: majflt * cost::MAJFLT_US,
            raw: majflt,
            pure: p2,
        });
    }
    if nivcsw > 0.0 {
        d.terms.push(ResidualTerm {
            name: "ctxsw (involuntary / blocked-on-host)",
            modeled_us: nivcsw * cost::CTXSW_US,
            raw: nivcsw,
            pure: p4,
        });
    }
    if nvcsw > 0.0 {
        d.terms.push(ResidualTerm {
            name: "ctxsw (voluntary / blocked-on-lock-io)",
            modeled_us: nvcsw * cost::CTXSW_US,
            raw: nvcsw,
            pure: p3,
        });
    }
    if runnable_ns > 0.0 {
        // schedstat runnable time is already a TIME (ns) — name it directly.
        d.terms.push(ResidualTerm {
            name: "runnable-waiting-for-cpu (queueing)",
            modeled_us: runnable_ns / 1000.0,
            raw: runnable_ns,
            pure: p5,
        });
    }
    if rss_delta != 0.0 {
        // RSS growth in pages → minor-fault-equivalent zeroing cost. Reported
        // as context; not double-counted into the residual sum if minflt is
        // present (they overlap), so flag it as informational by zeroing its
        // modeled cost when minflt already covers it.
        let pages = (rss_delta.abs() / 4096.0).round();
        let modeled = if minflt > 0.0 { 0.0 } else { pages * cost::MINFLT_US };
        d.terms.push(ResidualTerm {
            name: "rss-growth (alloc/zeroing, info)",
            modeled_us: modeled,
            raw: rss_delta,
            pure: p6,
        });
    }

    let named: f64 = d.terms.iter().map(|t| t.modeled_us).sum();
    d.unnamed_residual_us = (d.residual_us - named).max(0.0);
    d
}

/// Render the decompose verdict (the decision-view line + the split).
pub fn render(d: &Decomposition) -> String {
    let mut out = String::new();
    let wall = d.wall_us.max(1.0);
    out.push_str(&format!(
        "  wall                  : {:.2}ms\n",
        d.wall_us / 1000.0
    ));
    out.push_str(&format!(
        "  consumer own work     : {:.2}ms ({:.1}%)  (COMPUTE+OUTPUT self-time)\n",
        d.named_region_us / 1000.0,
        100.0 * d.named_region_us / wall
    ));
    out.push_str(&format!(
        "  wait/residual         : {:.2}ms ({:.1}%)  (consumer blocked on producers + unmodeled)\n",
        d.residual_us / 1000.0,
        100.0 * d.residual_us / wall
    ));
    out.push_str(
        "  (the rusage counters below are summed ACROSS ALL THREADS, so a term can\n   exceed the consumer's own self-time — it NAMES the producer-side mechanism\n   the consumer waits on. % is of WALL.)\n",
    );
    if d.terms.is_empty() {
        out.push_str(
            "  NAMED residual        : (no getrusage/schedstat counters in trace — \
             re-run gzippy with GZIPPY_TIMELINE + residual instrumentation)\n",
        );
    } else {
        out.push_str("  NAMED residual split  :\n");
        let mut terms = d.terms.clone();
        terms.sort_by(|a, b| b.modeled_us.partial_cmp(&a.modeled_us).unwrap());
        for t in &terms {
            let flag = if t.pure { "" } else { " [SMEARED]" };
            out.push_str(&format!(
                "    {:<38}: {:>8.2}ms ({:>4.1}% of wall)  raw={:.0}{}\n",
                t.name,
                t.modeled_us / 1000.0,
                100.0 * t.modeled_us / wall,
                t.raw,
                flag
            ));
        }
        out.push_str(&format!(
            "    {:<38}: {:>8.2}ms ({:>4.1}% of wall)\n",
            "still-unnamed",
            d.unnamed_residual_us / 1000.0,
            100.0 * d.unnamed_residual_us / wall
        ));
        let top = terms.first().unwrap();
        out.push_str(&format!(
            "  VERDICT: dominant NAMED mechanism = {} ({:.1}% of wall, {:.0} events).\n",
            top.name,
            100.0 * top.modeled_us / wall,
            top.raw
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{AttributedValue, CellKey, RegionCell};

    fn bundle_with(counters: &[(&str, f64)], wall: f64) -> ProfileBundle {
        let mut b = ProfileBundle {
            wall_us: wall,
            ..Default::default()
        };
        let mut cell = RegionCell::default();
        for (n, v) in counters {
            cell.counters.insert(
                n.to_string(),
                AttributedValue {
                    value: *v,
                    purity: 1.0,
                },
            );
        }
        b.cells.insert(
            CellKey {
                tid: 1,
                region: "decode".into(),
                partition_idx: Some(0),
            },
            cell,
        );
        b
    }

    #[test]
    fn names_pagefault_residual() {
        // wall 1000µs, named regions 700µs => residual 300µs. 200 minor faults
        // @1µs = 200µs named, leaving 100µs unnamed.
        let b = bundle_with(&[(C_MINFLT, 200.0), (C_NIVCSW, 10.0)], 1000.0);
        let d = decompose(&b, 700.0);
        assert!((d.residual_us - 300.0).abs() < 1e-6);
        // minor faults 200µs + nivcsw 30µs = 230µs named of the 300µs residual.
        let named: f64 = d.terms.iter().map(|t| t.modeled_us).sum();
        assert!((named - 230.0).abs() < 1e-6, "named={named}");
        assert!((d.unnamed_residual_us - 70.0).abs() < 1e-6);
        assert!(d.named_residual_frac() > 0.76 && d.named_residual_frac() < 0.77);
    }

    #[test]
    fn empty_counters_name_nothing() {
        let b = bundle_with(&[], 1000.0);
        let d = decompose(&b, 700.0);
        assert!(d.terms.is_empty());
        assert!((d.unnamed_residual_us - 300.0).abs() < 1e-6);
    }
}
