#![allow(dead_code)]
//! decompose.rs — the `fulcrum decompose` view: NAME the model residual.
//!
//! The model (`model.rs`) historically left a 17–41% "residual" — wall the
//! named regions didn't explain. That residual is not noise; it is page-fault
//! servicing, allocator zeroing, involuntary context switches (preemption /
//! blocked-on-host), and runnable-but-not-running queueing. This view turns
//!
//! ```text
//! wall = Σ(named regions) + 17% UNEXPLAINED
//! ```
//!
//! into
//!
//! ```text
//! wall = Σ(named regions) + page-fault X% + ctxsw Y% + alloc Z% + blocked-on-host W%
//! ```
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
    /// WALL-RELEVANT modeled time cost, µs. This is the raw cross-thread CPU
    /// cost (`cpu_us`) normalized by the run's parallelism, so it is
    /// comparable to the single-thread wall. NEVER store an un-normalized
    /// cross-thread CPU sum here — that is the D1 lie (a 320%-of-wall headline).
    pub modeled_us: f64,
    /// Raw cross-thread CPU cost, µs (Σ over all (tid,region) cells × per-event
    /// cost). This is CPU-seconds, NOT a wall fraction: at T>1 the work runs in
    /// parallel, so `cpu_us` can legitimately exceed the wall. Kept for honest
    /// reporting as CPU-µs; it must not be rendered as "% of wall".
    pub cpu_us: f64,
    /// Raw event count / bytes (for context).
    pub raw: f64,
    /// Whether the contributing counter values were pure (per the join).
    pub pure: bool,
    /// Whether the per-event cost that produced `modeled_us` is CALIBRATED.
    /// `false` => a fabricated/conservative midpoint constant (e.g. the 1µs/
    /// minor-fault guess) that must NOT drive an authoritative headline.
    pub calibrated: bool,
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
    /// Fraction of the residual that the named terms account for.
    ///
    /// NOT clamped. A value > 1.0 is a CONSERVATION VIOLATION: the named
    /// mechanisms model MORE wall than the residual contains — i.e. the
    /// count→time model OVER-attributes (commonly because a per-event cost is
    /// an un-calibrated guess). Clamping this to 1.0 (the old `.min(1.0)`)
    /// laundered an 8× over-attribution into a reassuring "100% explained";
    /// callers must instead surface the violation (see
    /// [`Decomposition::conservation_violated`]).
    pub fn named_residual_frac(&self) -> f64 {
        let named: f64 = self.terms.iter().map(|t| t.modeled_us).sum();
        if self.residual_us <= 0.0 {
            // Nothing to explain. If we still modeled named cost over a
            // zero/negative residual, that itself is a conservation violation.
            return if named > 0.0 { f64::INFINITY } else { 1.0 };
        }
        named / self.residual_us
    }

    /// True when the named terms sum to MORE than the residual — the model
    /// attributed more wall than exists. This is a measurement/attribution
    /// error to be FLAGGED, never rendered as "fully explained".
    pub fn conservation_violated(&self) -> bool {
        self.named_residual_frac() > 1.0 + 1e-9
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

    // PARALLELISM normalization (the D1 fix). The counters above are summed
    // ACROSS ALL producer threads, so `count × per-event-cost` is a cross-thread
    // CPU sum. At T>1 that work overlaps on N cores; presenting it directly as
    // "% of a single-thread wall" inflates without bound (T16 page-faults =
    // 320% of a 10ms wall). The wall-relevant figure divides the CPU sum by the
    // run's parallelism. `cpu_us` keeps the honest un-normalized CPU cost.
    let parallelism = (bundle.n_threads.max(1)) as f64;
    let push = |d: &mut Decomposition,
                name: &'static str,
                cpu_us: f64,
                raw: f64,
                pure: bool,
                calibrated: bool| {
        d.terms.push(ResidualTerm {
            name,
            modeled_us: cpu_us / parallelism,
            cpu_us,
            raw,
            pure,
            calibrated,
        });
    };

    if minflt > 0.0 {
        // fabricated 1µs/fault midpoint => un-calibrated.
        push(
            &mut d,
            "page-fault (minor)",
            minflt * cost::MINFLT_US,
            minflt,
            p1,
            false,
        );
    }
    if majflt > 0.0 {
        push(
            &mut d,
            "page-fault (major)",
            majflt * cost::MAJFLT_US,
            majflt,
            p2,
            false,
        );
    }
    if nivcsw > 0.0 {
        push(
            &mut d,
            "ctxsw (involuntary / blocked-on-host)",
            nivcsw * cost::CTXSW_US,
            nivcsw,
            p4,
            false,
        );
    }
    if nvcsw > 0.0 {
        push(
            &mut d,
            "ctxsw (voluntary / blocked-on-lock-io)",
            nvcsw * cost::CTXSW_US,
            nvcsw,
            p3,
            false,
        );
    }
    if runnable_ns > 0.0 {
        // schedstat runnable time is a MEASURED time (ns), not a fabricated
        // constant => calibrated. Still a cross-thread sum, so normalize.
        push(
            &mut d,
            "runnable-waiting-for-cpu (queueing)",
            runnable_ns / 1000.0,
            runnable_ns,
            p5,
            true,
        );
    }
    if rss_delta != 0.0 {
        // RSS growth in pages → minor-fault-equivalent zeroing cost. Reported
        // as context; not double-counted into the residual sum if minflt is
        // present (they overlap), so flag it as informational by zeroing its
        // modeled cost when minflt already covers it.
        let pages = (rss_delta.abs() / 4096.0).round();
        let cpu_us = if minflt > 0.0 {
            0.0
        } else {
            pages * cost::MINFLT_US
        };
        push(
            &mut d,
            "rss-growth (alloc/zeroing, info)",
            cpu_us,
            rss_delta,
            p6,
            false,
        );
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
        "  (the rusage counters below are summed ACROSS ALL THREADS; the modeled µs\n   is normalized by the run's parallelism so it is comparable to the\n   single-thread wall. CPU-µs (un-normalized cross-thread cost) is shown\n   separately and is NOT a wall fraction.)\n",
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
            let pct = 100.0 * t.modeled_us / wall;
            // CLAMP + FLAG: a term whose NORMALIZED cost still exceeds the wall
            // is a measurement/attribution error (a cross-thread CPU sum that
            // cannot be a wall fraction). Show the clamp, never print 320%.
            let (disp_pct, overflow_flag) = if pct > 100.0 {
                (
                    100.0,
                    " [>100% of WALL — cross-thread CPU sum, NOT a wall fraction; measurement error]",
                )
            } else {
                (pct, "")
            };
            let smear_flag = if t.pure { "" } else { " [SMEARED]" };
            let calib_flag = if t.calibrated {
                ""
            } else {
                " [un-calibrated cost]"
            };
            out.push_str(&format!(
                "    {:<38}: {:>8.2}ms ({:>4.1}% of wall, {:.2}ms CPU)  raw={:.0}{}{}{}\n",
                t.name,
                t.modeled_us / 1000.0,
                disp_pct,
                t.cpu_us / 1000.0,
                t.raw,
                smear_flag,
                calib_flag,
                overflow_flag
            ));
        }
        out.push_str(&format!(
            "    {:<38}: {:>8.2}ms ({:>4.1}% of wall)\n",
            "still-unnamed",
            d.unnamed_residual_us / 1000.0,
            100.0 * d.unnamed_residual_us / wall
        ));
        if d.conservation_violated() {
            out.push_str(&format!(
                "  CONSERVATION VIOLATION: named terms model {:.1}× the residual \
                 (over-attribution) — the wall is NOT fully explained; treat the split as un-trustworthy.\n",
                d.named_residual_frac()
            ));
        }
        let top = terms.first().unwrap();
        let top_pct = 100.0 * top.modeled_us / wall;
        // REFUSE the authoritative headline when the leading candidate rests on
        // an un-calibrated constant or overflows the wall — print the RANKING
        // only, not a calibrated wall-fraction claim.
        if !top.calibrated || top_pct > 100.0 {
            out.push_str(&format!(
                "  VERDICT: WITHHELD — leading residual candidate = {} ({:.0} events). \
                 It rests on an un-calibrated cost constant and/or exceeds 100% of wall \
                 (cross-thread CPU sum); reporting the RANKING only, not a calibrated \
                 wall-fraction headline.\n",
                top.name, top.raw
            ));
        } else {
            out.push_str(&format!(
                "  VERDICT: dominant NAMED mechanism = {} ({:.1}% of wall, {:.0} events).\n",
                top.name, top_pct, top.raw
            ));
        }
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

    /// D1 guard: a cross-thread fault sum is normalized by parallelism so the
    /// modeled (wall-relevant) cost never exceeds the wall, while the raw
    /// CPU-µs is preserved un-normalized. Pre-fix this term modeled 320% of wall.
    #[test]
    fn parallel_fault_sum_is_normalized_not_a_wall_fraction() {
        let mut b = ProfileBundle {
            wall_us: 10_000.0,
            n_threads: 16,
            ..Default::default()
        };
        for tid in 1..=16u64 {
            let mut cell = RegionCell::default();
            cell.counters.insert(
                C_MINFLT.to_string(),
                AttributedValue {
                    value: 2000.0,
                    purity: 1.0,
                },
            );
            b.cells.insert(
                CellKey {
                    tid,
                    region: "decode".into(),
                    partition_idx: Some(tid),
                },
                cell,
            );
        }
        let d = decompose(&b, 4_000.0);
        let pf = d
            .terms
            .iter()
            .find(|t| t.name.contains("page-fault (minor)"))
            .unwrap();
        // raw cross-thread CPU cost is honestly 32ms...
        assert!((pf.cpu_us - 32_000.0).abs() < 1e-6, "cpu_us={}", pf.cpu_us);
        // ...but the wall-relevant modeled cost is normalized to 32/16 = 2ms.
        assert!(
            (pf.modeled_us - 2_000.0).abs() < 1e-6,
            "modeled_us={}",
            pf.modeled_us
        );
        assert!(100.0 * pf.modeled_us / d.wall_us <= 100.0);
        // fabricated 1µs/fault => un-calibrated.
        assert!(!pf.calibrated);
    }

    /// D2 guard: over-attribution surfaces as named_residual_frac > 1.0 and a
    /// conservation violation — never laundered into "100% explained".
    #[test]
    fn over_attribution_is_a_conservation_violation_not_clamped() {
        let b = bundle_with(&[(C_MINFLT, 50_000.0)], 10_000.0);
        let d = decompose(&b, 4_000.0); // residual = 6ms, named = 50ms
        assert!(d.named_residual_frac() > 1.0);
        assert!(d.conservation_violated());
        assert!(render(&d).contains("CONSERVATION VIOLATION"));
    }

    /// D1 render guard: an un-calibrated / overflowing dominant term WITHHOLDS
    /// the authoritative VERDICT headline and never prints a >100% wall fraction.
    #[test]
    fn render_withholds_headline_for_uncalibrated_overflow() {
        let b = bundle_with(&[(C_MINFLT, 50_000.0)], 10_000.0);
        let d = decompose(&b, 4_000.0);
        let r = render(&d);
        assert!(r.contains("VERDICT: WITHHELD"), "{r}");
        assert!(r.contains(">100% of WALL"), "{r}");
        assert!(!r.contains("dominant NAMED mechanism"), "{r}");
    }
}
