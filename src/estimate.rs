//! Counterfactual cost estimator — PREDICT a structural change's wall delta
//! BEFORE building it.
//!
//! This is the capability that would have stopped two multi-hour falsified
//! levers: it combines a region's **access counts** ([`crate::region_hw`] +
//! the trace) with the **measured per-operation cost** of the primitive a
//! change swaps in ([`crate::microbench`]) into a grounded arithmetic
//! prediction of the wall move — not a hunch.
//!
//! ## The model
//!
//! A change is described as a set of [`Delta`]s, each saying "this region used
//! to perform `count` ops at `from` cycles each; it will now perform `count'`
//! ops at `to` cycles each" (plus optional NEW one-time work). The region's
//! per-iteration cycle change is the sum of those deltas. The WALL change is
//! that region-cycle change scaled by:
//!
//!   1. how much of the region's cycles the changed ops actually are (you don't
//!      get to move cycles the change doesn't touch), and
//!   2. the region's **on-critical-path share** — the FULCRUM invariant that
//!      only time on the consumer's critical path moves the wall. A change to a
//!      fully-overlapped off-path region predicts ≈0, exactly as the v1 layer
//!      found for the 212 ms absorb copy.
//!
//! Formally, for a region R with baseline wall `wall_R` (its on-path
//! contribution) and a set of deltas:
//!
//! ```text
//!   delta_cycles_R   = Σ_d ( count'_d · to_d − count_d · from_d )  +  Σ_d new_cycles_d
//!   delta_wall_R     = delta_cycles_R / region_cycle_rate          (cycles → wall seconds)
//!   predicted_wall_% = on_path_share_R · ( delta_wall_R / wall_R )
//! ```
//!
//! `region_cycle_rate` is the region's measured cycles-per-second-of-wall (from
//! its IPC and clock); when unknown we fall back to the box clock. The result
//! is a SIGNED percentage of total wall: negative = speedup, positive =
//! slowdown.
//!
//! ## Why this catches the known failures (the validation gate)
//!
//! * **u8 + journal** swapped a u16 masked-ring store (cheap, ~1 cyc, in-L1)
//!   for a u8 store PLUS a journal append PLUS a later journal-replay pass over
//!   ~21M entries / ~296 MB that is a fresh cache-cold streaming read. The
//!   estimator multiplies 21M replay ops by the *measured* DRAM-streaming
//!   cost — a large positive (slowdown) term the eye misses but the arithmetic
//!   cannot. PLUS it accounts for the lost ISA-L clean-tail fast path as
//!   re-added slow-path cycles. Net: a big positive %, NOT a win.
//! * **incompressible flat** isn't a per-op change at all — it's that the
//!   region's on-path share is already ≈ its serial share (no parallel slack to
//!   recover). Modeled as a change with ~0 movable on-path share ⇒ ≈0 predicted
//!   improvement, matching "it just doesn't parallelize."
//! * **inline match-copy** removed per-iteration yield-check / bounds overhead
//!   on the hot copy: a modest negative cyc/op delta over the copy count, on a
//!   high-on-path region ⇒ a few-percent speedup, matching the measured +5%.

use crate::critpath::CritPath;
use crate::microbench::BenchResult;
use crate::rank;
use crate::config::Config;

/// One per-operation cost change inside a region.
#[derive(Debug, Clone)]
pub struct Delta {
    /// Human label (e.g. "marker-ring store: u16→u8").
    pub what: String,
    /// Baseline op count per UNIT OF WORK (one decoded run / one full decode,
    /// consistent with how `wall_cycles` below is scoped).
    pub count_from: f64,
    /// Baseline cycles per op (measured by a microbench, or known).
    pub cyc_from: f64,
    /// Op count after the change (often == count_from; differs when the change
    /// adds/removes operations, e.g. a journal that appends a 2nd op per byte).
    pub count_to: f64,
    /// Cycles per op after the change (measured candidate primitive).
    pub cyc_to: f64,
    /// One-time NEW cycles the change introduces per unit of work that have no
    /// baseline counterpart (e.g. a whole journal-replay pass). Defaults 0.
    pub new_cycles: f64,
}

impl Delta {
    /// Convenience constructor for a pure per-op swap (same count, new cost).
    pub fn swap(what: &str, count: f64, cyc_from: f64, cyc_to: f64) -> Self {
        Delta {
            what: what.to_string(),
            count_from: count,
            cyc_from,
            count_to: count,
            cyc_to,
            new_cycles: 0.0,
        }
    }
    /// Convenience constructor for added work (no baseline): N ops at C cycles.
    pub fn added(what: &str, count: f64, cyc: f64) -> Self {
        Delta {
            what: what.to_string(),
            count_from: 0.0,
            cyc_from: 0.0,
            count_to: count,
            cyc_to: cyc,
            new_cycles: 0.0,
        }
    }
    /// Convenience constructor for removed work (e.g. eliding a fast path):
    /// negative contribution.
    pub fn removed(what: &str, count: f64, cyc: f64) -> Self {
        Delta {
            what: what.to_string(),
            count_from: count,
            cyc_from: cyc,
            count_to: 0.0,
            cyc_to: 0.0,
            new_cycles: 0.0,
        }
    }

    /// Net cycles this delta adds (per unit of work). Positive = slower.
    pub fn delta_cycles(&self) -> f64 {
        self.count_to * self.cyc_to - self.count_from * self.cyc_from + self.new_cycles
    }
}

/// A region's measured baseline for the estimate.
#[derive(Debug, Clone)]
pub struct RegionBaseline {
    pub region: String,
    /// Total wall the WHOLE run takes (seconds) — the denominator for the % .
    pub total_wall_s: f64,
    /// This region's ON-CRITICAL-PATH share of the wall (0..1), from FULCRUM's
    /// critical-path layer. This is the cap on how much of `delta_wall` reaches
    /// the wall.
    pub on_path_share: f64,
    /// The region's effective clock in cycles/second (IPC × freq, or just the
    /// box freq). Converts cycle deltas to wall seconds.
    pub cycles_per_s: f64,
    /// Baseline cycles the region spends per unit of work, IF KNOWN — used to
    /// sanity-bound a delta (you can't remove more cycles than the region has).
    /// `None` to skip the bound.
    pub region_cycles_per_unit: Option<f64>,
    /// Units of work per run (e.g. number of decoded chunks), so per-unit cycle
    /// deltas scale to the whole run. Default 1.0 if the deltas are already
    /// whole-run counts.
    pub units_per_run: f64,
}

/// The estimate for one proposed change.
#[derive(Debug, Clone)]
pub struct Estimate {
    pub change: String,
    pub region: String,
    /// Net cycles added across the whole run (Σ deltas × units).
    pub run_delta_cycles: f64,
    /// That as wall seconds at the region clock.
    pub run_delta_wall_s: f64,
    /// As a SIGNED fraction of total wall, BEFORE the on-path cap.
    pub raw_wall_frac: f64,
    /// As a SIGNED fraction of total wall, AFTER the on-path cap (the headline
    /// prediction). Negative = predicted speedup.
    pub predicted_wall_frac: f64,
    /// Per-delta cycle contributions, for the explanation.
    pub breakdown: Vec<(String, f64)>,
    /// Confidence note (what the prediction trusts / where it's soft).
    pub confidence: String,
}

impl Estimate {
    /// Predicted wall move as a percentage with sign (negative = faster).
    pub fn predicted_pct(&self) -> f64 {
        self.predicted_wall_frac * 100.0
    }
}

/// Compute the counterfactual estimate for a change = a set of deltas applied
/// to one region with a measured baseline.
pub fn estimate(change: &str, base: &RegionBaseline, deltas: &[Delta]) -> Estimate {
    let mut breakdown = Vec::new();
    let mut per_unit_cycles = 0.0;
    for d in deltas {
        let dc = d.delta_cycles();
        per_unit_cycles += dc;
        breakdown.push((d.what.clone(), dc));
    }
    let run_delta_cycles = per_unit_cycles * base.units_per_run;

    // Bound a *speedup* by the region's actual cycle budget: you cannot remove
    // more cycles than the region spends. (Slowdowns are unbounded above.)
    let run_delta_cycles = if let Some(budget_per_unit) = base.region_cycles_per_unit {
        let budget = budget_per_unit * base.units_per_run;
        if run_delta_cycles < 0.0 {
            run_delta_cycles.max(-budget)
        } else {
            run_delta_cycles
        }
    } else {
        run_delta_cycles
    };

    let run_delta_wall_s = if base.cycles_per_s > 0.0 {
        run_delta_cycles / base.cycles_per_s
    } else {
        0.0
    };
    let raw_wall_frac = if base.total_wall_s > 0.0 {
        run_delta_wall_s / base.total_wall_s
    } else {
        0.0
    };
    // The on-path cap: only the region's on-critical-path share of a change
    // reaches the wall. A SPEEDUP (negative) is capped by on-path share (you
    // only recover the on-path portion). A SLOWDOWN (positive) on added serial
    // work is *also* gated by on-path share when it lands on overlapped work,
    // BUT added work that creates a NEW serial dependency (a replay pass that
    // the consumer must wait on) lands fully on the path. We model the
    // common case — the change stays within the region's existing on-path
    // character — by scaling both directions by on_path_share, and let the
    // caller raise on_path_share→1.0 for a change that serializes a previously
    // overlapped region (see the journal postdiction, which does exactly that).
    let predicted_wall_frac = raw_wall_frac * base.on_path_share;

    let confidence = build_confidence(base, deltas, raw_wall_frac, predicted_wall_frac);

    Estimate {
        change: change.to_string(),
        region: base.region.clone(),
        run_delta_cycles,
        run_delta_wall_s,
        raw_wall_frac,
        predicted_wall_frac,
        breakdown,
        confidence,
    }
}

fn build_confidence(
    base: &RegionBaseline,
    deltas: &[Delta],
    raw: f64,
    capped: f64,
) -> String {
    let mut notes = Vec::new();
    if base.on_path_share < 0.05 {
        notes.push("region barely on the critical path — wall move is heavily capped (likely a non-lever)".to_string());
    }
    if base.region_cycles_per_unit.is_none() {
        notes.push("no region cycle budget supplied — speedup is NOT bounded by region size (may over-claim)".to_string());
    }
    // Flag deltas whose op count is large and whose cost came from a cold tier
    // (the journal-replay trap): those dominate and need the most trustworthy
    // microbench.
    let big = deltas
        .iter()
        .filter(|d| d.delta_cycles().abs() > 0.3 * raw.abs().max(1.0))
        .map(|d| d.what.as_str())
        .collect::<Vec<_>>();
    if !big.is_empty() {
        notes.push(format!("dominated by: {}", big.join(", ")));
    }
    if (raw - capped).abs() > raw.abs() * 0.2 {
        notes.push(format!(
            "on-path cap moved the estimate from {:+.0}% (raw) to {:+.0}% (wall)",
            raw * 100.0,
            capped * 100.0
        ));
    }
    if notes.is_empty() {
        "well-grounded (on-path, region-bounded, microbench-backed)".to_string()
    } else {
        notes.join("; ")
    }
}

/// Helper: read a region's on-critical-path share from a FULCRUM critical-path
/// result + config, the same way [`rank`] does, so an estimate's `on_path_share`
/// comes from the SAME measurement that ranks the lever.
pub fn on_path_share(crit: &CritPath, cfg: &Config, region: &str) -> f64 {
    let m = rank::on_path_by_region(crit, cfg);
    *m.get(region).unwrap_or(&0.0)
}

/// Look up a measured per-op cost (cycles) from a microbench result set by
/// name substring — so the estimator's `cyc_from`/`cyc_to` come from real
/// measurements, not literals.
pub fn cyc_of(results: &[BenchResult], name_substr: &str) -> Option<f64> {
    results
        .iter()
        .find(|r| r.name.contains(name_substr))
        .map(|r| r.cycles_per_op())
}

/// Render a set of estimates as a report.
pub fn render(estimates: &[Estimate]) -> String {
    let mut s = String::new();
    s.push_str("\n========  COUNTERFACTUAL WALL-DELTA PREDICTIONS  ========\n");
    s.push_str(
        "predicted_wall% = (Σ delta-cycles × units / region-clock / total-wall) × on-path-share.\n\
         Negative = predicted SPEEDUP. Grounded in measured access counts × measured per-op cost.\n\n",
    );
    for e in estimates {
        s.push_str(&format!(
            "  CHANGE: {}\n  region: {}   PREDICTED WALL: {:+.1}%   (raw {:+.1}% before on-path cap)\n",
            e.change,
            e.region,
            e.predicted_pct(),
            e.raw_wall_frac * 100.0,
        ));
        s.push_str(&format!(
            "    run delta: {:+.3} Gcyc  →  {:+.4} s\n",
            e.run_delta_cycles / 1e9,
            e.run_delta_wall_s
        ));
        for (what, dc) in &e.breakdown {
            s.push_str(&format!("      {:<44} {:+.3} Gcyc\n", what, dc / 1e9));
        }
        s.push_str(&format!("    confidence: {}\n\n", e.confidence));
    }
    s
}
