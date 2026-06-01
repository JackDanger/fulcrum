//! Counterfactual cost estimator — PREDICT a structural change's wall delta
//! BEFORE building it.
//!
//! This is the capability that would have stopped multi-hour falsified levers
//! before any code was written: it combines a region's **access counts**
//! ([`crate::region_hw`] + the trace) with the **measured per-operation cost**
//! of the primitive a change swaps in ([`crate::microbench`]) into a grounded
//! arithmetic prediction of the wall move — not a hunch.
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
//!      found for a 200+ ms fully-overlapped copy.
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
//! * **per-element side-journal** swaps a wide masked-ring store (cheap, ~1 cyc,
//!   in-L1) for a narrow store PLUS a journal append PLUS a later journal-replay
//!   pass over ~21M entries / ~296 MB that is a fresh cache-cold streaming read.
//!   The estimator multiplies 21M replay ops by the *measured* DRAM-streaming
//!   cost — a large positive (slowdown) term the eye misses but the arithmetic
//!   cannot. PLUS it accounts for the lost clean-tail fast path as re-added
//!   slow-path cycles. Net: a big positive %, NOT a win.
//! * **memcpy-bound flat** isn't a per-op change at all — it's that the region's
//!   on-path share is already ≈ its serial share (no parallel slack to recover).
//!   Modeled as a change with ~0 movable on-path share ⇒ ≈0 predicted
//!   improvement, matching "it just doesn't parallelize."
//! * **inner-loop instruction-reduction** removed per-iteration yield-check /
//!   bounds overhead on the hot copy: a modest negative cyc/op delta over the
//!   op count, on a high-on-path region ⇒ a few-percent speedup, matching the
//!   measured win.

use crate::config::Config;
use crate::critpath::CritPath;
use crate::microbench::BenchResult;
use crate::rank;

/// One per-operation cost change inside a region.
#[derive(Debug, Clone)]
pub struct Delta {
    /// Human label (e.g. "ring store: wide→narrow").
    pub what: String,
    /// Baseline op count per UNIT OF WORK (one decoded run / one full decode,
    /// consistent with how `wall_cycles` below is scoped).
    pub count_from: f64,
    /// Baseline cycles per op (measured by a microbench, or known).
    pub cyc_from: f64,
    /// Op count after the change (often == count_from; differs when the change
    /// adds/removes operations, e.g. a side-journal that appends a 2nd op per
    /// element).
    pub count_to: f64,
    /// Cycles per op after the change (measured candidate primitive).
    pub cyc_to: f64,
    /// One-time NEW cycles the change introduces per unit of work that have no
    /// baseline counterpart (e.g. a whole side-journal replay pass). Defaults 0.
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
    /// Units of work per run (e.g. number of processed chunks), so per-unit
    /// cycle deltas scale to the whole run. Default 1.0 if the deltas are
    /// already whole-run counts.
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
    ///
    /// DEPRECATED as a headline: a bare point estimate reads as more precise
    /// than this model is. Prefer [`Estimate::bracket`] — the cycle-multiply
    /// model reliably gets the SIGN and ORDER OF MAGNITUDE but UNDER-predicts
    /// magnitude (it omits DRAM-bandwidth contention and pipeline/branch
    /// serialization), so the honest output is a sign + a confidence bracket,
    /// not a single number.
    pub fn predicted_pct(&self) -> f64 {
        self.predicted_wall_frac * 100.0
    }

    /// The honest output: a SIGN + an order-of-magnitude CONFIDENCE BRACKET
    /// `[lo_pct, hi_pct]` (both signed, lo ≤ hi). This is what should be quoted,
    /// never the bare point.
    ///
    /// Rationale, grounded in the postdiction record (`tests/estimator_*`):
    /// the cycle-multiply point estimate is a LOWER BOUND on magnitude for two
    /// classes of change the model does not term:
    ///   * **bandwidth-bound** work — the model charges per-op latency, but a
    ///     streaming pass that saturates DRAM bandwidth costs MORE wall than the
    ///     latency sum once it contends with other cores; and
    ///   * **inner-loop pipeline/branch** effects — removing a per-iteration
    ///     branch/dependency unblocks more retire slots than the raw cycle delta.
    ///
    /// So we widen the point into a bracket whose magnitude spans
    /// `[point, point × K]` (K = the modeling-uncertainty factor below),
    /// preserving the sign. A near-zero point (an off-path / non-lever change)
    /// stays a tight bracket around zero — the model is CONFIDENT about
    /// non-levers, which is its most-validated regime.
    pub fn bracket(&self) -> ConfidenceBracket {
        let point = self.predicted_wall_frac;
        let mag = point.abs();
        // Non-lever regime: a tiny predicted move is trustworthy AS small (the
        // on-path cap is the validated part). Keep the bracket tight.
        if mag < 0.01 {
            return ConfidenceBracket {
                sign: Sign::of(point),
                lo_frac: point - 0.005,
                hi_frac: point + 0.005,
                order: "≈0 (non-lever): bracket is tight around zero — the on-path cap is the model's most-validated output".to_string(),
            };
        }
        // The modeling-uncertainty factor: the point is a lower bound on
        // magnitude; the upper bound inflates it. We use 2.5× as a generic
        // order-of-magnitude span (the n=3 cross-tool study found ~1.3–2.2×
        // mispredictions on memory-bound cells), and round to an order label.
        const K: f64 = 2.5;
        // The bracket spans the same sign from |point| to K·|point|.
        let (lo_mag, hi_mag) = (mag, mag * K);
        let (lo_frac, hi_frac) = if point < 0.0 {
            // speedup: more-negative is the bigger effect → hi(=less negative)
            // is the conservative end. Keep lo ≤ hi numerically.
            (-hi_mag, -lo_mag)
        } else {
            (lo_mag, hi_mag)
        };
        ConfidenceBracket {
            sign: Sign::of(point),
            lo_frac,
            hi_frac,
            order: order_label(mag),
        }
    }
}

/// The sign of a predicted wall move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sign {
    /// Predicted SPEEDUP (wall down).
    Speedup,
    /// Predicted SLOWDOWN (wall up).
    Slowdown,
    /// Predicted ≈ no change.
    Flat,
}

impl Sign {
    fn of(frac: f64) -> Sign {
        if frac < -0.005 {
            Sign::Speedup
        } else if frac > 0.005 {
            Sign::Slowdown
        } else {
            Sign::Flat
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Sign::Speedup => "SPEEDUP",
            Sign::Slowdown => "SLOWDOWN",
            Sign::Flat => "FLAT",
        }
    }
}

/// An order-of-magnitude confidence bracket for a predicted wall move. Both
/// bounds are SIGNED fractions of total wall (negative = faster), `lo ≤ hi`.
#[derive(Debug, Clone)]
pub struct ConfidenceBracket {
    pub sign: Sign,
    pub lo_frac: f64,
    pub hi_frac: f64,
    /// A human order-of-magnitude label ("a few %", "~10%", "tens of %").
    pub order: String,
}

impl ConfidenceBracket {
    /// The bracket as a signed percentage pair `[lo, hi]`.
    pub fn pct(&self) -> (f64, f64) {
        (self.lo_frac * 100.0, self.hi_frac * 100.0)
    }
    /// One-line honest summary: sign + order + the bracket.
    pub fn summary(&self) -> String {
        let (lo, hi) = self.pct();
        format!(
            "{} — {} (confidence bracket [{:+.1}%, {:+.1}%])",
            self.sign.label(),
            self.order,
            lo,
            hi
        )
    }
}

/// Coarse order-of-magnitude label for a wall-fraction magnitude.
fn order_label(mag: f64) -> String {
    let p = mag * 100.0;
    if p < 3.0 {
        "a few % at most".to_string()
    } else if p < 12.0 {
        "~single-digit-to-10%".to_string()
    } else if p < 40.0 {
        "tens of %".to_string()
    } else {
        "order-of-half-the-wall or more (catastrophic)".to_string()
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
    // overlapped region (see the side-journal postdiction, which does exactly
    // that).
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

fn build_confidence(base: &RegionBaseline, deltas: &[Delta], raw: f64, capped: f64) -> String {
    let mut notes = Vec::new();
    if base.on_path_share < 0.05 {
        notes.push(
            "region barely on the critical path — wall move is heavily capped (likely a non-lever)"
                .to_string(),
        );
    }
    if base.region_cycles_per_unit.is_none() {
        notes.push("no region cycle budget supplied — speedup is NOT bounded by region size (may over-claim)".to_string());
    }
    // Flag deltas whose op count is large and whose cost came from a cold tier
    // (the side-journal-replay trap): those dominate and need the most
    // trustworthy microbench.
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

/// Render a set of estimates as a report. The HEADLINE is the SIGN + an
/// order-of-magnitude CONFIDENCE BRACKET — never a bare point estimate, which
/// would read as more precise than this cycle-multiply model is.
pub fn render(estimates: &[Estimate]) -> String {
    let mut s = String::new();
    s.push_str("\n========  COUNTERFACTUAL WALL-DELTA PREDICTIONS  ========\n");
    s.push_str(
        "This model reliably gets the SIGN and ORDER OF MAGNITUDE; it UNDER-predicts magnitude on\n\
         memory-bandwidth-bound and inner-loop pipeline changes (no DRAM-contention / serialization\n\
         term). So the headline is a SIGNED CONFIDENCE BRACKET, not a point. The point estimate\n\
         (Σ delta-cycles × units / region-clock / total-wall × on-path-share) is the LOWER bound on\n\
         magnitude; the bracket's upper end carries the modeling uncertainty.\n\n",
    );
    for e in estimates {
        let b = e.bracket();
        s.push_str(&format!(
            "  CHANGE: {}\n  region: {}\n  >>> PREDICTION: {}\n",
            e.change,
            e.region,
            b.summary(),
        ));
        s.push_str(&format!(
            "      point estimate (lower-bound magnitude): {:+.1}%   (raw {:+.1}% before on-path cap)\n",
            e.predicted_pct(),
            e.raw_wall_frac * 100.0,
        ));
        s.push_str(&format!(
            "      run delta: {:+.3} Gcyc  →  {:+.4} s\n",
            e.run_delta_cycles / 1e9,
            e.run_delta_wall_s
        ));
        for (what, dc) in &e.breakdown {
            s.push_str(&format!("      {:<44} {:+.3} Gcyc\n", what, dc / 1e9));
        }
        s.push_str(&format!("      grounding: {}\n\n", e.confidence));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(on_path: f64) -> RegionBaseline {
        RegionBaseline {
            region: "r".into(),
            total_wall_s: 1.0,
            on_path_share: on_path,
            cycles_per_s: 1e9,
            region_cycles_per_unit: None,
            units_per_run: 1.0,
        }
    }

    #[test]
    fn bracket_preserves_sign_and_brackets_the_point() {
        // A speedup change: removing 50M ops at 3 cyc on a fully-on-path region.
        let e = estimate(
            "remove per-iter branch",
            &base(1.0),
            &[Delta::removed("branch", 50e6, 3.0)],
        );
        let b = e.bracket();
        assert_eq!(b.sign, Sign::Speedup);
        let (lo, hi) = b.pct();
        // The point estimate must lie inside [lo, hi], and both must be negative
        // (a speedup), with lo (more negative) ≤ hi.
        assert!(lo <= hi);
        assert!(hi <= 0.0 && lo < 0.0);
        let point = e.predicted_pct();
        assert!(
            point >= lo - 1e-6 && point <= hi + 1e-6,
            "point {point} must lie within bracket [{lo},{hi}]"
        );
        // The model UNDER-predicts magnitude: |lo| (the big end) must exceed the
        // point magnitude.
        assert!(lo.abs() >= point.abs());
    }

    #[test]
    fn non_lever_bracket_is_tight_around_zero() {
        // A change on a region with ~zero on-path share predicts ≈0 and the
        // bracket must stay tight around zero (the model's most-validated case).
        let e = estimate(
            "speed an off-path copy",
            &base(0.001),
            &[Delta::removed("copy", 200e6, 1.0)],
        );
        let b = e.bracket();
        let (lo, hi) = b.pct();
        assert!(
            hi - lo <= 2.0,
            "non-lever bracket should be tight, got [{lo},{hi}]"
        );
        assert!(b.order.contains("non-lever") || matches!(b.sign, Sign::Flat));
    }

    #[test]
    fn slowdown_bracket_is_positive() {
        // A big added streaming pass: a slowdown. Bracket must be positive and
        // bracket the point from below.
        let e = estimate(
            "add side-journal replay",
            &base(1.0),
            &[Delta::added("replay 21M cold", 21e6, 30.0)],
        );
        let b = e.bracket();
        assert_eq!(b.sign, Sign::Slowdown);
        let (lo, hi) = b.pct();
        assert!(lo > 0.0 && hi >= lo);
        assert!(e.predicted_pct() <= hi + 1e-6 && e.predicted_pct() >= lo - 1e-6);
    }
}
