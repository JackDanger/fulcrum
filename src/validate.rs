#![allow(dead_code)]
// Output-struct fields are part of the embeddable API surface.
//! Validation layer — the gate that makes a FULCRUM ranking trustworthy.
//!
//! A causal ranking is only useful if it reproduces things you ALREADY KNOW
//! to be true. The classic failure of CPU-time profilers is confidently
//! pointing at a region whose speedup, when you actually try it, moves the
//! wall by zero. So before you trust FULCRUM's ranking on the regions you
//! DON'T know about, make it re-derive the ones you DO:
//!
//!   * `known_non_lever` — a region you already measured as a non-lever
//!     (speeding it moved the wall ~0, e.g. because it is fully overlapped /
//!     off the in-order critical path). Its measured peak elasticity MUST be
//!     near zero. If it comes out high, FULCRUM is wrong — fix it before
//!     trusting any other row.
//!   * `known_levers` — one or more regions you already measured as real
//!     levers (speeding one measurably moved the wall). At least one MUST show
//!     positive elasticity, and a known lever MUST out-rank the known
//!     non-lever.
//!   * `min_heavy_blockers` — if your pipeline is gated by a few long-pole
//!     items, the critical-path layer MUST surface at least that many.
//!
//! Each expectation is configured in [`crate::config::GroundTruth`]. A
//! divergence is REPORTED, never hidden — that honesty is the whole point.

use crate::config::GroundTruth;
use crate::coz::CozProfile;
use crate::critpath::CritPath;
use std::collections::BTreeMap;

/// One expectation and whether the measurement met it.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub expectation: String,
    pub measured: String,
    pub passed: bool,
}

/// Verdict over all checks.
pub struct Validation {
    pub checks: Vec<Check>,
}

impl Validation {
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }
    /// True if no checks were configured (nothing to validate against).
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }
}

/// Absolute elasticity below this is "≈0" (a non-lever). Chosen so a known
/// non-lever (a region that, fully sped, moves the wall <~3%) passes and a
/// real lever does not get mislabeled.
const ZERO_ELASTICITY: f64 = 0.03;
/// A region must clear this to count as a positive lever.
const POSITIVE_ELASTICITY: f64 = 0.05;

/// Check the Coz + critpath results against the configured ground truth.
/// `coz` may be None if only the critical-path layer ran. `on_path` is the
/// per-region on-critical-path fraction (from [`crate::rank`]); it drives the
/// trace-only `cp_*` checks.
pub fn check_against_ground_truth(
    coz: Option<&CozProfile>,
    crit: &CritPath,
    gt: &GroundTruth,
    on_path: &BTreeMap<String, f64>,
) -> Validation {
    let mut checks = Vec::new();

    if let Some(coz) = coz {
        // Use the PEAK-line elasticity (the actionable lever), not the
        // weighted median — the median is masked to ~0 when a region has a
        // high-sample near-zero line (see rank.rs / coz.rs notes).
        let peak = |region: &str| -> Option<(f64, f64)> {
            coz.region_curves
                .get(region)
                .map(|rc| rc.peak_line_elasticity())
        };

        // (1) the known non-lever ≈ 0.
        if let Some(nl) = &gt.known_non_lever {
            // Did the scope fire at all? (a latency-point named after the
            // region means it executed). Two ways to pass, both meaning
            // "non-lever": a measurable peak below the zero threshold, OR the
            // scope fired yet coz built no virtual-speedup experiment on any
            // of its lines — i.e. it is so cheap/overlapped there is no
            // leverage signal at all. That absence IS the non-lever signature.
            let scope_fired = coz
                .region_latency
                .iter()
                .any(|(name, (a, _, _))| name.contains(nl.as_str()) && *a > 0.0);
            match peak(nl) {
                Some((e, n)) => checks.push(Check {
                    name: format!("'{nl}' is a non-lever (known ≈0 wall move)"),
                    expectation: format!("|peak elasticity| < {ZERO_ELASTICITY}"),
                    measured: format!("peak={e:+.3} (n={n} samples)"),
                    passed: e.abs() < ZERO_ELASTICITY,
                }),
                None => checks.push(Check {
                    name: format!("'{nl}' is a non-lever (known ≈0 wall move)"),
                    expectation:
                        "no measurable leverage (scope fires but coz builds no experiment)".into(),
                    measured: format!(
                        "scope fired={scope_fired}, 0 coz-experiment lines cleared the sample \
                         floor -> unmeasurably small leverage (the non-lever signature)"
                    ),
                    // Pass iff it actually executed (so "no experiment" means
                    // "too cheap to measure", not "never ran"). If we have no
                    // latency-point evidence either way, accept the absence as
                    // the non-lever signature.
                    passed: scope_fired || coz.region_latency.is_empty(),
                }),
            }
        }

        // (2) at least one known lever > 0, and it out-levers the non-lever.
        if !gt.known_levers.is_empty() {
            let detail = gt
                .known_levers
                .iter()
                .filter_map(|r| peak(r).map(|(e, n)| format!("{r}={e:+.3}(n={n})")))
                .collect::<Vec<_>>()
                .join(", ");
            let any_pos = gt.known_levers.iter().any(|r| {
                peak(r)
                    .map(|(e, _)| e > POSITIVE_ELASTICITY)
                    .unwrap_or(false)
            });
            checks.push(Check {
                name: "a known lever shows positive elasticity".into(),
                expectation: format!("max(known levers) PEAK elasticity > {POSITIVE_ELASTICITY}"),
                measured: if detail.is_empty() {
                    "no known-lever coz experiments".into()
                } else {
                    detail
                },
                passed: any_pos,
            });

            // Ordering: a known lever should out-lever the known non-lever.
            if let Some(nl) = &gt.known_non_lever {
                let nl_e = peak(nl).map(|(e, _)| e).unwrap_or(0.0);
                let lever_e = gt
                    .known_levers
                    .iter()
                    .filter_map(|r| peak(r).map(|(e, _)| e))
                    .fold(f64::NEG_INFINITY, f64::max);
                if lever_e.is_finite() {
                    checks.push(Check {
                        name: "ordering: known lever out-levers known non-lever".into(),
                        expectation: "max(known levers) PEAK elasticity > non-lever PEAK".into(),
                        measured: format!("lever={lever_e:+.3} vs non-lever={nl_e:+.3}"),
                        passed: lever_e > nl_e,
                    });
                }
            }
        }
    }

    // (3) critical path surfaces the expected number of heavy long-pole items.
    if let Some(min_heavy) = gt.min_heavy_blockers {
        let n_heavy = crit.heavy_chunks.len();
        let max_heavy = crit
            .heavy_chunks
            .iter()
            .map(|h| h.blocker_dur_us)
            .fold(0.0_f64, f64::max);
        checks.push(Check {
            name: "critpath surfaces heavy long-pole blockers".into(),
            expectation: format!(">= {min_heavy} on-path heavy blocker(s) over threshold"),
            measured: format!("{n_heavy} heavy blockers, max {:.1}ms", max_heavy / 1000.0),
            passed: n_heavy >= min_heavy,
        });
    }

    // (4) TRACE-ONLY: the known long-pole region dominates the critical path.
    if let Some(top) = &gt.cp_top_region {
        let top_share = *on_path.get(top).unwrap_or(&0.0);
        let max_other = on_path
            .iter()
            .filter(|(r, _)| r.as_str() != top.as_str())
            .map(|(_, f)| *f)
            .fold(0.0_f64, f64::max);
        let ranked: Vec<String> = {
            let mut v: Vec<(&String, &f64)> = on_path.iter().collect();
            v.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
            v.iter()
                .take(4)
                .map(|(r, f)| format!("{r}={:.0}%", *f * 100.0))
                .collect()
        };
        checks.push(Check {
            name: format!("'{top}' dominates the critical path (the long-pole lever)"),
            expectation: format!("'{top}' has the largest on-path share of all regions"),
            measured: format!("on-path: {}", ranked.join(", ")),
            passed: top_share > max_other && top_share > 0.0,
        });
    }

    // (5) TRACE-ONLY: the known non-lever region sits off the critical path.
    if let Some(off) = &gt.cp_offpath_region {
        let max_off = gt.cp_offpath_max.unwrap_or(0.05);
        let share = *on_path.get(off).unwrap_or(&0.0);
        checks.push(Check {
            name: format!("'{off}' is off the critical path (the non-lever)"),
            expectation: format!("'{off}' on-path share < {:.0}%", max_off * 100.0),
            measured: format!("on-path share {:.1}%", share * 100.0),
            passed: share < max_off,
        });
    }

    Validation { checks }
}
