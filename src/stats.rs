//! stats.rs — sample statistics + distribution health (the SPREAD-RESOLUTION
//! invariant). A faithful Rust port of `decide/fulcrum/core/stats.py`.
//!
//! A delta smaller than the arms' spread is not a finding, and wall
//! distributions go bimodal under scheduling regimes (a median can sit on
//! either mode) — whole sessions have been spent "measuring" such ties. Every
//! verdict therefore carries RESOLVED/UNRESOLVED with N-needed, a sub-spread
//! delta is NEVER presented as a finding, and bimodality is detected on every
//! sample set.
//!
//! ## Unification (don't fork)
//!
//! [`sample_stats`], [`bimodal`], and [`SampleStats`] already had a canonical,
//! battle-tested implementation in [`crate::perturb`] (the keystone gate). To
//! keep ONE impl, this module RE-EXPORTS them rather than forking a second copy
//! — `crate::stats` is the unified namespace mirroring `core/stats.py`, while
//! the arithmetic stays in one place. The two functions that were missing from
//! the Rust surface ([`resolution`] and [`dist_health_str`]) live here, plus
//! [`read_samples`] (the canonical whitespace-float loader the perturb sweep
//! consumes).

pub use crate::perturb::{bimodal, sample_stats, SampleStats};

use std::path::Path;

/// Default bimodality gap multiplier (the N=21 lesson). Mirrors
/// `stats.BIMODAL_K`.
pub const BIMODAL_K: f64 = 3.0;

/// Read a whitespace-separated list of floats from `path`; missing file or
/// unparseable tokens yield an empty / filtered list (never an error — a
/// missing samples file means "no data", which downstream renders as NO-DATA).
/// Mirrors `stats.read_samples`.
pub fn read_samples(path: &Path) -> Vec<f64> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .split_whitespace()
            .filter_map(|tok| tok.parse::<f64>().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolution verdict: `(status, n_needed)`.
///
/// `RESOLVED` (with `n_needed == None`) iff `|delta|` exceeds the larger arm
/// spread (absolute seconds); else `UNRESOLVED` with an N-needed estimate
/// `ceil(n * (margin/|delta|)^2)`, floored at `n+2` and capped at 99. A zero
/// delta is maximally unresolved (`n_needed == 99`).
///
/// Faithful port of `stats.resolution` — same branch order, same cap, same
/// floor — so the literal N-needed values match the Python oracle.
pub fn resolution(
    delta_s: f64,
    spread_a_s: f64,
    spread_b_s: f64,
    n: usize,
) -> (Resolution, Option<usize>) {
    let margin = spread_a_s.max(spread_b_s);
    if delta_s.abs() > margin {
        return (Resolution::Resolved, None);
    }
    if delta_s == 0.0 {
        return (Resolution::Unresolved, Some(99));
    }
    let raw = (n as f64 * (margin / delta_s.abs()).powi(2)).ceil() as i64;
    // Python: min(99, max(n+2, ceil(...))).
    let need = raw.max(n as i64 + 2).min(99);
    (Resolution::Unresolved, Some(need as usize))
}

/// The two-state resolution verdict. `RESOLVED`/`UNRESOLVED` tokens match the
/// Python string contract via [`Resolution::token`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Resolved,
    Unresolved,
}

impl Resolution {
    /// The literal token the Python oracle emits (`"RESOLVED"` / `"UNRESOLVED"`).
    pub fn token(self) -> &'static str {
        match self {
            Resolution::Resolved => "RESOLVED",
            Resolution::Unresolved => "UNRESOLVED",
        }
    }
}

/// One-line distribution health string: `n=… spread=…%` plus `BIMODAL` when the
/// largest-gap heuristic fires; `no-data` for an empty sample set. Mirrors
/// `stats.dist_health_str` byte-for-byte (same `:.1f` spread formatting).
pub fn dist_health_str(xs: &[f64]) -> String {
    match sample_stats(xs) {
        None => "no-data".to_string(),
        Some(st) => {
            let mut parts = vec![
                format!("n={}", st.n),
                format!("spread={:.1}%", st.spread_pct),
            ];
            if bimodal(xs, BIMODAL_K) {
                parts.push("BIMODAL".to_string());
            }
            parts.join(" ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── resolution: the N-needed monotone contract (test_decide.py §3) ──
    #[test]
    fn resolution_monotone_and_resolved() {
        let r1 = resolution(0.001, 0.010, 0.010, 9);
        let r2 = resolution(0.005, 0.010, 0.010, 9);
        let r3 = resolution(0.020, 0.010, 0.010, 9);
        assert_eq!(r1.0, Resolution::Unresolved);
        assert_eq!(r2.0, Resolution::Unresolved);
        // smaller delta => larger N-needed
        assert!(r1.1.unwrap() > r2.1.unwrap());
        // supra-spread delta => RESOLVED, no N-needed
        assert_eq!(r3, (Resolution::Resolved, None));
    }

    #[test]
    fn resolution_zero_delta_is_max_unresolved() {
        assert_eq!(
            resolution(0.0, 0.010, 0.010, 9),
            (Resolution::Unresolved, Some(99))
        );
    }

    #[test]
    fn resolution_cap_and_floor() {
        // Tiny delta on a wide spread saturates the 99 cap.
        let (st, n) = resolution(1e-9, 1.0, 1.0, 9);
        assert_eq!(st, Resolution::Unresolved);
        assert_eq!(n, Some(99));
        // Floor at n+2: a delta just under margin still needs at least n+2.
        let (st2, n2) = resolution(0.0099, 0.010, 0.010, 9);
        assert_eq!(st2, Resolution::Unresolved);
        assert!(n2.unwrap() >= 11, "floor n+2 (=11) honored, got {n2:?}");
    }

    // Cross-check the exact Python arithmetic for a known input:
    // resolution(0.005, 0.010, 0.010, 9):
    //   margin=0.010, ratio=2.0, ratio^2=4.0, 9*4=36 -> ceil=36,
    //   max(11,36)=36, min(99,36)=36.
    #[test]
    fn resolution_exact_value_matches_python() {
        assert_eq!(
            resolution(0.005, 0.010, 0.010, 9),
            (Resolution::Unresolved, Some(36))
        );
        // resolution(0.001,...,9): ratio=10, ^2=100, 9*100=900 -> cap 99.
        assert_eq!(
            resolution(0.001, 0.010, 0.010, 9),
            (Resolution::Unresolved, Some(99))
        );
    }

    #[test]
    fn resolution_token_strings() {
        assert_eq!(Resolution::Resolved.token(), "RESOLVED");
        assert_eq!(Resolution::Unresolved.token(), "UNRESOLVED");
    }

    // ── dist_health_str ──
    #[test]
    fn dist_health_no_data() {
        assert_eq!(dist_health_str(&[]), "no-data");
    }

    #[test]
    fn dist_health_unimodal() {
        let uni = [1.00, 1.01, 1.02, 1.03, 1.015, 1.025, 1.005];
        let s = dist_health_str(&uni);
        assert!(s.starts_with("n=7 "), "got {s}");
        assert!(!s.contains("BIMODAL"), "unimodal must not flag: {s}");
    }

    #[test]
    fn dist_health_bimodal_flagged() {
        let bi = [1.00, 1.01, 1.005, 1.30, 1.31, 1.305, 1.302];
        let s = dist_health_str(&bi);
        assert!(s.contains("BIMODAL"), "bimodal must flag: {s}");
        assert!(s.starts_with("n=7 "), "got {s}");
    }

    #[test]
    fn dist_health_spread_format_one_decimal() {
        // [1.0, 1.1] -> spread = 10.0% exactly, formatted with one decimal.
        let s = dist_health_str(&[1.0, 1.1]);
        assert!(s.contains("spread=10.0%"), "one-decimal spread: {s}");
    }

    // ── read_samples ──
    #[test]
    fn read_samples_missing_is_empty() {
        let p = std::path::Path::new("/nonexistent/fulcrum/samples.txt");
        assert!(read_samples(p).is_empty());
    }

    #[test]
    fn read_samples_parses_whitespace_floats() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("fulcrum_stats_test_{}.txt", std::process::id()));
        std::fs::write(&p, "1.0 2.5\n3.25\t  4.0\nnot_a_float 5.5").unwrap();
        let xs = read_samples(&p);
        std::fs::remove_file(&p).ok();
        assert_eq!(xs, vec![1.0, 2.5, 3.25, 4.0, 5.5]);
    }
}
