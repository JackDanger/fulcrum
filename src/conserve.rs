//! `conserve` — the ONE shared conservation-check helper (P5).
//!
//! Several instruments re-implement the same pattern: "the named parts must sum
//! to the whole within a tolerance, else the decomposition is unsound and the
//! number is REFUSED" (phasebreak's consumer-wall residual, dispatchgap's
//! per-worker gap accounting, decompose's bucket closure, scaling's deficit
//! partition, and now `cellwhy`'s taxonomy join). This module factors that into
//! a single PURE, unit-tested primitive so the RESIDUAL is computed and the
//! REFUSE threshold applied identically everywhere — no hand-rolled epsilon per
//! call site.
//!
//! The tolerance is ABSOLUTE (same units as `parts`/`whole`). Build a relative
//! tolerance with [`tol_frac_floor`] and pass it in — that keeps the policy
//! (how big a residual is acceptable) at the call site while the arithmetic
//! stays here.

/// The outcome of a conservation check. `residual = whole - Σparts`; a POSITIVE
/// residual means the parts under-account for the whole (an unnamed remainder),
/// a NEGATIVE residual means they over-count (double-counting / overlap).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Residual {
    pub sum: f64,
    pub whole: f64,
    pub residual: f64,
    pub tol: f64,
    pub within: bool,
}

impl Residual {
    /// Residual as a fraction of the whole (0.0 when whole==0).
    pub fn fraction(&self) -> f64 {
        if self.whole == 0.0 {
            0.0
        } else {
            self.residual / self.whole
        }
    }
}

/// Σparts vs `whole` within an ABSOLUTE tolerance `tol`. Returns `Ok(Residual)`
/// when `|whole - Σparts| <= tol` (the decomposition CLOSES — the residual is a
/// legitimately-small unnamed remainder), and `Err(message)` when it does not
/// (the decomposition is UNSOUND — REFUSE rather than report a misleading
/// breakdown). PURE — unit-tested.
pub fn conserve(parts: &[f64], whole: f64, tol: f64) -> Result<Residual, String> {
    let sum: f64 = parts.iter().sum();
    let residual = whole - sum;
    let within = residual.abs() <= tol;
    let r = Residual {
        sum,
        whole,
        residual,
        tol,
        within,
    };
    if within {
        Ok(r)
    } else {
        Err(format!(
            "CONSERVATION: |residual|={:.4} > tol={:.4} (Σparts={:.4}, whole={:.4}, \
             residual={:.4}) — the decomposition does not close; the named parts \
             {} the whole",
            residual.abs(),
            tol,
            sum,
            whole,
            residual,
            if residual > 0.0 {
                "under-account for"
            } else {
                "over-count"
            }
        ))
    }
}

/// A relative-plus-floor absolute tolerance: `max(floor, frac * whole)`. The
/// common shape (e.g. phasebreak's `max(500us, 12% of consumer_wall)`) built
/// once. PURE.
pub fn tol_frac_floor(whole: f64, frac: f64, floor: f64) -> f64 {
    (whole.abs() * frac).max(floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conserves_within_tolerance() {
        let r = conserve(&[1.0, 2.0, 3.0], 6.2, 0.5).unwrap();
        assert!((r.residual - 0.2).abs() < 1e-9);
        assert!(r.within);
        assert!((r.sum - 6.0).abs() < 1e-9);
    }

    #[test]
    fn refuses_when_under_accounting() {
        let e = conserve(&[1.0, 2.0], 10.0, 0.5).unwrap_err();
        assert!(e.contains("CONSERVATION"), "{e}");
        assert!(e.contains("under-account"), "{e}");
    }

    #[test]
    fn refuses_when_over_counting() {
        let e = conserve(&[8.0, 8.0], 10.0, 0.5).unwrap_err();
        assert!(e.contains("over-count"), "{e}");
    }

    #[test]
    fn boundary_is_inclusive() {
        // residual exactly == tol PASSES (inclusive).
        assert!(conserve(&[9.5], 10.0, 0.5).is_ok());
    }

    #[test]
    fn fraction_and_tol_helper() {
        let r = conserve(&[90.0], 100.0, 15.0).unwrap();
        assert!((r.fraction() - 0.10).abs() < 1e-9);
        assert_eq!(tol_frac_floor(100.0, 0.12, 500.0), 500.0); // floor wins
        assert_eq!(tol_frac_floor(100_000.0, 0.12, 500.0), 12_000.0); // frac wins
    }

    #[test]
    fn empty_parts_residual_is_whole() {
        let r = conserve(&[], 0.0, 0.0).unwrap();
        assert_eq!(r.residual, 0.0);
        assert!(conserve(&[], 5.0, 0.0).is_err());
    }
}
