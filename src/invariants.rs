//! invariants.rs — THE INVARIANT SET (the Rust-native registry).
//!
//! A port of `decide/fulcrum/core/invariants.py`'s registry concept: each
//! invariant is a rule the tool *executes* (refusal or label) with a self-test
//! proving the enforcement fires. Violations raise [`InvariantViolation`] so a
//! contaminated comparison can never silently produce a number that later gets
//! quoted as truth. `fulcrum invariants` renders this registry.
//!
//! This is the first invariant migrated to the unified Rust binary: the keystone
//! gate **PERTURBATION-OR-NO-LEVER**, enforced by [`crate::perturb`]. The
//! integration agent ports the remaining entries (SINK-LAW, FROZEN-OR-LABELED,
//! SHA-OR-VOID, …) as their gates land in Rust.

use std::fmt;

/// An enforced invariant fired. `.invariant` carries the scar-name. Mirrors the
/// Python `InvariantViolation(InstrumentError)`; the perturb gate's
/// [`crate::perturb::LeverClaimRefused`] is the typed specialization for
/// PERTURBATION-OR-NO-LEVER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantViolation {
    pub invariant: String,
    pub message: String,
}

impl InvariantViolation {
    pub fn new(invariant: impl Into<String>, message: impl Into<String>) -> InvariantViolation {
        InvariantViolation {
            invariant: invariant.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.invariant, self.message)
    }
}

impl std::error::Error for InvariantViolation {}

impl From<crate::perturb::LeverClaimRefused> for InvariantViolation {
    fn from(e: crate::perturb::LeverClaimRefused) -> InvariantViolation {
        InvariantViolation::new(crate::perturb::LeverClaimRefused::INVARIANT, e.message)
    }
}

/// One registered invariant: the scar-name, the rule the tool enforces, the
/// historical failure that made it law, and where the refusal/label lives.
#[derive(Debug, Clone, Copy)]
pub struct Invariant {
    pub name: &'static str,
    pub rule: &'static str,
    pub scar: &'static str,
    pub enforcement: &'static str,
}

/// THE INVARIANT SET (Rust-native). Currently the keystone gate; extended as the
/// other Python invariants land in this binary.
pub const INVARIANTS: &[Invariant] = &[Invariant {
    name: "PERTURBATION-OR-NO-LEVER",
    rule: "The word 'lever' / 'fund the fix' is a GATED OUTPUT of a causal \
           perturbation, never a sentence emitted from an attribution. A region R \
           is promoted to evidence_tier=perturbation/LEVER ONLY if its \
           pre-registered slow-injection (busy-spin at t={10,20,30}% of R's own \
           measured self-time) produces a MONOTONIC + PROPORTIONAL + SIGNIFICANT \
           (|Δwall| > 2× inter-run spread, N≥9) wall response AND a \
           frequency-neutral SLEEP control reproduces it (a busy-spin alone can \
           depress all-core turbo and inflate the delta — the spin-only response \
           is an ARTIFACT, not a lever). A FLAT response in both arms is the \
           equally-STRONG SLACK verdict (R is provably off the critical path). A \
           removal-oracle measures the speed-up CEILING only — a bound is NOT a \
           carrier, so a CEILING-ONLY cell (oracle without a confirming \
           slow-inject) can NEVER license a build (slow-down slope != speed-up \
           ceiling). A control baseline that swings > spread between A/A runs \
           VOIDs the cell. The CELL exposes the claim through \
           PerturbCell::lever_sentence(), which RETURNS Err(LeverClaimRefused) \
           for any non-(perturbation/LEVER) cell — the structural chokepoint that \
           makes an attribution-voiced lever impossible to type.",
    scar: "~12 of 17 false conclusions in one campaign were 'X is THE lever' \
           voiced from a span/share/counter/annotate BEFORE any region removal or \
           slow-injection confirmed the wall responds: fix-clean-path-overhead (a \
           function-annotate 1.10x clean share — the clean path was SLACK at the \
           wall), build-the-window-fix (an oracle CEILING read as a build mandate \
           before the carrier was isolated), ring→drain 'THE ACTUAL LEVER' (a \
           code-read), the B-width flip-rate counter, the one-tax-explains-both \
           phantom. Each conserved as a story while the wall never moved.",
    enforcement: "perturb::analyze_sweep verdict gate (LEVER requires busy \
                  RESPONDS ∧ sleep RESPONDS; SLACK both FLAT; ARTIFACT \
                  busy-RESPONDS ∧ sleep-FLAT; CEILING-ONLY oracle-only; VOID on \
                  baseline swing / non-monotone); perturb::PerturbCell::\
                  lever_sentence returns Err(LeverClaimRefused); \
                  perturb::render_perturb routes ALL prose through the gated \
                  methods; perturb::tests (KNOWN lever / KNOWN slack / A/A / \
                  spin-artifact / unstable-baseline / non-monotone / underpowered \
                  / ceiling-only + the refusal fires)",
}];

/// Look up a registered invariant by its scar-name.
pub fn lookup(name: &str) -> Option<&'static Invariant> {
    INVARIANTS.iter().find(|i| i.name == name)
}

/// Render the registry (the `fulcrum invariants` view).
pub fn render() -> String {
    let mut lines = vec![
        "THE INVARIANT SET — each rule named for the scar that made it law".to_string(),
        "=".repeat(72),
    ];
    for inv in INVARIANTS {
        lines.push(format!("\n{}", inv.name));
        lines.push(format!("  rule        : {}", inv.rule));
        lines.push(format!("  scar        : {}", inv.scar));
        lines.push(format!("  enforcement : {}", inv.enforcement));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perturbation_invariant_is_registered() {
        let inv = lookup("PERTURBATION-OR-NO-LEVER").expect("keystone invariant registered");
        assert_eq!(inv.name, crate::perturb::LeverClaimRefused::INVARIANT);
    }

    #[test]
    fn render_includes_the_keystone_gate() {
        let out = render();
        assert!(out.contains("PERTURBATION-OR-NO-LEVER"));
        assert!(out.contains("frequency-neutral SLEEP control"));
    }

    #[test]
    fn lever_claim_refused_converts_to_invariant_violation() {
        let refused = crate::perturb::LeverClaimRefused::new("nope");
        let v: InvariantViolation = refused.into();
        assert_eq!(v.invariant, "PERTURBATION-OR-NO-LEVER");
        assert!(format!("{v}").starts_with("[PERTURBATION-OR-NO-LEVER]"));
    }
}
