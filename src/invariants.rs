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

/// THE INVARIANT SET (Rust-native). The full registry migrated from the Python
/// `decide/fulcrum/core/invariants.py` oracle — each rule named for the scar that
/// made it law, the enforcement pointing at the Rust gate that executes it.
pub const INVARIANTS: &[Invariant] = &[
    Invariant {
        name: "SINK-LAW",
        rule: "Both arms of ANY comparison use identical regular-file sinks; the tool \
           REFUSES mixed-sink or half-rebased comparisons. Non-file sinks (FIFO, \
           /dev/null) are flagged on sight.",
        scar: "The 2026-06-11 HALF-PHANTOM matrix: rg re-based to file-sink while gz \
           kept /dev/null numbers — 'T1 0.973' was a phantom; the 'gzippy is \
           sink-insensitive' claim was falsified (~110ms@T1 real output cost). \
           Earlier: the writev-phantom (a FIFO with a draining reader).",
        enforcement: "provenance::check_sink_symmetric (DERIVED-SINK-SYMMETRIC REFUSED); \
                  pipeline gate 1 raises it as the first short-circuit.",
    },
    Invariant {
        name: "FROZEN-OR-LABELED",
        rule: "A wall number from a thawed/loaded/readback-failed box is REFUSED for \
           ranking; --allow-thaw downgrades refusal to an UNFROZEN label on every \
           affected row. Freeze state is a fingerprint field.",
        scar: "ocl_cf's 0.945<->0.989 drift from a thawed box (the freeze guard was \
           WARN-only); a bench-lock TTL lapse mid-A/B caught only by absolute-level \
           sanity.",
        enforcement: "perturb::frozen_ok + render_perturb freeze label; runner manifest \
                  freeze_state/quiet_state keys.",
    },
    Invariant {
        name: "SHA-OR-VOID",
        rule: "Every measured run's output is sha-verified against the corpus pin; any \
           mismatch VOIDS the cell. A knob arm with wrong bytes is recorded as its \
           own finding (switch not byte-transparent), never ranked.",
        scar: "'A speed win with wrong bytes is a loss' (Rule 4); the read-slurp bug \
           produced a false SHA DIVERGENCE — the check must be structural.",
        enforcement: "runner per-run sha capture (sha_ok); perturb::Sweep.sha_ok gate.",
    },
    Invariant {
        name: "SPREAD-RESOLUTION",
        rule: "Every verdict carries RESOLVED/UNRESOLVED with N-needed; a sub-spread \
           delta is NEVER presented as a finding; bimodality is detected and \
           flagged on every sample set.",
        scar: "Sessions spent measuring TIEs; the N=21 silesia-T16 lesson — comparator \
           distributions go bimodal/quantized and a median can sit on either mode.",
        enforcement: "perturb::sample_stats / bimodal; quantity significance_verdict \
                  (forced-TIE when |Δ|≤spread, UNDERPOWERED when N<9).",
    },
    Invariant {
        name: "CAUSAL-OR-HYPOTHESIS",
        rule: "No row is ranked as actionable without a tool-executed causal A/B; \
           everything else is HYPOTHESIS + the exact pre-registered perturbation \
           command. Attribution is a hypothesis generator, never the verdict.",
        scar: "The 377ms pair-drain phantom, the per-EOB stop cost, the KEY-MISMATCH \
           re-key lever — attribution that did NOT convert at the wall.",
        enforcement: "perturb::PerturbCell::hypothesis_sentence vs lever_sentence; the \
                  PERTURBATION-OR-NO-LEVER chokepoint.",
    },
    Invariant {
        name: "EFFECT-VERIFIED-OR-FLAGGED",
        rule: "A kill-switch A/B is causal only if a counter predicate proves the \
           switch engaged/disengaged; knobs without an in-tree counter are labeled \
           EFFECT-UNVERIFIED; a failed predicate voids the A/B.",
        scar: "The rpmalloc stats line printed in BOTH arms; oracle.sh built duplicate \
           env keys (env last-wins => ZERO injection, silently).",
        enforcement: "provenance::check_oracle_fired (ON differs from OFF, reaches \
                  expected) — VOID otherwise; runner oracle_<name>_{on,off,expected}.",
    },
    Invariant {
        name: "SELF-TEST-OR-NO-TRUST",
        rule: "The analyzers carry synthetic-input self-tests with positive AND \
           negative controls and assertion-fires-on-corruption tests; output is \
           labeled untrusted when the engine's self-test stamp is missing/stale.",
        scar: "Two instruments were silently broken (a clean-window oracle that re-ran \
           the bootstrap; another that emitted EMPTY output); the busy+idle==span \
           check was once a tautology.",
        enforcement: "every gate module's #[cfg(test)] suite (perturb/comparability/ \
                  provenance/quantity/finding/pipeline) with positive+negative \
                  controls; the combined `cargo test` count is the stamp.",
    },
    Invariant {
        name: "CONSERVATION-OR-NO-LOCATE",
        rule: "A locate result must CLOSE its wall ledger: wall == critical-path \
           classified time (compute + wait) + residual, with park spans \
           non-covering; FLAGGED when (residual + wait-only-carried)/wall exceeds \
           the threshold; a negative residual or overlapping path REFUSES.",
        scar: "Localization by producer-side attribution manufactured phantoms (the \
           377ms pair-drain, the combine_crc '62ms serial CRC' nested-span \
           double-count): un-closed ledgers let wall time hide in unattributed gaps.",
        enforcement: "(SPECCED in Rust) — the locate ledger is the model/critpath \
                  closure; carried from Python locate.locate_one until ported.",
    },
    Invariant {
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
    },
    Invariant {
        name: "FINGERPRINT-OR-NO-COMPARE",
        rule: "Every stored number carries {sink, mask, freeze, binary sha, corpus \
           sha, protocol version, comparator version, host identity}; \
           ratios/deltas across incompatible or unknown fingerprints are REFUSED; \
           ledger contradiction checks compare ONLY fingerprint-compatible rows.",
        scar: "The cyc/iter 'regression' that was a TSC frequency-state mismatch; the \
           stale rg-anchor ('0.98x' vs a banked 926.6 when the live comparator ran \
           810).",
        enforcement: "finding::Finding::fingerprint + derive_id (cell identity); \
                  finding::Scope::supports (cross-scope citation refusal); runner \
                  manifest fingerprint keys.",
    },
    Invariant {
        name: "TMA-CLOSURE-OR-NO-BREAKDOWN",
        rule: "A TMA top-down breakdown must CLOSE on the hardware slot total \
           (retiring + bad-spec + frontend + backend == slots, within tolerance). \
           TMA-NO-SLOTS / TMA-PARTIAL-LEVEL1 / TMA-CLOSURE / TMA-BACKEND-INCOHERENT \
           REFUSE outright. Only frequency-invariant FRACTIONS are reported.",
        scar: "The two live wall hypotheses (mem-BW vs core-IPC bound) predict \
           different TMA buckets; reading raw perf stat without a closure guard can \
           manufacture the preferred hypothesis (the 690M double-count analogue).",
        enforcement: "(SPECCED in Rust) — carried from Python cycles.build_tma until \
                  ported; the closure-refusal contract is preserved by this registry.",
    },
    Invariant {
        name: "INSN-CLOSURE-OR-NO-LEDGER",
        rule: "An instruction ledger must CLOSE on the measured retired-instruction \
           total (measured_total == categorized + uncategorized + residual, each \
           symbol in AT MOST one category). INSN-EVENT-MISMATCH / INSN-CLOSURE \
           (over-count) / INSN-AMBIGUOUS-PARTITION REFUSE; closure is \
           necessary-but-not-sufficient for the per-category split.",
        scar: "The campaign's hand-built instruction ledger DOUBLE-COUNTED by 690M — a \
           symbol assigned to two buckets, the categories summed past the measured \
           retired total, the residual narrated away.",
        enforcement: "(SPECCED in Rust) — carried from Python insn.build_ledger until \
                  ported; the event-mismatch + over-count + ambiguity refusals are \
                  preserved by this registry.",
    },
    Invariant {
        name: "PROVENANCE-OR-VOID",
        rule: "A measurement is not emitted as a CELL unless the DERIVED capture proves \
           the instrument tested the right thing on the right binary. Five \
           sub-checks: DERIVED-CONSUMER (knob has a grep-confirmed src consumer at \
           commit), DERIVED-ORACLE-FIRED (ON differs from OFF + reaches expected), \
           DERIVED-SINK-SYMMETRIC (both arms + comparator sink identical), \
           DERIVED-SHA-CURRENT (commit==HEAD via git diff src), COMPARATOR-PRESENT \
           (named ELF exists + A/A==1.0). Uncaptured == INCOMPLETE (non-citable, \
           never refused); present-but-wrong VOIDs/REFUSES.",
        scar: "The campaign's most expensive bias (>=5 errors): a file-output sink \
           penalized the faster arm; an oracle env var no-op'd to the normal path; \
           a tracer gated on the wrong env var was inert; pred_available hardcoded \
           false; the rg comparator ELF absent on a box unnoticed.",
        enforcement: "provenance::run_gate (DERIVED-SINK-SYMMETRIC raises; VOID/STALE \
                  carried in GateReport); pipeline gate 1 short-circuit; \
                  provenance::tests one fixture per sub-check.",
    },
    Invariant {
        name: "QUANTITY-DIMENSION-OR-REFUSE",
        rule: "Every value carries a DIMENSION over base units (wall_s, cpu_s, byte, \
           cycle, insn). Arithmetic is dimensioned: × adds dims, ÷ subtracts, +/- \
           and comparison REQUIRE identical dims. Refusals: DIMENSION-REFUSED \
           (share×wall asserted as bytes), LICENSE-REFUSED (unlicensed \
           dimension-changing conversion / begged cross-arm ratio), SHARE-RANGE \
           (share not in [0,1]), FUNCTION-SHARE-LEAKAGE, SIGNIFICANCE-UNDERPOWERED \
           / forced-TIE, VOLUME-COUNTER-UNVALIDATED.",
        scar: "Conclusion #11, the decode-volume phantom: a CPU-busy-SHARE multiplied \
           by a WALL-time read as DECODED BYTES — '1.33x more bytes' — a quantity \
           with no volume counter and a CIRCULAR cross-tool ratio.",
        enforcement: "quantity::require_dim/add/ratio (DIMENSION-REFUSED); bridge + \
                  LicensingAssertion (LICENSE-REFUSED); Quantity::build (SHARE-RANGE); \
                  promote_function_share_to_wall; Comparison + significance_verdict; \
                  assert_volume_counter_selftest; pipeline gate 2; quantity::tests.",
    },
];

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
    fn full_registry_migrated_from_python_oracle() {
        // 14 invariants ported from decide/fulcrum/core/invariants.py.
        assert_eq!(INVARIANTS.len(), 14, "the full invariant set is registered");
        for name in [
            "SINK-LAW",
            "FROZEN-OR-LABELED",
            "SHA-OR-VOID",
            "SPREAD-RESOLUTION",
            "CAUSAL-OR-HYPOTHESIS",
            "EFFECT-VERIFIED-OR-FLAGGED",
            "SELF-TEST-OR-NO-TRUST",
            "CONSERVATION-OR-NO-LOCATE",
            "PERTURBATION-OR-NO-LEVER",
            "FINGERPRINT-OR-NO-COMPARE",
            "TMA-CLOSURE-OR-NO-BREAKDOWN",
            "INSN-CLOSURE-OR-NO-LEDGER",
            "PROVENANCE-OR-VOID",
            "QUANTITY-DIMENSION-OR-REFUSE",
        ] {
            assert!(lookup(name).is_some(), "{name} must be registered");
        }
    }

    #[test]
    fn the_five_pipeline_gates_are_named_invariants() {
        for gate in [
            "PROVENANCE-OR-VOID",
            "QUANTITY-DIMENSION-OR-REFUSE",
            "PERTURBATION-OR-NO-LEVER",
            "FINGERPRINT-OR-NO-COMPARE", // comparability gate's fingerprint law
            "SINK-LAW",                  // provenance/comparability sink law
        ] {
            assert!(lookup(gate).is_some());
        }
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
