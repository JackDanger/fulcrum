//! excess unit tests — every refusal + verdict is a RED-before/GREEN-after fixture.
//!
//! "RED-before" = the fixture is built so a NAIVE single-corpus tool (the
//! hand-read-rg-source + eyeball-the-loss-corpus judgment this module replaces)
//! would mis-call it (e.g. INTRINSIC ⇒ "win", or a no-control attribution ⇒
//! EXCESS); "GREEN-after" = `evaluate` returns the correct gated verdict and the
//! chokepoint refuses to voice a non-excess region.

use super::*;

const BYTES: f64 = 1_000_000.0;

/// One cycle sample at a given cyc/byte and instr/byte.
fn sample(cpb: f64, ipb: f64) -> Sample {
    Sample {
        cycles: cpb * BYTES,
        instructions: ipb * BYTES,
        bytes: BYTES,
        procs_running: 0.0,
    }
}

/// An arm of `n` samples centered on `cpb` with symmetric ±`j` jitter (absolute
/// spread `2·j`). instr/byte is pinned at 2× cpb (irrelevant to the cycle path).
fn arm(n: usize, cpb: f64, j: f64) -> Vec<Sample> {
    (0..n)
        .map(|i| {
            let sgn = if i % 2 == 0 { 1.0 } else { -1.0 };
            sample(cpb + sgn * j, 2.0 * cpb)
        })
        .collect()
}

/// A region: gz/rg on loss, gz/rg on control (control optional).
fn region(label: &str, loss_gz: f64, loss_rg: f64, control: Option<(f64, f64)>) -> Region {
    Region {
        label: label.to_string(),
        loss: ArmPair {
            gz: arm(8, loss_gz, 0.01),
            rg: arm(8, loss_rg, 0.01),
        },
        control: control.map(|(cgz, crg)| ArmPair {
            gz: arm(8, cgz, 0.01),
            rg: arm(8, crg, 0.01),
        }),
    }
}

fn input(regions: Vec<Region>) -> ExcessInput {
    ExcessInput {
        regions,
        metric: Metric::Cycle,
        epsilon: DEFAULT_EPSILON,
        loss_corpus: "silesia".to_string(),
        control_corpus: "nasa".to_string(),
        arch: "intel-i7-13700T".to_string(),
        cross_arch_replicated: true, // LAW unless a test flips it
        gz_sha: "gzaaaa".to_string(),
        rg_sha: "rgbbbb".to_string(),
    }
}

fn find<'a>(rep: &'a ExcessReport, label: &str) -> &'a RegionReport {
    rep.regions
        .iter()
        .find(|r| r.label == label)
        .unwrap_or_else(|| panic!("region {label} not found"))
}

// ── (a) gz-high-on-loss + reverses-on-control → EXCESS ──────────────────────
// RED-before: a single-corpus tool sees gz 2.0 vs rg 1.0 on loss and calls it a
// recoverable win. GREEN: control shows gz ties rg (1.0 vs 1.0) ⇒ EXCESS, real.
#[test]
fn high_on_loss_vanishes_on_control_is_excess() {
    let rep = evaluate(&input(vec![region(
        "marker-resolve",
        2.0,
        1.0,
        Some((1.0, 1.0)),
    )]));
    let r = find(&rep, "marker-resolve");
    assert_eq!(r.verdict, Verdict::Excess, "{}", r.reason);
    assert!(r.is_excess());
    assert!(r.excess_sentence().is_ok());
    // recoverable = loss_gz − loss_rg = 1.0
    assert!(
        (r.recoverable - 1.0).abs() < 1e-6,
        "recoverable={}",
        r.recoverable
    );
}

// Reversal (control gz FASTER than rg) is also EXCESS.
#[test]
fn high_on_loss_reverses_on_control_is_excess() {
    let rep = evaluate(&input(vec![region(
        "marker-resolve",
        2.0,
        1.0,
        Some((0.8, 1.0)), // gz faster on control
    )]));
    let r = find(&rep, "marker-resolve");
    assert_eq!(r.verdict, Verdict::Excess, "{}", r.reason);
}

// ── (b) gz-high-on-BOTH → INTRINSIC ─────────────────────────────────────────
// RED-before: a single-corpus tool sees gz 2.0 vs rg 1.0 on loss and calls it a
// win. GREEN: control ALSO shows gz 2.0 vs rg 1.0 ⇒ rg pays it too ⇒ INTRINSIC,
// recoverable 0, chokepoint refuses to voice it.
#[test]
fn high_on_both_corpora_is_intrinsic() {
    let rep = evaluate(&input(vec![region(
        "backref-emit",
        2.0,
        1.0,
        Some((2.0, 1.0)),
    )]));
    let r = find(&rep, "backref-emit");
    assert_eq!(r.verdict, Verdict::Intrinsic, "{}", r.reason);
    assert!(!r.is_excess());
    assert!(r.excess_sentence().is_err());
    assert_eq!(r.recoverable, 0.0);
}

// ── (c) within-spread → INCONCLUSIVE ────────────────────────────────────────
// RED-before: gz 1.02 vs rg 1.00 looks like a tiny gz excess. GREEN: the Δ (0.02)
// is within the arms' spread (±0.05 ⇒ spread 0.10) ⇒ UNRESOLVED ⇒ INCONCLUSIVE.
#[test]
fn sub_spread_loss_gap_is_inconclusive() {
    let mut reg = region("tiny-gap", 1.02, 1.00, Some((1.0, 1.0)));
    reg.loss.gz = arm(8, 1.02, 0.05); // spread 0.10 ≫ Δ 0.02
    reg.loss.rg = arm(8, 1.00, 0.05);
    let rep = evaluate(&input(vec![reg]));
    let r = find(&rep, "tiny-gap");
    assert_eq!(r.verdict, Verdict::Inconclusive, "{}", r.reason);
    assert_eq!(r.loss_resolution, Resolution::Unresolved);
    assert!(r.excess_sentence().is_err());
}

// ── (d) no control arm → refuses EXCESS ─────────────────────────────────────
// RED-before: gz 2.0 vs rg 1.0 on loss with NO control corpus — a single-corpus
// tool calls it EXCESS. GREEN: without the control differential it is only an
// ATTRIBUTION ⇒ INCONCLUSIVE, EXCESS refused.
#[test]
fn no_control_arm_refuses_excess() {
    let rep = evaluate(&input(vec![region("marker-resolve", 2.0, 1.0, None)]));
    let r = find(&rep, "marker-resolve");
    assert_ne!(
        r.verdict,
        Verdict::Excess,
        "EXCESS must be refused w/o control"
    );
    assert_eq!(r.verdict, Verdict::Inconclusive, "{}", r.reason);
    assert!(r.excess_sentence().is_err());
    assert!(r.reason.contains("ATTRIBUTION"));
    // an empty control ArmPair must also refuse.
    let mut reg = region("marker-resolve2", 2.0, 1.0, None);
    reg.control = Some(ArmPair::default());
    let rep2 = evaluate(&input(vec![reg]));
    assert_eq!(
        find(&rep2, "marker-resolve2").verdict,
        Verdict::Inconclusive
    );
}

// ── (e) instr-only input → INSTR-ONLY ───────────────────────────────────────
// RED-before: the same gz-high-on-loss / vanishes-on-control shape that WOULD be
// EXCESS, but the samples are INSTRUCTION counts. GREEN: NOT-A-CYCLE-VERDICT.
#[test]
fn instruction_metric_is_instr_only() {
    let mut inp = input(vec![region("marker-resolve", 2.0, 1.0, Some((1.0, 1.0)))]);
    inp.metric = Metric::Instr;
    let rep = evaluate(&inp);
    let r = find(&rep, "marker-resolve");
    assert_eq!(r.verdict, Verdict::InstrOnly, "{}", r.reason);
    assert!(r.excess_sentence().is_err());
    assert_eq!(
        rep.recoverable_budget, 0.0,
        "no cycle budget from instr data"
    );
    assert!(!rep.budget_is_law());
}

// ── (f) recoverable budget sums ONLY excess regions ─────────────────────────
// A mix: one EXCESS (recoverable 1.0), one INTRINSIC (0), one INCONCLUSIVE (0).
// Budget must equal exactly the EXCESS region's recoverable.
#[test]
fn budget_sums_only_excess_regions() {
    let rep = evaluate(&input(vec![
        region("excess-A", 2.0, 1.0, Some((1.0, 1.0))), // EXCESS, +1.0
        region("excess-B", 3.0, 1.0, Some((1.0, 1.0))), // EXCESS, +2.0
        region("intrinsic", 2.0, 1.0, Some((2.0, 1.0))), // INTRINSIC, 0
        region("noctrl", 2.0, 1.0, None),               // INCONCLUSIVE, 0
    ]));
    assert_eq!(find(&rep, "excess-A").verdict, Verdict::Excess);
    assert_eq!(find(&rep, "excess-B").verdict, Verdict::Excess);
    assert_eq!(find(&rep, "intrinsic").verdict, Verdict::Intrinsic);
    assert_eq!(find(&rep, "noctrl").verdict, Verdict::Inconclusive);
    // 1.0 + 2.0 only; intrinsic + noctrl contribute nothing.
    assert!(
        (rep.recoverable_budget - 3.0).abs() < 1e-6,
        "budget={}",
        rep.recoverable_budget
    );
    assert_eq!(rep.excess_regions().count(), 2);
    // ranked: EXCESS first, by recoverable desc (excess-B before excess-A).
    assert_eq!(rep.regions[0].label, "excess-B");
    assert_eq!(rep.regions[1].label, "excess-A");
}

// ── (g) single-arch → NOT-YET-LAW ───────────────────────────────────────────
// A real EXCESS budget on one arch must be stamped NOT-YET-LAW until replicated.
#[test]
fn single_arch_is_not_yet_law() {
    let mut inp = input(vec![region("marker-resolve", 2.0, 1.0, Some((1.0, 1.0)))]);
    inp.cross_arch_replicated = false;
    let rep = evaluate(&inp);
    assert_eq!(rep.scope, Scope::NotYetLaw);
    assert!(!rep.budget_is_law(), "single-arch budget cannot be law");
    assert!(
        rep.recoverable_budget > 0.0,
        "budget still reported here-and-now"
    );
    assert!(rep.render().contains("NOT-YET-LAW"));
    // cross-arch replicated ⇒ law.
    inp.cross_arch_replicated = true;
    let rep2 = evaluate(&inp);
    assert_eq!(rep2.scope, Scope::Law);
    assert!(rep2.budget_is_law());
}

// ── provenance: one gz/rg sha carried for every region (refusal 4) ──────────
#[test]
fn shas_are_carried_into_the_report() {
    let rep = evaluate(&input(vec![region("r", 2.0, 1.0, Some((1.0, 1.0)))]));
    assert_eq!(rep.gz_sha, "gzaaaa");
    assert_eq!(rep.rg_sha, "rgbbbb");
    assert!(rep.render().contains("gzaaaa"));
}

// ── artifact JSON roundtrips (the load path) ────────────────────────────────
#[test]
fn artifact_json_roundtrips_and_omits_procs_running() {
    // procs_running omitted from samples (serde default) — excess is not rq-gated.
    let json = r#"{
        "regions": [
            {"label":"marker-resolve",
             "loss":{"gz":[{"cycles":2.0,"instructions":4.0,"bytes":1.0}],
                     "rg":[{"cycles":1.0,"instructions":2.0,"bytes":1.0}]},
             "control":{"gz":[{"cycles":1.0,"instructions":2.0,"bytes":1.0}],
                        "rg":[{"cycles":1.0,"instructions":2.0,"bytes":1.0}]}}
        ],
        "loss_corpus":"silesia","control_corpus":"nasa","arch":"amd",
        "cross_arch_replicated":false,"gz_sha":"g","rg_sha":"r"
    }"#;
    let inp: ExcessInput = serde_json::from_str(json).expect("parse");
    assert_eq!(inp.metric, Metric::Cycle); // default
    assert!((inp.epsilon - DEFAULT_EPSILON).abs() < 1e-12); // default
    let rep = evaluate(&inp);
    assert_eq!(find(&rep, "marker-resolve").verdict, Verdict::Excess);
    assert_eq!(rep.scope, Scope::NotYetLaw);
}
