//! optgate unit tests — every refusal is a RED-before/GREEN-after fixture.
//!
//! "RED-before" = the fixture is constructed so that an instrument WITHOUT the
//! refusal (the ad-hoc cyc-diff scripts this gate replaces) would call it a WIN;
//! "GREEN-after" = `evaluate` returns the refusal verdict instead, and
//! `wall_win_sentence` refuses to voice a win.

use super::*;

const BYTES: f64 = 1_000_000.0;

/// One sample at a given cyc/byte + instr/byte + run-queue.
fn sample(cpb: f64, ipb: f64, rq: f64) -> Sample {
    Sample {
        cycles: cpb * BYTES,
        instructions: ipb * BYTES,
        bytes: BYTES,
        procs_running: rq,
    }
}

/// An arm of `n` interleaved samples centered on (`cpb`,`ipb`) with a symmetric
/// ± jitter (so the absolute spread is `2·j`), all at run-queue `rq`.
fn arm(label: &str, n: usize, cpb: f64, ipb: f64, rq: f64, jcpb: f64, jipb: f64) -> Arm {
    let mut s = Vec::with_capacity(n);
    for i in 0..n {
        let sgn = if i % 2 == 0 { 1.0 } else { -1.0 };
        s.push(sample(cpb + sgn * jcpb, ipb + sgn * jipb, rq));
    }
    Arm::new(label, s)
}

/// A baseline VALID input that, untouched, yields a clean WIN (cross-arch
/// replicated → LAW). Each test perturbs ONE field to trip ONE refusal.
fn winning_input() -> OptGateInput {
    OptGateInput {
        // targeted cell: cyc/byte 10.0 → 9.0 (Δ 1.0 ≫ spread 0.1); instr also down.
        base: arm("base", 12, 10.0, 20.0, 1.0, 0.05, 0.05).with_sha("REF"),
        after: arm("after", 12, 9.0, 18.0, 1.0, 0.05, 0.05).with_sha("REF"),
        rg: arm("rg", 12, 8.0, 16.0, 1.0, 0.05, 0.05),
        reference_sha: "REF".to_string(),
        // clean-path (T1): unchanged → no regression.
        clean_base: arm("clean_base", 12, 5.0, 10.0, 1.0, 0.05, 0.05).with_sha("REF"),
        clean_after: arm("clean_after", 12, 5.0, 10.0, 1.0, 0.05, 0.05).with_sha("REF"),
        k: 4.0,
        clean_k: 1.0,
        arch: "intel-i7-13700T".to_string(),
        cross_arch_replicated: true,
        base_commit: "aaaa".to_string(),
        after_commit: "bbbb".to_string(),
    }
}

// ── Refusal 1: CYC/BYTE IS THE METRIC, NOT INSTRUCTION-COUNT ────────────────
// RED-before: instr/byte drops a lot (the memcpy lesson, −17.7%) while cyc/byte
// is flat (IPC fell). A naive instruction-counter calls this a win.
#[test]
fn instruction_only_is_not_a_wall_win() {
    let mut inp = winning_input();
    // cyc/byte essentially flat: 10.0 → 9.98 (Δ 0.02 ≪ spread 0.1) — UNRESOLVED.
    inp.after = arm("after", 12, 9.98, 16.46, 1.0, 0.05, 0.05).with_sha("REF");
    // instr/byte 20.0 → 16.46 (−17.7%, Δ 3.54 ≫ spread 0.1) — RESOLVED improvement.
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::InstructionOnly, "{}", v.reason);
    assert!(!v.is_wall_win_here());
    assert!(v.wall_win_sentence().is_err());
    // IPC must be reported as fallen.
    assert!(v.after_ipc < v.base_ipc, "IPC should have fallen");
}

// ── Refusal 2: QUIET-WINDOW-OR-VOID ─────────────────────────────────────────
// RED-before: a real cyc/byte win, but the box was loaded (run-queue 8 ≫ k+slack).
#[test]
fn loaded_window_voids_the_cyc_verdict() {
    let mut inp = winning_input();
    // same WIN-shaped deltas, but the window was not quiet (rq = 8 > 4+1).
    inp.base = arm("base", 12, 10.0, 20.0, 8.0, 0.05, 0.05).with_sha("REF");
    inp.after = arm("after", 12, 9.0, 18.0, 8.0, 0.05, 0.05).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::VoidQuiet, "{}", v.reason);
    assert!(!v.is_wall_win_here());
    assert!(v.wall_win_sentence().is_err());
    assert!(v.reason.contains("not quiet"));
}

// A quiet window at exactly k+slack passes (boundary).
#[test]
fn quiet_window_at_ceiling_passes() {
    let mut inp = winning_input();
    inp.base = arm("base", 12, 10.0, 20.0, 5.0, 0.05, 0.05).with_sha("REF"); // k+slack=5
    inp.after = arm("after", 12, 9.0, 18.0, 5.0, 0.05, 0.05).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::Win, "{}", v.reason);
}

// ── Refusal 3: GZ-EXCESS-VS-RG (headline ratio), not internal share ─────────
#[test]
fn headline_gz_rg_gap_closure_is_computed() {
    let mut inp = winning_input();
    // base cyc/byte 12, after 11, rg 10 → ratios 1.2 → 1.1; gap closed = 0.1/0.2 = 50%.
    inp.base = arm("base", 12, 12.0, 24.0, 1.0, 0.02, 0.02).with_sha("REF");
    inp.after = arm("after", 12, 11.0, 22.0, 1.0, 0.02, 0.02).with_sha("REF");
    inp.rg = arm("rg", 12, 10.0, 20.0, 1.0, 0.02, 0.02);
    let v = evaluate(&inp);
    assert!(
        (v.gz_rg_ratio_before - 1.2).abs() < 1e-9,
        "{}",
        v.gz_rg_ratio_before
    );
    assert!(
        (v.gz_rg_ratio_after - 1.1).abs() < 1e-9,
        "{}",
        v.gz_rg_ratio_after
    );
    assert!(
        (v.gap_closed_frac - 0.5).abs() < 1e-9,
        "{}",
        v.gap_closed_frac
    );
}

// ── Refusal 4: BYTE-EXACT GATE ──────────────────────────────────────────────
// RED-before: a real cyc/byte win, but the AFTER output bytes differ.
#[test]
fn byte_mismatch_voids_the_win() {
    let mut inp = winning_input();
    inp.after = arm("after", 12, 9.0, 18.0, 1.0, 0.05, 0.05).with_sha("WRONG");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::VoidBytes, "{}", v.reason);
    assert!(v.wall_win_sentence().is_err());
}

#[test]
fn missing_after_sha_voids_the_win() {
    let mut inp = winning_input();
    inp.after = arm("after", 12, 9.0, 18.0, 1.0, 0.05, 0.05); // no sha attached
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::VoidBytes, "{}", v.reason);
}

// ── Refusal 5: CLEAN-PATH NO-REGRESSION ─────────────────────────────────────
// RED-before: a real targeted win, but the T1 clean path got significantly slower.
#[test]
fn clean_path_regression_refuses_the_win() {
    let mut inp = winning_input();
    // clean-path cyc/byte 5.0 → 6.0 (Δ −1.0 ≪ −spread) — a regression.
    inp.clean_after = arm("clean_after", 12, 6.0, 10.0, 1.0, 0.05, 0.05).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::Regression, "{}", v.reason);
    assert!(v.clean_regressed);
    assert!(v.wall_win_sentence().is_err());
}

// A clean-path delta within spread is NOT a regression (the win stands).
#[test]
fn clean_path_within_spread_is_not_a_regression() {
    let mut inp = winning_input();
    inp.clean_after = arm("clean_after", 12, 5.02, 10.0, 1.0, 0.05, 0.05).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::Win, "{}", v.reason);
    assert!(!v.clean_regressed);
}

// ── Refusal 6: SIGNIFICANCE (N≥12 + Δ vs spread) ────────────────────────────
#[test]
fn underpowered_below_min_n_refuses() {
    let mut inp = winning_input();
    inp.base = arm("base", 8, 10.0, 20.0, 1.0, 0.05, 0.05).with_sha("REF");
    inp.after = arm("after", 8, 9.0, 18.0, 1.0, 0.05, 0.05).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::Underpowered, "{}", v.reason);
    assert!(v.wall_win_sentence().is_err());
}

// RED-before: a sub-spread cyc/byte delta (and no instr resolution) — a TIE,
// never a win.
#[test]
fn sub_spread_delta_is_a_tie_not_a_win() {
    let mut inp = winning_input();
    // cyc/byte 10.0 → 9.95 (Δ 0.05 < spread 0.2); instr also flat.
    inp.base = arm("base", 12, 10.0, 20.0, 1.0, 0.10, 0.10).with_sha("REF");
    inp.after = arm("after", 12, 9.95, 19.95, 1.0, 0.10, 0.10).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::Tie, "{}", v.reason);
    assert!(v.wall_win_sentence().is_err());
}

// A significant cyc/byte SLOWDOWN on the targeted cell is a regression.
#[test]
fn significant_cyc_slowdown_is_a_regression() {
    let mut inp = winning_input();
    inp.base = arm("base", 12, 9.0, 18.0, 1.0, 0.05, 0.05).with_sha("REF");
    inp.after = arm("after", 12, 10.0, 20.0, 1.0, 0.05, 0.05).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::Regression, "{}", v.reason);
}

// ── Refusal 7: SCOPE STAMP (single-arch NOT-YET-LAW) ────────────────────────
// RED-before: a genuine cyc/byte win measured on ONE arch is NOT yet law.
#[test]
fn single_arch_win_is_not_yet_law() {
    let mut inp = winning_input();
    inp.cross_arch_replicated = false;
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::Win, "{}", v.reason);
    assert_eq!(v.scope, Scope::NotYetLaw);
    // a here-and-now win, but NOT bankable / NOT a law sentence.
    assert!(v.is_wall_win_here());
    assert!(!v.is_banked_wall_win());
    assert!(v.wall_win_sentence().is_err());
}

#[test]
fn cross_arch_replicated_win_is_law_and_voices() {
    let inp = winning_input(); // cross_arch_replicated = true
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::Win, "{}", v.reason);
    assert_eq!(v.scope, Scope::Law);
    assert!(v.is_banked_wall_win());
    let sentence = v.wall_win_sentence().expect("a LAW win must voice");
    assert!(sentence.contains("WALL WIN"), "{sentence}");
    assert!(sentence.contains("replicated cross-arch"), "{sentence}");
}

// ── The structural chokepoint: only WIN+LAW may voice a wall win ────────────
#[test]
fn wall_win_sentence_refused_for_every_non_win() {
    for verdict in [
        Verdict::Tie,
        Verdict::InstructionOnly,
        Verdict::Regression,
        Verdict::Underpowered,
        Verdict::VoidBytes,
        Verdict::VoidQuiet,
    ] {
        let mut v = evaluate(&winning_input());
        v.verdict = verdict;
        let err = v.wall_win_sentence().unwrap_err();
        assert_eq!(err.verdict, verdict);
    }
}

// ── perf-stat ingestion seam (Sample::from_stat_text) ───────────────────────
#[test]
fn sample_from_stat_text_parses_cyc_and_instr() {
    let text = "\
 1,000,000,000      cycles
   500,000,000      instructions
";
    let s = Sample::from_stat_text(text, 1_000_000.0, 1.0).expect("parse");
    assert_eq!(s.cycles, 1_000_000_000.0);
    assert_eq!(s.instructions, 500_000_000.0);
    assert!((s.cyc_per_byte() - 1000.0).abs() < 1e-9);
    assert!((s.ipc() - 0.5).abs() < 1e-9);
}

#[test]
fn sample_from_stat_text_missing_cycles_refuses() {
    let text = "   500,000,000      instructions\n";
    let err = Sample::from_stat_text(text, 1_000_000.0, 1.0).unwrap_err();
    assert_eq!(err.invariant, cycles::OPTGATE_NO_CYCLES);
}

// ── full render smoke (no panic; carries shas + scope) ──────────────────────
#[test]
fn render_includes_scope_and_provenance() {
    let v = evaluate(&winning_input());
    let r = v.render();
    assert!(r.contains("WIN"));
    assert!(r.contains("LAW"));
    assert!(r.contains("aaaa") && r.contains("bbbb"), "shas present");
    assert!(r.contains("cyc/byte"));
    assert!(r.contains("gz/rg"));
}
