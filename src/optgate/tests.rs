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
///
/// The jitter PHASE depends on the label (`after`/`clean_after` get the opposite
/// phase from `base`) so that index-paired deltas are NOT artificially constant —
/// otherwise the ADDITION-1 paired sign-test would call a tiny-but-perfectly-
/// correlated delta "significant", masking what these fixtures actually test.
fn arm(label: &str, n: usize, cpb: f64, ipb: f64, rq: f64, jcpb: f64, jipb: f64) -> Arm {
    let phase = if label.contains("after") { 1 } else { 0 };
    let mut s = Vec::with_capacity(n);
    for i in 0..n {
        let sgn = if (i + phase) % 2 == 0 { 1.0 } else { -1.0 };
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
        aa: None,
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

// ── Refusal 2: QUIET-WINDOW-OR-VOID + ADDITION-2 CONTENTION-INVARIANT ────────
// A loaded window with a clear, flat, paired win CERTIFIES contention-invariant
// (a sound wall win on a contended box) instead of blindly voiding.
#[test]
fn loaded_window_certifies_contention_invariant_win() {
    let mut inp = winning_input();
    // WIN-shaped deltas, window NOT quiet (rq = 8 > 4+1), but the after/base
    // ratio is flat and the paired sign-test is strongly significant.
    inp.base = arm("base", 12, 10.0, 20.0, 8.0, 0.05, 0.05).with_sha("REF");
    inp.after = arm("after", 12, 9.0, 18.0, 8.0, 0.05, 0.05).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::WinContentionInvariant, "{}", v.reason);
    assert!(v.is_wall_win_here());
    assert!(v.contention.as_ref().unwrap().certified);
    // cross_arch_replicated = true ⇒ Law ⇒ voices a wall win.
    let s = v
        .wall_win_sentence()
        .expect("a contention-invariant LAW win must voice");
    assert!(s.contains("WALL WIN [CONTENTION-INVARIANT]"), "{s}");
}

// RED: a loaded window where the after/base ratio TRENDS with the run-queue
// (the two binaries have different contention-sensitivity) — VOID, not certified.
#[test]
fn loaded_window_with_trending_ratio_voids() {
    let mut inp = winning_input();
    // Build base/after by hand: at low load (rq=6) after/base≈0.90, at high load
    // (rq=10) after/base≈0.70 — a ratio that trends ⇒ confounded ⇒ VOID.
    let mut base_s = Vec::new();
    let mut after_s = Vec::new();
    for i in 0..12 {
        let high = i % 2 == 1;
        let rq = if high { 10.0 } else { 6.0 };
        let bcpb = 10.0;
        let acpb = if high { 7.0 } else { 9.0 };
        base_s.push(Sample {
            cycles: bcpb * BYTES,
            instructions: 20.0 * BYTES,
            bytes: BYTES,
            procs_running: rq,
        });
        after_s.push(Sample {
            cycles: acpb * BYTES,
            instructions: 18.0 * BYTES,
            bytes: BYTES,
            procs_running: rq,
        });
    }
    inp.base = Arm::new("base", base_s).with_sha("REF");
    inp.after = Arm::new("after", after_s).with_sha("REF");
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::VoidQuiet, "{}", v.reason);
    assert!(!v.is_wall_win_here());
    assert!(v.reason.contains("ratio-trended"), "{}", v.reason);
    assert!(v.wall_win_sentence().is_err());
}

// An A/A arm that is ASYMMETRIC (slot-position bias) refuses certification.
#[test]
fn loaded_window_with_asymmetric_aa_voids() {
    let mut inp = winning_input();
    inp.base = arm("base", 12, 10.0, 20.0, 8.0, 0.05, 0.05).with_sha("REF");
    inp.after = arm("after", 12, 9.0, 18.0, 8.0, 0.05, 0.05).with_sha("REF");
    // A/A measured ~25% faster than base, far outside the tiny base spread ⇒
    // the apparatus is NOT symmetric (the base slot is biased).
    inp.aa = Some(arm("base_AA", 12, 7.5, 20.0, 8.0, 0.01, 0.01));
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::VoidQuiet, "{}", v.reason);
    assert!(v.reason.contains("A-A-failed"), "{}", v.reason);
}

// A symmetric A/A arm under load still certifies the win.
#[test]
fn loaded_window_with_symmetric_aa_certifies() {
    let mut inp = winning_input();
    inp.base = arm("base", 12, 10.0, 20.0, 8.0, 0.05, 0.05).with_sha("REF");
    inp.after = arm("after", 12, 9.0, 18.0, 8.0, 0.05, 0.05).with_sha("REF");
    inp.aa = Some(arm("base_AA", 12, 10.0, 20.0, 8.0, 0.05, 0.05));
    let v = evaluate(&inp);
    assert_eq!(v.verdict, Verdict::WinContentionInvariant, "{}", v.reason);
    assert!(v.contention.as_ref().unwrap().aa_present);
    assert!(v.contention.as_ref().unwrap().aa_symmetric);
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
    // paired stats line is present (ADDITION 1).
    assert!(r.contains("paired"), "paired line present: {r}");
}

// ── ADDITION 1: the two-sided sign-test p-value (binomial, no crates) ────────
#[test]
fn sign_test_unanimous_is_tiny() {
    // 12 vs 0: p = 2·0.5^12 = 2/4096 ≈ 4.88e-4.
    let p = sign_test_two_sided(12, 0);
    assert!((p - 2.0 * 0.5_f64.powi(12)).abs() < 1e-12, "{p}");
    assert!(p < 0.01);
}

#[test]
fn sign_test_even_split_is_one() {
    // 6 vs 6: two-sided p saturates at 1.0.
    assert!((sign_test_two_sided(6, 6) - 1.0).abs() < 1e-12);
}

#[test]
fn sign_test_symmetric_in_args() {
    assert!((sign_test_two_sided(10, 2) - sign_test_two_sided(2, 10)).abs() < 1e-12);
}

#[test]
fn sign_test_zero_samples_is_one() {
    assert_eq!(sign_test_two_sided(0, 0), 1.0);
}

#[test]
fn sign_test_known_value_11_of_12() {
    // 11 pos / 1 neg: p = 2·(C(12,0)+C(12,1))·0.5^12 = 2·13/4096 ≈ 6.35e-3.
    let p = sign_test_two_sided(11, 1);
    let want = 2.0 * (1.0 + 12.0) * 0.5_f64.powi(12);
    assert!((p - want).abs() < 1e-12, "{p} vs {want}");
}

// ── ADDITION 1: PairedStats from explicit deltas ────────────────────────────
#[test]
fn paired_stats_unanimous_positive_is_significant() {
    let deltas: Vec<f64> = (0..12).map(|i| 1.0 + 0.01 * i as f64).collect();
    let ps = PairedStats::from_deltas(&deltas);
    assert_eq!(ps.n_pos, 12);
    assert_eq!(ps.n_neg, 0);
    assert!(ps.significant);
    assert!(ps.after_is_faster());
    assert!(ps.median_delta > 0.0);
}

#[test]
fn paired_stats_mixed_sign_is_not_significant() {
    // 6 up, 6 down — sign-test p = 1.0, minority 6 ≫ bound ⇒ not significant.
    let deltas = [
        0.1, -0.1, 0.1, -0.1, 0.1, -0.1, 0.1, -0.1, 0.1, -0.1, 0.1, -0.1,
    ];
    let ps = PairedStats::from_deltas(&deltas);
    assert_eq!(ps.n_pos, 6);
    assert_eq!(ps.n_neg, 6);
    assert!(!ps.significant);
}

#[test]
fn paired_stats_one_stray_on_21_still_significant() {
    // 20 pos / 1 neg on n=21: minority 1 ≤ max(1, 0.05·21=1.05) and p tiny.
    let mut deltas: Vec<f64> = (0..20).map(|_| 1.0).collect();
    deltas.push(-0.5);
    let ps = PairedStats::from_deltas(&deltas);
    assert_eq!(ps.n, 21);
    assert_eq!(ps.n_neg, 1);
    assert!(ps.significant, "one stray of 21 is still near-unanimous");
}

#[test]
fn paired_stats_two_strays_on_21_not_significant() {
    // 19 pos / 2 neg on n=21: minority 2 > 1.05 ⇒ NOT near-unanimous.
    let mut deltas: Vec<f64> = (0..19).map(|_| 1.0).collect();
    deltas.push(-0.5);
    deltas.push(-0.5);
    let ps = PairedStats::from_deltas(&deltas);
    assert_eq!(ps.n_neg, 2);
    assert!(!ps.significant, "two strays of 21 breaks near-unanimity");
}

#[test]
fn paired_stats_not_pairable_when_unequal_n() {
    let base = arm("base", 12, 10.0, 20.0, 1.0, 0.05, 0.05);
    let after = arm("after", 8, 9.0, 18.0, 1.0, 0.05, 0.05);
    assert!(PairedStats::from_arms_cpb(&base, &after).is_none());
}

// ── ADDITION 2: ContentionCert stratification (flat vs trending) ─────────────

/// Build base/after arms with a per-rep ratio and run-queue schedule.
fn ratio_arms(specs: &[(f64, f64)]) -> (Arm, Arm) {
    // specs[i] = (after/base ratio, procs_running)
    let mut bs = Vec::new();
    let mut as_ = Vec::new();
    for (ratio, rq) in specs {
        bs.push(Sample {
            cycles: 10.0 * BYTES,
            instructions: 20.0 * BYTES,
            bytes: BYTES,
            procs_running: *rq,
        });
        as_.push(Sample {
            cycles: 10.0 * ratio * BYTES,
            instructions: 18.0 * BYTES,
            bytes: BYTES,
            procs_running: *rq,
        });
    }
    (Arm::new("base", bs), Arm::new("after", as_))
}

#[test]
fn contention_cert_flat_ratio_certifies() {
    // ratio ≈ 0.90 at both low (rq=4) and high (rq=8) load ⇒ FLAT.
    let specs: Vec<(f64, f64)> = (0..12)
        .map(|i| {
            let rq = if i % 2 == 0 { 4.0 } else { 8.0 };
            (0.90, rq)
        })
        .collect();
    let (base, after) = ratio_arms(&specs);
    let paired = PairedStats::from_arms_cpb(&base, &after);
    let cert = ContentionCert::certify(&base, &after, None, paired.as_ref());
    assert!(cert.ratio_flat, "{:?}", cert);
    assert!(cert.paired_significant);
    assert!(cert.certified, "{:?}", cert);
    assert!(cert.after_is_faster);
    assert!(cert.n_strata_ge2 >= 2);
}

#[test]
fn contention_cert_trending_ratio_does_not_certify() {
    // ratio 0.90 at rq=4 but 0.70 at rq=8 ⇒ trends with load ⇒ NOT flat.
    let specs: Vec<(f64, f64)> = (0..12)
        .map(|i| if i % 2 == 0 { (0.90, 4.0) } else { (0.70, 8.0) })
        .collect();
    let (base, after) = ratio_arms(&specs);
    let paired = PairedStats::from_arms_cpb(&base, &after);
    let cert = ContentionCert::certify(&base, &after, None, paired.as_ref());
    assert!(!cert.ratio_flat, "{:?}", cert);
    assert!(!cert.certified);
    assert_eq!(cert.failure.as_deref(), Some("ratio-trended"));
}

// ── ADDITION 2: the A/A apparatus-symmetry sub-check ─────────────────────────
#[test]
fn contention_cert_asymmetric_aa_fails() {
    let specs: Vec<(f64, f64)> = (0..12)
        .map(|i| (0.90, if i % 2 == 0 { 4.0 } else { 8.0 }))
        .collect();
    let (base, after) = ratio_arms(&specs);
    let paired = PairedStats::from_arms_cpb(&base, &after);
    // base ≈ 10 cyc/B, A/A ≈ 8 cyc/B ⇒ 25% slot-position bias, far past spread.
    let aa = arm("base_AA", 12, 8.0, 20.0, 6.0, 0.02, 0.02);
    let cert = ContentionCert::certify(&base, &after, Some(&aa), paired.as_ref());
    assert!(cert.aa_present);
    assert!(!cert.aa_symmetric);
    assert!(!cert.certified);
    assert_eq!(cert.failure.as_deref(), Some("A-A-failed"));
}

#[test]
fn contention_cert_symmetric_aa_passes() {
    let specs: Vec<(f64, f64)> = (0..12)
        .map(|i| (0.90, if i % 2 == 0 { 4.0 } else { 8.0 }))
        .collect();
    let (base, after) = ratio_arms(&specs);
    let paired = PairedStats::from_arms_cpb(&base, &after);
    // A/A ≈ base (10 cyc/B) ⇒ symmetric apparatus.
    let mut aa_s = Vec::new();
    for i in 0..12 {
        let sgn = if i % 2 == 0 { 1.0 } else { -1.0 };
        aa_s.push(sample(10.0 + sgn * 0.05, 20.0, 6.0));
    }
    let aa = Arm::new("base_AA", aa_s);
    let cert = ContentionCert::certify(&base, &after, Some(&aa), paired.as_ref());
    assert!(cert.aa_present);
    assert!(cert.aa_symmetric, "{:?}", cert);
    assert!(cert.certified);
}
