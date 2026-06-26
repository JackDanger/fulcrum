//! Integration tests for `fulcrum optimality` — the §7 instrument self-cal gate.
//!
//! These lock the GATE LAW: the instrument's attribution must be INSTR-disjoint,
//! per-op-perturbation-isolated (inject 2× into op X → ONLY bucket X grows),
//! deterministic (A/A), and end-to-end. The real-data fixture is a genuine
//! end-to-end perf-script of fresh gzippy-native decoding logs.gz at T1 captured
//! on the Intel trainer (scope-stamped in the build doc) — so the gate is proven
//! on REAL capture data, not just a synthetic stream.

use fulcrum::insn_attr::Arch;
use fulcrum::optimality::{gen_fixture, run_self_cal};

#[test]
fn synthetic_fixture_loud_passes_all_legs() {
    let fixture = gen_fixture();
    let sc = run_self_cal(&fixture, Arch::X86, None);
    assert!(sc.spine_disjoint, "(a) spine disjoint");
    assert!(sc.perturb_passed, "(b) perturbation calibration");
    assert!(sc.aa_deterministic, "(c) A/A determinism");
    assert!(sc.end_to_end_ok, "(d) end-to-end coverage");
    assert!(sc.passed, "self-cal LOUD-PASS");
}

#[test]
fn real_logs_t1_capture_loud_passes() {
    // Real end-to-end gzippy-native logs-T1 capture (Intel trainer).
    let script = include_str!("fixtures/optimality_logs_t1_gz.script");
    let sc = run_self_cal(script, Arch::X86, None);

    // (a) disjoint spine: every classified sample lands in exactly one bucket.
    assert!(
        sc.spine_disjoint,
        "Σ buckets {} != classified {}",
        sc.spine_sum, sc.spine_classified
    );
    assert!(sc.spine_classified > 1000, "real capture has many samples");

    // (b) perturbation calibration must pass for EVERY present op — no
    // cross-contamination on real, varied instruction mix.
    assert!(sc.perturb_passed, "perturbation calibration on real data");
    assert!(
        sc.perturb.len() >= 10,
        "real capture exercises a wide instruction mix ({} ops)",
        sc.perturb.len()
    );
    for row in &sc.perturb {
        assert_eq!(
            row.op_after,
            row.baseline * 2,
            "op {} doubled exactly",
            row.op
        );
        assert!(
            row.other_buckets_unchanged,
            "op {} injection leaked into {:?}",
            row.op, row.leaked_into
        );
        assert!(row.total_grew_exactly, "op {} total grew exactly", row.op);
    }

    // (c) + (d)
    assert!(sc.aa_deterministic, "A/A deterministic on real data");
    assert!(sc.end_to_end_ok, "end-to-end coverage on real data");
    assert!(sc.passed, "real-data self-cal LOUD-PASS");
}
