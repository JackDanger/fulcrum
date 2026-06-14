//! CI self-tests for the COMPARABILITY GATE (`fulcrum::comparability`).
//!
//! These lock the four refusal predicates against the exact over-claims that
//! motivated the gate, so a regression that re-opens any of them fails CI:
//!
//!   * #10 "reopen/templated-block is gzippy-specific" — REFUSED when the marker
//!     count is identical across arms (predicate 2, shared-ness).
//!   * #15 "T1 settled tie" — VOIDED while igzip/libdeflate are unmeasured
//!     (predicate 4, settled).
//!   * "prepend is native-heavy" off ONE build — ONE-ARM-INCONCLUSIVE
//!     (predicate 1, two-arm).
//!   * single-(arch,corpus) "law" — auto-stamped HYPOTHESIS (predicate 3).

use fulcrum::comparability::{
    evaluate, evaluate_law, ArmPresence, Capture, GateClaim, GateVerdict, WorkCounter,
    EvidenceTier, FIELD_TOOL_ROSTER,
};
use fulcrum::compare::{BinaryKind, ThreadCell};

fn base_capture(arch: &str, arms: Vec<ArmPresence>, counters: Vec<WorkCounter>) -> Capture {
    Capture {
        cell_id: format!("{arch}/t1/silesia"),
        commit_sha: "abc1234".into(),
        corpus: "silesia".into(),
        arch: arch.into(),
        threads: ThreadCell::Fixed(1),
        sink: "regular-file".into(),
        n: 9,
        inter_run_spread: 0.02,
        arms,
        counters,
    }
}

fn native(id: &str, wall: f64) -> ArmPresence {
    ArmPresence::native(id, wall)
}

/// PREDICATE 1 — a one-build profile cannot speak a "X-specific vs rg" claim.
#[test]
fn one_build_profile_auto_tags_one_arm_inconclusive() {
    let cap = base_capture("amd-zen2", vec![native("gzippy-native", 300.0)], vec![]);
    let claim = GateClaim::SubjectSpecific {
        subject: "gzippy-native".into(),
        contrast: "rapidgzip".into(),
        counter: None,
        equal_spread: 0.05,
    };
    let o = evaluate(&cap, &claim);
    assert_eq!(o.verdict.label(), "ONE-ARM-INCONCLUSIVE");
    assert!(matches!(o.verdict, GateVerdict::OneArmInconclusive { .. }));
}

/// PREDICATE 1 — a present-but-non-native rg ELF (pip wheel) VOIDS the two-arm
/// requirement: the comparator must be the native ELF.
#[test]
fn missing_native_rg_elf_voids_two_arm_claim() {
    let mut rg = ArmPresence::native("rapidgzip", 250.0).requiring_native_elf();
    rg.binary_kind = BinaryKind::Interpreted("python".into());
    let cap = base_capture("amd-zen2", vec![native("gzippy-native", 300.0), rg], vec![]);
    let claim = GateClaim::SubjectSpecific {
        subject: "gzippy-native".into(),
        contrast: "rapidgzip".into(),
        counter: None,
        equal_spread: 0.05,
    };
    assert!(matches!(
        evaluate(&cap, &claim).verdict,
        GateVerdict::OneArmInconclusive { .. }
    ));
}

/// PREDICATE 1 — an arm measured but never A/A self-tested is untrusted.
#[test]
fn no_aa_self_test_voids_two_arm_claim() {
    let mut rg = ArmPresence::native("rapidgzip", 250.0);
    rg.aa_ratio = None; // never self-tested
    let cap = base_capture("amd-zen2", vec![native("gzippy-native", 300.0), rg], vec![]);
    let claim = GateClaim::SubjectSpecific {
        subject: "gzippy-native".into(),
        contrast: "rapidgzip".into(),
        counter: None,
        equal_spread: 0.05,
    };
    match evaluate(&cap, &claim).verdict {
        GateVerdict::OneArmInconclusive { why, .. } => assert!(why.contains("A/A")),
        v => panic!("expected ONE-ARM-INCONCLUSIVE, got {v:?}"),
    }
}

/// PREDICATE 2 (#10) — equal marker count REFUSES a gzippy-specific claim.
#[test]
fn equal_marker_count_refuses_specificity() {
    let markers = WorkCounter::new(
        "marker_count",
        &[("gzippy-native", 1_000_000.0), ("rapidgzip", 1_000_000.0)],
    );
    let cap = base_capture(
        "amd-zen2",
        vec![native("gzippy-native", 300.0), native("rapidgzip", 250.0)],
        vec![markers],
    );
    let claim = GateClaim::SubjectSpecific {
        subject: "gzippy-native".into(),
        contrast: "rapidgzip".into(),
        counter: Some("marker_count".into()),
        equal_spread: 0.05,
    };
    assert_eq!(evaluate(&cap, &claim).verdict.label(), "SHARED-REFUSED");
}

/// PREDICATE 2 — a genuinely different counter ADMITS the specificity.
#[test]
fn differing_counter_admits_specificity() {
    let markers = WorkCounter::new(
        "decoded_bytes",
        &[("gzippy-native", 2_000_000.0), ("rapidgzip", 1_000_000.0)],
    );
    let cap = base_capture(
        "amd-zen2",
        vec![native("gzippy-native", 300.0), native("rapidgzip", 250.0)],
        vec![markers],
    );
    let claim = GateClaim::SubjectSpecific {
        subject: "gzippy-native".into(),
        contrast: "rapidgzip".into(),
        counter: Some("decoded_bytes".into()),
        equal_spread: 0.05,
    };
    assert!(evaluate(&cap, &claim).verdict.admitted());
}

/// PREDICATE 3 — single-(arch,corpus) result is a HYPOTHESIS, not a law.
#[test]
fn single_arch_law_is_hypothesis_two_arch_replicated() {
    let amd = base_capture("amd-zen2", vec![], vec![]);
    let intel = base_capture("intel-i7-13700", vec![], vec![]);

    let one = evaluate_law(&[&amd], "kernel-share is 24% everywhere");
    assert_eq!(one.evidence_tier, EvidenceTier::Hypothesis);
    assert_eq!(one.verdict.label(), "HYPOTHESIS-ONLY");

    let two = evaluate_law(&[&amd, &intel], "decode kernel gates the wall");
    assert_eq!(two.evidence_tier, EvidenceTier::Replicated);
    assert!(two.verdict.admitted());
}

/// PREDICATE 4 (#15) — "T1 settled" is unspeakable while igzip is unmeasured.
#[test]
fn t1_settled_voided_when_field_tools_unmeasured() {
    let cap = Capture::score_like(
        "amd-zen2/t1/silesia",
        "abc1234",
        "silesia",
        "amd-zen2",
        ThreadCell::Fixed(1),
        9,
        250.0, // rg
        252.0, // native
        251.0, // isal
        0.01,
        0.01,
    );
    let claim = GateClaim::Settled {
        subject: "gzippy-native".into(),
        field_tools: FIELD_TOOL_ROSTER.iter().map(|s| s.to_string()).collect(),
        tie_bar: 0.99,
    };
    match evaluate(&cap, &claim).verdict {
        GateVerdict::SettledVoided { missing_tools, .. } => {
            assert!(missing_tools.contains(&"igzip".to_string()));
            assert!(missing_tools.contains(&"libdeflate".to_string()));
            assert!(missing_tools.contains(&"zlib-ng".to_string()));
        }
        v => panic!("expected SETTLED-VOIDED, got {v:?}"),
    }
}

/// PREDICATE 4 — a full measured roster with the subject at-or-faster ADMITS.
#[test]
fn full_roster_at_bar_admits_settled() {
    let cap = base_capture(
        "amd-zen2",
        vec![
            native("gzippy-native", 100.0),
            native("rapidgzip", 101.0),
            native("igzip", 100.5),
            native("libdeflate", 102.0),
            native("zlib-ng", 140.0),
        ],
        vec![],
    );
    let claim = GateClaim::Settled {
        subject: "gzippy-native".into(),
        field_tools: FIELD_TOOL_ROSTER.iter().map(|s| s.to_string()).collect(),
        tie_bar: 0.99,
    };
    assert!(evaluate(&cap, &claim).verdict.admitted());
}

/// CLI self-test: the `fulcrum comparability` subcommand exits NONZERO on a
/// refusal (so CI can gate an over-claim) and zero on an admitted claim.
#[test]
fn cli_refusal_exits_nonzero() {
    use std::io::Write;
    use std::process::Command;

    let bin = env!("CARGO_BIN_EXE_fulcrum");
    let dir = std::env::temp_dir();
    let one_build = dir.join("fulcrum_cg_one_build.json");
    let mut f = std::fs::File::create(&one_build).unwrap();
    write!(
        f,
        r#"{{"cell_id":"amd-zen2/t1/silesia","arch":"amd-zen2","threads":"T1","n":9,
            "arms":[{{"id":"gzippy-native","measured":true,"binary_kind":"native",
                     "aa_ratio":1.0,"aa_spread":0.01,"wall_ms":300.0}}],"counters":[]}}"#
    )
    .unwrap();

    // One build present, rg contrast absent ⇒ ONE-ARM-INCONCLUSIVE ⇒ exit != 0.
    let out = Command::new(bin)
        .args([
            "comparability",
            "--capture",
            one_build.to_str().unwrap(),
            "--claim",
            "subject-specific",
            "--subject",
            "gzippy-native",
            "--contrast",
            "rapidgzip",
        ])
        .output()
        .expect("run fulcrum");
    assert!(!out.status.success(), "one-build claim must be refused (nonzero exit)");
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(so.contains("ONE-ARM-INCONCLUSIVE"), "stdout: {so}");
}
