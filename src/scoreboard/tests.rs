//! Self-tests for `fulcrum scoreboard`. The load-bearing tests are the refusal
//! semantics (a missing evidence field can NEVER serialize as a verdict), TOST
//! equivalence, the diff significance/flip logic, and dry-run spec validation.

use super::*;

fn hex(c: char) -> String {
    std::iter::repeat(c).take(64).collect()
}

fn full_evidence() -> Evidence {
    Evidence {
        cell: Some(CellId {
            box_id: "b".into(),
            corpus: "silesia".into(),
            threads: 8,
            subject: "gz".into(),
            comparator: "rg".into(),
        }),
        subject: Some(ToolProv {
            label: "gz".into(),
            bin: "/gz".into(),
            sha256: hex('a'),
            argv: "-d -c -p 8".into(),
        }),
        comparator: Some(ToolProv {
            label: "rg".into(),
            bin: "/rg".into(),
            sha256: hex('b'),
            argv: "-d -c -P 8".into(),
        }),
        corpus: Some(CorpusProv {
            name: "silesia".into(),
            path: "/s.gz".into(),
            pin_sha256: hex('c'),
            decompressed_sha256: hex('d'),
        }),
        box_id: Some("b".into()),
        box_cpu: Some("EPYC".into()),
        run_queue_samples: vec![0.1, 0.1, 0.1],
        timestamp: Some("2026-07-05T00:00:00Z".into()),
        src_sha: Some("deadbee".into()),
        n: 15,
        threads: 8,
        mask: Some("0-7".into()),
        subject_median_ms: Some(100.0),
        comparator_median_ms: Some(120.0),
        subject_rel_spread: Some(0.01),
        comparator_rel_spread: Some(0.01),
        aa_rel_spread: Some(0.01),
        paired: Some(PairedStats {
            n_pos: 15,
            n_neg: 0,
            n_tie: 0,
            p_value: 0.0,
            log_ratios: vec![(100.0f64 / 120.0).ln(); 15],
        }),
        subject_correct: Some(true),
        comparator_correct: Some(true),
        subject_walls: vec![100.0; 15],
        comparator_walls: vec![120.0; 15],
        quiesce: None,
    }
}

// ── REFUSAL SEMANTICS ────────────────────────────────────────────────────────

#[test]
fn refusal_fires_on_each_missing_field() {
    let crit = Criteria::default();

    // A complete evidence set must NOT refuse.
    match assemble(&full_evidence(), &crit) {
        RunCell::Refused(r) => panic!("full evidence refused: {:?}", r.missing),
        _ => {}
    }

    // Removing any one required field must yield REFUSED with that field named.
    let cases: Vec<(&str, Box<dyn Fn(&mut Evidence)>)> = vec![
        ("subject.sha256", Box::new(|e: &mut Evidence| e.subject.as_mut().unwrap().sha256.clear())),
        ("comparator.sha256", Box::new(|e: &mut Evidence| e.comparator.as_mut().unwrap().sha256.clear())),
        ("corpus.pin_sha256", Box::new(|e: &mut Evidence| e.corpus.as_mut().unwrap().pin_sha256.clear())),
        ("corpus.decompressed_sha256", Box::new(|e: &mut Evidence| e.corpus.as_mut().unwrap().decompressed_sha256.clear())),
        ("box.cpu", Box::new(|e: &mut Evidence| e.box_cpu = None)),
        ("box.run_queue_samples", Box::new(|e: &mut Evidence| e.run_queue_samples.clear())),
        ("src_sha", Box::new(|e: &mut Evidence| e.src_sha = Some(String::new()))),
        ("timestamp", Box::new(|e: &mut Evidence| e.timestamp = None)),
        ("mask", Box::new(|e: &mut Evidence| e.mask = None)),
        ("subject.wall_median_ms", Box::new(|e: &mut Evidence| e.subject_median_ms = None)),
        ("aa.spread", Box::new(|e: &mut Evidence| e.aa_rel_spread = None)),
        ("paired", Box::new(|e: &mut Evidence| e.paired = None)),
        ("subject.correctness", Box::new(|e: &mut Evidence| e.subject_correct = None)),
    ];
    for (field, mutate) in cases {
        let mut ev = full_evidence();
        mutate(&mut ev);
        match assemble(&ev, &crit) {
            RunCell::Refused(r) => assert!(
                r.missing.iter().any(|m| m == field),
                "missing {field} not reported; got {:?}",
                r.missing
            ),
            other => panic!("expected REFUSED for missing {field}, got {other:?}"),
        }
    }
}

#[test]
fn refused_never_serializes_as_verdict() {
    let mut ev = full_evidence();
    ev.src_sha = Some(String::new());
    let cell = assemble(&ev, &Criteria::default());
    let json = serde_json::to_string(&cell).unwrap();
    assert!(json.contains("\"state\":\"REFUSED\""), "got {json}");
    assert!(!json.contains("\"state\":\"VERDICT\""));
}

#[test]
fn quiesce_unrestored_is_refused() {
    let mut ev = full_evidence();
    ev.quiesce = Some(QuiesceProv {
        used: true,
        process: "llama-server".into(),
        method: "SIGSTOP".into(),
        stopped: true,
        restored: false,
    });
    match assemble(&ev, &Criteria::default()) {
        RunCell::Refused(r) => assert!(r.missing.iter().any(|m| m == "quiesce.restored")),
        other => panic!("expected REFUSED, got {other:?}"),
    }
}

#[test]
fn wrong_bytes_is_void_not_verdict() {
    let mut ev = full_evidence();
    ev.subject_correct = Some(false);
    match assemble(&ev, &Criteria::default()) {
        RunCell::Void(v) => assert!(v.reason.contains("correctness")),
        other => panic!("expected VOID, got {other:?}"),
    }
}

#[test]
fn loaded_verdict_with_hole_normalizes_to_refused() {
    // Build a legit verdict, then blank a provenance field to simulate a
    // hand-written/corrupted artifact, and confirm load-time re-validation.
    let ev = full_evidence();
    let mut cell = assemble(&ev, &Criteria::default());
    if let RunCell::Verdict(v) = &mut cell {
        v.provenance.subject.sha256.clear();
    } else {
        panic!("expected a verdict to corrupt");
    }
    match revalidate_loaded(cell) {
        RunCell::Refused(r) => assert!(r.missing.iter().any(|m| m == "subject.sha256")),
        other => panic!("expected REFUSED on load, got {other:?}"),
    }
}

// ── VERDICT CLASSIFICATION ───────────────────────────────────────────────────

#[test]
fn certified_win_when_significant_and_beyond_spread() {
    let ev = full_evidence(); // subject 100 vs comparator 120, 15/0 paired
    match assemble(&ev, &Criteria::default()) {
        RunCell::Verdict(v) => {
            assert_eq!(v.verdict, "WIN");
            assert_eq!(v.criterion, "certified");
            assert!(v.ratio > 1.0);
        }
        other => panic!("expected certified WIN, got {other:?}"),
    }
}

#[test]
fn loaded_box_gives_contention_invariant() {
    let mut ev = full_evidence();
    ev.run_queue_samples = vec![8.0, 8.0, 8.0];
    match assemble(&ev, &Criteria::default()) {
        RunCell::Verdict(v) => assert_eq!(v.criterion, "contention-invariant"),
        other => panic!("expected contention-invariant, got {other:?}"),
    }
}

#[test]
fn aa_noise_cap_voids_not_ties() {
    // Equal medians (would-be TIE) but A/A spread over the cap ⇒ VOID, never TIE.
    let mut ev = full_evidence();
    ev.comparator_median_ms = Some(100.0);
    ev.aa_rel_spread = Some(0.50); // 50% >> 5% cap
    ev.paired = Some(PairedStats {
        n_pos: 7,
        n_neg: 8,
        n_tie: 0,
        p_value: 1.0,
        log_ratios: vec![0.0; 15],
    });
    match assemble(&ev, &Criteria::default()) {
        RunCell::Void(v) => assert!(v.reason.contains("A/A spread")),
        other => panic!("expected VOID from AA cap, got {other:?}"),
    }
}

#[test]
fn large_delta_certifies_despite_noisy_aa() {
    // 2.13× win (subject 35ms vs comparator 74.7ms) at A/A 7.85% — the delta is
    // ~14× the apparatus noise. The A/A cap gates equivalence only; a WIN whose
    // effect exceeds aa_win_mult×A/A (1.5×7.85% = 11.8% << 113%) MUST certify.
    // (Regression test for the 2026-07-05 blanket-void defect.)
    let mut ev = full_evidence();
    ev.subject_median_ms = Some(35.0);
    ev.comparator_median_ms = Some(74.7);
    ev.aa_rel_spread = Some(0.0785);
    ev.subject_rel_spread = Some(0.05);
    ev.comparator_rel_spread = Some(0.05);
    ev.paired = Some(PairedStats {
        n_pos: 15,
        n_neg: 0,
        n_tie: 0,
        p_value: 0.0,
        log_ratios: vec![(35.0f64 / 74.7).ln(); 15],
    });
    match assemble(&ev, &Criteria::default()) {
        RunCell::Verdict(v) => {
            assert_eq!(v.verdict, "WIN");
            assert!(v.ratio > 2.0);
        }
        other => panic!("expected WIN despite noisy A/A, got {other:?}"),
    }
}

#[test]
fn small_delta_with_noisy_aa_still_voids() {
    // 4% delta at A/A 8%: the effect is within aa_win_mult×A/A (1.5×8% = 12%),
    // and equal-ish walls can't TOST-certify at over-cap A/A ⇒ VOID.
    let mut ev = full_evidence();
    ev.subject_median_ms = Some(100.0);
    ev.comparator_median_ms = Some(104.0);
    ev.aa_rel_spread = Some(0.08);
    ev.paired = Some(PairedStats {
        n_pos: 12,
        n_neg: 3,
        n_tie: 0,
        p_value: 0.03,
        log_ratios: vec![(100.0f64 / 104.0).ln(); 15],
    });
    match assemble(&ev, &Criteria::default()) {
        RunCell::Void(_) => {}
        other => panic!("expected VOID for small delta under noisy A/A, got {other:?}"),
    }
}

#[test]
fn mm_large_deficit_certifies_loss_at_k1_5() {
    // The calibrating cell: M1 mm_large-T1-vs-libdeflate. Subject (gz) is 17.9%
    // slower than the comparator (libdeflate) — a real, paired-significant,
    // arm-spread-exceeding LOSS. At the OLD k=3.0 it was VOIDed only because
    // 3×A/A (3×7.6% = 22.8%) fabricated a bar above the 17.9% effect, inverting
    // the Gate-1 Δ>spread law. At the calibrated k=1.5 the bar is 1.5×7.6% =
    // 11.4% < 17.9%, so it CERTIFIES as LOSS.
    let mut ev = full_evidence();
    ev.subject_median_ms = Some(100.0); // gz
    ev.comparator_median_ms = Some(82.1); // libdeflate: ratio 0.821, |ratio−1|=17.9%
    ev.aa_rel_spread = Some(0.076);
    ev.subject_rel_spread = Some(0.075);
    ev.comparator_rel_spread = Some(0.075);
    ev.paired = Some(PairedStats {
        n_pos: 0,
        n_neg: 15,
        n_tie: 0,
        p_value: 0.0,
        log_ratios: vec![(82.1f64 / 100.0).ln(); 15],
    });
    // Default (calibrated) criteria certify the LOSS.
    match assemble(&ev, &Criteria::default()) {
        RunCell::Verdict(v) => {
            assert_eq!(v.verdict, "LOSS");
            assert!(v.ratio < 1.0);
        }
        other => panic!("expected certified LOSS at k=1.5, got {other:?}"),
    }
    // Sanity: at the OLD k=3.0 the same cell VOIDs (11.4%<17.9%<22.8%),
    // proving the calibration is what flips it.
    let strict = Criteria { aa_win_mult: 3.0, ..Criteria::default() };
    match assemble(&ev, &strict) {
        RunCell::Void(_) => {}
        other => panic!("expected VOID at k=3.0 (pre-calibration), got {other:?}"),
    }
}

#[test]
fn tiny_effect_at_noisy_aa_stays_void_at_k1_5() {
    // A 1.5% effect at 7% A/A must NOT certify at the calibrated k=1.5: the bar
    // is max(arm, 1.5×7% = 10.5%) and 1.5% << 10.5%. The consistent sub-margin
    // offset also can't TOST-tie at over-cap A/A ⇒ VOID (never a phantom win).
    let mut ev = full_evidence();
    ev.subject_median_ms = Some(100.0);
    ev.comparator_median_ms = Some(101.5); // 1.5% effect
    ev.aa_rel_spread = Some(0.07);
    ev.subject_rel_spread = Some(0.02);
    ev.comparator_rel_spread = Some(0.02);
    ev.paired = Some(PairedStats {
        n_pos: 9,
        n_neg: 6,
        n_tie: 0,
        p_value: 0.3,
        log_ratios: vec![(100.0f64 / 101.5).ln(); 15],
    });
    match assemble(&ev, &Criteria::default()) {
        RunCell::Void(_) => {}
        other => panic!("expected VOID for tiny effect under noisy A/A, got {other:?}"),
    }
}

#[test]
fn recertify_flips_k3_void_to_loss_at_k1_5() {
    // The mm_large cell exactly as the OLD k=3.0 certifier VOIDed it: 17.9%
    // deficit, paired-significant, effect > arm-spread but < 3×A/A (22.8%). The
    // new certifier PERSISTS the reps into the VOID, so `recertify` re-runs
    // `assemble` at the calibrated k=1.5 and certifies the LOSS — no box re-run.
    let mut ev = full_evidence();
    ev.subject_median_ms = Some(100.0);
    ev.comparator_median_ms = Some(82.1); // ratio 0.821, |ratio−1|=17.9%
    ev.aa_rel_spread = Some(0.076);
    ev.subject_rel_spread = Some(0.075);
    ev.comparator_rel_spread = Some(0.075);
    ev.paired = Some(PairedStats {
        n_pos: 0,
        n_neg: 15,
        n_tie: 0,
        p_value: 0.0,
        log_ratios: vec![(82.1f64 / 100.0).ln(); 15],
    });
    let strict = Criteria { aa_win_mult: 3.0, ..Criteria::default() };
    let voided = assemble(&ev, &strict);
    match &voided {
        RunCell::Void(v) => {
            assert!(v.paired.is_some(), "VOID must persist reps for recertify");
            assert_eq!(v.aa_rel_spread, Some(0.076));
        }
        other => panic!("expected VOID at k=3.0, got {other:?}"),
    }
    // Recertify at the calibrated default (k=1.5).
    let (recert, did) = recertify_cell(voided, &Criteria::default());
    assert!(did, "cell carried stats ⇒ must recertify");
    match recert {
        RunCell::Verdict(v) => {
            assert_eq!(v.verdict, "LOSS");
            assert!(v.ratio < 1.0);
        }
        other => panic!("expected LOSS after recertify, got {other:?}"),
    }
}

#[test]
fn recertify_preserves_statsless_void() {
    // A pre-recertify VOID (no stored reps) can't be recertified: it is
    // PRESERVED unchanged, never reclassified from thin air (refusal semantics).
    let ev = full_evidence();
    let cell = assemble(&ev, &Criteria::default());
    let prov = cell.provenance().clone();
    let bare = RunCell::Void(VoidCell {
        cell: cell.cell().clone(),
        reason: "legacy void without stored reps".into(),
        subject_wall_median_ms: 100.0,
        comparator_wall_median_ms: 120.0,
        subject_rel_spread: None,
        comparator_rel_spread: None,
        aa_rel_spread: None,
        paired: None,
        subject_correct: None,
        comparator_correct: None,
        provenance: prov,
    });
    let (out, did) = recertify_cell(bare, &Criteria::default());
    assert!(!did, "statsless VOID must be preserved, not recertified");
    match out {
        RunCell::Void(v) => assert!(v.reason.contains("legacy void")),
        other => panic!("expected preserved VOID, got {other:?}"),
    }
}

#[test]
fn tost_ties_when_within_margin() {
    // Equal medians, tiny paired log-ratios inside ±ln(1.01), AA under cap.
    let mut ev = full_evidence();
    ev.comparator_median_ms = Some(100.0);
    ev.subject_median_ms = Some(100.0);
    ev.aa_rel_spread = Some(0.01);
    let tiny: Vec<f64> = (0..15).map(|i| ((i % 3) as f64 - 1.0) * 0.0005).collect();
    ev.paired = Some(PairedStats {
        n_pos: 7,
        n_neg: 8,
        n_tie: 0,
        p_value: 1.0,
        log_ratios: tiny,
    });
    match assemble(&ev, &Criteria::default()) {
        RunCell::Verdict(v) => {
            assert_eq!(v.verdict, "TIE");
            assert_eq!(v.criterion, "equivalence(TOST)");
        }
        other => panic!("expected TOST TIE, got {other:?}"),
    }
}

#[test]
fn tost_math_direct() {
    // Tight distribution around 0 ⇒ equivalent at 1%.
    let tight: Vec<f64> = (0..30).map(|i| ((i % 3) as f64 - 1.0) * 0.001).collect();
    assert!(tost_equivalent(&tight, 1.0));
    // A consistent 3% offset ⇒ NOT equivalent at 1%.
    let off: Vec<f64> = (0..30).map(|_| 0.03).collect();
    assert!(!tost_equivalent(&off, 1.0));
    // Wide noise ⇒ CI too wide ⇒ NOT equivalent (noise can't buy a TIE).
    let wide: Vec<f64> = (0..30).map(|i| if i % 2 == 0 { 0.05 } else { -0.05 }).collect();
    assert!(!tost_equivalent(&wide, 1.0));
}

#[test]
fn sign_test_wiring_matches_optgate() {
    assert!(paired_significant(15, 0, 15));
    assert!(!paired_significant(8, 7, 15));
}

// ── DIFF ─────────────────────────────────────────────────────────────────────

fn artifact_with(cell: RunCell) -> Artifact {
    Artifact {
        protocol_version: PROTOCOL_VERSION,
        kind: "scoreboard".into(),
        timestamp: "t".into(),
        src_sha: "s".into(),
        n: 15,
        boxes: vec![BoxResult {
            id: "b".into(),
            platform: "linux".into(),
            cpu: "EPYC".into(),
            cells: vec![cell],
        }],
        recertified: None,
    }
}

fn win_cell(ratio: f64, verdict: &str) -> RunCell {
    let ev = full_evidence();
    let mut c = assemble(&ev, &Criteria::default());
    if let RunCell::Verdict(v) = &mut c {
        v.ratio = ratio;
        v.verdict = verdict.to_string();
    }
    c
}

#[test]
fn diff_flags_flip_and_exits_nonzero() {
    let before = artifact_with(win_cell(1.20, "WIN"));
    let after = artifact_with(win_cell(0.80, "LOSS"));
    let (rows, regressions) = diff_artifacts(&before, &after);
    assert!(regressions >= 1);
    assert!(rows.iter().any(|r| r.class == "FLIP"));
}

#[test]
fn diff_improved_exits_zero() {
    let before = artifact_with(win_cell(1.10, "WIN"));
    let after = artifact_with(win_cell(1.30, "WIN"));
    let (rows, regressions) = diff_artifacts(&before, &after);
    assert_eq!(regressions, 0);
    assert!(rows.iter().any(|r| r.class == "IMPROVED"));
}

#[test]
fn diff_regression_on_ratio_drop() {
    let before = artifact_with(win_cell(1.30, "WIN"));
    let after = artifact_with(win_cell(1.10, "WIN"));
    let (_rows, regressions) = diff_artifacts(&before, &after);
    assert_eq!(regressions, 1);
}

// ── SPEC / DRY-RUN ───────────────────────────────────────────────────────────

fn valid_spec_json() -> String {
    format!(
        r#"{{
      "n": 5, "src_sha": "abc1234",
      "boxes": [{{
        "id":"local","exec":{{"local":true}},"platform":"macos","cpu":"M1",
        "subject":{{"label":"gz","bin":"/bin/echo","args_tmpl":"-d -c -p {{T}}"}},
        "comparators":[{{"label":"gzip","bin":"/usr/bin/gzip","args_tmpl":"-d -c"}}],
        "corpora":[{{"name":"tiny","path":"/t.gz","pin_sha256":"{p}","decompressed_sha256":"{d}"}}],
        "threads":[1,2],"mask_tmpl":"0-{{Tm1}}"
      }}]
    }}"#,
        p = hex('c'),
        d = hex('d'),
    )
}

#[test]
fn dry_run_plan_counts_cells() {
    let spec: Spec = serde_json::from_str(&valid_spec_json()).unwrap();
    validate_spec(&spec).unwrap();
    let plan = plan(&spec);
    // 1 corpus × 2 threads × 1 comparator = 2 cells.
    assert_eq!(plan.len(), 2);
}

#[test]
fn spec_rejects_bad_pin_and_empty_grid() {
    let bad_pin = valid_spec_json().replace(&hex('c'), "not-hex");
    let spec: Spec = serde_json::from_str(&bad_pin).unwrap();
    assert!(validate_spec(&spec).is_err());

    let empty_grid = valid_spec_json().replace("\"threads\":[1,2]", "\"threads\":[]");
    let spec: Spec = serde_json::from_str(&empty_grid).unwrap();
    assert!(validate_spec(&spec).is_err());
}

// ── SCRIPT GENERATION ────────────────────────────────────────────────────────

#[test]
fn measure_script_has_dev_null_and_rotates() {
    let subj = ArmCmd { label: "subject".into(), bin: "/gz".into(), argv: "-d -c".into(), env: vec![] };
    let cmp = ArmCmd { label: "comparator".into(), bin: "/rg".into(), argv: "-d -c".into(), env: vec![] };
    let s = build_measure_script("linux", "0-7", "/s.gz", &subj, &cmp, 6);
    assert!(s.contains(">/dev/null"), "timed reps must sink to /dev/null");
    assert!(s.contains("CORR subject"));
    assert!(s.contains("comparator_aa"), "must run an A/A arm");
    // /proc/uptime is FORBIDDEN: centisecond resolution quantizes sub-200ms
    // walls (2026-07-06 defect). Linux must use a nanosecond clock.
    assert!(!s.contains("/proc/uptime"), "10ms-resolution clock is forbidden");
    assert!(s.contains("date +%s%N"), "linux nanosecond clock");
    assert!(s.contains("taskset -c 0-7"));
}

#[test]
fn macos_script_uses_monotonic_and_no_taskset() {
    let subj = ArmCmd { label: "subject".into(), bin: "/gz".into(), argv: "-d -c".into(), env: vec![] };
    let cmp = ArmCmd { label: "comparator".into(), bin: "/gzip".into(), argv: "-d -c".into(), env: vec![] };
    let s = build_measure_script("macos", "0-3", "/s.gz", &subj, &cmp, 3);
    assert!(s.contains("time.monotonic_ns"));
    assert!(!s.contains("taskset"), "no taskset on macos");
}

#[test]
fn quiesce_restore_verifies_and_watchdog_detached() {
    let start = build_quiesce_start("llama-server", 600);
    assert!(start.contains("kill -STOP"));
    assert!(start.contains("nohup setsid"), "watchdog must be detached");
    assert!(start.contains("sleep 600"));
    let restore = build_quiesce_restore(&["111".into(), "222".into()], "999", "/tmp/pf");
    assert!(restore.contains("kill -CONT"));
    assert!(restore.contains("QRESTORED"));
    assert!(restore.contains("kill 999"), "must kill the watchdog");
}

// ── LOCAL SMOKE (exercises the REAL run loop end-to-end via LocalRunner) ──────

#[test]
fn local_smoke_runs_full_orchestration() {
    // Tiny real corpus: gzip a small payload, pin its shas, race gzip vs gzip.
    let dir = std::env::temp_dir().join(format!("fulcrum_sb_smoke_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let raw = dir.join("payload.txt");
    let gz = dir.join("payload.txt.gz");
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&raw, &payload).unwrap();

    // create .gz via the system gzip
    let ok = Command::new("gzip")
        .args(["-kf", raw.to_str().unwrap()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok || !gz.exists() {
        eprintln!("smoke: system gzip unavailable — skipping");
        return;
    }

    // shas
    let pin = super::super::score::sha256_file_hex(&gz).unwrap();
    let decomp = super::super::score::sha256_file_hex(&raw).unwrap();

    let spec = Spec {
        n: 4,
        src_sha: "smoke123".into(),
        criteria: Criteria::default(),
        boxes: vec![BoxSpec {
            id: "local".into(),
            exec: ExecSpec { local: true, ssh: None },
            platform: if cfg!(target_os = "macos") { "macos".into() } else { "linux".into() },
            cpu: String::new(),
            quiesce: None,
            subject: ToolSpec {
                label: "gzip-subject".into(),
                bin: "gzip".into(),
                args_tmpl: "-d -c".into(),
                env: Default::default(),
                threads_max: None,
            },
            comparators: vec![ToolSpec {
                label: "gzip-rival".into(),
                bin: "gzip".into(),
                args_tmpl: "-d -c".into(),
                env: Default::default(),
                threads_max: None,
            }],
            corpora: vec![CorpusSpec {
                name: "tiny".into(),
                path: gz.to_str().unwrap().to_string(),
                pin_sha256: pin,
                decompressed_sha256: decomp,
            }],
            threads: vec![1],
            mask_tmpl: None, // no taskset on the smoke host
        }],
    };

    validate_spec(&spec).unwrap();
    let runner = LocalRunner;
    let mut cache = BTreeMap::new();
    let cell = measure_cell(
        &runner,
        &spec.boxes[0],
        &spec.boxes[0].corpora[0],
        1,
        &spec.boxes[0].comparators[0],
        &spec,
        &mut cache,
    );

    // Must NOT be REFUSED — every evidence field was captured through the real loop.
    match &cell {
        RunCell::Refused(r) => panic!("smoke cell REFUSED (loop failed to capture): {:?}", r.missing),
        RunCell::Verdict(v) => {
            // gzip vs gzip on the same input ⇒ correct bytes both arms; a decisive
            // WIN/LOSS between identical tools is implausible — expect TIE, else VOID.
            assert!(
                v.verdict == "TIE" || v.criterion == "contention-invariant",
                "gzip-vs-gzip should not be a clean WIN/LOSS: {:?}",
                v
            );
        }
        RunCell::Void(_) => { /* acceptable: noisy laptop ⇒ uncertifiable */ }
    }

    // The artifact must round-trip and re-validate without becoming REFUSED
    // (proves provenance is complete end-to-end).
    let art = Artifact {
        protocol_version: PROTOCOL_VERSION,
        kind: "scoreboard".into(),
        timestamp: "t".into(),
        src_sha: "smoke123".into(),
        n: 4,
        boxes: vec![BoxResult {
            id: "local".into(),
            platform: "x".into(),
            cpu: "x".into(),
            cells: vec![cell],
        }],
        recertified: None,
    };
    let json = serde_json::to_string(&art).unwrap();
    let back: Artifact = serde_json::from_slice(json.as_bytes()).unwrap();
    let revalidated = revalidate_loaded(back.boxes[0].cells[0].clone());
    assert!(
        !matches!(revalidated, RunCell::Refused(_)),
        "round-tripped smoke cell should not be refused"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
