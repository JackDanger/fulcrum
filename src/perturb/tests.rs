//! perturb self-tests — the harness must reproduce a KNOWN lever and a KNOWN
//! slack before any of its verdicts count (SELF-TEST-OR-NO-TRUST applied to the
//! keystone gate).
//!
//! A 1:1 port of `decide/fulcrum/selftests/test_perturb.py` — every `check(...)`
//! in the Python reference becomes one `#[test]` here, with the SAME asserted
//! verdict/refusal so the Rust harness is faithful to the verified oracle.

use super::*;
use std::collections::BTreeMap;

const SELF_MS: f64 = 100.0; // region self-time: 100ms → injected 10/20/30ms
const SELF_S: f64 = SELF_MS / 1000.0;

/// n samples with min=minval, max=minval+spread_s (deterministic spread).
fn samples_n(minval: f64, spread_s: f64, n: usize) -> Vec<f64> {
    if n == 1 {
        return vec![minval];
    }
    (0..n)
        .map(|i| minval + spread_s * i as f64 / (n as f64 - 1.0))
        .collect()
}

/// samples() with the Python defaults (spread_s=0.002, n=9).
fn samples(minval: f64) -> Vec<f64> {
    samples_n(minval, 0.002, 9)
}

/// Arm levels with delta(t) = crit · injected(t). crit=1.0 → fully critical;
/// crit=0 → flat (slack).
fn linear_arm_n(crit: f64, base: f64, spread_s: f64, n: usize) -> BTreeMap<u32, Vec<f64>> {
    let mut out = BTreeMap::new();
    for pct in [10u32, 20, 30] {
        let inj = (pct as f64 / 100.0) * SELF_S;
        out.insert(pct, samples_n(base + crit * inj, spread_s, n));
    }
    out
}

fn linear_arm(crit: f64) -> BTreeMap<u32, Vec<f64>> {
    linear_arm_n(crit, 1.000, 0.002, 9)
}

fn base_sweep() -> Sweep {
    Sweep {
        region: Some("test.region".to_string()),
        perturb_cmd: Some("oracle.sh --region R sweep".to_string()),
        cell_id: Some("perturb_test".to_string()),
        region_self_ms: SELF_MS,
        sha_ok: Some("1".to_string()),
        baseline: samples(1.000),
        baseline_mid: Vec::new(),
        baseline_recheck: samples(1.0001),
        spin: BTreeMap::new(),
        sleep: BTreeMap::new(),
        oracle_removed: None,
    }
}

// ── 1. KNOWN LEVER — criticality 1.0, busy AND sleep dose-respond ───────────

#[test]
fn known_lever_verdict_is_perturbation_lever() {
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Lever);
    assert_eq!(cell.evidence_tier, Tier::Perturbation);
}

#[test]
fn known_lever_criticality_is_one_and_ci_excludes_zero() {
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert!((cell.criticality.unwrap() - 1.0).abs() < 0.05);
    assert!(cell.criticality_lo.unwrap() > 0.0);
}

#[test]
fn known_lever_may_claim_lever_true() {
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert!(cell.may_claim_lever());
}

#[test]
fn known_lever_sentence_emits_gated_claim_and_oracle_ceiling() {
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    let sent = cell
        .lever_sentence()
        .expect("LEVER cell must emit a sentence");
    assert!(sent.contains("LEVER"));
    assert!(sent.contains("Funding a fix here is licensed"));
    assert!(sent.contains("oracle ceiling"));
}

#[test]
fn arm_response_criticality_one_is_responds() {
    let sw_spin = linear_arm(1.0);
    let ar = arm_response(&samples(1.000), &sw_spin, SELF_S);
    assert_eq!(ar.kind, ArmKind::Responds);
    assert!(ar.monotonic);
    assert!(ar.linear);
    assert!(ar.significant);
}

// ── 2. KNOWN SLACK — flat both arms (the fix-clean-path #14 shape) ──────────

#[test]
fn known_slack_verdict_is_perturbation_slack() {
    let mut sw = base_sweep();
    sw.region = Some("clean-path decode loop (annotate 1.10x share)".to_string());
    sw.spin = linear_arm(0.0);
    sw.sleep = linear_arm(0.0);
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Slack);
    assert_eq!(cell.evidence_tier, Tier::Perturbation);
}

#[test]
fn known_slack_may_claim_lever_false() {
    let mut sw = base_sweep();
    sw.region = Some("clean-path decode loop (annotate 1.10x share)".to_string());
    sw.spin = linear_arm(0.0);
    sw.sleep = linear_arm(0.0);
    let cell = analyze_sweep(&sw);
    assert!(!cell.may_claim_lever());
}

#[test]
fn arm_response_criticality_zero_is_flat() {
    let sw_spin = linear_arm(0.0);
    let ar0 = arm_response(&samples(1.000), &sw_spin, SELF_S);
    assert_eq!(ar0.kind, ArmKind::Flat);
    assert!(!ar0.significant);
}

// ── 3. A/A — perturbed == baseline → reads 1.0±spread (slope ~0) ────────────

#[test]
fn a_a_identical_arms_read_slack_within_spread() {
    let mut sw = base_sweep();
    let flat: BTreeMap<u32, Vec<f64>> = [10u32, 20, 30]
        .into_iter()
        .map(|p| (p, samples(1.000)))
        .collect();
    sw.spin = flat.clone();
    sw.sleep = flat;
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Slack);
    assert!(cell.delta_ms.unwrap().abs() <= cell.spread_ms.unwrap());
}

#[test]
fn a_a_criticality_is_zero() {
    let mut sw = base_sweep();
    let flat: BTreeMap<u32, Vec<f64>> = [10u32, 20, 30]
        .into_iter()
        .map(|p| (p, samples(1.000)))
        .collect();
    sw.spin = flat.clone();
    sw.sleep = flat;
    let cell = analyze_sweep(&sw);
    assert!(cell.criticality.unwrap().abs() < 0.05);
}

// ── 4. SPIN ARTIFACT — busy responds, sleep FLAT ───────────────────────────

#[test]
fn spin_artifact_verdict() {
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(0.0);
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Artifact);
}

#[test]
fn spin_artifact_may_claim_lever_false() {
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(0.0);
    let cell = analyze_sweep(&sw);
    assert!(!cell.may_claim_lever());
}

// ── 5. UNSTABLE BASELINE — A/A swing > spread VOIDs the cell ────────────────

#[test]
fn unstable_baseline_swing_voids() {
    let mut sw = base_sweep();
    sw.baseline = samples(1.000);
    sw.baseline_recheck = samples(1.050);
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Void);
    assert!(cell.notes.iter().any(|n| n.contains("swung")));
}

// ── 6. NON-MONOTONE — busy significant but t20 < t10 → VOID ─────────────────

#[test]
fn non_monotone_voids_instrument() {
    let nonmono: BTreeMap<u32, Vec<f64>> = [
        (10u32, samples(1.030)),
        (20, samples(1.005)),
        (30, samples(1.030)),
    ]
    .into_iter()
    .collect();
    let mut sw = base_sweep();
    sw.spin = nonmono.clone();
    sw.sleep = nonmono;
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Void);
    assert!(cell
        .notes
        .iter()
        .any(|n| n.to_uppercase().contains("MONOTON")));
}

// ── 7. UNDERPOWERED — N<9 → INCONCLUSIVE + N-needed ────────────────────────

#[test]
fn underpowered_is_inconclusive_with_n_needed() {
    let mut sw = base_sweep();
    sw.baseline = samples_n(1.000, 0.002, 5);
    sw.baseline_recheck = samples_n(1.0001, 0.002, 5);
    sw.spin = linear_arm_n(1.0, 1.000, 0.002, 5);
    sw.sleep = linear_arm_n(1.0, 1.000, 0.002, 5);
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Inconclusive);
    assert_eq!(cell.n_needed, Some(9));
}

// ── 8. CEILING-ONLY — only the removal oracle ──────────────────────────────

#[test]
fn ceiling_only_verdict_and_tier() {
    let mut sw = base_sweep();
    sw.region = Some("window-absent bootstrap bundle".to_string());
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::CeilingOnly);
    assert_eq!(cell.evidence_tier, Tier::Oracle);
}

#[test]
fn ceiling_only_ceiling_is_100ms() {
    let mut sw = base_sweep();
    sw.region = Some("window-absent bootstrap bundle".to_string());
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert!((cell.oracle_ceiling_ms.unwrap() - 100.0).abs() < 1.0);
}

#[test]
fn ceiling_only_may_claim_lever_false() {
    let mut sw = base_sweep();
    sw.region = Some("window-absent bootstrap bundle".to_string());
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert!(!cell.may_claim_lever());
}

// ── 9. THE REFUSAL FIRES ───────────────────────────────────────────────────

fn refusal_cases() -> Vec<(&'static str, PerturbCell)> {
    let mut slack = base_sweep();
    slack.spin = linear_arm(0.0);
    slack.sleep = linear_arm(0.0);

    let mut artifact = base_sweep();
    artifact.spin = linear_arm(1.0);
    artifact.sleep = linear_arm(0.0);

    let mut ceiling = base_sweep();
    ceiling.oracle_removed = Some(samples(0.900));

    let mut void = base_sweep();
    void.baseline = samples(1.000);
    void.baseline_recheck = samples(1.050);
    void.spin = linear_arm(1.0);
    void.sleep = linear_arm(1.0);

    vec![
        ("SLACK", analyze_sweep(&slack)),
        ("ARTIFACT", analyze_sweep(&artifact)),
        ("CEILING", analyze_sweep(&ceiling)),
        ("VOID", analyze_sweep(&void)),
    ]
}

#[test]
fn refusal_raises_for_every_non_lever_cell() {
    for (name, cell) in refusal_cases() {
        assert!(
            cell.lever_sentence().is_err(),
            "{name} cell must refuse a lever sentence"
        );
    }
}

#[test]
fn refusal_message_names_the_perturbation() {
    for (name, cell) in refusal_cases() {
        let err = cell.lever_sentence().unwrap_err();
        assert!(
            err.message.contains("perturbation that would test this is"),
            "{name} refusal must name the perturbation"
        );
    }
}

// ── 10. LOADER round-trip + renderer routes prose through the gate ──────────

fn write_sweep_dir(d: &std::path::Path, sweep: &Sweep, freeze: bool) {
    use std::io::Write;
    std::fs::create_dir_all(d).unwrap();
    let w = |path: std::path::PathBuf, xs: &[f64]| {
        let s = xs
            .iter()
            .map(|x| format!("{x:.6}"))
            .collect::<Vec<_>>()
            .join(" ");
        std::fs::write(path, s).unwrap();
    };
    let mut meta = std::fs::File::create(d.join("meta.txt")).unwrap();
    if let Some(r) = &sweep.region {
        writeln!(meta, "region={r}").unwrap();
    }
    if let Some(p) = &sweep.perturb_cmd {
        writeln!(meta, "perturb_cmd={p}").unwrap();
    }
    if let Some(c) = &sweep.cell_id {
        writeln!(meta, "cell_id={c}").unwrap();
    }
    writeln!(meta, "region_self_ms={}", sweep.region_self_ms).unwrap();
    if let Some(s) = &sweep.sha_ok {
        writeln!(meta, "sha_ok={s}").unwrap();
    }
    if freeze {
        writeln!(meta, "freeze_state=frozen").unwrap();
        writeln!(meta, "quiet_state=quiet").unwrap();
    }
    drop(meta);
    w(d.join("baseline.txt"), &sweep.baseline);
    w(d.join("baseline_recheck.txt"), &sweep.baseline_recheck);
    for (arm, levels) in [("spin", &sweep.spin), ("sleep", &sweep.sleep)] {
        let ad = d.join(arm);
        std::fs::create_dir_all(&ad).unwrap();
        for (pct, xs) in levels {
            w(ad.join(format!("t{pct}.txt")), xs);
        }
    }
    if let Some(orc) = &sweep.oracle_removed {
        w(d.join("oracle_removed.txt"), orc);
    }
}

fn unique_tmp(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("fulcrum_perturb_{tag}_{nanos}"))
}

#[test]
fn loader_round_trips_to_lever_with_freeze_meta() {
    let d = unique_tmp("loader");
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    write_sweep_dir(&d, &sw, true);
    let (loaded, meta) = load_sweep(&d).expect("load");
    let cell = analyze_sweep(&loaded);
    assert_eq!(cell.verdict, Verdict::Lever);
    assert_eq!(meta.get("freeze_state").map(String::as_str), Some("frozen"));
    assert!(frozen_ok(&meta));
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn render_lever_prints_invariant_and_gated_sentence() {
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    let out = render_perturb(&cell, true);
    assert!(out.contains("PERTURBATION-OR-NO-LEVER"));
    assert!(out.contains("Funding a fix here is licensed"));
    assert!(out.contains("criticality"));
}

#[test]
fn render_slack_omits_lever_sentence_and_marks_unreachable() {
    let mut sw = base_sweep();
    sw.spin = linear_arm(0.0);
    sw.sleep = linear_arm(0.0);
    let cell = analyze_sweep(&sw);
    let out = render_perturb(&cell, true);
    assert!(!out.contains("Funding a fix here is licensed"));
    assert!(out.contains("UNREACHABLE"));
    assert!(out.contains("SLACK"));
}

// ── 11. WORKED EXAMPLE #14 — fix-clean-path-overhead → SLACK, un-voiceable ──

#[test]
fn worked_14_fix_clean_path_is_slack_and_unvoiceable() {
    let mut sw = base_sweep();
    sw.region = Some("clean-path decode overhead (function-annotate 1.10x)".to_string());
    sw.perturb_cmd =
        Some("oracle.sh --region clean_path --inject {10,20,30} --sleep-ctl".to_string());
    sw.spin = linear_arm(0.0);
    sw.sleep = linear_arm(0.0);
    let c14 = analyze_sweep(&sw);
    assert_eq!(c14.verdict, Verdict::Slack);
    let raised = c14.lever_sentence().unwrap_err();
    assert!(raised.message.contains("clean-path"));
}

// ── 12. WORKED EXAMPLE #6 — build-the-window-fix → CEILING-ONLY, gated ──────

#[test]
fn worked_6_build_window_fix_is_ceiling_only_and_gated() {
    let mut sw = base_sweep();
    sw.region = Some("window-absent bootstrap (oracle ceiling read)".to_string());
    sw.perturb_cmd =
        Some("oracle.sh --region window_absent --inject {10,20,30} --sleep-ctl".to_string());
    sw.oracle_removed = Some(samples(0.880));
    let c6 = analyze_sweep(&sw);
    assert_eq!(c6.verdict, Verdict::CeilingOnly);
    assert!(!c6.may_claim_lever());
    assert!(c6.lever_sentence().is_err());
}

#[test]
fn worked_6_only_legal_sentence_states_ceiling_is_not_a_carrier() {
    let mut sw = base_sweep();
    sw.region = Some("window-absent bootstrap (oracle ceiling read)".to_string());
    sw.oracle_removed = Some(samples(0.880));
    let c6 = analyze_sweep(&sw);
    assert!(c6.hypothesis_sentence().to_lowercase().contains("carrier"));
}

// ── Projection onto the canonical Finding CELL ─────────────────────────────

#[test]
fn lever_cell_projects_to_a_citable_located_finding() {
    use crate::finding::{EvidenceTier, Scope, Threads, Verdict as FVerdict};
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    let f = cell.to_finding(
        "abc1234",
        Scope::new("silesia", "amd-zen2", Threads::Fixed(8)),
        "regular-file",
        "2026-06-14",
    );
    assert!(f.is_citable().is_ok());
    assert_eq!(f.verdict, FVerdict::Located);
    assert_eq!(f.evidence_tier, EvidenceTier::Perturbation);
}

// ── 13. KEYSTONE: a lone outlier must NOT manufacture a STRONG SLACK ────────
//
// Regression guard for the dispersion defect: the inter-run spread used to be
// max(max−min) (outlier-sensitive) while the delta was a central statistic, so
// ONE slow sample inflated the 2×spread bar without moving the delta → a real
// criticality-1.0 region read "not significant" → both arms FLAT → a STRONG,
// false Verdict::Slack ("do NOT fund a fix here") from a single noisy run. The
// fix (robust IQR spread + median-to-median delta) makes the bar immune to a
// lone tail outlier. These tests are RED on the pre-fix code and GREEN after.

/// A clean evenly-spaced set with ONE high outlier appended — a single noisy
/// run (scheduling hiccup) on an otherwise clean set. min unchanged; the
/// outlier sits beyond Q3 so a robust IQR ignores it, but max−min explodes.
fn samples_with_hiccup(minval: f64, spread_s: f64, n: usize, hiccup_s: f64) -> Vec<f64> {
    let mut v = samples_n(minval, spread_s, n);
    v.push(minval + hiccup_s);
    v
}

#[test]
fn lone_baseline_hiccup_does_not_manufacture_slack() {
    // criticality 1.0, ~30ms wall response in BOTH arms, ONE +60ms hiccup in
    // the baseline set. Pre-fix: bar = 2×60ms = 120ms ≫ 30ms delta → FLAT/FLAT
    // → STRONG SLACK. Post-fix: IQR ignores the hiccup → significant → LEVER.
    let mut sw = base_sweep();
    sw.baseline = samples_with_hiccup(1.000, 0.002, 9, 0.060);
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert_ne!(
        cell.verdict,
        Verdict::Slack,
        "a lone baseline hiccup must NEVER yield a STRONG SLACK"
    );
    assert!(
        matches!(cell.verdict, Verdict::Lever | Verdict::Inconclusive),
        "expected LEVER or INCONCLUSIVE, got {:?}",
        cell.verdict
    );
    // The strongest carrier reading: this clean-but-for-one-sample sweep should
    // recover the lever, not merely dodge the false slack.
    assert_eq!(cell.verdict, Verdict::Lever);
    assert!(cell.may_claim_lever());
}

#[test]
fn lone_perturbed_arm_hiccup_does_not_manufacture_slack() {
    // Same region, but the +60ms hiccup is in the perturbed arm's OWN strongest
    // (t=30%) spin sample — the perturbed arm's jitter, not the baseline's.
    let mut sw = base_sweep();
    let mut spin = linear_arm(1.0);
    spin.insert(
        30,
        samples_with_hiccup(1.0 + 1.0 * (0.30 * SELF_S), 0.002, 9, 0.060),
    );
    sw.spin = spin;
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert_ne!(
        cell.verdict,
        Verdict::Slack,
        "a lone spin-arm hiccup must NEVER yield a STRONG SLACK"
    );
    assert!(
        matches!(cell.verdict, Verdict::Lever | Verdict::Inconclusive),
        "expected LEVER or INCONCLUSIVE, got {:?}",
        cell.verdict
    );
    assert_eq!(cell.verdict, Verdict::Lever);
}

#[test]
fn clean_true_slack_still_reads_slack() {
    // True-negative preserved: a genuinely flat region with clean, well-powered
    // samples STILL reads a STRONG SLACK (the gate must not become useless).
    let mut sw = base_sweep();
    sw.spin = linear_arm(0.0);
    sw.sleep = linear_arm(0.0);
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Slack);
    assert_eq!(cell.evidence_tier, Tier::Perturbation);
    assert!(!cell.may_claim_lever());
    // and the SLACK is justified by POWER, not just a flat reading.
    assert!(cell.notes.iter().any(|n| n.contains("POWERED")));
}

#[test]
fn clean_criticality_one_still_reads_lever() {
    // True-positive preserved: a clean criticality-1.0 sweep STILL reads LEVER.
    let mut sw = base_sweep();
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    sw.oracle_removed = Some(samples(0.900));
    let cell = analyze_sweep(&sw);
    assert_eq!(cell.verdict, Verdict::Lever);
    assert_eq!(cell.evidence_tier, Tier::Perturbation);
    assert!((cell.criticality.unwrap() - 1.0).abs() < 0.05);
}

#[test]
fn underpowered_spread_reads_inconclusive_not_slack() {
    // Symmetric conservativeness: a region whose inter-run spread is too wide to
    // resolve even a criticality-1.0 response (inj(30%) ≤ 2×spread) must read
    // INCONCLUSIVE, NEVER a STRONG SLACK — the SLACK side is now as conservative
    // as the LEVER side. Tiny region_self_ms shrinks inj(30%) below the bar.
    let mut sw = base_sweep();
    sw.region_self_ms = 1.0; // self_s=0.001 → inj(30%)=0.0003 s ≪ 2×IQR(=~0.002 s)
    sw.spin = linear_arm(0.0);
    sw.sleep = linear_arm(0.0);
    let cell = analyze_sweep(&sw);
    assert_ne!(
        cell.verdict,
        Verdict::Slack,
        "an underpowered sweep must NEVER yield a STRONG SLACK"
    );
    assert_eq!(cell.verdict, Verdict::Inconclusive);
}

// ── 14. The robust statistic primitives behave as documented ────────────────

#[test]
fn iqr_spread_is_immune_to_a_lone_tail_outlier() {
    // The crux: a clean set and the same set + one big outlier have nearly equal
    // IQR (robust), whereas their max−min differ by the whole outlier (fragile).
    let clean = samples_n(1.000, 0.002, 9);
    let dirty = samples_with_hiccup(1.000, 0.002, 9, 0.060);
    let iqr_clean = sample_stats(&clean).unwrap().iqr;
    let iqr_dirty = sample_stats(&dirty).unwrap().iqr;
    assert!(
        (iqr_dirty - iqr_clean).abs() < 0.001,
        "IQR must barely move with a lone outlier: clean={iqr_clean} dirty={iqr_dirty}"
    );
    let range_clean = {
        let s = sample_stats(&clean).unwrap();
        s.max - s.min
    };
    let range_dirty = {
        let s = sample_stats(&dirty).unwrap();
        s.max - s.min
    };
    assert!(
        range_dirty > range_clean + 0.05,
        "the OLD max−min measure DOES explode with the outlier (that was the bug)"
    );
}

#[test]
fn median_delta_equals_min_delta_for_clean_evenly_spaced_sets() {
    // The robust delta is backward-compatible on clean data: median-to-median
    // equals the old min-to-min because the per-set median offset cancels.
    let base = samples_n(1.000, 0.002, 9);
    let arm = samples_n(1.030, 0.002, 9);
    let sb = sample_stats(&base).unwrap();
    let sa = sample_stats(&arm).unwrap();
    let median_delta = sa.med - sb.med;
    let min_delta = sa.min - sb.min;
    assert!(
        (median_delta - min_delta).abs() < 1e-9,
        "median_delta={median_delta} min_delta={min_delta}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// NOISY-BOX cleaning primitives — occupancy filter, IQR fence, clean composition,
// bracket drift, and the FULL-CELL A/A bracket extension to analyze_sweep.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn occupancy_filter_rejects_preempted_samples() {
    let xs = vec![1.0, 1.1, 1.2, 1.3];
    // 1.1 and 1.3 were preempted (occupancy below the floor).
    let occ = vec![0.99, 0.40, 0.97, 0.20];
    let (kept, rejected) = occupancy_filter(&xs, &occ, OCCUPANCY_MIN);
    assert_eq!(kept, vec![1.0, 1.2]);
    assert_eq!(rejected, 2);
}

#[test]
fn occupancy_filter_short_occ_keeps_unmatched_tail() {
    // missing occupancy ⇒ assume clean (graceful), never a phantom reject.
    let xs = vec![1.0, 1.1, 1.2];
    let occ = vec![0.40]; // only the first has occupancy
    let (kept, rejected) = occupancy_filter(&xs, &occ, OCCUPANCY_MIN);
    assert_eq!(kept, vec![1.1, 1.2]);
    assert_eq!(rejected, 1);
}

#[test]
fn serial_cell_is_not_false_voided_as_contaminated() {
    // A legitimately partly-serial T4 cell: every sample reads occupancy ~0.60
    // (serial bootstrap + parallel tail) on a PERFECTLY QUIET box, with NO
    // preemption. Under the old absolute 0.90 floor EVERY sample is rejected
    // (reject_frac → 1.0 ⇒ a false CONTAMINATION VOID that hides a real
    // measurement). The relativized floor must keep them all.
    let xs = samples_n(0.500, 0.004, 11);
    let occ = vec![
        0.58, 0.60, 0.61, 0.59, 0.62, 0.60, 0.61, 0.58, 0.60, 0.59, 0.62,
    ];
    let cr = clean_samples(&xs, &occ);
    assert_eq!(
        cr.rejected, 0,
        "a clean serial-by-design cell must NOT be rejected (was a false-VOID)"
    );
    assert_eq!(cr.kept.len(), 11);
}

#[test]
fn serial_cell_still_rejects_a_real_preemption_dip() {
    // Same serial cell (occ ~0.60), but one sample was genuinely preempted: its
    // occupancy DIPS to 0.30, well below the cell's own norm. The relativized
    // floor (0.60 × 0.90 = 0.54) must still catch it.
    let xs = vec![0.50, 0.51, 0.52, 0.53, 0.54, 0.55, 0.56, 0.57, 0.58, 0.99];
    let occ = vec![0.60, 0.61, 0.59, 0.60, 0.62, 0.58, 0.61, 0.60, 0.59, 0.30];
    let (kept, rejected) = occupancy_filter(&xs, &occ, effective_occupancy_min(&occ));
    assert_eq!(
        rejected, 1,
        "the 0.30 dip below the cell's norm is preemption"
    );
    assert!(!kept.contains(&0.99), "the preempted sample is dropped");
}

#[test]
fn effective_floor_keeps_strict_bar_for_saturating_cell() {
    // A saturating cell (median occupancy ≥ 0.90) keeps the strict absolute
    // floor — the fix must NOT weaken the saturating path.
    let saturating = vec![0.99, 0.98, 1.0, 0.97, 0.99];
    assert!((effective_occupancy_min(&saturating) - OCCUPANCY_MIN).abs() < 1e-12);
    // A serial cell relativizes to reference × OCCUPANCY_REL_FRAC.
    let serial = vec![0.60, 0.61, 0.59, 0.60, 0.62];
    let eff = effective_occupancy_min(&serial);
    assert!((eff - 0.60 * OCCUPANCY_REL_FRAC).abs() < 1e-9, "eff={eff}");
    assert!(eff < OCCUPANCY_MIN);
    // Empty occupancy ⇒ the absolute floor (graceful; filter no-ops anyway).
    assert!((effective_occupancy_min(&[]) - OCCUPANCY_MIN).abs() < 1e-12);
}

#[test]
fn iqr_fence_drops_a_lone_high_outlier() {
    let mut xs = samples_n(1.000, 0.004, 9);
    xs.push(5.0); // a gross outlier
    let (kept, dropped) = iqr_fence(&xs);
    assert_eq!(dropped, 1, "the 5.0 outlier is fenced out");
    assert!(!kept.contains(&5.0));
    // a clean, evenly-spaced set loses nothing.
    let (kept2, dropped2) = iqr_fence(&samples_n(1.000, 0.004, 9));
    assert_eq!(dropped2, 0);
    assert_eq!(kept2.len(), 9);
}

#[test]
fn iqr_fence_too_few_samples_unchanged() {
    let xs = vec![1.0, 9.0, 1.0];
    let (kept, dropped) = iqr_fence(&xs);
    assert_eq!(dropped, 0, "<4 samples ⇒ no defensible quartiles");
    assert_eq!(kept.len(), 3);
}

#[test]
fn clean_samples_composes_occupancy_then_fence() {
    let mut xs = samples_n(1.000, 0.004, 9);
    let mut occ = vec![0.99; 9];
    // append a preempted sample AND a dispersion outlier.
    xs.push(1.5);
    occ.push(0.30); // preempted → occupancy-rejected first
    xs.push(9.0);
    occ.push(0.99); // clean occupancy but a fence outlier
    let cr = clean_samples(&xs, &occ);
    assert_eq!(cr.rejected, 2, "one occupancy reject + one fence reject");
    assert!(!cr.kept.contains(&1.5) && !cr.kept.contains(&9.0));
    assert!(!cr.bimodal_after_fence, "the cleaned set is unimodal");
}

#[test]
fn bracket_drift_swing_and_end_to_end() {
    let d = bracket_drift(&[1.000, 1.025, 1.050]).unwrap();
    assert!((d.swing_s - 0.050).abs() < 1e-9, "worst pairwise = 50ms");
    assert!((d.end_to_end_pct - 5.0).abs() < 1e-6, "first→last = 5%");
    // a mid-cell excursion that first==last would hide is still caught by swing.
    let d2 = bracket_drift(&[1.000, 1.040, 1.000]).unwrap();
    assert!((d2.swing_s - 0.040).abs() < 1e-9);
    assert!(
        d2.end_to_end_pct.abs() < 1e-9,
        "first==last ⇒ 0% end-to-end"
    );
    assert!(bracket_drift(&[1.0]).is_none(), "<2 points ⇒ None");
}

#[test]
fn full_cell_bracket_voids_a_mid_excursion_that_2point_misses() {
    // FIRST == LAST (a 2-point A/A would read steady), but a MID excursion of
    // 40ms ≫ the IQR floor VOIDs under the FULL-CELL bracket.
    let mut sw = base_sweep();
    sw.baseline = samples_n(1.000, 0.002, 9);
    sw.baseline_mid = samples_n(1.040, 0.002, 9);
    sw.baseline_recheck = samples_n(1.000, 0.002, 9);
    sw.spin = linear_arm(1.0);
    sw.sleep = linear_arm(1.0);
    let pc = analyze_sweep(&sw);
    assert_eq!(pc.verdict, Verdict::Void, "mid-cell drift VOIDs the cell");
    assert!(pc.notes.iter().any(|n| n.contains("control bracket swung")));
    // CONTROL: with a STEADY mid block the same cell is a clean LEVER again.
    sw.baseline_mid = samples_n(1.000, 0.002, 9);
    let pc2 = analyze_sweep(&sw);
    assert_eq!(pc2.verdict, Verdict::Lever, "a steady bracket still levers");
}

#[test]
fn noisy_box_constants_are_the_pre_registered_values() {
    assert_eq!(OCCUPANCY_MIN, 0.90);
    assert_eq!(REJECT_VOID_FRAC, 0.50);
    assert_eq!(DRIFT_VOID_K, 2.0);
    assert_eq!(DRIFT_VOID_PCT, 3.0);
    assert_eq!(N_RAW, 15);
    assert_eq!(N_RAW_ESCALATED, 21);
    assert_eq!(ESCALATE_REJECT_FRAC, 0.33);
    assert_eq!(PROCS_RUNNING_SLACK, 1);
}
