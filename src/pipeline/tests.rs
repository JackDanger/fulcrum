//! THE ALL-RUST END-TO-END pipeline self-test.
//!
//! A faithful port of `decide/fulcrum/selftests/test_pipeline.py`: the known-good
//! measurement banks a CERTIFIED Finding with a cell_id; each of the six known-bad
//! inputs is refused at the CORRECT named gate, with the resolving measurement.
//! No subprocess, no Python — every gate runs in-process over the unified cell.

use super::*;
use crate::comparability::{ArmPresence, Capture, GateClaim};
use crate::compare::ThreadCell;
use crate::finding::{SrcChange, SrcChangeOracle, Store, Threads};
use crate::perturb::Sweep;
use crate::provenance::{ArmSink, OracleProbe, Provenance};
use crate::quantity;
use std::collections::BTreeMap;

const SELF_MS: f64 = 100.0;
const SELF_S: f64 = SELF_MS / 1000.0;

// ── deterministic sample/arm builders (mirror perturb/tests.rs) ──────────────

fn samples(minval: f64) -> Vec<f64> {
    (0..9).map(|i| minval + 0.002 * i as f64 / 8.0).collect()
}

fn linear_arm(crit: f64) -> BTreeMap<u32, Vec<f64>> {
    let mut out = BTreeMap::new();
    for pct in [10u32, 20, 30] {
        let inj = (pct as f64 / 100.0) * SELF_S;
        out.insert(pct, samples(1.000 + crit * inj));
    }
    out
}

/// A sweep that reproduces a KNOWN LEVER (busy AND sleep dose-respond at crit≈1).
fn lever_sweep() -> Sweep {
    Sweep {
        region: Some("ParallelSM/per-chunk-serialization".to_string()),
        perturb_cmd: Some("oracle.sh --region R sweep".to_string()),
        cell_id: Some("perturb_test".to_string()),
        region_self_ms: SELF_MS,
        sha_ok: Some("1".to_string()),
        baseline: samples(1.000),
        baseline_recheck: samples(1.0001),
        spin: linear_arm(1.0),
        sleep: linear_arm(1.0),
        oracle_removed: Some(samples(0.900)),
    }
}

/// A sweep that reads ARTIFACT (busy responds, sleep flat — turbo-depression, not
/// causation).
fn artifact_sweep() -> Sweep {
    let mut sw = lever_sweep();
    sw.sleep = linear_arm(0.0);
    sw.oracle_removed = None;
    sw
}

// ── provenance builders ──────────────────────────────────────────────────────

/// A clean provenance: knob consumed, oracle fired, sinks symmetric, sha current,
/// comparator present + A/A clean.
fn clean_provenance() -> Provenance {
    let mut knob = BTreeMap::new();
    knob.insert("GZIPPY_FORCE_PARALLEL_SM".to_string(), Some(2));
    let mut oracles = BTreeMap::new();
    oracles.insert(
        "window_seed".to_string(),
        OracleProbe::new("window_seed", Some(128), Some(0), Some(128)),
    );
    let mut ab = BTreeMap::new();
    ab.insert(
        "gz_vs_rg".to_string(),
        vec![
            ArmSink::new("gz", "regular-file"),
            ArmSink::new("rg", "regular-file"),
        ],
    );
    Provenance {
        commit_sha: "abc1234".into(),
        head_sha: Some("abc1234".into()),
        src_changed: Some("0".into()),
        knob_consumers: knob,
        oracles,
        ab_sinks: ab,
        comparator_sink: "regular-file".into(),
        comparator_path: "/usr/local/bin/rapidgzip".into(),
        comparator_present: Some(true),
        comparator_aa_ratio: Some(1.0),
        comparator_aa_spread_pct: Some(0.0),
    }
}

// ── comparability builders ───────────────────────────────────────────────────

fn two_arm_capture() -> Capture {
    Capture {
        cell_id: "amd-zen2/t1/silesia".into(),
        commit_sha: "abc1234".into(),
        corpus: "silesia".into(),
        arch: "amd-zen2".into(),
        threads: ThreadCell::Fixed(1),
        sink: "regular-file".into(),
        n: 9,
        inter_run_spread: 0.02,
        arms: vec![
            ArmPresence::native("gzippy-native", 300.0),
            ArmPresence::native("rapidgzip", 310.0),
        ],
        counters: vec![],
    }
}

fn one_arm_capture() -> Capture {
    let mut c = two_arm_capture();
    c.arms = vec![ArmPresence::native("gzippy-native", 300.0)];
    c
}

fn subject_claim() -> GateClaim {
    GateClaim::SubjectSpecific {
        subject: "gzippy-native".into(),
        contrast: "rapidgzip".into(),
        counter: None,
        equal_spread: 0.05,
    }
}

// ── a deterministic freshness oracle for the cite gate ───────────────────────

struct FixedOracle(SrcChange);
impl SrcChangeOracle for FixedOracle {
    fn src_changed_since(&self, _commit_sha: &str) -> SrcChange {
        self.0.clone()
    }
}

// ── input assembly ───────────────────────────────────────────────────────────

fn base_input<'a>(quantity_check: Option<QuantityCheck<'a>>) -> PipelineInput<'a> {
    PipelineInput {
        region: "ParallelSM/per-chunk-serialization".into(),
        claim: "per-chunk serialization gates the T1 wall".into(),
        commit_sha: "abc1234".into(),
        corpus: "silesia".into(),
        arch: "amd-zen2".into(),
        threads: Threads::Fixed(1),
        sink: "regular-file".into(),
        method: "oracle.sh --region R sweep".into(),
        created_utc: "2026-06-14".into(),
        provenance: clean_provenance(),
        differ: None,
        quantity_check,
        sweep: lever_sweep(),
        capture: two_arm_capture(),
        gate_claim: subject_claim(),
        law_captures: vec![],
    }
}

fn fresh_store() -> (Store, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "fulcrum_pipeline_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    (Store::default(), dir.join("findings.jsonl"))
}

// ── 1. KNOWN-GOOD → CERTIFIED, banked, citable ───────────────────────────────

#[test]
fn known_good_banks_a_certified_finding_with_cell_id() {
    let inp = base_input(None);
    let (mut store, path) = fresh_store();
    let oracle = FixedOracle(SrcChange::Fresh);
    let out = run_pipeline(&inp, &mut store, &path, &oracle);
    let res = out.expect("known-good must CERTIFY");
    assert!(
        res.cell.cell_id.starts_with("F-") && res.cell.cell_id.len() == 14,
        "minted cell_id: {}",
        res.cell.cell_id
    );
    // it is actually in the store and on disk.
    assert!(store.get(&res.cell.cell_id).is_some());
    let disk = std::fs::read_to_string(&path).unwrap();
    assert!(disk.contains(&res.cell.cell_id));
    // it survived gate 5 as a STRONG citation.
    assert!(res.comparability_verdict.contains("ADMITTED"));
    assert!(res.bank_note.contains("STRONG"));
}

// ── 2. file-sink → PROVENANCE / DERIVED-SINK-SYMMETRIC ────────────────────────

#[test]
fn file_sink_asymmetry_refuses_at_provenance_sink() {
    let mut inp = base_input(None);
    inp.provenance.ab_sinks.insert(
        "gz_vs_rg".into(),
        vec![
            ArmSink::new("gz", "/dev/null"),
            ArmSink::new("rg", "regular-file"),
        ],
    );
    let (mut store, path) = fresh_store();
    let r = run_pipeline(&inp, &mut store, &path, &FixedOracle(SrcChange::Fresh)).unwrap_err();
    assert_eq!(r.gate, G_PROVENANCE);
    assert_eq!(r.sub_check, "DERIVED-SINK-SYMMETRIC");
    assert!(r.resolving_measurement.contains("regular-file"));
}

// ── 3. inert-oracle → PROVENANCE / DERIVED-ORACLE-FIRED ───────────────────────

#[test]
fn inert_oracle_refuses_at_provenance_oracle_fired() {
    let mut inp = base_input(None);
    inp.provenance.oracles.insert(
        "window_seed".into(),
        OracleProbe::new("window_seed", Some(0), Some(0), Some(128)),
    );
    let (mut store, path) = fresh_store();
    let r = run_pipeline(&inp, &mut store, &path, &FixedOracle(SrcChange::Fresh)).unwrap_err();
    assert_eq!(r.gate, G_PROVENANCE);
    assert_eq!(r.sub_check, "DERIVED-ORACLE-FIRED");
}

// ── 4. share × wall asserted as bytes → DIMENSIONED-QUANTITY / DIMENSION-REFUSED

#[test]
fn share_times_wall_as_bytes_refuses_at_quantity_dimension() {
    let check: QuantityCheck = Box::new(|| {
        let share = quantity::measured(0.31, "share", "cell").unwrap();
        let wall = quantity::measured(1.0, "wall_seconds", "cell").unwrap();
        let product = quantity::mul(&share, &wall).unwrap(); // dim = wall_seconds
        quantity::require_dim(&product, "bytes")?; // DIMENSION-REFUSED
        Ok(())
    });
    let inp = base_input(Some(check));
    let (mut store, path) = fresh_store();
    let r = run_pipeline(&inp, &mut store, &path, &FixedOracle(SrcChange::Fresh)).unwrap_err();
    assert_eq!(r.gate, G_QUANTITY);
    assert_eq!(r.sub_check, "DIMENSION-REFUSED");
}

// ── 5. attribution-only sweep → PERTURBATION (ARTIFACT, not a lever) ──────────

#[test]
fn attribution_only_refuses_at_perturbation() {
    let mut inp = base_input(None);
    inp.sweep = artifact_sweep();
    let (mut store, path) = fresh_store();
    let r = run_pipeline(&inp, &mut store, &path, &FixedOracle(SrcChange::Fresh)).unwrap_err();
    assert_eq!(r.gate, G_PERTURBATION);
    // the verdict token is ARTIFACT (busy responds, sleep flat).
    assert_eq!(r.sub_check, "ARTIFACT");
}

// ── 6. one-build capture → COMPARABILITY / ONE-ARM-INCONCLUSIVE ───────────────

#[test]
fn one_build_refuses_at_comparability_one_arm() {
    let mut inp = base_input(None);
    inp.capture = one_arm_capture();
    let (mut store, path) = fresh_store();
    let r = run_pipeline(&inp, &mut store, &path, &FixedOracle(SrcChange::Fresh)).unwrap_err();
    assert_eq!(r.gate, G_COMPARABILITY);
    assert_eq!(r.sub_check, "ONE-ARM-INCONCLUSIVE");
}

// ── 7. stale src → FINDING-STORE / STALE ──────────────────────────────────────

#[test]
fn stale_src_refuses_at_finding_store_stale() {
    let inp = base_input(None);
    let (mut store, path) = fresh_store();
    // gates 1–4 pass; the cite oracle reports the src moved since the commit.
    let r = run_pipeline(&inp, &mut store, &path, &FixedOracle(SrcChange::Stale)).unwrap_err();
    assert_eq!(r.gate, G_FINDING);
    assert_eq!(r.sub_check, "STALE");
}

// ── refusals always name a resolving measurement ─────────────────────────────

#[test]
fn every_refusal_names_a_resolving_measurement() {
    let cases: Vec<PipelineInput> = {
        let mut v = Vec::new();
        // sink
        let mut a = base_input(None);
        a.provenance.ab_sinks.insert(
            "gz_vs_rg".into(),
            vec![
                ArmSink::new("gz", "/dev/null"),
                ArmSink::new("rg", "regular-file"),
            ],
        );
        v.push(a);
        // one-arm
        let mut b = base_input(None);
        b.capture = one_arm_capture();
        v.push(b);
        v
    };
    for inp in &cases {
        let (mut store, path) = fresh_store();
        let r = run_pipeline(inp, &mut store, &path, &FixedOracle(SrcChange::Fresh)).unwrap_err();
        assert!(
            !r.resolving_measurement.is_empty(),
            "gate {} gave no resolve",
            r.gate
        );
        assert!(r.render().contains("resolve:"));
    }
}

// ── the runner → artifacts → in-process pipeline seam (no subprocess) ────────

#[test]
fn run_artifacts_flow_through_the_pipeline_and_bank() {
    use crate::runner::{self, Mode, RunSpec};
    // a fixture spec whose perturb arm reproduces a lever (spin=sleep crit 1.0).
    let spec_json = r#"{
      "runid":"e2e","arch":"amd","feature":"gzippy-native",
      "gzippy_bin":"/box/gzippy","comparator_bin":"/box/rg","comparator_path":"/box/rg",
      "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
      "threads":[4],"n":9,"knob_n":9,
      "knobs":[{"name":"dist_amort","env":"GZIPPY_DIST_AMORT=0","pred":"none"}],
      "oracles":[{"name":"seed_windows","expected":14}],
      "perturbations":[{"region":"ParallelSM/per-chunk","region_self_ms":500.0,
                        "perturb_cmd":"oracle.sh per-chunk","cell":"silesia:4"}],
      "host":{"cpu_model":"EPYC","kernel":"6.1","id":"abc123"},
      "fixture":{
        "commit_sha":"deadbeefcafe","head_sha":"deadbeefcafe","src_changed":"0",
        "bin_sha":"feed","rg_version":"rapidgzip 0.16.0",
        "knob_consumers":{"GZIPPY_DIST_AMORT":2},
        "oracle_counters":{"seed_windows":{"on":14,"off":0}},
        "comparator_present":true,"comparator_aa_ratio":1.0,"comparator_aa_spread_pct":1.0,
        "corpus_sha":{"silesia":"abc"},"corpus_raw_bytes":{"silesia":211000000.0},
        "cells":{
          "silesia:4":{"gz_wall_ms":120.0,"rg_wall_ms":110.0,"spread_pct":0.4,
                       "decoded_bytes":211000000.0,"output_bytes":211000000.0,
                       "marker_count_gz":1000.0,"marker_count_rg":1000.0,
                       "verbose":"WORKER_DECODED_BYTES=211000000 output_bytes=211000000"}
        },
        "knobs":{"dist_amort":{"base_ms":300.0,"knob_ms":305.0,"sha_ok":"1"}},
        "perturb":{"ParallelSM/per-chunk":{"baseline_ms":1000.0,"spin_crit":1.0,
                   "sleep_crit":1.0,"oracle_removed_ms":900.0,"spread_ms":2.0}}
      }
    }"#;
    let spec: RunSpec = serde_json::from_str(spec_json).expect("spec");
    let (mut store, store_path) = fresh_store();
    let out = std::env::temp_dir().join(format!("fulcrum_e2e_{}", std::process::id()));
    let run_dir = runner::run(&spec, &out, Mode::Fixture).expect("runner emit");

    let results = run_from_artifacts(
        &run_dir,
        &mut store,
        &store_path,
        &FixedOracle(SrcChange::Fresh),
    )
    .expect("artifact bridge");
    assert!(!results.is_empty(), "at least one cell flowed");
    let (label, outcome) = &results[0];
    let res = outcome
        .as_ref()
        .unwrap_or_else(|r| panic!("cell {label} refused: {}", r.render()));
    assert!(res.cell.cell_id.starts_with("F-"));
    // and it actually banked into the store on disk.
    assert!(std::fs::read_to_string(&store_path)
        .unwrap()
        .contains(&res.cell.cell_id));
}

// ── the gate order is fixed and the tokens are stable ─────────────────────────

#[test]
fn gate_order_is_the_five_named_gates() {
    assert_eq!(
        GATE_ORDER,
        [
            G_PROVENANCE,
            G_QUANTITY,
            G_PERTURBATION,
            G_COMPARABILITY,
            G_FINDING
        ]
    );
}
