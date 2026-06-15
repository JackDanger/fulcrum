//! CI self-tests for the CLI `fulcrum run … --gate` freshness-oracle selection
//! (the dry-run fixture-oracle gap, HARDENING-BACKLOG #6).
//!
//! Before the fix the gated CLI path hardcoded a live `GitSrcOracle`, so a
//! `--dry-run` over a SYNTHETIC/fixture commit could never certify — the freshness
//! gate refused with `UNKNOWN(commit … not in repo)`. The fix adds an EXPLICIT
//! `--fixture-oracle` flag that routes the gated pipeline through a `FixedOracle`
//! (always FRESH); it is REFUSED with `--live` so it can never silently certify a
//! real finding as fresh.
//!
//! These lock both halves:
//!   * dry-run + `--fixture-oracle` BANKS a CERTIFIED cell (red before the flag
//!     existed — `unknown flag`; green after).
//!   * the fixture oracle does NOT leak: a `--gate` run WITHOUT the flag keeps the
//!     real `GitSrcOracle` and STILL refuses a non-repo (synthetic) commit at the
//!     freshness gate; and `--fixture-oracle --live` is refused outright.

use std::path::PathBuf;
use std::process::Command;

/// A fixture spec whose perturb arm reproduces a lever (spin==sleep crit 1.0) and
/// whose `fixture` block carries a SYNTHETIC commit (`deadbeefcafe`) that is not in
/// any git repo — the exact case the live `GitSrcOracle` cannot validate.
const SMOKE_SPEC: &str = r#"{
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

/// A per-test scratch dir under the temp root (unique by test name + pid + nanos).
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!(
        "fulcrum_dryrun_{tag}_{}_{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_spec(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("spec.json");
    std::fs::write(&p, SMOKE_SPEC).unwrap();
    p
}

/// dry-run + `--fixture-oracle` + `--gate` BANKS a CERTIFIED cell with a cell_id.
#[test]
fn dry_run_fixture_oracle_banks_certified_cell() {
    let bin = env!("CARGO_BIN_EXE_fulcrum");
    let dir = scratch("certify");
    let spec = write_spec(&dir);
    let store = dir.join("store.jsonl");
    let out = dir.join("art");

    let res = Command::new(bin)
        .args([
            "run",
            spec.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--dry-run",
            "--gate",
            "--fixture-oracle",
        ])
        .output()
        .expect("run fulcrum");

    let so = String::from_utf8_lossy(&res.stdout);
    assert!(res.status.success(), "exit nonzero; stdout:\n{so}");
    assert!(
        so.contains("PIPELINE CERTIFIED"),
        "fixture-oracle dry-run must CERTIFY; stdout:\n{so}"
    );
    assert!(
        so.contains("1/1 cell(s) CERTIFIED"),
        "exactly one cell must certify; stdout:\n{so}"
    );
    // a banked cell carries an F- cell_id, and it lands on disk in the store.
    assert!(
        so.contains("banked F-"),
        "a CERTIFIED cell must report its F- cell_id; stdout:\n{so}"
    );
    let banked = std::fs::read_to_string(&store).expect("store written");
    assert!(
        banked.contains("\"cell_id\":\"F-") || banked.contains("F-"),
        "the certified cell must be banked into the store; store:\n{banked}"
    );
}

/// GUARD: the fixture oracle must NOT leak. A `--gate` run WITHOUT
/// `--fixture-oracle` keeps the real `GitSrcOracle` — the SAME source-of-truth a
/// live run uses — so a non-repo (synthetic) commit STILL refuses at the freshness
/// gate (STALE/UNKNOWN), banking nothing.
#[test]
fn gate_without_fixture_oracle_refuses_synthetic_commit() {
    let bin = env!("CARGO_BIN_EXE_fulcrum");
    let dir = scratch("strict");
    let spec = write_spec(&dir);
    let store = dir.join("store.jsonl");
    let out = dir.join("art");

    let res = Command::new(bin)
        .args([
            "run",
            spec.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--dry-run",
            "--gate",
            // NOTE: no --fixture-oracle ⇒ real GitSrcOracle (the live oracle).
        ])
        .output()
        .expect("run fulcrum");

    let so = String::from_utf8_lossy(&res.stdout);
    let se = String::from_utf8_lossy(&res.stderr);
    assert!(
        se.contains("LIVE GitSrcOracle"),
        "without the flag the LIVE oracle must be selected; stderr:\n{se}"
    );
    assert!(
        so.contains("STALE") && so.contains("not in repo"),
        "the live oracle must REFUSE a non-repo commit at the freshness gate; stdout:\n{so}"
    );
    assert!(
        so.contains("0/1 cell(s) CERTIFIED"),
        "nothing may be certified through the live oracle for a synthetic commit; stdout:\n{so}"
    );
}

/// GUARD: `--fixture-oracle --live` is refused outright (exit 2) before any work,
/// so the fixture oracle can never be applied to a real run.
#[test]
fn fixture_oracle_with_live_is_refused() {
    let bin = env!("CARGO_BIN_EXE_fulcrum");
    let dir = scratch("liveguard");
    let spec = write_spec(&dir);

    let res = Command::new(bin)
        .args([
            "run",
            spec.to_str().unwrap(),
            "--live",
            "--gate",
            "--fixture-oracle",
        ])
        .output()
        .expect("run fulcrum");

    assert_eq!(
        res.status.code(),
        Some(2),
        "--fixture-oracle --live must exit 2; stderr:\n{}",
        String::from_utf8_lossy(&res.stderr)
    );
    let se = String::from_utf8_lossy(&res.stderr);
    assert!(
        se.contains("REFUSED") && se.contains("cannot combine with --live"),
        "the refusal must name the contradictory combo; stderr:\n{se}"
    );
}
