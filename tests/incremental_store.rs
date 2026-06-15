//! CI self-tests for the INCREMENTAL store + per-cell progress (HARDENING-BACKLOG
//! "incremental store / streaming output").
//!
//! Before this fix `fulcrum run … --gate` measured EVERY cell, then emitted the
//! gate results + banked the store in ONE batch at the very end — so the log was
//! empty mid-run (unmonitorable) and a driver that died before the end lost ALL
//! completed cells (this exhausted three baseline agents). The fix banks each
//! CERTIFIED cell to the store JSONL IMMEDIATELY as it is produced (before the
//! next cell is measured) and emits one progress line per completed cell.
//!
//! These lock the contract WITHOUT a live box (fixture mode + the fixture
//! freshness oracle), so they run in CI:
//!   * a multi-cell run banks cell N BEFORE cell N+1 begins (the store grows
//!     incrementally on disk, not all-at-once);
//!   * a simulated mid-run ABORT after cell k leaves the k completed cells banked
//!     + readable from the store (partial progress survives);
//!   * a per-cell progress record is produced for each cell with verdict + cell_id;
//!   * a RESUME re-run SKIPS already-CERTIFIED in-scope cells (idempotent).

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use fulcrum::finding::{FixedOracle, Store};
use fulcrum::runner::{self, CellProgress, CellReporter, Mode, RunSpec};

/// A fixture spec with THREE distinct cells (silesia at T1, T4, T8) and a
/// perturbation lever (spin==sleep crit 1.0) so every cell CERTIFIES through the
/// fixture freshness oracle. Each (corpus, T) is a distinct CELL → a distinct
/// banked finding, so the store grows by one per cell.
fn three_cell_spec() -> RunSpec {
    let json = r#"{
      "runid":"inc","arch":"amd","feature":"gzippy-native",
      "gzippy_bin":"/box/gzippy","comparator_bin":"/box/rg","comparator_path":"/box/rg",
      "corpora":[{"id":"silesia","path":"<BENCH_ROOT>/silesia.gz"}],
      "threads":[1,4,8],"n":9,"knob_n":9,
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
          "silesia:1":{"gz_wall_ms":120.0,"rg_wall_ms":110.0,"spread_pct":0.4,
                       "decoded_bytes":211000000.0,"output_bytes":211000000.0,
                       "marker_count_gz":1000.0,"marker_count_rg":1000.0,
                       "verbose":"WORKER_DECODED_BYTES=211000000 output_bytes=211000000"},
          "silesia:4":{"gz_wall_ms":120.0,"rg_wall_ms":110.0,"spread_pct":0.4,
                       "decoded_bytes":211000000.0,"output_bytes":211000000.0,
                       "marker_count_gz":1000.0,"marker_count_rg":1000.0,
                       "verbose":"WORKER_DECODED_BYTES=211000000 output_bytes=211000000"},
          "silesia:8":{"gz_wall_ms":120.0,"rg_wall_ms":110.0,"spread_pct":0.4,
                       "decoded_bytes":211000000.0,"output_bytes":211000000.0,
                       "marker_count_gz":1000.0,"marker_count_rg":1000.0,
                       "verbose":"WORKER_DECODED_BYTES=211000000 output_bytes=211000000"}
        },
        "knobs":{"dist_amort":{"base_ms":300.0,"knob_ms":305.0,"sha_ok":"1"}},
        "perturb":{"ParallelSM/per-chunk":{"baseline_ms":1000.0,"spin_crit":1.0,
                   "sleep_crit":1.0,"oracle_removed_ms":900.0,"spread_ms":2.0}}
      }
    }"#;
    serde_json::from_str(json).expect("parse fixture spec")
}

/// A per-test scratch dir (unique by tag + pid + nanos).
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("fulcrum_inc_{tag}_{}_{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Count the non-blank JSONL lines currently on disk in the store.
fn store_lines(path: &Path) -> usize {
    match std::fs::read_to_string(path) {
        Ok(t) => t.lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
}

/// A reporter that records, after EACH cell, the store's on-disk line count and
/// the cell's progress record. Optionally ABORTS (Break) after `break_after`
/// cells have been processed.
struct RecordingReporter {
    store_path: PathBuf,
    /// store line count observed right after each cell finished.
    lines_after: Vec<usize>,
    progress: Vec<CellProgress>,
    break_after: Option<usize>,
}

impl RecordingReporter {
    fn new(store_path: &Path, break_after: Option<usize>) -> Self {
        RecordingReporter {
            store_path: store_path.to_path_buf(),
            lines_after: Vec::new(),
            progress: Vec::new(),
            break_after,
        }
    }
}

impl CellReporter for RecordingReporter {
    fn on_cell(&mut self, p: &CellProgress) -> ControlFlow<()> {
        self.lines_after.push(store_lines(&self.store_path));
        self.progress.push(p.clone());
        if let Some(k) = self.break_after {
            if self.progress.len() >= k {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }
}

/// (1) A multi-cell run banks cell N to the store BEFORE cell N+1 begins — the
/// store grows incrementally (1, 2, 3), NOT all-at-once (0, 0, 3 in a batch
/// world). The reporter reads the on-disk store right after each cell.
#[test]
fn banks_each_cell_before_the_next_begins() {
    let spec = three_cell_spec();
    let dir = scratch("incr");
    let store_path = dir.join("store.jsonl");
    let out = dir.join("art");
    let mut store = Store::load(&store_path).unwrap();
    let oracle = FixedOracle::fresh();
    let mut reporter = RecordingReporter::new(&store_path, None);

    let summary = runner::run_and_gate_incremental(
        &spec,
        &out,
        Mode::Fixture,
        false,
        &mut store,
        &store_path,
        &oracle,
        &mut reporter,
    )
    .expect("incremental run");

    assert_eq!(summary.total, 3, "three planned cells");
    assert_eq!(summary.certified, 3, "all three cells CERTIFY in fixture");
    // The store grew by exactly one per cell — proving incremental (not batched)
    // persistence. A batch world would read [0, 0, 3] here.
    assert_eq!(
        reporter.lines_after,
        vec![1, 2, 3],
        "store must grow incrementally (one banked cell per completed cell)"
    );
    assert_eq!(store_lines(&store_path), 3, "all three durably banked");
}

/// (2) A simulated mid-run ABORT after cell k leaves the k completed cells banked
/// + READABLE from the store on disk (partial progress survives a context-death).
#[test]
fn partial_progress_survives_mid_run_abort() {
    let spec = three_cell_spec();
    let dir = scratch("abort");
    let store_path = dir.join("store.jsonl");
    let out = dir.join("art");
    let mut store = Store::load(&store_path).unwrap();
    let oracle = FixedOracle::fresh();
    // Abort right after the 2nd cell is banked (simulating a driver death).
    let mut reporter = RecordingReporter::new(&store_path, Some(2));

    let summary = runner::run_and_gate_incremental(
        &spec,
        &out,
        Mode::Fixture,
        false,
        &mut store,
        &store_path,
        &oracle,
        &mut reporter,
    )
    .expect("incremental run (aborted)");

    assert!(summary.aborted, "the reporter requested an abort");
    assert_eq!(
        summary.certified, 2,
        "exactly two cells completed before abort"
    );
    // The two completed cells are durably banked AND reloadable from a FRESH
    // Store (not just the in-memory one) — partial progress survived.
    let reloaded = Store::load(&store_path).expect("reload partial store");
    assert_eq!(
        reloaded.findings.len(),
        2,
        "the two completed cells must be readable from the store after the abort"
    );
    for f in &reloaded.findings {
        f.is_citable().expect("a banked partial cell is citable");
    }
}

/// (3) A per-cell progress record is produced for every cell, carrying the
/// verdict + the banked cell_id (the monitorable per-cell line a `tail -f` sees).
#[test]
fn emits_a_progress_record_per_cell_with_verdict_and_id() {
    let spec = three_cell_spec();
    let dir = scratch("prog");
    let store_path = dir.join("store.jsonl");
    let out = dir.join("art");
    let mut store = Store::load(&store_path).unwrap();
    let oracle = FixedOracle::fresh();
    let mut reporter = RecordingReporter::new(&store_path, None);

    runner::run_and_gate_incremental(
        &spec,
        &out,
        Mode::Fixture,
        false,
        &mut store,
        &store_path,
        &oracle,
        &mut reporter,
    )
    .expect("incremental run");

    assert_eq!(reporter.progress.len(), 3, "one progress record per cell");
    for (i, p) in reporter.progress.iter().enumerate() {
        assert_eq!(p.index, i + 1, "1-based cell index");
        assert_eq!(p.total, 3);
        assert!(p.cleared, "each fixture cell certifies");
        assert!(!p.verdict.is_empty(), "the verdict is named");
        let id = p
            .cell_id
            .as_deref()
            .expect("a CERTIFIED cell has a cell_id");
        assert!(id.starts_with("F-"), "a derived cell_id, got {id:?}");
        // the greppable line carries the coordinate + verdict + id.
        let line = p.line();
        assert!(
            line.contains("FULCRUM_CELL"),
            "tail-able token; got {line:?}"
        );
        assert!(
            line.contains("CERTIFIED"),
            "verdict in the line; got {line:?}"
        );
        assert!(line.contains(id), "cell_id in the line; got {line:?}");
    }
}

/// (4) A RESUME re-run SKIPS already-CERTIFIED in-scope cells (idempotent): the
/// first run banks all three; a second run with `resume=true` measures none of
/// them again and banks no duplicates.
#[test]
fn resume_skips_already_certified_cells() {
    let spec = three_cell_spec();
    let dir = scratch("resume");
    let store_path = dir.join("store.jsonl");
    let out = dir.join("art");
    let oracle = FixedOracle::fresh();

    // First run: bank all three.
    let mut store = Store::load(&store_path).unwrap();
    let mut r1 = RecordingReporter::new(&store_path, None);
    let s1 = runner::run_and_gate_incremental(
        &spec,
        &out,
        Mode::Fixture,
        false,
        &mut store,
        &store_path,
        &oracle,
        &mut r1,
    )
    .expect("first run");
    assert_eq!(s1.certified, 3);
    assert_eq!(store_lines(&store_path), 3);

    // Second run with resume: every cell is already CERTIFIED → all skipped, no
    // new banks, no duplicates.
    let mut store2 = Store::load(&store_path).unwrap();
    let mut r2 = RecordingReporter::new(&store_path, None);
    let s2 = runner::run_and_gate_incremental(
        &spec,
        &out,
        Mode::Fixture,
        true,
        &mut store2,
        &store_path,
        &oracle,
        &mut r2,
    )
    .expect("resume run");
    assert_eq!(s2.skipped, 3, "all three cells resume-skipped");
    assert_eq!(s2.certified, 0, "nothing re-banked on resume");
    assert!(
        r2.progress.iter().all(|p| p.skipped),
        "every resume record is a skip"
    );
    assert_eq!(
        store_lines(&store_path),
        3,
        "resume bank no duplicates (store unchanged)"
    );
}
