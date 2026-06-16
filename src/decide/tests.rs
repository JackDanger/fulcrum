//! Value/token-parity port of `decide/fulcrum/selftests/test_decide.py` §7–§11
//! (the end-to-end `analyze_run` checks). The unit-level pieces it exercises
//! (§1 knob harness, §3 resolution, §4 routing guard, §5 prof parser + bank,
//! §6 effect predicates) are covered in `causal`, `stats`, and `config`
//! `adapter_tests`; this file proves `analyze_run` CONSUMES them the same way
//! the Python oracle does — same ranked table / DO-THIS-NEXT / brief tokens.

use super::*;
use crate::config::GzippyAdapter;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const GZ: [f64; 7] = [1.380, 1.382, 1.379, 1.385, 1.381, 1.383, 1.380];
const RG: [f64; 7] = [0.920, 0.922, 0.918, 0.925, 0.921, 0.919, 0.923];

const PROF_TXT: &str = concat!(
    "[contig-prof] CONTIG (Block::decode_clean_into_contig):\n",
    "  calls=1768 total_cyc=1000000 classed_cyc=900000 (90.0% of total; rest=careful+entry/exit+unchained tail)\n",
    "  lit1   : iters=      100000 cyc=        90000   10.0% of classed,    0.9 cyc/iter\n",
    "  litpack: iters=       50000 cyc=        45000    5.0% of classed,    0.9 cyc/iter, lits=120000\n",
    "  litchn : iters=      200000 cyc=       206000   22.9% of classed,    1.0 cyc/iter, lits=500000\n",
    "  backref: iters=       16140 cyc=       563400   62.6% of classed,   34.9 cyc/iter, bytes=900000 dist_long=3\n",
    "  careful: cyc=50000 (5.0% of total) outer_iters=123\n",
    "  disttbl: builds=1765 reuses=3 (P3.4 dynamic-block dist_table amortization)\n",
    "[contig-prof] WRAPPER (decode_huffman_body_resumable):\n",
    "  calls=0 total_cyc=0 classed_cyc=0 (0.0%)\n",
);

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!("{prefix}_{pid}_{nanos}_{n}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_samples(path: &Path, xs: &[f64]) {
    let body = xs
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, body).unwrap();
}

fn write_manifest(d: &Path, freeze: &str, extra: &str) {
    let body = format!(
        "runid=st\nbin=<BENCH_ROOT>/bin-test\nbin_sha=deadbeef\nfeature=gzippy-native\n\
         rg_version=rapidgzip 0.16.0\nfreeze_state={freeze}\nquiet_state=quiet\n\
         governor=performance\nno_turbo=1\nrunnable_avg=1.0\n\
         cell_done=silesia:1:mask=0:sha_ok=1\n{extra}"
    );
    std::fs::write(d.join("manifest.txt"), body).unwrap();
}

/// The canonical synthetic decide artifact dir (cell silesia:T1).
fn make_artifact(d: &Path, with_knobs: bool, freeze: &str) {
    let cdir = d.join("cell_silesia_T1");
    std::fs::create_dir_all(&cdir).unwrap();
    write_manifest(d, freeze, "");
    write_samples(&cdir.join("wall_gz.txt"), &GZ);
    write_samples(&cdir.join("wall_rg.txt"), &RG);
    std::fs::write(cdir.join("prof.txt"), PROF_TXT).unwrap();
    if !with_knobs {
        return;
    }
    // hit_drive: disabling it makes the cell FASTER by 60ms (feature COSTS).
    let kdir = cdir.join("knob_hit_drive");
    std::fs::create_dir_all(&kdir).unwrap();
    write_samples(&kdir.join("base.txt"), &GZ);
    let minus: Vec<f64> = GZ.iter().map(|x| x - 0.060).collect();
    write_samples(&kdir.join("knob.txt"), &minus);
    std::fs::write(
        kdir.join("meta.txt"),
        "knob=hit_drive\nenv=GZIPPY_NO_HIT_DRIVE=1\npred=none\ncell=silesia:1\nmask=0\nsha_ok=1\n",
    )
    .unwrap();
    // dist_amort: null.
    let k2 = cdir.join("knob_dist_amort");
    std::fs::create_dir_all(&k2).unwrap();
    write_samples(&k2.join("base.txt"), &GZ);
    write_samples(&k2.join("knob.txt"), &GZ);
    std::fs::write(
        k2.join("meta.txt"),
        "knob=dist_amort\nenv=GZIPPY_DIST_AMORT=0\npred=prof_dist\ncell=silesia:1\nmask=0\nsha_ok=1\n",
    )
    .unwrap();
    let edir = d.join("knob_effects_silesia_T1");
    std::fs::create_dir_all(&edir).unwrap();
    std::fs::write(
        edir.join("effect_base_dist_amort.txt"),
        "disttbl: builds=2790 reuses=7 \n",
    )
    .unwrap();
    std::fs::write(
        edir.join("effect_knob_dist_amort.txt"),
        "disttbl: builds=0 reuses=0 \n",
    )
    .unwrap();
}

// --- §7: end-to-end ranked table + DO-THIS-NEXT. ---------------------------
#[test]
fn e2e_ranked_table_and_do_next() {
    let ad = GzippyAdapter::new();
    let d = scratch("fulcrum_decide_st");
    make_artifact(&d, true, "acknowledged");
    let run = load_run(&d, &ad).unwrap();
    let rep = analyze_run(&run, &ad, false, None, None).unwrap();

    assert!(
        rep.rows
            .iter()
            .any(|r| r.component.contains("knob.hit_drive") && r.tier == 1),
        "hit_drive-COSTS row lands in tier 1"
    );
    assert!(
        rep.rows
            .iter()
            .any(|r| r.component.contains("knob.dist_amort")
                && r.tier == 4
                && r.status.contains("CAUSAL-NULL")),
        "dist_amort null -> tier 4 CAUSAL-NULL"
    );
    assert!(
        rep.rows[0].component.starts_with("knob.hit_drive"),
        "ranking puts the causal-COSTS row first"
    );
    assert!(
        rep.do_next.contains("knob.hit_drive"),
        "DO-THIS-NEXT picks the top CAUSAL-VERIFIED-COSTS row"
    );
    assert!(
        rep.rows.iter().any(|r| r.component == "engine.backref"),
        "engine.backref hypothesis row present from prof"
    );
    assert!(
        rep.brief.falsifier.contains("CAUSAL-NULL"),
        "decision brief present with a concrete falsifier"
    );

    // Deterministic ranking.
    let rep2 = analyze_run(&load_run(&d, &ad).unwrap(), &ad, false, None, None).unwrap();
    let c1: Vec<&str> = rep.rows.iter().map(|r| r.component.as_str()).collect();
    let c2: Vec<&str> = rep2.rows.iter().map(|r| r.component.as_str()).collect();
    assert_eq!(c1, c2, "ranked table deterministic");
}

// --- §8: UNFROZEN refusal + --allow-thaw label. ----------------------------
#[test]
fn unfrozen_refusal_and_allow_thaw() {
    let ad = GzippyAdapter::new();
    let d = scratch("fulcrum_decide_st8");
    make_artifact(&d, true, "thawed");
    let run = load_run(&d, &ad).unwrap();
    let err = analyze_run(&run, &ad, false, None, None).unwrap_err();
    match &err {
        DecideError::Instrument(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("FROZEN-OR-LABELED"),
                "UNFROZEN refusal names the scar tag: {msg}"
            );
        }
        other => panic!("expected InstrumentError, got {other:?}"),
    }
    let rep = analyze_run(&run, &ad, true, None, None).unwrap();
    assert!(
        rep.rows.iter().any(|r| r.status.contains("UNFROZEN")),
        "--allow-thaw labels every wall-derived row UNFROZEN"
    );
}

// --- §9: no causal action -> top engine hypothesis. ------------------------
#[test]
fn no_causal_action_top_engine_hypothesis() {
    let ad = GzippyAdapter::new();
    let d = scratch("fulcrum_decide_st9");
    make_artifact(&d, true, "frozen");
    // Drop the only causal (tier-1) knob.
    std::fs::remove_dir_all(d.join("cell_silesia_T1").join("knob_hit_drive")).unwrap();
    let rep = analyze_run(&load_run(&d, &ad).unwrap(), &ad, false, None, None).unwrap();
    assert!(
        rep.do_next.contains("engine.backref"),
        "no causal action -> DO-THIS-NEXT = top bounded engine HYPOTHESIS"
    );
    assert!(
        rep.brief.falsifier.contains("flat"),
        "hypothesis brief: falsifier = flat perturbation response"
    );
}

// --- §10: "reverted" knob DO-THIS-NEXT uses "reconcile" phrasing. ----------
#[test]
fn reverted_knob_reconcile() {
    let ad = GzippyAdapter::new();
    let d = scratch("fulcrum_decide_st10");
    let cdir = d.join("cell_silesia_T1");
    let kslab = cdir.join("knob_slab_alloc");
    std::fs::create_dir_all(&kslab).unwrap();
    write_manifest(&d, "frozen", "");
    write_samples(&cdir.join("wall_gz.txt"), &GZ);
    write_samples(&cdir.join("wall_rg.txt"), &RG);
    write_samples(&kslab.join("base.txt"), &GZ);
    let minus: Vec<f64> = GZ.iter().map(|x| x - 0.060).collect();
    write_samples(&kslab.join("knob.txt"), &minus);
    std::fs::write(
        kslab.join("meta.txt"),
        "knob=slab_alloc\nenv=GZIPPY_SLAB_ALLOC=1\npred=rpmalloc_stats\ncell=silesia:1\nmask=0\nsha_ok=1\n",
    )
    .unwrap();
    let edir = d.join("knob_effects_silesia_T1");
    std::fs::create_dir_all(&edir).unwrap();
    std::fs::write(
        edir.join("effect_base_slab_alloc.txt"),
        "[rpmalloc final] slab_hits=0 slab_installs=0\n",
    )
    .unwrap();
    std::fs::write(
        edir.join("effect_knob_slab_alloc.txt"),
        "[rpmalloc final] slab_hits=22 slab_installs=23\n[rpmalloc final] mapped_peak=64M\n",
    )
    .unwrap();

    let rep = analyze_run(&load_run(&d, &ad).unwrap(), &ad, false, None, None).unwrap();
    assert!(
        rep.rows
            .iter()
            .any(|r| r.component.contains("slab_alloc") && r.tier == 1),
        "slab_alloc CAUSAL-VERIFIED-COSTS lands tier 1"
    );
    assert!(
        rep.do_next.contains("reconcile"),
        "DO-THIS-NEXT for 'reverted' knob uses 'reconcile' phrasing"
    );
    assert!(
        !rep.do_next.contains("fix/condition"),
        "'fix/condition' phrasing absent for reverted knob"
    );
    assert!(
        rep.rows
            .iter()
            .filter(|r| r.component.contains("slab_alloc"))
            .any(|r| r.status.contains("slab engaged")),
        "slab-engagement effect-verified note in slab_alloc status"
    );
}

// --- §11: EFFECT-VERIFIED-OR-FLAGGED demotes a non-flipping switch. --------
#[test]
fn effect_check_failed_demotes_to_tier5() {
    let ad = GzippyAdapter::new();
    let d = scratch("fulcrum_decide_st11");
    let cdir = d.join("cell_silesia_T1");
    let ksb = cdir.join("knob_seeded_block");
    std::fs::create_dir_all(&ksb).unwrap();
    write_manifest(&d, "frozen", "");
    write_samples(&cdir.join("wall_gz.txt"), &GZ);
    write_samples(&cdir.join("wall_rg.txt"), &RG);
    write_samples(&ksb.join("base.txt"), &GZ);
    let minus: Vec<f64> = GZ.iter().map(|x| x - 0.060).collect();
    write_samples(&ksb.join("knob.txt"), &minus);
    std::fs::write(
        ksb.join("meta.txt"),
        "knob=seeded_block\nenv=GZIPPY_SEEDED_BLOCK=0\npred=verbose_seeded\ncell=silesia:1\nmask=0\nsha_ok=1\n",
    )
    .unwrap();
    let edir = d.join("knob_effects_silesia_T1");
    std::fs::create_dir_all(&edir).unwrap();
    std::fs::write(
        edir.join("effect_base_seeded_block.txt"),
        "seeded_block=16 seeded_wrapper=16 \n",
    )
    .unwrap();
    // knob arm STILL seeded_block=16 => the kill-switch did not flip.
    std::fs::write(
        edir.join("effect_knob_seeded_block.txt"),
        "seeded_block=16 seeded_wrapper=0 \n",
    )
    .unwrap();

    let rep = analyze_run(&load_run(&d, &ad).unwrap(), &ad, false, None, None).unwrap();
    let sb_rows: Vec<&Row> = rep
        .rows
        .iter()
        .filter(|r| r.component.contains("seeded_block"))
        .collect();
    assert_eq!(sb_rows.len(), 1);
    assert_eq!(sb_rows[0].tier, 5);
    assert!(
        sb_rows[0].status.contains("EFFECT-CHECK-FAILED"),
        "demoted to tier 5 EFFECT-CHECK-FAILED"
    );
    assert_eq!(
        sb_rows[0].effect_verified,
        Some(false),
        "row records effect_verified=False"
    );
}

// --- parse_manifest structures the cell_done meta. -------------------------
#[test]
fn parse_manifest_cell_meta() {
    let m = parse_manifest_text(
        "runid=x\ncell_done=silesia:1:mask=0:sha_ok=1\nknob_done=hit_drive\nbin=/b\n",
    );
    assert_eq!(m.get("runid"), Some("x"));
    assert_eq!(m.get("bin"), Some("/b"));
    assert_eq!(m.cells_done, vec!["silesia:1:mask=0:sha_ok=1"]);
    assert_eq!(m.knobs_done, vec!["hit_drive"]);
    let meta = m.cell_meta.get(&("silesia".to_string(), 1)).unwrap();
    assert_eq!(meta.get("mask").map(String::as_str), Some("0"));
    assert_eq!(meta.get("sha_ok").map(String::as_str), Some("1"));
}

// --- multi-tool comparator arms: ingest + rank vs EACH champion. ----------
// gzippy-native is the SUBJECT; libdeflate/igzip/zlibng/pigz are additional
// comparator arms beside rapidgzip. Each `wall_<tool>.txt` is loaded into the
// cell and surfaced as its own scoreboard line (ratio = tool/gz, bar 0.99x),
// with an A/A self-stability label from `aa_<tool>_{a,b}.txt`.
#[test]
fn multitool_comparator_scoreboard() {
    let ad = GzippyAdapter::new();
    let d = scratch("fulcrum_decide_multitool");
    let cdir = d.join("cell_silesia_T1");
    std::fs::create_dir_all(&cdir).unwrap();
    write_manifest(
        &d,
        "frozen",
        "libdeflate_version=libdeflate 1.19\npigz_version=pigz 2.8\n\
         sink_libdeflate_derived=regular-file\nsink_pigz_derived=regular-file\n\
         comp_present=libdeflate,pigz\n",
    );
    write_samples(&cdir.join("wall_gz.txt"), &GZ); // gz min = 1.379
    write_samples(&cdir.join("wall_rg.txt"), &RG);
    // libdeflate SLOWER than gz -> ratio = 1.50/1.379 ≈ 1.088 >= 0.99 => PASS.
    let ld = [1.500, 1.502, 1.499, 1.505, 1.501, 1.503, 1.500];
    write_samples(&cdir.join("wall_libdeflate.txt"), &ld);
    // pigz FASTER than gz -> ratio = 1.300/1.379 ≈ 0.943 < 0.99 => FAIL.
    let pg = [1.300, 1.302, 1.299, 1.305, 1.301, 1.303, 1.300];
    write_samples(&cdir.join("wall_pigz.txt"), &pg);
    // A/A self-stability for libdeflate (two interleaved arms, ~1.0).
    write_samples(&cdir.join("aa_libdeflate_a.txt"), &ld);
    write_samples(&cdir.join("aa_libdeflate_b.txt"), &ld);

    let run = load_run(&d, &ad).unwrap();
    let cell = run.cells.get(&("silesia".to_string(), 1)).unwrap();
    assert!(
        cell.comparators.contains_key("libdeflate") && cell.comparators.contains_key("pigz"),
        "comparator wall files loaded into the cell"
    );
    assert!(
        !cell.comparators.contains_key("gz") && !cell.comparators.contains_key("rg"),
        "gz/rg are NOT folded into the generic comparator map"
    );
    assert!(
        cell.comparator_aa.contains_key("libdeflate"),
        "A/A self-stability arms loaded"
    );

    let rep = analyze_run(&run, &ad, false, None, None).unwrap();
    let board = rep.scoreboard.join("\n");
    assert!(
        board.contains("libdeflate") && board.contains("PASS"),
        "libdeflate comparator line present and PASSes (gz within bar): {board}"
    );
    assert!(
        board
            .lines()
            .any(|l| l.contains("pigz") && l.contains("FAIL")),
        "pigz comparator line present and FAILs (gz misses bar): {board}"
    );
    assert!(
        board.contains("A/A"),
        "A/A self-stability label rendered on the comparator line: {board}"
    );
    // rapidgzip stays the primary scoreboard line (unchanged shape).
    assert!(
        board.contains("silesia:T1") && board.contains("ratio="),
        "primary gz-vs-rg scoreboard line intact"
    );
}

// --- canon_mask canonicalizes by MEANING, not formatting. -----------------
#[test]
fn canon_mask_parity() {
    assert_eq!(canon_mask("0-3"), "0,1,2,3");
    assert_eq!(canon_mask("3,1,2,0"), "0,1,2,3");
    assert_eq!(canon_mask("0,1-3,7"), "0,1,2,3,7");
    assert_eq!(canon_mask(""), "unknown");
    assert_eq!(canon_mask("unknown"), "unknown");
    assert_eq!(canon_mask("bogus"), "unknown");
    // Same MEANING, different formatting -> equal canonical forms.
    assert_eq!(
        canon_mask("0-15"),
        canon_mask("0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15")
    );
}
