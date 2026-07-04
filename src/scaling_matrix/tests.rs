//! Box-independent unit tests for the PURE logic of `fulcrum scaling --box`:
//! arg parsing, median/spread math, the Gate-0 predicates, and the
//! WIN/TIE/LOSS + goal classification. The measurement orchestration (`run`)
//! needs real binaries + a box and is reconnect-validated, not tested here.

use super::*;

// ── parse_threads ──────────────────────────────────────────────────────────

#[test]
fn parse_threads_ascending_unique() {
    assert_eq!(parse_threads("1,2,4,8").unwrap(), vec![1, 2, 4, 8]);
    // dedup + sort
    assert_eq!(parse_threads("8,2,2,1").unwrap(), vec![1, 2, 8]);
    // whitespace tolerated
    assert_eq!(parse_threads(" 1 , 3 ").unwrap(), vec![1, 3]);
}

#[test]
fn parse_threads_rejects_zero_and_garbage() {
    assert!(parse_threads("0,1").is_err());
    assert!(parse_threads("1,x").is_err());
    assert!(parse_threads("").is_err());
    assert!(parse_threads(",,").is_err());
}

// ── render_tmpl ─────────────────────────────────────────────────────────────

#[test]
fn render_tmpl_substitutes_thread_count() {
    assert_eq!(render_tmpl("-d -c -p{T}", 4), vec!["-d", "-c", "-p4"]);
    assert_eq!(render_tmpl("-d -c -P {T}", 16), vec!["-d", "-c", "-P", "16"]);
    // no placeholder → verbatim
    assert_eq!(render_tmpl("-d -c", 2), vec!["-d", "-c"]);
}

// ── median / percentile / rel_spread ────────────────────────────────────────

#[test]
fn median_odd_and_even() {
    assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
    assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), 2.5);
    assert_eq!(median(&[]), 0.0);
    // unsorted input is handled (internal sort)
    assert_eq!(median(&[10.0, 1.0, 5.0, 2.0, 8.0]), 5.0);
}

#[test]
fn percentile_interpolates() {
    let s = vec![0.0, 10.0, 20.0, 30.0, 40.0];
    assert_eq!(percentile(&s, 0.0), 0.0);
    assert_eq!(percentile(&s, 1.0), 40.0);
    assert_eq!(percentile(&s, 0.5), 20.0);
    assert_eq!(percentile(&s, 0.25), 10.0);
    assert_eq!(percentile(&s, 0.75), 30.0);
}

#[test]
fn rel_spread_zero_for_constant_sample() {
    assert_eq!(rel_spread(&[5.0, 5.0, 5.0, 5.0, 5.0]), 0.0);
    // IQR/median for a symmetric spread: q3-q1 = 30-10 = 20, median 20 → 1.0
    assert!((rel_spread(&[0.0, 10.0, 20.0, 30.0, 40.0]) - 1.0).abs() < 1e-9);
}

// ── classify: WIN / TIE / LOSS vs spread ────────────────────────────────────

#[test]
fn classify_win_when_faster_and_significant() {
    // gz 80, rg 100 → ratio 0.8, Δ 0.20; spread 0.05 → WIN
    assert_eq!(classify(80.0, 100.0, 0.05), Verdict::Win);
}

#[test]
fn classify_loss_when_slower_and_significant() {
    // gz 130, rg 100 → ratio 1.3, Δ 0.30; spread 0.05 → LOSS
    assert_eq!(classify(130.0, 100.0, 0.05), Verdict::Loss);
}

#[test]
fn classify_tie_when_delta_within_spread() {
    // gz 103, rg 100 → Δ 0.03 <= spread 0.05 → TIE, even though gz slower
    assert_eq!(classify(103.0, 100.0, 0.05), Verdict::Tie);
    // gz 97, rg 100 → Δ 0.03 <= spread 0.05 → TIE, even though gz faster
    assert_eq!(classify(97.0, 100.0, 0.05), Verdict::Tie);
    // just inside the band (Δ 0.04 < spread 0.05) → TIE (Δ must EXCEED spread
    // for a verdict; the exact Δ==spread edge is left to float semantics).
    assert_eq!(classify(96.0, 100.0, 0.05), Verdict::Tie);
}

#[test]
fn classify_tie_on_degenerate_input() {
    assert_eq!(classify(0.0, 100.0, 0.05), Verdict::Tie);
    assert_eq!(classify(100.0, 0.0, 0.05), Verdict::Tie);
}

// ── Gate-0(a): comparator self-1.0 detection ────────────────────────────────

#[test]
fn self_consistent_accepts_near_unity() {
    // rg 100 vs rgAA 101 → ratio 0.990, within a 5% spread
    assert!(self_consistent(100.0, 101.0, 0.05));
}

#[test]
fn self_consistent_rejects_drifted_comparator() {
    // rg 100 vs rgAA 120 → ratio 0.833, drift 0.167 > spread 0.03 (and > floor)
    assert!(!self_consistent(100.0, 120.0, 0.03));
}

#[test]
fn self_consistent_has_tolerance_floor() {
    // Tiny measured spread must not fail a 1% jitter (floor 0.02 kicks in).
    assert!(self_consistent(100.0, 101.0, 0.0));
    // But a 5% drift still fails against the floor.
    assert!(!self_consistent(100.0, 105.0, 0.0));
}

// ── Gate-0(b): sha == oracle ────────────────────────────────────────────────

#[test]
fn check_sha_accepts_matching_both() {
    assert!(check_sha("ABCD", "abcd", "abcd").is_ok());
}

#[test]
fn check_sha_rejects_mismatch() {
    // gz differs
    assert!(check_sha("dead", "abcd", "abcd").is_err());
    // rg differs
    assert!(check_sha("abcd", "beef", "abcd").is_err());
    // empty oracle
    assert!(check_sha("abcd", "abcd", "").is_err());
}

// ── Gate-0(c): sink-law ─────────────────────────────────────────────────────

#[test]
fn check_sink_requires_matching_devnull() {
    assert!(check_sink("/dev/null", "/dev/null").is_ok());
    // mismatched sinks
    assert!(check_sink("/dev/null", "out.bin").is_err());
    // matching but a FILE sink (penalizes faster arm)
    assert!(check_sink("out.bin", "out.bin").is_err());
}

// ── Gate-0(d): path assertion ───────────────────────────────────────────────

#[test]
fn check_path_requires_parallelsm() {
    assert!(check_path("... path=ParallelSM ...").is_ok());
    assert!(check_path("path=LibdeflateSingle").is_err());
    assert!(check_path("").is_err());
}

// ── goal_status ─────────────────────────────────────────────────────────────

#[test]
fn goal_status_all_win_is_strict() {
    let (met, strict) = goal_status(&[Verdict::Win, Verdict::Win, Verdict::Win]);
    assert!(met);
    assert!(strict);
}

#[test]
fn goal_status_win_or_tie_meets_but_not_strict() {
    let (met, strict) = goal_status(&[Verdict::Win, Verdict::Tie, Verdict::Win]);
    assert!(met);
    assert!(!strict);
}

#[test]
fn goal_status_any_loss_fails() {
    let (met, strict) = goal_status(&[Verdict::Win, Verdict::Loss, Verdict::Win]);
    assert!(!met);
    assert!(!strict);
    let (met2, _) = goal_status(&[Verdict::Tie, Verdict::Loss]);
    assert!(!met2);
}

#[test]
fn goal_status_empty_is_not_met() {
    let (met, strict) = goal_status(&[]);
    assert!(!met);
    assert!(!strict);
}

// ── combined_spread ─────────────────────────────────────────────────────────

#[test]
fn combined_spread_sums_tool_spreads() {
    // gz constant (spread 0), rg IQR/median = 1.0 → combined 1.0
    let cs = combined_spread(&[5.0, 5.0, 5.0], &[0.0, 10.0, 20.0, 30.0, 40.0]);
    assert!((cs - 1.0).abs() < 1e-9);
}

// ── parse_args ──────────────────────────────────────────────────────────────

fn sv(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

#[test]
fn parse_args_minimal_ok() {
    let a = sv(&[
        "--box", "trainer", "--gz", "/b/gz", "--rg", "/b/rg", "--corpus", "/c/silesia.gz",
        "--oracle-sha", "deadbeef",
    ]);
    let cfg = parse_args(&a).unwrap();
    assert_eq!(cfg.box_host, "trainer");
    assert_eq!(cfg.gz_bin, "/b/gz");
    assert_eq!(cfg.rg_bin, "/b/rg");
    assert_eq!(cfg.corpus, "/c/silesia.gz");
    assert_eq!(cfg.oracle_sha, "deadbeef");
    // defaults
    assert_eq!(cfg.n, 15);
    assert_eq!(cfg.threads, vec![1, 2, 3, 4, 5, 6, 7, 8, 12, 16]);
    assert_eq!(cfg.gz_tmpl, "-d -c -p{T}");
    assert_eq!(cfg.rg_tmpl, "-d -c -P {T}");
    assert_eq!(cfg.gz_env, vec![("GZIPPY_FORCE_PARALLEL_SM".to_string(), "1".to_string())]);
}

#[test]
fn parse_args_overrides() {
    let a = sv(&[
        "--box", "solvency", "--gz", "g", "--rg", "r", "--corpus", "c", "--oracle-sha", "sha",
        "--threads", "1,2,4", "--n", "21", "--gz-tmpl", "-d -c -p {T}", "--rg-tmpl", "-d -o /dev/null -P {T}",
        "--gz-env", "GZIPPY_FORCE_PARALLEL_SM=1 GZIPPY_X=2", "--out", "/tmp/out.json",
    ]);
    let cfg = parse_args(&a).unwrap();
    assert_eq!(cfg.threads, vec![1, 2, 4]);
    assert_eq!(cfg.n, 21);
    assert_eq!(cfg.gz_tmpl, "-d -c -p {T}");
    assert_eq!(cfg.rg_tmpl, "-d -o /dev/null -P {T}");
    assert_eq!(cfg.gz_env.len(), 2);
    assert_eq!(cfg.out.as_deref(), Some("/tmp/out.json"));
}

#[test]
fn parse_args_requires_all_mandatory() {
    // missing --box
    assert!(parse_args(&sv(&["--gz", "g", "--rg", "r", "--corpus", "c", "--oracle-sha", "s"])).is_err());
    // missing --oracle-sha
    assert!(parse_args(&sv(&["--box", "b", "--gz", "g", "--rg", "r", "--corpus", "c"])).is_err());
    // unknown arg
    assert!(parse_args(&sv(&["--box", "b", "--gz", "g", "--rg", "r", "--corpus", "c", "--oracle-sha", "s", "--bogus"])).is_err());
    // help sentinel
    assert_eq!(parse_args(&sv(&["--help"])).unwrap_err(), "HELP");
}

#[test]
fn parse_args_n_zero_rejected() {
    let a = sv(&["--box", "b", "--gz", "g", "--rg", "r", "--corpus", "c", "--oracle-sha", "s", "--n", "0"]);
    assert!(parse_args(&a).is_err());
}

// ── LOAD-IMMUNITY CERTIFICATE: cell_status / certified_ratio ────────────────

#[test]
fn self_within_spread_certifies_cell_and_emits_ratio() {
    // rg 100 vs rgAA 101 under load → self-1.0 = 0.990 within 5% spread → CERTIFIED.
    let ok = self_consistent(100.0, 101.0, 0.05);
    assert!(ok);
    let status = cell_status(ok);
    assert_eq!(status, CellStatus::Certified);
    assert!(status.is_certified());
    // A certified cell EMITS its gz/rg ratio.
    assert_eq!(certified_ratio(status, 0.83), Some(0.83));
}

#[test]
fn self_outside_spread_voids_cell_and_suppresses_ratio() {
    // rg 100 vs rgAA 130 → self-1.0 = 0.769, drift 0.23 > spread 0.03 → VOID.
    let ok = self_consistent(100.0, 130.0, 0.03);
    assert!(!ok);
    let status = cell_status(ok);
    assert_eq!(status, CellStatus::Void);
    assert!(!status.is_certified());
    assert_eq!(status.label(), "VOID(load-noise)");
    // A VOID cell emits NO ratio (needs re-measure).
    assert_eq!(certified_ratio(status, 0.83), None);
}

// ── verdict summary: certified vs void counts ───────────────────────────────

#[test]
fn count_status_tallies_certified_and_void() {
    let statuses = [
        CellStatus::Certified,
        CellStatus::Void,
        CellStatus::Certified,
        CellStatus::Certified,
        CellStatus::Void,
    ];
    assert_eq!(count_status(&statuses), (3, 2));
    // all certified
    assert_eq!(count_status(&[CellStatus::Certified, CellStatus::Certified]), (2, 0));
    // all void
    assert_eq!(count_status(&[CellStatus::Void]), (0, 1));
    // empty
    assert_eq!(count_status(&[]), (0, 0));
}

#[test]
fn goal_computed_over_certified_cells_only() {
    // A matrix where the ONLY loss is on a VOID cell must NOT fail the goal —
    // void cells emit no verdict, so they are excluded from goal_status.
    let cells = [
        (Verdict::Win, CellStatus::Certified),
        (Verdict::Loss, CellStatus::Void), // load-noise loss — excluded
        (Verdict::Tie, CellStatus::Certified),
    ];
    let certified: Vec<Verdict> = cells
        .iter()
        .filter(|(_, s)| s.is_certified())
        .map(|(v, _)| *v)
        .collect();
    let (met, strict) = goal_status(&certified);
    assert!(met, "a LOSS on a VOID cell must not sink the goal");
    assert!(!strict);
    // But a certified LOSS DOES fail the goal.
    let with_cert_loss = [Verdict::Win, Verdict::Loss];
    let (met2, _) = goal_status(&with_cert_loss);
    assert!(!met2);
    // And if NOTHING is certified, the goal is not met (empty ⇒ false).
    let (met3, _) = goal_status(&[]);
    assert!(!met3);
}

// ── load-state capture: parse_load_1min (Linux + macOS formats) ─────────────

#[test]
fn parse_load_1min_linux_proc_loadavg() {
    // /proc/loadavg: "0.52 0.48 0.44 1/234 5678"
    assert_eq!(parse_load_1min("0.52 0.48 0.44 1/234 5678"), Some(0.52));
    assert_eq!(parse_load_1min("  12.34 5.6 7.8 2/99 1"), Some(12.34));
}

#[test]
fn parse_load_1min_macos_sysctl() {
    // sysctl -n vm.loadavg: "{ 4.74 4.15 4.06 }"
    assert_eq!(parse_load_1min("{ 4.74 4.15 4.06 }"), Some(4.74));
    assert_eq!(parse_load_1min("{ 0.00 0.01 0.05 }"), Some(0.0));
}

#[test]
fn parse_load_1min_rejects_garbage() {
    assert_eq!(parse_load_1min(""), None);
    assert_eq!(parse_load_1min("   "), None);
    assert_eq!(parse_load_1min("{ }"), None);
    assert_eq!(parse_load_1min("unknown"), None);
}

// ── --retry arg parsing ─────────────────────────────────────────────────────

#[test]
fn parse_args_retry_default_and_override() {
    let base = sv(&[
        "--box", "b", "--gz", "g", "--rg", "r", "--corpus", "c", "--oracle-sha", "s",
    ]);
    assert_eq!(parse_args(&base).unwrap().retry, 2); // default
    let mut a = base.clone();
    a.extend(sv(&["--retry", "5"]));
    assert_eq!(parse_args(&a).unwrap().retry, 5);
    // retry 0 is legal (no auto-retry).
    let mut a0 = base.clone();
    a0.extend(sv(&["--retry", "0"]));
    assert_eq!(parse_args(&a0).unwrap().retry, 0);
    // non-numeric rejected.
    let mut bad = base.clone();
    bad.extend(sv(&["--retry", "x"]));
    assert!(parse_args(&bad).is_err());
}

// ── end-to-end classification of a synthetic matrix ─────────────────────────

#[test]
fn synthetic_matrix_goal_logic() {
    // Build cells like a real run: gz wins low T, loses high T (the campaign's
    // known shape), verify goal_status catches the LOSS.
    let make = |gz: &[f64], rg: &[f64]| -> Verdict {
        classify(median(gz), median(rg), combined_spread(gz, rg))
    };
    // T1: gz clearly faster
    let v1 = make(&[80.0, 81.0, 82.0], &[100.0, 101.0, 99.0]);
    // T16: gz clearly slower (the loss the whole campaign chases)
    let v16 = make(&[176.0, 175.0, 177.0], &[100.0, 101.0, 99.0]);
    assert_eq!(v1, Verdict::Win);
    assert_eq!(v16, Verdict::Loss);
    let (met, strict) = goal_status(&[v1, v16]);
    assert!(!met, "a LOSS at any T must fail the goal");
    assert!(!strict);
}
