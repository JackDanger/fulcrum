//! Unit tests for `fulcrum counterdiff` — exercise only the PURE layer (no perf,
//! no fs): parse, substitution, hygiene, CSV parse, stats, categorize, verdict.

use super::*;
use std::collections::BTreeMap;

fn s(v: &str) -> String {
    v.to_string()
}

#[test]
fn parse_minimal_ok() {
    let args = vec![
        s("--subject-bin"),
        s("/bin/gz"),
        s("--comparator-cmd"),
        s("rapidgzip -d -c -P {t}"),
        s("--corpus"),
        s("a.gz"),
    ];
    let cfg = parse_args(&args).expect("parse ok");
    assert_eq!(cfg.subject_bin, "/bin/gz");
    assert_eq!(cfg.comparators.len(), 1);
    assert_eq!(cfg.comparators[0].cmd, split_args("rapidgzip -d -c -P {t}"));
    assert_eq!(cfg.corpora, vec![s("a.gz")]);
    assert_eq!(cfg.threads, vec![1]);
    assert_eq!(cfg.n, 11);
}

#[test]
fn parse_requires_subject_comparator_corpus() {
    assert!(parse_args(&[s("--corpus"), s("a.gz")]).is_err());
    assert!(parse_args(&[s("--subject-bin"), s("/b")]).is_err());
    let no_corpus = vec![
        s("--subject-bin"),
        s("/b"),
        s("--comparator-cmd"),
        s("rg -P {t}"),
    ];
    assert!(parse_args(&no_corpus).is_err());
}

#[test]
fn parse_help_signal() {
    assert_eq!(parse_args(&[s("--help")]).unwrap_err(), "HELP");
    assert_eq!(parse_args(&[s("-h")]).unwrap_err(), "HELP");
}

#[test]
fn parse_repeatable_comparators_and_label() {
    let args = vec![
        s("--subject-bin"),
        s("/b"),
        s("--comparator-cmd"),
        s("igzip -d -c"),
        s("--comparator-cmd"),
        s("rapidgzip -d -c -P {t}"),
        s("--comparator-label"),
        s("rg-native"),
        s("--corpus"),
        s("a.gz"),
    ];
    let cfg = parse_args(&args).expect("ok");
    assert_eq!(cfg.comparators.len(), 2);
    assert_eq!(cfg.comparators[0].label, "igzip");
    assert_eq!(cfg.comparators[1].label, "rg-native");
}

#[test]
fn parse_threads_comma_and_repeat() {
    assert_eq!(parse_threads("3,4").unwrap(), vec![3, 4]);
    assert_eq!(parse_threads("8").unwrap(), vec![8]);
    assert!(parse_threads("0").is_err());
    assert!(parse_threads("x").is_err());
    let args = vec![
        s("--subject-bin"),
        s("/b"),
        s("--comparator-cmd"),
        s("rg -P {t}"),
        s("--corpus"),
        s("a.gz"),
        s("--threads"),
        s("3"),
        s("--threads"),
        s("4"),
    ];
    let cfg = parse_args(&args).unwrap();
    assert_eq!(cfg.threads, vec![3, 4]);
}

#[test]
fn substitute_threads_replaces_glued_and_standalone() {
    assert_eq!(
        substitute_threads(&split_args("-d -c -P{t}"), 3),
        split_args("-d -c -P3")
    );
    assert_eq!(
        substitute_threads(&split_args("-d -c -p {t}"), 4),
        split_args("-d -c -p 4")
    );
}

#[test]
fn rapidgzip_thread_flag_hygiene() {
    // good: -P{t}
    assert!(check_thread_flag(&split_args("rapidgzip -d -c -P{t}")).is_ok());
    assert!(check_thread_flag(&split_args("rapidgzip -d -c -P 4")).is_ok());
    // bad: lowercase -p on rapidgzip is the trap.
    assert!(check_thread_flag(&split_args("rapidgzip -d -c -p 4")).is_err());
    // bad: no -P at all.
    assert!(check_thread_flag(&split_args("rapidgzip -d -c")).is_err());
    // non-rapidgzip: no constraint (gzippy uses -p legitimately).
    assert!(check_thread_flag(&split_args("/root/gz -d -c -p 4")).is_ok());
    assert!(check_thread_flag(&split_args("igzip -d -c -T 4")).is_ok());
}

#[test]
fn is_rapidgzip_detects_basename() {
    assert!(is_rapidgzip(&split_args(
        "/root/archive/rg-build-src/build/src/tools/rapidgzip -P 4"
    )));
    assert!(!is_rapidgzip(&split_args("igzip -d -c")));
}

#[test]
fn build_perf_argv_shape() {
    let argv = build_perf_argv(
        &[s("instructions"), s("cycles")],
        "8",
        &[(s("X"), s("1"))],
        &[s("/root/gz"), s("-d"), s("-c"), s("-p"), s("3")],
        "a.gz",
    );
    assert_eq!(argv[0], "stat");
    assert_eq!(argv[1], "-x");
    assert_eq!(argv[2], ",");
    assert_eq!(argv[3], "-e");
    assert_eq!(argv[4], "instructions,cycles");
    assert!(argv.contains(&s("taskset")));
    assert!(argv.contains(&s("env")));
    assert!(argv.contains(&s("X=1")));
    assert_eq!(argv.last().unwrap(), "a.gz");
}

#[test]
fn parse_perf_csv_handles_rows_comments_unsupported() {
    let txt = "\
# started on ...
4784039493,,instructions,775410000,100.00,,
2336347036,,cycles,775410000,100.00,,
<not supported>,,some_weird_event,0,0.00,,
<not counted>,,another,0,0.00,,
775.41,msec,task-clock,775410000,100.00,,
";
    let rows = parse_perf_csv(txt);
    let m: BTreeMap<_, _> = rows.into_iter().collect();
    assert_eq!(m.get("instructions").copied(), Some(4784039493.0));
    assert_eq!(m.get("cycles").copied(), Some(2336347036.0));
    assert_eq!(m.get("task-clock").copied(), Some(775.41));
    assert!(!m.contains_key("some_weird_event"));
    assert!(!m.contains_key("another"));
}

#[test]
fn median_and_spread() {
    assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
    assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), 2.5);
    assert_eq!(median(&[]), 0.0);
    // tight cluster → small relative spread.
    let tight = [10.0, 10.1, 9.9, 10.0, 10.05];
    assert!(rel_spread(&tight) < 0.05);
}

#[test]
fn categorize_amd_events() {
    assert_eq!(
        categorize("ic_fetch_stall.ic_stall_back_pressure"),
        Category::FrontendFetch
    );
    assert_eq!(categorize("de_dis_uop_queue_empty_di0"), Category::FrontendFetch);
    assert_eq!(
        categorize("de_dis_dispatch_token_stalls1.int_phy_reg_file_token_stall"),
        Category::BackendDispatchRegister
    );
    assert_eq!(categorize("branch-misses"), Category::BadSpeculation);
    assert_eq!(categorize("L1-dcache-load-misses"), Category::CacheMemory);
    assert_eq!(categorize("dTLB-load-misses"), Category::CacheMemory);
    assert_eq!(categorize("l2_cache_req_stat.ls_rd_blk_c"), Category::CacheMemory);
    assert_eq!(categorize("instructions"), Category::Neutral);
    assert!(Category::FrontendFetch.is_cycle_stall());
    assert!(Category::BackendDispatchRegister.is_cycle_stall());
    assert!(!Category::CacheMemory.is_cycle_stall());
}

fn rep(val: f64, n: usize) -> Vec<f64> {
    vec![val; n]
}

#[test]
fn assemble_rows_and_verdict_frontend_dominant() {
    // Synthetic: reproduce the ground-truth shape — back_pressure has the largest
    // per-byte EXCESS (frontend), int_phy_reg has the highest RATIO (secondary).
    let mut subj: EvMap = BTreeMap::new();
    let mut comp: EvMap = BTreeMap::new();
    let mut aa: EvMap = BTreeMap::new();
    // back_pressure: gz 11.0 vs comp 9.2 → ratio 1.20, big excess 1.8
    subj.insert(s("ic_fetch_stall.ic_stall_back_pressure"), rep(11.0, 11));
    comp.insert(s("ic_fetch_stall.ic_stall_back_pressure"), rep(9.2, 11));
    aa.insert(s("ic_fetch_stall.ic_stall_back_pressure"), rep(11.0, 11));
    // int_phy_reg: gz 0.8 vs comp 0.4 → ratio 2.0, small excess 0.4
    subj.insert(
        s("de_dis_dispatch_token_stalls1.int_phy_reg_file_token_stall"),
        rep(0.8, 11),
    );
    comp.insert(
        s("de_dis_dispatch_token_stalls1.int_phy_reg_file_token_stall"),
        rep(0.4, 11),
    );
    aa.insert(
        s("de_dis_dispatch_token_stalls1.int_phy_reg_file_token_stall"),
        rep(0.8, 11),
    );
    // a cache counter (not a cycle-stall → not in verdict ranking)
    subj.insert(s("L1-dcache-load-misses"), rep(0.5, 11));
    comp.insert(s("L1-dcache-load-misses"), rep(0.5, 11));
    aa.insert(s("L1-dcache-load-misses"), rep(0.5, 11));

    let rows = assemble_rows(&subj, &comp, &aa);
    let bp = rows
        .iter()
        .find(|r| r.event.contains("back_pressure"))
        .unwrap();
    assert!((bp.ratio - 1.1957).abs() < 0.01);
    assert!(!bp.tie);
    let cache = rows.iter().find(|r| r.event.contains("dcache")).unwrap();
    assert!(cache.tie, "identical cache counter should be a TIE");

    let v = rank_verdict(&rows).expect("verdict");
    assert_eq!(v.dominant, "frontend-fetch");
    assert!(v.top_event.contains("back_pressure"));
    assert!(v.secondary_event.contains("int_phy_reg_file"));
    assert!((v.secondary_ratio - 2.0).abs() < 0.01);
}

#[test]
fn verdict_none_when_no_cycle_stalls() {
    let mut subj: EvMap = BTreeMap::new();
    let mut comp: EvMap = BTreeMap::new();
    let aa: EvMap = BTreeMap::new();
    subj.insert(s("instructions"), rep(5.0, 11));
    comp.insert(s("instructions"), rep(5.0, 11));
    let rows = assemble_rows(&subj, &comp, &aa);
    assert!(rank_verdict(&rows).is_none());
}

#[test]
fn tie_when_within_aa_noise() {
    // gz/comp ratio 1.02 but the A/A arm drifts 5% → should be a TIE.
    let mut subj: EvMap = BTreeMap::new();
    let mut comp: EvMap = BTreeMap::new();
    let mut aa: EvMap = BTreeMap::new();
    subj.insert(s("ic_fetch_stall.ic_stall_any"), rep(10.2, 11));
    comp.insert(s("ic_fetch_stall.ic_stall_any"), rep(10.0, 11));
    // AA arm whose median drifts ~5% from the subject → apparatus noise floor
    // 0.0515 > the 0.02 gz/comp ratio ⇒ TIE.
    aa.insert(s("ic_fetch_stall.ic_stall_any"), rep(9.7, 11));
    let rows = assemble_rows(&subj, &comp, &aa);
    assert!(rows[0].tie, "within A/A noise must be a TIE");
}

#[test]
fn amd_batches_have_anchors() {
    for b in amd_batches() {
        assert!(b.events.contains(&s("instructions")));
        assert!(b.events.contains(&s("cycles")));
        assert!(b.events.len() <= 6, "batch {} too wide", b.name);
    }
}

#[test]
fn batches_for_always_appends_user_fault_batch() {
    for vendor in [Vendor::Amd, Vendor::Intel, Vendor::Unknown] {
        let bs = batches_for(vendor);
        let last = bs.last().expect("at least one batch");
        assert_eq!(last.name, "E_user_faults");
        for ev in ["instructions:u", "cycles:u", "page-faults", "minor-faults", "major-faults"] {
            assert!(last.events.contains(&s(ev)), "missing {ev} for {vendor:?}");
        }
        // hardware (PMU) part is only 4 — the rest are software, no multiplexing.
        let hw = last
            .events
            .iter()
            .filter(|e| !e.contains("faults"))
            .count();
        assert_eq!(hw, 4, "more than 4 PMU counters would multiplex");
    }
}

#[test]
fn user_kernel_split_decode_wins_overhead_faults() {
    // The ground-truth shape: gz decode is FEWER user-cycles + HIGHER user-IPC,
    // but gz FAULTS MORE → the loss is page-fault overhead, not decode.
    let uk = compute_user_kernel_split(
        // subj_cyc, subj_ucyc, comp_cyc, comp_ucyc
        1.034, 0.907, 1.000, 1.000, // gz total higher but user LOWER
        // subj_uinstr, comp_uinstr
        2.0, 1.95, // gz slightly more user instr, but at higher IPC
        // subj_pf, comp_pf
        1.738, 1.000, // gz faults 1.738x
        // minor, major
        1.700, 1.000, 0.001, 0.001,
    );
    assert!(uk.self_test_pass, "cycles:u<=cycles + faults nonzero");
    assert!(uk.user_cyc_ratio < 1.0, "gz user-mode fewer cycles");
    assert!(uk.user_ipc_ratio > 1.0, "gz user-mode higher IPC");
    assert!((uk.page_faults_ratio - 1.738).abs() < 1e-9);
    assert!(uk.subj_kernel_share > uk.comp_kernel_share, "gz more kernel share");
    assert!(uk.verdict.contains("DECODE: gz user-mode is FASTER"), "{}", uk.verdict);
    assert!(uk.verdict.contains("FAULTS MORE"), "{}", uk.verdict);
}

#[test]
fn user_kernel_split_self_test_catches_violations() {
    // cycles:u > cycles (impossible) → self-test fail.
    let bad_cyc = compute_user_kernel_split(
        1.0, 1.5, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
    );
    assert!(!bad_cyc.subj_user_le_total);
    assert!(!bad_cyc.self_test_pass);
    // zero faults → self-test fail.
    let bad_faults = compute_user_kernel_split(
        1.0, 0.9, 1.0, 0.9, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    );
    assert!(!bad_faults.faults_nonzero);
    assert!(!bad_faults.self_test_pass);
}

#[test]
fn ratio_safe_div() {
    assert_eq!(ratio(2.0, 4.0), 0.5);
    assert!(ratio(1.0, 0.0).is_nan());
}
