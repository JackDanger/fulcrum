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
    assert_eq!(
        categorize("de_dis_uop_queue_empty_di0"),
        Category::FrontendFetch
    );
    assert_eq!(
        categorize("de_dis_dispatch_token_stalls1.int_phy_reg_file_token_stall"),
        Category::BackendDispatchRegister
    );
    assert_eq!(categorize("branch-misses"), Category::BadSpeculation);
    assert_eq!(categorize("L1-dcache-load-misses"), Category::CacheMemory);
    assert_eq!(categorize("dTLB-load-misses"), Category::CacheMemory);
    assert_eq!(
        categorize("l2_cache_req_stat.ls_rd_blk_c"),
        Category::CacheMemory
    );
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
        for ev in [
            "instructions:u",
            "cycles:u",
            "page-faults",
            "minor-faults",
            "major-faults",
        ] {
            assert!(last.events.contains(&s(ev)), "missing {ev} for {vendor:?}");
        }
        // hardware (PMU) part is only 4 — the rest are software, no multiplexing.
        let hw = last.events.iter().filter(|e| !e.contains("faults")).count();
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
    assert!(
        uk.subj_kernel_share > uk.comp_kernel_share,
        "gz more kernel share"
    );
    assert!(
        uk.verdict.contains("DECODE: gz user-mode is FASTER"),
        "{}",
        uk.verdict
    );
    assert!(uk.verdict.contains("FAULTS MORE"), "{}", uk.verdict);
}

#[test]
fn user_kernel_split_self_test_catches_violations() {
    // cycles:u > cycles (impossible) → self-test fail.
    let bad_cyc =
        compute_user_kernel_split(1.0, 1.5, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0);
    assert!(!bad_cyc.subj_user_le_total);
    assert!(!bad_cyc.self_test_pass);
    // zero faults → self-test fail.
    let bad_faults =
        compute_user_kernel_split(1.0, 0.9, 1.0, 0.9, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    assert!(!bad_faults.faults_nonzero);
    assert!(!bad_faults.self_test_pass);
}

#[test]
fn ratio_safe_div() {
    assert_eq!(ratio(2.0, 4.0), 0.5);
    assert!(ratio(1.0, 0.0).is_nan());
}

// ── 2026-08-01 regression guards ────────────────────────────────────────────
//
// Every test below encodes a defect that was OBSERVED IN PRODUCTION on this
// date, on solvency, in the encoder campaign's first-ever attempt to run the
// counter layer. Each one hung or lied silently. They are watchdogged so that
// a reintroduction FAILS in seconds instead of hanging CI forever.

/// Run `f` on a worker thread; panic if it does not finish inside `secs`.
/// A SPIN or a PIPE DEADLOCK in the code under test becomes a test FAILURE
/// with a named cause, not an infinite hang.
fn with_watchdog<T: Send + 'static>(
    secs: u64,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(_) => panic!(
            "WATCHDOG: {what} did not complete within {secs}s — spin or pipe deadlock reintroduced"
        ),
    }
}

/// REGRESSION GUARD (2026-08-01, solvency): `--no-self-update` and `--compress`
/// are VALUELESS flags. This parser's loop has NO shared `i += 1` at the bottom
/// — every arm advances the index itself — while `board.rs` and `candidates.rs`
/// (the loops the one-line arm was copied from) DO have a shared increment.
/// Copying the arm without the increment made `parse_args` spin forever on the
/// first valueless flag: state R, zero children, banner-then-nothing, 6+ min on
/// a 200 KB input before it was killed. The first-ever encoder counter run died
/// here, BEFORE parse even returned.
#[test]
fn valueless_flags_terminate_the_parse_loop() {
    let cfg = with_watchdog(10, "parse_args with valueless flags", || {
        parse_args(&[
            s("--no-self-update"),
            s("--compress"),
            s("--subject-bin"),
            s("/bin/gz"),
            s("--gz-args"),
            s("-6 -c -p {t}"),
            s("--comparator-cmd"),
            s("libdeflate-gzip -6 -c"),
            s("--corpus"),
            s("a.txt"),
        ])
    })
    .expect("parse ok");
    assert!(cfg.compress);
    assert_eq!(cfg.gz_args, split_args("-6 -c -p {t}"));
}

/// REGRESSION GUARD: compress mode with subject args that pin no thread count.
/// gzippy with no `-p` uses num_cpus — a whole callgrind profile was mislabelled
/// T1 when it was T16 and the finding had to be retracted. The parser must
/// REFUSE (never warn) unless the caller declares the subject single-threaded.
#[test]
fn compress_mode_refuses_an_unpinned_subject() {
    // Watchdogged: every parse_args call carrying `--compress` spun forever
    // before the increment fix; a refusal test must fail, not hang.
    let err = with_watchdog(10, "parse_args (unpinned subject)", || {
        parse_args(&[
            s("--compress"),
            s("--subject-bin"),
            s("/bin/gz"),
            s("--gz-args"),
            s("-6 -c"),
            s("--comparator-cmd"),
            s("libdeflate-gzip -6 -c"),
            s("--corpus"),
            s("a.txt"),
        ])
    })
    .unwrap_err();
    assert!(err.contains("-p"), "refusal must name the missing pin: {err}");
    assert!(
        err.contains("--subject-single-threaded"),
        "refusal must name the escape hatch: {err}"
    );

    // The declared escape hatch lifts the refusal.
    let cfg = with_watchdog(10, "parse_args (escape hatch)", || {
        parse_args(&[
            s("--compress"),
            s("--subject-single-threaded"),
            s("--subject-bin"),
            s("/bin/gz"),
            s("--gz-args"),
            s("-6 -c"),
            s("--comparator-cmd"),
            s("libdeflate-gzip -6 -c"),
            s("--corpus"),
            s("a.txt"),
        ])
    })
    .expect("escape hatch parses");
    assert!(cfg.subject_single_threaded);

    // An explicit `-p1` pin also lifts it.
    with_watchdog(10, "parse_args (-p1 pin)", || {
        parse_args(&[
            s("--compress"),
            s("--subject-bin"),
            s("/bin/gz"),
            s("--gz-args"),
            s("-6 -c -p1"),
            s("--comparator-cmd"),
            s("libdeflate-gzip -6 -c"),
            s("--corpus"),
            s("a.txt"),
        ])
    })
    .expect("-p1 pin parses");
}

/// REGRESSION GUARD: `--compress` while --gz-args still carries `-d` (the
/// DECODE default). Forgetting --gz-args in compress mode inherits
/// "-d -c -p {t}" and measures decompression while reporting an encoder cell.
#[test]
fn compress_mode_refuses_decode_subject_args() {
    let err = with_watchdog(10, "parse_args (decode default args)", || {
        parse_args(&[
            s("--compress"),
            s("--subject-bin"),
            s("/bin/gz"),
            s("--comparator-cmd"),
            s("libdeflate-gzip -6 -c"),
            s("--corpus"),
            s("a.txt"),
        ])
    })
    .unwrap_err();
    assert!(
        err.contains("-d"),
        "refusal must name the decode-args contradiction: {err}"
    );
}

/// REGRESSION GUARD: thread-capable comparators (gzippy, pigz) must pin their
/// thread count in compress mode; single-threaded rivals (libdeflate-gzip,
/// gzip, igzip) are exempt.
#[test]
fn compress_comparator_pin_guard() {
    assert!(check_compress_comparator_pin(&split_args("libdeflate-gzip -6 -c")).is_ok());
    assert!(check_compress_comparator_pin(&split_args("gzip -6 -c")).is_ok());
    assert!(check_compress_comparator_pin(&split_args("pigz -6 -c")).is_err());
    assert!(check_compress_comparator_pin(&split_args("pigz -6 -p1 -c")).is_ok());
    assert!(check_compress_comparator_pin(&split_args("/root/gzippy/target/release/gzippy -6 -c")).is_err());
    assert!(check_compress_comparator_pin(&split_args("/root/gzippy/target/release/gzippy -6 -c -p {t}")).is_ok());
}

/// REGRESSION GUARD (2026-08-01): the compress-mode round-trip verifier piped
/// the arm's whole output through `gzip -dc` by writing it all, synchronously,
/// before reading any of the verifier's stdout. Once the verifier's stdout pipe
/// filled (~64 KiB) it stopped reading stdin, our write blocked, and the run
/// hung forever. Any real corpus (MBs compressed, MBs decompressed) deadlocks;
/// only toy inputs survive — which is exactly how the bug passed its first
/// manual check. The writer must run on its own thread (see `paired.rs`, which
/// already did this correctly).
#[test]
fn compress_verify_survives_outputs_larger_than_a_pipe_buffer() {
    // ~8 MiB of xorshift bytes: incompressible, so BOTH the compressed stream
    // (~8 MiB) and the decompressed stream (8 MiB) far exceed any pipe buffer.
    let mut state = 0x9e3779b97f4a7c15u64;
    let mut raw = Vec::with_capacity(8 << 20);
    while raw.len() < (8 << 20) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        raw.extend_from_slice(&state.to_le_bytes());
    }
    let dir = std::env::temp_dir().join(format!("fulcrum-cdtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let corpus = dir.join("pipe-deadlock.bin");
    std::fs::write(&corpus, &raw).expect("write corpus");
    let corpus_s = corpus.display().to_string();
    let want_sha = hex32(&sha256(&raw));

    let oracle = split_args("gzip -dc");
    let got = with_watchdog(120, "run_arm_sha compress round-trip on an 8 MiB corpus", move || {
        run_arm_sha("gzip", &[], &split_args("-1 -c"), &corpus_s, Some(&oracle))
    });
    let _ = std::fs::remove_file(&corpus);
    let _ = std::fs::remove_dir(&dir);
    let (sha, n) = got.expect("round-trip verify");
    assert_eq!(n, raw.len(), "verifier must yield the decompressed byte count");
    assert_eq!(sha, want_sha, "round-trip sha must equal the input sha");
}

/// The decode-mode oracle failure must TEACH the fix: running the decode-mode
/// gate on an encoder cell (oracle `gzip -dc` on a PLAIN corpus) is exactly the
/// mistake that left the counter layer unused for the whole encoder campaign.
/// The error must name `--compress`.
#[test]
fn decode_oracle_failure_names_compress_mode() {
    let dir = std::env::temp_dir().join(format!("fulcrum-cdtest-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let corpus = dir.join("plain.txt");
    std::fs::write(&corpus, b"this is not gzip data, it is the raw corpus\n").expect("write");
    let err = run_oracle(
        &split_args("gzip -dc"),
        &corpus.display().to_string(),
        false,
    )
    .unwrap_err();
    let _ = std::fs::remove_file(&corpus);
    let _ = std::fs::remove_dir(&dir);
    assert!(
        err.contains("--compress"),
        "decode-mode oracle failure on a plain corpus must point at --compress: {err}"
    );
}
